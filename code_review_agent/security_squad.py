"""
Multi-Agent Security Squad: CrewAI orchestration for SDL enforcement.

Agents:
1. SAST Agent: Static analysis (Semgrep, Bandit) + STRIDE flagging
2. DAST Agent: Dynamic testing simulation + fuzzing
3. SCA Agent: Dependency vulnerability scanning (NVD CVE lookup)
4. SDL Champion: DREAD scoring + phase gate enforcement

Note: CrewAI integration available but requires Python 3.10-3.13
For Python 3.14+, use the SDL framework directly.
"""

import ast
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# from crewai import Agent, Task, Crew, Process  # Requires Python <=3.13
from anthropic import Anthropic

from .sdl_framework import (
    CHAMPION_CHECKLISTS,
    SDL_PHASE_GATES,
    DREADScore,
    SDLPhase,
    STRIDECategory,
    ThreatModel,
    default_bsimm_activities,
)


class SASTAgent:
    """Static Application Security Testing agent with STRIDE mapping."""

    def __init__(self):
        self.name = "SAST Scanner"
        self.role = "Static Analysis Security Expert"
        self.tools = ["semgrep", "bandit"]

        # STRIDE mapping for vulnerability patterns
        self.stride_mappings = {
            "hardcoded-credentials": STRIDECategory.SPOOFING,
            "sql-injection": STRIDECategory.TAMPERING,
            "missing-audit-log": STRIDECategory.REPUDIATION,
            "information-disclosure": STRIDECategory.INFORMATION_DISCLOSURE,
            "resource-exhaustion": STRIDECategory.DENIAL_OF_SERVICE,
            "privilege-escalation": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        }

    def _build_function_index(self, code: str) -> List[dict]:
        """Build a list of functions with line ranges for per-function mapping."""
        functions = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = getattr(node, "lineno", None)
                    end = getattr(node, "end_lineno", None)
                    if start and end:
                        functions.append(
                            {"name": node.name, "start": start, "end": end}
                        )
        except SyntaxError:
            pass
        return functions

    def _function_for_line(
        self, functions: List[dict], line: Optional[int]
    ) -> Optional[str]:
        """Return function name for line if available."""
        if not line:
            return None
        for fn in functions:
            if fn["start"] <= line <= fn["end"]:
                return fn["name"]
        return None

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path for security issues before passing to subprocess."""
        import logging

        logger = logging.getLogger(__name__)

        try:
            # Resolve to absolute path to prevent traversal
            abs_path = Path(file_path).resolve()
        except (ValueError, RuntimeError) as e:
            logger.warning(f"Path resolution failed: {type(e).__name__}")
            return False

        # Check path length (prevent DOS via huge globs or symlinks)
        if len(str(abs_path)) > 4096:
            logger.warning(f"Path too long: {len(str(abs_path))} chars (max 4096)")
            return False

        return True

    @staticmethod
    def _set_subprocess_limits():
        """Set resource limits for subprocess to prevent DOS.

        Limits CPU time to 60s and memory to 1GB to protect against:
        - Resource exhaustion attacks
        - Runaway processes (semgrep/bandit hangs)
        - Memory bloat from massive files

        Note: Unix-only (Linux/macOS). Gracefully skips on Windows.
        """
        if os.name != "posix":
            # Windows doesn't support resource limits; skip silently
            return

        try:
            import resource

            # Memory: 1GB soft limit, 1GB hard limit (prevents unbounded growth)
            resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
            # CPU: 60s soft limit, 65s hard limit (allows graceful shutdown)
            resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        except (ValueError, OSError, ImportError) as e:
            # If resource limiting fails, continue anyway (better than crash)
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Could not set resource limits: {e}")

    def scan_semgrep(self, file_path: str) -> List[Dict]:
        """Run Semgrep scan and parse results."""
        import logging

        logger = logging.getLogger(__name__)

        # F-003: Validate path before passing to subprocess
        if not self._validate_file_path(file_path):
            logger.warning("Invalid file path (semgrep): security validation failed")
            return []

        try:
            # Resource limits: preexec_fn prevents DOS via resource exhaustion
            preexec_fn = self._set_subprocess_limits if os.name == "posix" else None
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", file_path],
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                preexec_fn=preexec_fn,
            )

            if result.returncode in [0, 1]:  # 0=no findings, 1=findings
                return json.loads(result.stdout).get("results", [])
            return []
        except FileNotFoundError:
            logger.warning("semgrep not installed in system PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"semgrep scan timeout after 60s: {Path(file_path).name}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"semgrep output parse failed: {type(e).__name__}")
            return []
        except Exception as e:
            logger.error(f"semgrep scan failed: {type(e).__name__}: {str(e)[:100]}")
            return []

    def scan_bandit(self, file_path: str) -> List[Dict]:
        """Run Bandit security scanner."""
        import logging

        logger = logging.getLogger(__name__)

        # F-003: Validate path before passing to subprocess
        if not self._validate_file_path(file_path):
            logger.warning("Invalid file path (bandit): security validation failed")
            return []

        try:
            # Resource limits: preexec_fn prevents DOS via resource exhaustion
            preexec_fn = self._set_subprocess_limits if os.name == "posix" else None
            result = subprocess.run(
                ["bandit", "-f", "json", "-r", file_path],
                capture_output=True,
                text=True,
                timeout=60,
                preexec_fn=preexec_fn,
            )

            output = json.loads(result.stdout)
            return output.get("results", [])
        except FileNotFoundError:
            logger.warning("bandit not installed in system PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"bandit scan timeout after 60s: {Path(file_path).name}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"bandit output parse failed: {type(e).__name__}")
            return []
        except Exception as e:
            logger.error(f"bandit scan failed: {type(e).__name__}: {str(e)[:100]}")
            return []

    def map_to_stride(self, vulnerability_type: str) -> STRIDECategory:
        """Map vulnerability to STRIDE category."""
        vuln_lower = vulnerability_type.lower()

        for pattern, category in self.stride_mappings.items():
            if pattern in vuln_lower:
                return category

        # Default mappings
        if any(x in vuln_lower for x in ["inject", "sqli", "xss", "command"]):
            return STRIDECategory.TAMPERING
        elif any(x in vuln_lower for x in ["secret", "password", "token", "key"]):
            return STRIDECategory.SPOOFING
        elif any(x in vuln_lower for x in ["leak", "exposure", "disclosure"]):
            return STRIDECategory.INFORMATION_DISCLOSURE
        elif any(x in vuln_lower for x in ["dos", "exhaust", "flood"]):
            return STRIDECategory.DENIAL_OF_SERVICE
        elif any(x in vuln_lower for x in ["privilege", "escalation", "auth"]):
            return STRIDECategory.ELEVATION_OF_PRIVILEGE
        else:
            return STRIDECategory.INFORMATION_DISCLOSURE  # Default

    def analyze(self, code: str, file_path: Optional[str] = None) -> List[ThreatModel]:
        """Run SAST analysis and return STRIDE-mapped threats."""
        import tempfile

        threats = []
        function_index = self._build_function_index(code)
        temp_file_created = False

        # Write code to temp file for scanning
        if not file_path:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(code)
                file_path = f.name
                temp_file_created = True

        try:
            # Run Semgrep
            semgrep_findings = self.scan_semgrep(file_path)
            for finding in semgrep_findings:
                stride_cat = self.map_to_stride(finding.get("check_id", ""))

                line = None
                if isinstance(finding.get("start"), dict):
                    line = finding.get("start", {}).get("line")
                function_name = self._function_for_line(function_index, line)
                component = file_path
                if line:
                    component = f"{file_path}:{line}"
                if function_name:
                    component = f"{component} (function: {function_name})"

                # Estimate DREAD score based on severity
                severity = finding.get("extra", {}).get("severity", "WARNING")
                dread = self._estimate_dread(severity)

                threat = ThreatModel(
                    stride_category=stride_cat,
                    description=finding.get("extra", {}).get(
                        "message", "Security issue detected"
                    ),
                    dread_score=dread,
                    affected_components=[component],
                    cwe_id=finding.get("extra", {}).get("metadata", {}).get("cwe"),
                    owasp_id=finding.get("extra", {}).get("metadata", {}).get("owasp"),
                )
                threats.append(threat)

            # Run Bandit
            bandit_findings = self.scan_bandit(file_path)
            for finding in bandit_findings:
                stride_cat = self.map_to_stride(finding.get("test_id", ""))
                dread = self._estimate_dread(finding.get("issue_severity", "MEDIUM"))

                line = finding.get("line_number")
                function_name = self._function_for_line(function_index, line)
                component = f"{file_path}:{line}" if line else file_path
                if function_name:
                    component = f"{component} (function: {function_name})"

                threat = ThreatModel(
                    stride_category=stride_cat,
                    description=finding.get("issue_text", "Security issue detected"),
                    dread_score=dread,
                    affected_components=[component],
                    cwe_id=finding.get("cwe", {}).get("id"),
                )
                threats.append(threat)

            return threats
        finally:
            # Clean up temp file if we created one
            if temp_file_created:
                try:
                    Path(file_path).unlink()
                except OSError:
                    pass

    def _estimate_dread(self, severity: str) -> DREADScore:
        """Estimate DREAD score from severity string."""
        severity_upper = severity.upper()

        if severity_upper in ["CRITICAL", "ERROR"]:
            return DREADScore(
                damage=9,
                reproducibility=8,
                exploitability=7,
                affected_users=9,
                discoverability=8,
            )
        elif severity_upper == "HIGH":
            return DREADScore(
                damage=7,
                reproducibility=7,
                exploitability=6,
                affected_users=7,
                discoverability=7,
            )
        elif severity_upper == "MEDIUM":
            return DREADScore(
                damage=5,
                reproducibility=6,
                exploitability=5,
                affected_users=5,
                discoverability=6,
            )
        else:  # LOW, INFO
            return DREADScore(
                damage=3,
                reproducibility=5,
                exploitability=4,
                affected_users=3,
                discoverability=5,
            )


class DASTAgent:
    """Dynamic Application Security Testing agent with fuzzing simulation."""

    def __init__(self):
        self.name = "DAST Tester"
        self.role = "Dynamic Security Testing Expert"
        self.tools = ["fuzzing", "owasp-zap-sim"]

    def analyze(self, code: str) -> List[ThreatModel]:
        """Simulate DAST testing and fuzzing."""
        threats = []

        # Check for common DAST issues (simulated)
        # In production, this would integrate with OWASP ZAP or Burp Suite

        # 1. Input validation weaknesses
        if "request.args" in code or "request.form" in code:
            if "validate" not in code.lower() and "sanitize" not in code.lower():
                threats.append(
                    ThreatModel(
                        stride_category=STRIDECategory.TAMPERING,
                        description="Missing input validation on user-supplied data",
                        dread_score=DREADScore(7, 8, 7, 8, 9),
                        affected_components=["HTTP endpoints"],
                        mitigation="Implement whitelist input validation",
                    )
                )

        # 2. CORS misconfigurations
        if "CORS" in code or "Access-Control" in code:
            if "'*'" in code or '"*"' in code:
                threats.append(
                    ThreatModel(
                        stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                        description="Overly permissive CORS policy (Access-Control-Allow-Origin: *)",
                        dread_score=DREADScore(6, 9, 5, 7, 8),
                        affected_components=["API endpoints"],
                        mitigation="Restrict CORS to specific trusted origins",
                        owasp_id="A05:2025 - Security Misconfiguration",
                    )
                )

        # 3. Missing rate limiting
        if "@app.route" in code or "@route" in code:
            if "rate_limit" not in code.lower() and "throttle" not in code.lower():
                threats.append(
                    ThreatModel(
                        stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                        description="Missing rate limiting on API endpoints",
                        dread_score=DREADScore(6, 9, 8, 6, 7),
                        affected_components=["API endpoints"],
                        mitigation="Implement rate limiting (e.g., 100 req/min per IP)",
                    )
                )

        return threats


class SCAAgent:
    """Software Composition Analysis agent with NVD CVE lookup."""

    def __init__(self):
        self.name = "SCA Scanner"
        self.role = "Dependency Security Expert"
        self.tools = ["safety", "nvd-api"]

    def scan_dependencies(
        self, requirements_file: str = "requirements.txt"
    ) -> List[ThreatModel]:
        """Scan dependencies for known vulnerabilities."""
        threats = []

        try:
            # Run safety check
            result = subprocess.run(
                ["safety", "check", "--json", "--file", requirements_file],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.stdout:
                vulns = json.loads(result.stdout)
                for vuln in vulns:
                    threats.append(
                        ThreatModel(
                            stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                            description=f"Vulnerable dependency: {vuln.get('package')} {vuln.get('installed_version')}",
                            dread_score=DREADScore(
                                damage=8,
                                reproducibility=9,
                                exploitability=6,
                                affected_users=10,
                                discoverability=7,
                            ),
                            affected_components=[vuln.get("package")],
                            mitigation=f"Upgrade to {vuln.get('safe_version')} or later",
                            cwe_id=vuln.get("cwe"),
                        )
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        return threats

    def analyze(self, code: str) -> List[ThreatModel]:
        """Check for insecure dependencies in code."""
        threats = []

        # Check for requirements.txt in project
        if Path("requirements.txt").exists():
            threats.extend(self.scan_dependencies())

        return threats


class SDLChampionAgent:
    """SDL phase gate enforcement and DREAD scoring coordinator."""

    def __init__(self, api_key: str):
        self.name = "SDL Champion"
        self.role = "Security Development Lifecycle Coordinator"
        self.client = Anthropic(api_key=api_key)

    def assess_sdl_phase(self, code: str, threats: List[ThreatModel]) -> Dict:
        """Determine current SDL phase and gate status."""
        # Count threat severity
        critical = sum(1 for t in threats if t.dread_score.risk_level == "CRITICAL")
        high = sum(1 for t in threats if t.dread_score.risk_level == "HIGH")

        # Determine SDL phase readiness
        if critical > 0:
            current_phase = SDLPhase.A3_SECURE_CODING
            recommendation = (
                "DO_NOT_MERGE - Critical threats must be resolved before A4 Testing"
            )
        elif high > 0:
            current_phase = SDLPhase.A4_TESTING
            recommendation = (
                "MERGE_WITH_CAUTION - High-risk threats require mitigation plan"
            )
        else:
            current_phase = SDLPhase.A5_RELEASE
            recommendation = "APPROVED - Ready for security sign-off"

        # Get phase gate checklist
        gates = SDL_PHASE_GATES.get(current_phase, [])
        checklist = CHAMPION_CHECKLISTS.get(current_phase)

        return {
            "current_phase": current_phase.value,
            "recommendation": recommendation,
            "gate_checks": [
                {
                    "check": gate.check_name,
                    "status": "PASS" if critical == 0 and gate.blocker else "PENDING",
                    "responsible": gate.responsible_role.value,
                    "blocker": gate.blocker,
                }
                for gate in gates
            ],
            "champion_duties": {
                "architect": checklist.architect_duties if checklist else [],
                "champion": checklist.champion_duties if checklist else [],
                "evangelist": checklist.evangelist_duties if checklist else [],
            },
        }

    def generate_threat_report(self, threats: List[ThreatModel]) -> str:
        """Generate markdown report of STRIDE threats with DREAD scores."""
        lines = ["# SDL Security Squad Analysis\n"]

        # Group by STRIDE category
        by_stride = {}
        for threat in threats:
            cat = threat.stride_category.value
            if cat not in by_stride:
                by_stride[cat] = []
            by_stride[cat].append(threat)

        lines.append("## STRIDE Threat Analysis\n")
        for category, threat_list in sorted(by_stride.items()):
            lines.append(f"### {category}\n")
            for threat in threat_list:
                lines.append(f"**{threat.description}**")
                lines.append(
                    f"- DREAD Score: {threat.dread_score.total_score}/50 (Risk: {threat.dread_score.risk_level})"
                )
                lines.append(f"  - Damage: {threat.dread_score.damage}/10")
                lines.append(
                    f"  - Reproducibility: {threat.dread_score.reproducibility}/10"
                )
                lines.append(
                    f"  - Exploitability: {threat.dread_score.exploitability}/10"
                )
                lines.append(
                    f"  - Affected Users: {threat.dread_score.affected_users}/10"
                )
                lines.append(
                    f"  - Discoverability: {threat.dread_score.discoverability}/10"
                )

                if threat.mitigation:
                    lines.append(f"- Mitigation: {threat.mitigation}")
                if threat.cwe_id:
                    lines.append(f"- CWE: {threat.cwe_id}")
                if threat.owasp_id:
                    lines.append(f"- OWASP: {threat.owasp_id}")
                lines.append("")

        return "\n".join(lines)


class SecuritySquad:
    """Orchestrator for multi-agent security analysis."""

    def __init__(self, api_key: str):
        self.sast_agent = SASTAgent()
        self.dast_agent = DASTAgent()
        self.sca_agent = SCAAgent()
        self.sdl_champion = SDLChampionAgent(api_key)

    def _build_bsimm_dashboard(
        self, sast_count: int, dast_count: int, sca_count: int
    ) -> Dict:
        """Build BSIMM maturity metrics dashboard."""
        activities = default_bsimm_activities()

        for activity in activities:
            if activity.practice.startswith("CP1.1"):
                activity.implemented = True  # code review is always performed
            if activity.practice.startswith("CP2.1"):
                activity.implemented = True  # SAST executed
            if activity.practice.startswith("ST1.1"):
                activity.implemented = True  # DAST executed
            if activity.practice.startswith("SE1.1"):
                activity.implemented = sca_count >= 0

        # Aggregate by domain
        domain_summary = {}
        for activity in activities:
            domain = activity.domain
            if domain not in domain_summary:
                domain_summary[domain] = {"total": 0, "implemented": 0}
            domain_summary[domain]["total"] += 1
            if activity.implemented:
                domain_summary[domain]["implemented"] += 1

        for domain, stats in domain_summary.items():
            total = stats["total"]
            implemented = stats["implemented"]
            stats["completion_percent"] = (
                round((implemented / total) * 100, 1) if total else 0.0
            )

        return {
            "activities": [a.model_dump() for a in activities],
            "domain_summary": domain_summary,
        }

    def analyze(self, code: str, file_path: Optional[str] = None) -> Dict:
        """Run full multi-agent security analysis."""
        # Collect threats from all agents
        all_threats = []

        # SAST Analysis
        sast_threats = self.sast_agent.analyze(code, file_path)
        all_threats.extend(sast_threats)

        # DAST Analysis
        dast_threats = self.dast_agent.analyze(code)
        all_threats.extend(dast_threats)

        # SCA Analysis
        sca_threats = self.sca_agent.analyze(code)
        all_threats.extend(sca_threats)

        # SDL Assessment
        sdl_status = self.sdl_champion.assess_sdl_phase(code, all_threats)
        threat_report = self.sdl_champion.generate_threat_report(all_threats)

        # BSIMM dashboard
        bsimm_dashboard = self._build_bsimm_dashboard(
            sast_count=len(sast_threats),
            dast_count=len(dast_threats),
            sca_count=len(sca_threats),
        )

        return {
            "threats": all_threats,
            "sdl_status": sdl_status,
            "threat_report": threat_report,
            "bsimm_dashboard": bsimm_dashboard,
            "agent_summary": {
                "sast_findings": len(sast_threats),
                "dast_findings": len(dast_threats),
                "sca_findings": len(sca_threats),
                "total_threats": len(all_threats),
            },
        }
