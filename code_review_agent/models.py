"""Data models for code review agent.

Uses Pydantic for validation and serialization.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    """Risk level for GRC analysis."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Issue(BaseModel):
    """Individual code issue with security context."""
    
    severity: Severity
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    regulation_reference: Optional[str] = None  # For compliance issues
    
    # Security-specific fields
    owasp_id: Optional[str] = None  # e.g., "A03:2021 - Injection"
    cwe_id: Optional[str] = None  # e.g., "CWE-89"
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    impact: Optional[str] = None  # Business impact explanation
    
    class Config:
        use_enum_values = True


class ReviewCategory(BaseModel):
    """Review results for a specific category (security, logic, etc.)."""
    
    category: str
    issues: List[Issue] = Field(default_factory=list)
    
    def add_issue(self, issue: Issue) -> None:
        """Add an issue to this category."""
        self.issues.append(issue)
    
    @property
    def critical_count(self) -> int:
        """Count critical issues."""
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count high-severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)


class ReviewRecommendation(str, Enum):
    """Overall review recommendation."""
    DO_NOT_MERGE = "DO_NOT_MERGE"
    MERGE_WITH_CAUTION = "MERGE_WITH_CAUTION"
    APPROVED = "APPROVED"


class ReviewSummary(BaseModel):
    """Summary of all review findings."""
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    recommendation: ReviewRecommendation
    top_issues: List[str] = Field(default_factory=list)
    
    class Config:
        use_enum_values = True


class ReviewResult(BaseModel):
    """Complete code review result with optional SDL metadata."""
    
    file_path: Optional[str] = None
    security: ReviewCategory
    logic: ReviewCategory
    performance: ReviewCategory
    compliance: ReviewCategory
    summary: ReviewSummary
    sdl_metadata: Optional[dict] = None  # Security Squad analysis results
    
    def to_markdown(self) -> str:
        """Format review as markdown report."""
        
        lines = [
            "# Code Review Report",
            ""
        ]
        
        if self.file_path:
            lines.extend([
                f"**File:** `{self.file_path}`",
                ""
            ])
        
        # Summary
        lines.extend([
            "## Summary",
            "",
            f"- **Recommendation:** `{self.summary.recommendation}`",
            f"- **Critical Issues:** {self.summary.critical_count}",
            f"- **High Issues:** {self.summary.high_count}",
            f"- **Medium Issues:** {self.summary.medium_count}",
            f"- **Low Issues:** {self.summary.low_count}",
            ""
        ])
        
        if self.summary.top_issues:
            lines.extend([
                "### Top Issues",
                ""
            ])
            for issue in self.summary.top_issues:
                lines.append(f"- {issue}")
            lines.append("")
        
        # Detailed findings
        for category in [self.security, self.logic, self.performance, self.compliance]:
            if category.issues:
                lines.extend([
                    f"## {category.category.title()} Review",
                    ""
                ])
                
                # Group by severity
                for severity in Severity:
                    severity_issues = [i for i in category.issues if i.severity == severity]
                    if severity_issues:
                        lines.extend([
                            f"### {severity.value}",
                            ""
                        ])
                        
                        for issue in severity_issues:
                            lines.append(f"**{issue.description}**")
                            
                            if issue.line_number:
                                lines.append(f"- Line: {issue.line_number}")
                            
                            if issue.code_snippet:
                                lines.extend([
                                    "- Code:",
                                    "  ```python",
                                    f"  {issue.code_snippet}",
                                    "  ```"
                                ])
                            
                            if issue.fix_suggestion:
                                lines.extend([
                                    "- Fix:",
                                    "  ```python",
                                    f"  {issue.fix_suggestion}",
                                    "  ```"
                                ])
                            
                            if issue.regulation_reference:
                                lines.append(f"- Regulation: {issue.regulation_reference}")
                            
                            lines.append("")
        
        # SDL Multi-Agent Security Squad Results
        if self.sdl_metadata:
            lines.extend([
                "---",
                "",
                "# SDL Multi-Agent Security Squad Analysis",
                ""
            ])
            
            # SDL Phase Status
            if "sdl_status" in self.sdl_metadata:
                sdl_status = self.sdl_metadata["sdl_status"]
                lines.extend([
                    "## SDL Phase Status",
                    "",
                    f"**Current Phase:** {sdl_status.get('current_phase', 'Unknown')}",
                    f"**Recommendation:** {sdl_status.get('recommendation', 'N/A')}",
                    ""
                ])
                
                # Phase Gate Checklist
                if "gate_checks" in sdl_status:
                    lines.extend([
                        "### Phase Gate Checklist",
                        ""
                    ])
                    for check in sdl_status["gate_checks"]:
                        status_icon = "✅" if check["status"] == "PASS" else "⏳"
                        blocker_tag = " [BLOCKER]" if check["blocker"] else ""
                        lines.append(f"{status_icon} **{check['check']}**{blocker_tag}")
                        lines.append(f"   - Responsible: {check['responsible']}")
                    lines.append("")
                
                # Security Champion Duties
                if "champion_duties" in sdl_status:
                    duties = sdl_status["champion_duties"]
                    lines.extend([
                        "### Security Champion Checklist",
                        ""
                    ])
                    
                    for role in ["architect", "champion", "evangelist"]:
                        if duties.get(role):
                            lines.append(f"#### {role.title()}")
                            for duty in duties[role]:
                                lines.append(f"- [ ] {duty}")
                            lines.append("")

                # SDL Phase Mapping Table
                lines.extend([
                    "### SDL Phase Mapping (A1–A5)",
                    "",
                    "| Phase | Focus | Output |",
                    "|------|-------|--------|",
                    "| A1: Security Assessment | Requirements & risk identification | Security requirements, PIA |",
                    "| A2: Threat Modeling | STRIDE analysis | Threat model + DREAD scores |",
                    "| A3: Secure Coding | SAST + code review | Secure implementation evidence |",
                    "| A4: Security Testing | DAST + fuzzing | Test evidence & fixes |",
                    "| A5: Security Release | Sign-off + monitoring | Release approval & runbook |",
                    ""
                ])
            
            # STRIDE Threat Report
            if "threat_report" in self.sdl_metadata:
                lines.extend([
                    "## STRIDE/DREAD Threat Analysis",
                    "",
                    self.sdl_metadata["threat_report"]
                ])

            # BSIMM Maturity Dashboard
            if "bsimm_dashboard" in self.sdl_metadata:
                dashboard = self.sdl_metadata["bsimm_dashboard"]
                lines.extend([
                    "## BSIMM Maturity Dashboard",
                    "",
                    "### Domain Summary",
                    "",
                    "| Domain | Implemented | Total | Completion |",
                    "|--------|-------------|-------|------------|",
                ])
                for domain, stats in dashboard.get("domain_summary", {}).items():
                    lines.append(
                        f"| {domain} | {stats.get('implemented', 0)} | {stats.get('total', 0)} | {stats.get('completion_percent', 0)}% |"
                    )
                lines.append("")

                lines.extend([
                    "### Activities",
                    "",
                    "| Domain | Practice | Level | Implemented |",
                    "|--------|----------|-------|-------------|",
                ])
                for activity in dashboard.get("activities", []):
                    implemented = "✅" if activity.get("implemented") else "⏳"
                    lines.append(
                        f"| {activity.get('domain')} | {activity.get('practice')} | L{activity.get('level')} | {implemented} |"
                    )
                lines.append("")
            
            # Agent Summary
            if "agent_summary" in self.sdl_metadata:
                summary = self.sdl_metadata["agent_summary"]
                lines.extend([
                    "## Multi-Agent Findings Summary",
                    "",
                    f"- **SAST Findings:** {summary.get('sast_findings', 0)}",
                    f"- **DAST Findings:** {summary.get('dast_findings', 0)}",
                    f"- **SCA Findings:** {summary.get('sca_findings', 0)}",
                    f"- **Total Threats:** {summary.get('total_threats', 0)}",
                    ""
                ])
        
        return "\n".join(lines)
