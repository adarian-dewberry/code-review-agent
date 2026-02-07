"""
STRIDE/DREAD threat modeling and SDL phase tracking for SDL governance.

STRIDE Categories:
- Spoofing: Identity verification bypass
- Tampering: Data integrity violations
- Repudiation: Lack of audit trails
- Information Disclosure: Data leaks/exposure
- Denial of Service: Resource exhaustion
- Elevation of Privilege: Unauthorized access escalation

DREAD Scoring (1-10 scale per dimension):
- Damage: How bad would an attack be?
- Reproducibility: How easy is it to reproduce?
- Exploitability: How much work to launch attack?
- Affected Users: How many people impacted?
- Discoverability: How easy to find vulnerability?

SDL Phases (A1-A5):
- A1: Security Assessment (Requirements/Design)
- A2: Threat Modeling (Architecture Review)
- A3: Secure Coding (Implementation)
- A4: Security Testing (Verification)
- A5: Security Release (Deployment)
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class STRIDECategory(str, Enum):
    """STRIDE threat modeling categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class DREADScore(BaseModel):
    """DREAD risk scoring model (1-10 per dimension)."""

    damage: int = Field(ge=1, le=10, description="Severity of damage")
    reproducibility: int = Field(ge=1, le=10, description="Ease of reproduction")
    exploitability: int = Field(ge=1, le=10, description="Effort to exploit")
    affected_users: int = Field(ge=1, le=10, description="Number of impacted users")
    discoverability: int = Field(ge=1, le=10, description="Ease of discovery")

    @property
    def total_score(self) -> int:
        """Calculate total DREAD score (5-50)."""
        return self.damage + self.reproducibility + self.exploitability + self.affected_users + self.discoverability

    @property
    def average_score(self) -> float:
        """Calculate average DREAD score (1.0-10.0)."""
        return self.total_score / 5

    @property
    def risk_level(self) -> str:
        """Determine risk level from DREAD score."""
        avg = self.average_score
        if avg >= 8.0:
            return "CRITICAL"
        elif avg >= 6.0:
            return "HIGH"
        elif avg >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"


class SDLPhase(str, Enum):
    """SDL development phases."""

    A1_ASSESSMENT = "A1: Security Assessment"
    A2_THREAT_MODEL = "A2: Threat Modeling"
    A3_SECURE_CODING = "A3: Secure Coding"
    A4_TESTING = "A4: Security Testing"
    A5_RELEASE = "A5: Security Release"


class SecurityChampionRole(str, Enum):
    """Security Champion responsibilities."""

    ARCHITECT = "Security Architect"
    CHAMPION = "Security Champion"
    EVANGELIST = "Security Evangelist"


class ThreatModel(BaseModel):
    """STRIDE threat with DREAD scoring."""

    stride_category: STRIDECategory
    description: str
    dread_score: DREADScore
    affected_components: List[str] = Field(default_factory=list)
    mitigation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None

    @property
    def risk_priority(self) -> str:
        """Get risk priority from DREAD score."""
        return self.dread_score.risk_level


class SDLGateCheck(BaseModel):
    """SDL phase gate checklist item."""

    phase: SDLPhase
    check_name: str
    status: str = Field(default="PENDING")  # PENDING, PASS, FAIL
    responsible_role: SecurityChampionRole
    evidence: Optional[str] = None
    blocker: bool = Field(default=False, description="Blocks next phase if failed")


class BSIMMActivity(BaseModel):
    """BSIMM maturity model activity."""

    domain: str  # Governance, Intelligence, SSDL, Deployment
    practice: str  # e.g., "SM1.1: Publish process", "CP1.1: Perform code review"
    level: int = Field(ge=1, le=3, description="Maturity level 1-3")
    implemented: bool = Field(default=False)
    evidence: Optional[str] = None


class SecurityChampionChecklist(BaseModel):
    """Security Champion duties per SDL phase."""

    phase: SDLPhase
    architect_duties: List[str] = Field(default_factory=list)
    champion_duties: List[str] = Field(default_factory=list)
    evangelist_duties: List[str] = Field(default_factory=list)


# SDL Phase Gate Definitions
SDL_PHASE_GATES = {
    SDLPhase.A1_ASSESSMENT: [
        SDLGateCheck(
            phase=SDLPhase.A1_ASSESSMENT,
            check_name="Security Requirements Defined",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A1_ASSESSMENT,
            check_name="Privacy Impact Assessment Complete",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A1_ASSESSMENT,
            check_name="Regulatory Compliance Mapped",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=False,
        ),
    ],
    SDLPhase.A2_THREAT_MODEL: [
        SDLGateCheck(
            phase=SDLPhase.A2_THREAT_MODEL,
            check_name="STRIDE Analysis Complete",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A2_THREAT_MODEL,
            check_name="Attack Surface Documented",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A2_THREAT_MODEL,
            check_name="DREAD Scores Assigned",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=False,
        ),
    ],
    SDLPhase.A3_SECURE_CODING: [
        SDLGateCheck(
            phase=SDLPhase.A3_SECURE_CODING,
            check_name="SAST Scans Pass (Zero Critical)",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A3_SECURE_CODING,
            check_name="SCA Dependency Check Pass",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A3_SECURE_CODING,
            check_name="Code Review Complete (Security Focus)",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=True,
        ),
    ],
    SDLPhase.A4_TESTING: [
        SDLGateCheck(
            phase=SDLPhase.A4_TESTING,
            check_name="DAST Scans Pass (Zero High)",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A4_TESTING,
            check_name="Penetration Test Complete",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A4_TESTING,
            check_name="Fuzz Testing Complete",
            responsible_role=SecurityChampionRole.CHAMPION,
            blocker=False,
        ),
    ],
    SDLPhase.A5_RELEASE: [
        SDLGateCheck(
            phase=SDLPhase.A5_RELEASE,
            check_name="Security Sign-Off Obtained",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A5_RELEASE,
            check_name="Incident Response Plan Documented",
            responsible_role=SecurityChampionRole.ARCHITECT,
            blocker=True,
        ),
        SDLGateCheck(
            phase=SDLPhase.A5_RELEASE,
            check_name="Security Runbook Published",
            responsible_role=SecurityChampionRole.EVANGELIST,
            blocker=False,
        ),
    ],
}


# Security Champion Responsibilities
CHAMPION_CHECKLISTS = {
    SDLPhase.A1_ASSESSMENT: SecurityChampionChecklist(
        phase=SDLPhase.A1_ASSESSMENT,
        architect_duties=[
            "Define security requirements and acceptance criteria",
            "Conduct privacy impact assessment (PIA)",
            "Map regulatory compliance requirements (GDPR, CCPA, HIPAA)",
            "Establish security KPIs and metrics",
        ],
        champion_duties=[
            "Identify sensitive data handling requirements",
            "Document authentication/authorization needs",
            "Review third-party integrations for security risks",
        ],
        evangelist_duties=[
            "Train team on secure development practices",
            "Publish security coding guidelines",
            "Set up security Slack channel/wiki",
        ],
    ),
    SDLPhase.A2_THREAT_MODEL: SecurityChampionChecklist(
        phase=SDLPhase.A2_THREAT_MODEL,
        architect_duties=[
            "Facilitate STRIDE threat modeling sessions",
            "Document attack surface and data flows",
            "Assign DREAD risk scores to identified threats",
            "Define mitigation strategies for high-risk threats",
        ],
        champion_duties=[
            "Identify trust boundaries in architecture",
            "Map authentication/authorization flows",
            "Document external dependencies and APIs",
        ],
        evangelist_duties=[
            "Share threat modeling results with team",
            "Create threat model diagrams for documentation",
            "Conduct lunch-and-learn on threat modeling",
        ],
    ),
    SDLPhase.A3_SECURE_CODING: SecurityChampionChecklist(
        phase=SDLPhase.A3_SECURE_CODING,
        architect_duties=[
            "Review architecture for security anti-patterns",
            "Approve cryptographic algorithm choices",
            "Define secure configuration standards",
        ],
        champion_duties=[
            "Run SAST scans (Semgrep, Bandit) in CI/CD",
            "Perform security-focused code reviews",
            "Enforce pre-commit hooks for secret detection",
            "Verify SCA dependency scans pass",
        ],
        evangelist_duties=[
            "Share secure coding examples and snippets",
            "Document common vulnerability patterns",
            "Organize security code review workshops",
        ],
    ),
    SDLPhase.A4_TESTING: SecurityChampionChecklist(
        phase=SDLPhase.A4_TESTING,
        architect_duties=[
            "Coordinate penetration testing (external)",
            "Review security test coverage",
            "Approve risk acceptance for non-critical findings",
        ],
        champion_duties=[
            "Run DAST scans (OWASP ZAP, Burp Suite)",
            "Execute fuzz testing on input validation",
            "Test authentication/authorization edge cases",
            "Verify cryptographic implementation",
        ],
        evangelist_duties=[
            "Document security testing procedures",
            "Share pentesting findings and lessons learned",
            "Create security testing checklist for team",
        ],
    ),
    SDLPhase.A5_RELEASE: SecurityChampionChecklist(
        phase=SDLPhase.A5_RELEASE,
        architect_duties=[
            "Provide security sign-off for production release",
            "Review incident response and disaster recovery plans",
            "Approve security monitoring and alerting setup",
        ],
        champion_duties=[
            "Verify all security tests passed",
            "Ensure secrets management configured (Vault, AWS Secrets)",
            "Confirm HTTPS/TLS properly configured",
            "Document security runbook for ops team",
        ],
        evangelist_duties=[
            "Publish security release notes",
            "Conduct post-release security retrospective",
            "Share security wins and improvements",
        ],
    ),
}


def default_bsimm_activities() -> List[BSIMMActivity]:
    """Return baseline BSIMM activities for dashboard reporting."""
    return [
        BSIMMActivity(domain="Governance", practice="SM1.1: Publish security process", level=1),
        BSIMMActivity(domain="Governance", practice="SM2.1: Create security portal", level=2),
        BSIMMActivity(domain="Intelligence", practice="AM1.1: Perform security research", level=1),
        BSIMMActivity(domain="Intelligence", practice="AM2.1: Create technology standards", level=2),
        BSIMMActivity(domain="SSDL", practice="CP1.1: Perform code review", level=1),
        BSIMMActivity(domain="SSDL", practice="CP2.1: Use SAST tools", level=2),
        BSIMMActivity(domain="SSDL", practice="ST1.1: Perform security testing", level=1),
        BSIMMActivity(domain="Deployment", practice="SE1.1: Deploy security monitors", level=1),
        BSIMMActivity(domain="Deployment", practice="SE2.1: Ensure host security", level=2),
    ]
