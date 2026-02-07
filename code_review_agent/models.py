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
    """Complete code review result."""
    
    file_path: Optional[str] = None
    security: ReviewCategory
    logic: ReviewCategory
    performance: ReviewCategory
    compliance: ReviewCategory
    summary: ReviewSummary
    
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
        
        return "\n".join(lines)
