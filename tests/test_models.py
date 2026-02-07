"""Tests for data models."""

import pytest
from pydantic import ValidationError

from code_review_agent.models import (
    Severity, RiskLevel, Issue, ReviewCategory,
    ReviewSummary, ReviewRecommendation, ReviewResult
)


class TestSeverity:
    """Test Severity enum."""
    
    def test_severity_values(self):
        """Test all severity levels."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestRiskLevel:
    """Test RiskLevel enum."""
    
    def test_risk_level_values(self):
        """Test all risk levels."""
        assert RiskLevel.CRITICAL.value == "CRITICAL"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.LOW.value == "LOW"


class TestIssue:
    """Test Issue model."""
    
    def test_basic_issue(self):
        """Test creating a basic issue."""
        issue = Issue(
            severity=Severity.HIGH,
            description="SQL injection vulnerability",
            line_number=42,
            code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
            fix_suggestion="Use parameterized queries"
        )
        
        assert issue.severity == Severity.HIGH
        assert issue.description == "SQL injection vulnerability"
        assert issue.line_number == 42
    
    def test_issue_with_owasp_cwe(self):
        """Test issue with OWASP and CWE IDs."""
        issue = Issue(
            severity=Severity.CRITICAL,
            description="Command injection",
            line_number=10,
            code_snippet="os.system(user_input)",
            fix_suggestion="Use subprocess with argument list",
            owasp_id="A03:2021 - Injection",
            cwe_id="CWE-78",
            risk_level=RiskLevel.CRITICAL,
            impact="Arbitrary command execution"
        )
        
        assert issue.owasp_id == "A03:2021 - Injection"
        assert issue.cwe_id == "CWE-78"
        assert issue.risk_level == RiskLevel.CRITICAL
        assert issue.impact == "Arbitrary command execution"
    
    def test_issue_optional_fields(self):
        """Test issue with optional fields as None."""
        issue = Issue(
            severity=Severity.LOW,
            description="Minor code smell",
            code_snippet="x = 1",
            fix_suggestion="Rename variable"
        )
        
        assert issue.line_number is None
        assert issue.owasp_id is None
        assert issue.cwe_id is None
        assert issue.risk_level == RiskLevel.MEDIUM  # Default value
        assert issue.impact is None


class TestReviewCategory:
    """Test ReviewCategory model."""
    
    def test_empty_category(self):
        """Test creating empty review category."""
        category = ReviewCategory(category="security")
        
        assert category.category == "security"
        assert len(category.issues) == 0
        assert category.critical_count == 0
        assert category.high_count == 0
    
    def test_category_with_issues(self):
        """Test category with multiple issues."""
        issues = [
            Issue(
                severity=Severity.CRITICAL,
                description="Issue 1",
                code_snippet="code1",
                fix_suggestion="Fix 1"
            ),
            Issue(
                severity=Severity.HIGH,
                description="Issue 2",
                code_snippet="code2",
                fix_suggestion="Fix 2"
            ),
            Issue(
                severity=Severity.HIGH,
                description="Issue 3",
                code_snippet="code3",
                fix_suggestion="Fix 3"
            ),
        ]
        
        category = ReviewCategory(
            category="security",
            issues=issues
        )
        
        assert len(category.issues) == 3
        assert category.critical_count == 1
        assert category.high_count == 2


class TestReviewSummary:
    """Test ReviewSummary model."""
    
    def test_approved_summary(self):
        """Test summary with APPROVED recommendation."""
        summary = ReviewSummary(
            critical_count=0,
            high_count=0,
            medium_count=2,
            low_count=3,
            info_count=1,
            recommendation=ReviewRecommendation.APPROVED,
            top_issues=[]
        )
        
        assert summary.recommendation == ReviewRecommendation.APPROVED
        assert summary.critical_count == 0
        assert summary.high_count == 0
    
    def test_do_not_merge_summary(self):
        """Test summary with DO_NOT_MERGE recommendation."""
        summary = ReviewSummary(
            critical_count=2,
            high_count=5,
            medium_count=3,
            low_count=1,
            info_count=0,
            recommendation=ReviewRecommendation.DO_NOT_MERGE,
            top_issues=[
                "[SECURITY] SQL injection vulnerability",
                "[SECURITY] Command injection risk"
            ]
        )
        
        assert summary.recommendation == ReviewRecommendation.DO_NOT_MERGE
        assert summary.critical_count == 2
        assert len(summary.top_issues) == 2


class TestReviewResult:
    """Test ReviewResult model."""
    
    def test_complete_review_result(self):
        """Test creating complete review result."""
        security = ReviewCategory(category="security", issues=[])
        logic = ReviewCategory(category="logic", issues=[])
        performance = ReviewCategory(category="performance", issues=[])
        compliance = ReviewCategory(category="compliance", issues=[])
        
        summary = ReviewSummary(
            critical_count=1,
            high_count=2,
            medium_count=0,
            low_count=0,
            info_count=0,
            recommendation=ReviewRecommendation.MERGE_WITH_CAUTION,
            top_issues=["[SECURITY] Critical issue"]
        )
        
        result = ReviewResult(
            file_path="test.py",
            security=security,
            logic=logic,
            performance=performance,
            compliance=compliance,
            summary=summary
        )
        
        assert result.file_path == "test.py"
        assert result.security.category == "security"
        assert result.logic.category == "logic"
        assert result.summary.recommendation == ReviewRecommendation.MERGE_WITH_CAUTION
    
    def test_review_result_optional_file_path(self):
        """Test review result without file path."""
        result = ReviewResult(
            security=ReviewCategory(category="security"),
            logic=ReviewCategory(category="logic"),
            performance=ReviewCategory(category="performance"),
            compliance=ReviewCategory(category="compliance"),
            summary=ReviewSummary(
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                recommendation=ReviewRecommendation.APPROVED,
                top_issues=[]
            )
        )
        
        assert result.file_path is None
    
    def test_to_markdown_with_file_path(self):
        """Test markdown formatting with file path."""
        result = ReviewResult(
            file_path="example.py",
            security=ReviewCategory(category="security", issues=[]),
            logic=ReviewCategory(category="logic", issues=[]),
            performance=ReviewCategory(category="performance", issues=[]),
            compliance=ReviewCategory(category="compliance", issues=[]),
            summary=ReviewSummary(
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                recommendation=ReviewRecommendation.APPROVED,
                top_issues=[]
            )
        )
        
        markdown = result.to_markdown()
        assert "# Code Review Report" in markdown
        assert "**File:** `example.py`" in markdown
        assert "**Recommendation:** `APPROVED`" in markdown
    
    def test_to_markdown_without_file_path(self):
        """Test markdown formatting without file path."""
        result = ReviewResult(
            security=ReviewCategory(category="security", issues=[]),
            logic=ReviewCategory(category="logic", issues=[]),
            performance=ReviewCategory(category="performance", issues=[]),
            compliance=ReviewCategory(category="compliance", issues=[]),
            summary=ReviewSummary(
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                recommendation=ReviewRecommendation.APPROVED,
                top_issues=[]
            )
        )
        
        markdown = result.to_markdown()
        assert "# Code Review Report" in markdown
        assert "**File:**" not in markdown
    
    def test_to_markdown_with_issues(self):
        """Test markdown formatting with issues."""
        security_issue = Issue(
            severity=Severity.CRITICAL,
            description="SQL injection",
            line_number=42,
            code_snippet="cursor.execute(query)",
            fix_suggestion="Use parameterized queries",
            owasp_id="A03:2021",
            cwe_id="CWE-89"
        )
        
        result = ReviewResult(
            security=ReviewCategory(category="security", issues=[security_issue]),
            logic=ReviewCategory(category="logic", issues=[]),
            performance=ReviewCategory(category="performance", issues=[]),
            compliance=ReviewCategory(category="compliance", issues=[]),
            summary=ReviewSummary(
                critical_count=1,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                recommendation=ReviewRecommendation.DO_NOT_MERGE,
                top_issues=["SQL injection"]
            )
        )
        
        markdown = result.to_markdown()
        assert "## Security Review" in markdown
        assert "SQL injection" in markdown
        assert "Line: 42" in markdown
        assert "Use parameterized queries" in markdown
    
    def test_to_markdown_with_top_issues(self):
        """Test markdown includes top issues section."""
        result = ReviewResult(
            security=ReviewCategory(category="security", issues=[]),
            logic=ReviewCategory(category="logic", issues=[]),
            performance=ReviewCategory(category="performance", issues=[]),
            compliance=ReviewCategory(category="compliance", issues=[]),
            summary=ReviewSummary(
                critical_count=2,
                high_count=3,
                medium_count=0,
                low_count=0,
                info_count=0,
                recommendation=ReviewRecommendation.DO_NOT_MERGE,
                top_issues=[
                    "SQL injection vulnerability",
                    "Command injection risk",
                    "Hardcoded credentials"
                ]
            )
        )
        
        markdown = result.to_markdown()
        assert "### Top Issues" in markdown
        assert "SQL injection vulnerability" in markdown
        assert "Command injection risk" in markdown
        assert "Hardcoded credentials" in markdown

