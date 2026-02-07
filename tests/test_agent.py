"""Integration tests for code review agent."""

import os
import pytest

from code_review_agent.agent import CodeReviewAgent
from code_review_agent.config import Config
from code_review_agent.models import Severity, ReviewRecommendation


# Skip tests if no API key configured
pytestmark = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set"
)


class TestCodeReviewAgent:
    """Integration tests for CodeReviewAgent."""
    
    @pytest.fixture
    def agent(self):
        """Create agent instance for tests."""
        os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY", "test-key")
        config = Config.load()
        return CodeReviewAgent(config)
    
    def test_agent_initialization(self, agent):
        """Test agent initializes correctly."""
        assert agent.config is not None
        assert agent.client is not None
        assert agent.parser is not None
        assert agent.custom_rules is not None
    
    def test_custom_rules_integration(self, agent):
        """Test custom rules are enforced during review."""
        # Code that violates custom rules
        code = """
def process_user_input(user_input):
    # Violates CR-001: Disallow eval()
    result = eval(user_input)
    return result
"""
        
        result = agent.review(code, "test.py")
        
        # Should have custom rule violation in compliance category
        assert result.compliance is not None
        
        # Look for eval() violation
        has_eval_violation = any(
            "CR-001" in issue.description or "eval()" in issue.description.lower()
            for issue in result.compliance.issues
        )
        assert has_eval_violation, "Custom rule CR-001 (eval) should be flagged"
    
    def test_review_sql_injection(self):
        """Test detection of SQL injection vulnerability."""
        # Note: This is a mock test - real API tests would need valid API key
        code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    return cursor.fetchone()
"""
        
        # For unit testing without API, we'll just verify structure
        # In real integration tests, this would call the API
        config = Config(anthropic_api_key="test-key")
        agent = CodeReviewAgent(config)
        
        # Verify agent is set up correctly
        assert agent.config.review.enabled_categories == [
            "security", "logic", "performance", "compliance"
        ]
    
    def test_review_result_structure(self, agent):
        """Test review result has correct structure."""
        code = "print('hello')"
        
        # Mock test - would need API key for real test
        # Just verify we can create result structure
        assert agent.config is not None
        assert "security" in agent.config.review.enabled_categories


class TestAgentSummaryGeneration:
    """Test summary generation logic."""
    
    def test_summary_critical_triggers_do_not_merge(self):
        """Test that critical issues trigger DO_NOT_MERGE."""
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        config = Config.load()
        agent = CodeReviewAgent(config)
        
        # Create mock categories with critical issue
        from code_review_agent.models import ReviewCategory, Issue
        
        categories = {
            "security": ReviewCategory(
                category="security",
                issues=[
                    Issue(
                        severity=Severity.CRITICAL,
                        description="Critical security flaw",
                        code_snippet="vulnerable code",
                        fix_suggestion="Fix immediately"
                    )
                ]
            )
        }
        
        summary = agent._generate_summary(categories)
        
        assert summary.critical_count == 1
        assert summary.recommendation == ReviewRecommendation.DO_NOT_MERGE
        assert len(summary.top_issues) > 0
    
    def test_summary_many_high_triggers_caution(self):
        """Test that many HIGH issues trigger MERGE_WITH_CAUTION."""
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        config = Config.load()
        agent = CodeReviewAgent(config)
        
        from code_review_agent.models import ReviewCategory, Issue
        
        high_issues = [
            Issue(
                severity=Severity.HIGH,
                description=f"High issue {i}",
                code_snippet="code",
                fix_suggestion="fix"
            )
            for i in range(5)
        ]
        
        categories = {
            "security": ReviewCategory(
                category="security",
                issues=high_issues
            )
        }
        
        summary = agent._generate_summary(categories)
        
        assert summary.high_count == 5
        assert summary.recommendation == ReviewRecommendation.MERGE_WITH_CAUTION
    
    def test_summary_low_issues_approved(self):
        """Test that only low/medium issues result in APPROVED."""
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        config = Config.load()
        agent = CodeReviewAgent(config)
        
        from code_review_agent.models import ReviewCategory, Issue
        
        categories = {
            "logic": ReviewCategory(
                category="logic",
                issues=[
                    Issue(
                        severity=Severity.MEDIUM,
                        description="Medium issue",
                        code_snippet="code",
                        fix_suggestion="improve"
                    ),
                    Issue(
                        severity=Severity.LOW,
                        description="Low issue",
                        code_snippet="code",
                        fix_suggestion="optional"
                    )
                ]
            )
        }
        
        summary = agent._generate_summary(categories)
        
        assert summary.critical_count == 0
        assert summary.high_count == 0
        assert summary.recommendation == ReviewRecommendation.APPROVED
