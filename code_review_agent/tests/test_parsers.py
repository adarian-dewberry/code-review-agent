"""Tests for response parsers."""

from code_review_agent.models import Issue
from code_review_agent.parsers import parse_issues


class TestParsers:
    """Test suite for parser functions."""

    def test_parse_issues(self):
        """Test parsing issues from data."""
        issues_data = [
            {
                "severity": "warning",
                "category": "style",
                "line": 5,
                "description": "Unused variable",
                "suggestion": "Remove unused variable",
            }
        ]
        issues = parse_issues(issues_data)
        assert len(issues) == 1
        assert isinstance(issues[0], Issue)
        assert issues[0].severity == "warning"
