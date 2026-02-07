"""Unit tests for the code review agent."""

import pytest

from code_review_agent.agent import CodeReviewAgent


class TestCodeReviewAgent:
    """Test suite for CodeReviewAgent."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = CodeReviewAgent()

    def test_agent_initialization(self):
        """Test that agent initializes correctly."""
        assert self.agent is not None

    def test_review_with_sample_code(self):
        """Test reviewing sample code."""
        sample_code = "print('hello')"
        # TODO: Implement when Claude integration is ready
        # result = self.agent.review(sample_code)
        # assert result is not None
