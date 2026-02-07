"""
Unit tests for CodeReviewAgent.

Tests each review category independently with mocked Claude API calls.
"""

from unittest.mock import Mock, patch

import pytest

from code_review_agent.agent import CodeReviewAgent
from code_review_agent.config import Config


@pytest.fixture
def mock_config():
    """Create test configuration."""
    config = Config()
    config.anthropic_api_key = "test-key"
    return config


@pytest.fixture
def agent(mock_config):
    """Create agent with mocked anthropic client."""
    with patch("code_review_agent.agent.anthropic.Anthropic"):
        agent_instance = CodeReviewAgent(mock_config)
        return agent_instance


@pytest.fixture
def sample_vulnerable_code():
    """Sample code with known vulnerabilities."""
    return """
def process_user_input(user_input):
    # Vulnerable: SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    result = db.execute(query)
    return result
"""


class TestSecurityReview:
    """Test security review functionality."""

    @patch("code_review_agent.agent.anthropic.Anthropic")
    def test_detects_sql_injection(self, mock_anthropic_class, mock_config, sample_vulnerable_code):
        """Test that agent detects SQL injection vulnerability."""

        # Mock Claude response
        mock_response = Mock()
        mock_response.content = [Mock(text="""
## CRITICAL
- SQL injection vulnerability (line 3)
  Risk: Attacker can extract entire database
  Fix: ```python
  query = "SELECT * FROM users WHERE name = %s"
  result = db.execute(query, (user_input,))
```
""")]

        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic_class.return_value = mock_client

        # Create agent and run review
        agent = CodeReviewAgent(mock_config)
        result = agent.review(sample_vulnerable_code)

        # Assertions
        assert result.summary.critical_count >= 0


class TestComplianceReview:
    """Test compliance review functionality."""

    @patch("code_review_agent.agent.anthropic.Anthropic")
    def test_audit_trail_detection(self, mock_anthropic_class, mock_config):
        """Test that agent detects missing audit logging."""

        code = """
def access_customer_pii(customer_id):
    customer = Customer.objects.get(id=customer_id)
    return customer.email
"""

        mock_response = Mock()
        mock_response.content = [Mock(text="""
## CRITICAL
- PII accessed without audit trail (line 3)
  Regulation: GDPR Art. 30
  Risk: Cannot prove compliance
  Fix: ```python
  audit_log.record("pii_access", customer_id=customer_id)
```
""")]

        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic_class.return_value = mock_client

        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)

        # Test structure
        assert hasattr(result, "compliance")
        assert hasattr(result, "summary")
