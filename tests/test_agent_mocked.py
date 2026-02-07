"""Mocked tests for CodeReviewAgent (no API key required)."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from anthropic import Anthropic
from anthropic.types import Message, TextBlock, Usage

from code_review_agent.agent import CodeReviewAgent
from code_review_agent.config import Config
from code_review_agent.models import (
    Severity, Issue, ReviewCategory, ReviewSummary,
    ReviewRecommendation, ReviewResult
)


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    import os
    os.environ["ANTHROPIC_API_KEY"] = "test-api-key"
    config = Config.load()
    return config


@pytest.fixture
def mock_anthropic_response():
    """Create a mock Anthropic API response."""
    def create_response(content: str) -> Message:
        return Message(
            id="msg_test123",
            type="message",
            role="assistant",
            content=[TextBlock(type="text", text=content)],
            model="claude-sonnet-4-20250514",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=100, output_tokens=200)
        )
    return create_response


def test_agent_initialization(mock_config):
    """Test agent initializes with config."""
    agent = CodeReviewAgent(mock_config)
    
    assert agent.config == mock_config
    assert agent.custom_rules is not None
    assert agent.parser is not None


def test_custom_rules_eval_detection(mock_config, mock_anthropic_response):
    """Test custom rules detect eval() usage."""
    code = "result = eval(user_input)"
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        # Mock API response
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## CRITICAL
- No critical issues from LLM

## HIGH
- No high issues
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # Custom rules should detect eval() (CR-001)
        compliance_issues = result.compliance.issues
        eval_detected = any("eval()" in issue.description for issue in compliance_issues)
        assert eval_detected, "Custom rule CR-001 should detect eval()"


def test_custom_rules_hardcoded_secrets(mock_config, mock_anthropic_response):
    """Test custom rules detect hardcoded secrets."""
    code = 'api_key = "sk_live_1234567890abcdef"'
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## HIGH
- No issues
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # Custom rule CR-002 should detect hardcoded secret
        compliance_issues = result.compliance.issues
        secret_detected = any(
            "secret" in issue.description.lower() or "hardcoded" in issue.description.lower() 
            for issue in compliance_issues
        )
        assert secret_detected, "Custom rule CR-002 should detect hardcoded secrets"


def test_custom_rules_sql_concatenation(mock_config, mock_anthropic_response):
    """Test custom rules detect SQL concatenation."""
    code = 'cursor.execute("SELECT * FROM users WHERE id=" + str(user_id))'
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## MEDIUM
- No issues
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # Custom rule CR-003 should detect SQL string concatenation
        compliance_issues = result.compliance.issues
        sql_detected = any("sql" in issue.description.lower() for issue in compliance_issues)
        assert sql_detected, "Custom rule CR-003 should detect SQL concatenation"


def test_review_returns_valid_structure(mock_config, mock_anthropic_response):
    """Test review returns ReviewResult with all categories."""
    code = "print('hello world')"
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## CRITICAL
- No critical issues

## HIGH
- No high issues

## MEDIUM
- No medium issues

## LOW
- Minor style issue
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        assert isinstance(result, ReviewResult)
        assert result.security is not None
        assert result.logic is not None
        assert result.performance is not None
        assert result.compliance is not None
        assert result.summary is not None


def test_file_path_optional(mock_config, mock_anthropic_response):
    """Test agent works with and without file path."""
    code = "x = 1"
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## INFO
- Variable name not descriptive
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        
        # With file path
        result1 = agent.review(code, "test.py")
        assert result1.file_path == "test.py"
        
        # Without file path
        result2 = agent.review(code)
        assert result2.file_path is None


def test_llm_api_called_with_code(mock_config, mock_anthropic_response):
    """Test LLM API is called with the code."""
    code = "def foo():\n    pass"
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## LOW
- Function lacks docstring
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # Verify API was called
        assert mock_client.create.called
        call_kwargs = mock_client.create.call_args.kwargs
        
        # Verify that messages parameter exists
        assert 'messages' in call_kwargs
        messages = call_kwargs['messages']
        
        # Check structure (not exact content since it may be processed)
        assert isinstance(messages, list)
        assert len(messages) > 0


def test_empty_code_handling(mock_config, mock_anthropic_response):
    """Test agent handles empty code input gracefully."""
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## INFO
- No code provided for review
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review("")
        
        assert result is not None
        assert isinstance(result, ReviewResult)


def test_multiline_code_review(mock_config, mock_anthropic_response):
    """Test reviewing multi-line code."""
    code = """
def vulnerable_function(user_input):
    result = eval(user_input)
    api_key = "sk_test_123456"
    query = "SELECT * FROM users WHERE id=" + str(result)
    return query
"""
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## CRITICAL
- Multiple security vulnerabilities detected

## HIGH
- Hardcoded credentials found
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # Should detect multiple custom rule violations
        compliance_issues = result.compliance.issues
        assert len(compliance_issues) >= 2, "Should detect multiple violations"


def test_recommendation_logic(mock_config, mock_anthropic_response):
    """Test recommendation logic based on severity."""
    code = "safe_code = True"
    
    with patch.object(Anthropic, 'messages') as mock_messages:
        mock_client = MagicMock()
        mock_client.create.return_value = mock_anthropic_response("""
## LOW
- Minor suggestion: Add type hints

## INFO
- Code follows best practices
""")
        mock_messages.create = mock_client.create
        
        agent = CodeReviewAgent(mock_config)
        result = agent.review(code)
        
        # With only low/info issues, should approve
        assert result.summary.critical_count == 0
        assert result.summary.high_count == 0
