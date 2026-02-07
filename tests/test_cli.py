"""Tests for CLI functionality."""

import sys
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from code_review_agent.cli import main
from code_review_agent.models import (
    ReviewResult, ReviewSummary, ReviewRecommendation,
    Severity, ReviewCategory
)


@pytest.fixture
def mock_review_result():
    """Create a mock review result."""
    return ReviewResult(
        security=ReviewCategory(
            category="Security Analysis",
            issues=[]
        ),
        logic=ReviewCategory(
            category="Logic Issues",
            issues=[]
        ),
        performance=ReviewCategory(
            category="Performance",
            issues=[]
        ),
        compliance=ReviewCategory(
            category="Compliance",
            issues=[]
        ),
        summary=ReviewSummary(
            total_issues=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            recommendation=ReviewRecommendation.APPROVED,
            key_concerns=[]
        )
    )


@pytest.fixture
def mock_critical_result():
    """Create a review result with critical issues."""
    return ReviewResult(
        security=ReviewCategory(
            category="Security Analysis",
            issues=[]
        ),
        logic=ReviewCategory(
            category="Logic Issues",
            issues=[]
        ),
        performance=ReviewCategory(
            category="Performance",
            issues=[]
        ),
        compliance=ReviewCategory(
            category="Compliance",
            issues=[]
        ),
        summary=ReviewSummary(
            total_issues=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            recommendation=ReviewRecommendation.DO_NOT_MERGE,
            key_concerns=["SQL Injection found"]
        )
    )


def test_main_with_file_path(tmp_path, mock_review_result):
    """Test reviewing a file by path."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                main()
        
        mock_agent.review.assert_called_once()
        assert "APPROVE" in mock_stdout.getvalue() or "Security Analysis" in mock_stdout.getvalue()


def test_main_with_stdin(mock_review_result):
    """Test reviewing code from stdin."""
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', '--stdin']):
            with patch('sys.stdin', StringIO("print('test')")):
                with patch('sys.stdout', new_callable=StringIO):
                    main()
        
        mock_agent.review.assert_called_once()
        call_args = mock_agent.review.call_args[0]
        assert "print('test')" in call_args[0]


def test_main_file_not_found():
    """Test error handling for missing file."""
    with patch('sys.argv', ['code-review', 'review', 'nonexistent.py']):
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1
            assert "not found" in mock_stderr.getvalue().lower()


def test_main_no_input():
    """Test error when no file or stdin provided."""
    with patch('sys.argv', ['code-review', 'review']):
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1
            assert "must provide" in mock_stderr.getvalue().lower()


def test_main_ci_mode_critical(tmp_path, mock_critical_result):
    """Test CI mode exits with error on critical issues."""
    test_file = tmp_path / "test.py"
    test_file.write_text("eval(user_input)")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_critical_result
        
        with patch('sys.argv', ['code-review', 'review', '--ci-mode', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 1


def test_main_json_format(tmp_path, mock_review_result):
    """Test JSON output format."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', '--format', 'json', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                main()
        
        output = mock_stdout.getvalue()
        assert '"security"' in output or '"summary"' in output


def test_main_custom_config(tmp_path, mock_review_result):
    """Test loading custom config file."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    config_file = tmp_path / "custom_config.yaml"
    config_file.write_text("model:\n  name: claude-sonnet-4-20250514\n")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', '--config', str(config_file), str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO):
                main()
        
        mock_agent.review.assert_called_once()


def test_main_do_not_merge_exits_error(tmp_path, mock_critical_result):
    """Test normal mode exits with error on DO_NOT_MERGE."""
    test_file = tmp_path / "test.py"
    test_file.write_text("eval(user_input)")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_critical_result
        
        with patch('sys.argv', ['code-review', 'review', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 1


def test_main_data_privacy_warning(tmp_path, mock_review_result):
    """Test data privacy warning is shown in normal mode."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO):
                with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
                    main()
        
        stderr_output = mock_stderr.getvalue()
        assert "DATA PRIVACY WARNING" in stderr_output or "Anthropic" in stderr_output


def test_main_no_warning_in_ci_mode(tmp_path, mock_review_result):
    """Test data privacy warning is suppressed in CI mode."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    with patch('code_review_agent.cli.CodeReviewAgent') as MockAgent:
        mock_agent = MockAgent.return_value
        mock_agent.review.return_value = mock_review_result
        
        with patch('sys.argv', ['code-review', 'review', '--ci-mode', str(test_file)]):
            with patch('sys.stdout', new_callable=StringIO):
                with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
                    main()
        
        stderr_output = mock_stderr.getvalue()
        # Warning should not be shown in CI mode
        assert "DATA PRIVACY WARNING" not in stderr_output
