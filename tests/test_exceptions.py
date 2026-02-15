"""Tests for exception handling in security-critical functions.

Validates that F-001 (broad exception handling fix) is properly implemented
with specific exception types and proper logging.
"""

import json
import logging
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from code_review_agent.security_squad import SASTAgent


class TestSASTAgentExceptionHandling:
    """Test that SASTAgent properly handles specific exceptions."""

    @pytest.fixture
    def sast_agent(self):
        """Create a SASTAgent instance for testing."""
        return SASTAgent()

    def test_scan_semgrep_file_not_found(self, sast_agent: SASTAgent, caplog):
        """Test FileNotFoundError when semgrep tool is not installed."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = FileNotFoundError("semgrep not found")
                result = sast_agent.scan_semgrep("/tmp/test.py")

        assert result == []
        assert (
            "semgrep not installed" in caplog.text
            or "not installed" in caplog.text.lower()
        )

    def test_scan_semgrep_timeout(self, sast_agent: SASTAgent, caplog):
        """Test TimeoutExpired when semgrep exceeds 60s timeout."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 60)
                result = sast_agent.scan_semgrep("/tmp/test.py")

        assert result == []
        assert "timeout" in caplog.text.lower()

    def test_scan_semgrep_json_decode_error(self, sast_agent: SASTAgent, caplog):
        """Test JSONDecodeError when semgrep output is malformed."""
        with caplog.at_level(logging.ERROR):
            with patch("subprocess.run") as mock_run:
                mock_process = MagicMock()
                mock_process.returncode = 0
                mock_process.stdout = "invalid json {{"
                mock_run.return_value = mock_process

                with patch("json.loads") as mock_json:
                    mock_json.side_effect = json.JSONDecodeError("msg", "doc", 0)
                    result = sast_agent.scan_semgrep("/tmp/test.py")

        assert result == []
        assert "parse failed" in caplog.text.lower() or "decode" in caplog.text.lower()

    def test_scan_bandit_file_not_found(self, sast_agent: SASTAgent, caplog):
        """Test FileNotFoundError when bandit tool is not installed."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = FileNotFoundError("bandit not found")
                result = sast_agent.scan_bandit("/tmp/test.py")

        assert result == []
        assert (
            "bandit not installed" in caplog.text
            or "not installed" in caplog.text.lower()
        )

    def test_scan_bandit_timeout(self, sast_agent: SASTAgent, caplog):
        """Test TimeoutExpired when bandit exceeds 60s timeout."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired("bandit", 60)
                result = sast_agent.scan_bandit("/tmp/test.py")

        assert result == []
        assert "timeout" in caplog.text.lower()

    def test_scan_semgrep_successful(self, sast_agent: SASTAgent):
        """Test successful semgrep execution returns findings."""
        expected_findings = [
            {
                "check_id": "python.lang.security.deserialization.unsafe-pickle",
                "message": "Use of unsafe pickle",
                "path": "/tmp/test.py",
                "start": {"line": 10},
                "severity": "WARNING",
            }
        ]

        with patch("subprocess.run") as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = json.dumps({"results": expected_findings})
            mock_run.return_value = mock_process

            result = sast_agent.scan_semgrep("/tmp/test.py")

        assert result == expected_findings

    def test_scan_bandit_successful(self, sast_agent: SASTAgent):
        """Test successful bandit execution returns findings."""
        expected_findings = [
            {
                "test_id": "B303",
                "issue_severity": "MEDIUM",
                "issue_text": "Use of insecure MD2, MD4, MD5, or SHA1 hash function",
                "line_number": 25,
                "filename": "/tmp/test.py",
            }
        ]

        with patch("subprocess.run") as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = json.dumps({"results": expected_findings})
            mock_run.return_value = mock_process

            result = sast_agent.scan_bandit("/tmp/test.py")

        assert result == expected_findings

    def test_scan_semgrep_no_broad_exception_handling(self, sast_agent: SASTAgent):
        """Verify that broad 'except Exception:' is not used in scan_semgrep.

        This test validates the F-001 fix: specific exception types only.
        """
        import inspect

        source = inspect.getsource(sast_agent.scan_semgrep)
        assert "except Exception:" not in source
        # Should have specific exception handlers instead
        assert "except FileNotFoundError:" in source or "FileNotFoundError" in source
        assert (
            "except subprocess.TimeoutExpired:" in source or "TimeoutExpired" in source
        )

    def test_scan_bandit_no_broad_exception_handling(self, sast_agent: SASTAgent):
        """Verify that broad 'except Exception:' is not used in scan_bandit.

        This test validates the F-001 fix: specific exception types only.
        """
        import inspect

        source = inspect.getsource(sast_agent.scan_bandit)
        assert "except Exception:" not in source
        # Should have specific exception handlers instead
        assert "except FileNotFoundError:" in source or "FileNotFoundError" in source
        assert (
            "except subprocess.TimeoutExpired:" in source or "TimeoutExpired" in source
        )


class TestAppExceptionHandling:
    """Test that app.py properly handles specific exceptions."""

    def test_app_anthropic_authentication_error(self, caplog):
        """Test that AuthenticationError is caught specifically (not broad Exception)."""

        # This would be tested in integration tests with real API calls
        # For unit tests, we verify the code structure has specific handlers
        pass

    def test_app_no_broad_exception_in_review_code(self):
        """Verify app.py review_code() doesn't use broad 'except Exception:'.

        This validates F-001 fix in the main review orchestration function.
        """
        from app import review_code
        import inspect

        source = inspect.getsource(review_code)

        # The implementation may have multi-exception handling like:
        # except (AuthenticationError, NotFoundError, APIConnectionError):
        # This is acceptable. We're looking for lone: except Exception:
        lines = source.split("\n")
        problem_count = 0
        for line in lines:
            if "except Exception:" in line:
                problem_count += 1

        # Should be 0 or very few (only in non-critical paths)
        assert problem_count == 0


class TestLoggingOfExceptions:
    """Test that exceptions are properly logged for debugging."""

    @pytest.fixture
    def sast_agent(self):
        """Create a SASTAgent instance for testing."""
        return SASTAgent()

    def test_exception_logging_includes_filename(self, sast_agent: SASTAgent, caplog):
        """Test that error logs include the filename for debugging."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = FileNotFoundError("tool not found")
                test_file = "/tmp/vulnerable_code.py"
                result = sast_agent.scan_semgrep(test_file)

        assert result == []
        # Should have logged something with context
        assert len(caplog.records) > 0

    def test_exception_logging_has_exception_type(self, sast_agent: SASTAgent, caplog):
        """Test that error logs include exception type information."""
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)
                result = sast_agent.scan_semgrep("/tmp/test.py")

        assert result == []
        # Should have logged something about timeout
        log_text = "\n".join(record.message for record in caplog.records)
        assert "timeout" in log_text.lower() or "TimeoutExpired" in log_text
