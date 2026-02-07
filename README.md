# Code Review Agent

**Automated code review for AI-powered development.** Catches security issues, logic bugs, and compliance gaps that LLMs miss.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)

## Why?

LLMs (Claude, ChatGPT) are excellent at generating code quickly. But they miss:

- **Security vulnerabilities**: Prompt injection, SQL injection, data leaks
- **Compliance issues**: Missing audit trails, PII exposure, GDPR violations
- **Logic bugs**: Edge cases, null pointers, race conditions
- **Performance problems**: N+1 queries, memory leaks, inefficient algorithms

**Code Review Agent** provides automated, multi-pass review before you commit:

1. **Security Review**: Finds prompt injection, auth bypass, data leaks
2. **Compliance Review**: Ensures GDPR, CCPA, EU AI Act compliance
3. **Logic Review**: Catches edge cases, null pointers, error handling gaps
4. **Performance Review**: Identifies scalability issues, inefficient code

---

## Quick Start

### Installation
```bash
# Clone repo
git clone https://github.com/adariandewberry/code-review-agent.git
cd code-review-agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install with dev dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install

# Set API key
export ANTHROPIC_API_KEY=your_key_here
```

### Basic Usage
```bash
# Review a file
code-review review path/to/code.py

# Review git changes
git diff main | code-review review --stdin

# CI/CD mode (fails if critical issues found)
code-review review --ci-mode path/to/code.py
```

### Example Output

```markdown
# Code Review Report

**File:** `vendor_risk_scorer.py`

## Summary

- **Recommendation:** `DO_NOT_MERGE`
- **Critical Issues:** 2
- **High Issues:** 1
- **Medium Issues:** 3

### Top Issues
- [SECURITY] SQL injection vulnerability (line 45)
- [COMPLIANCE] PII accessed without audit trail (line 78)
- [SECURITY] Missing rate limiting (line 102)

## Security Review

### CRITICAL

**SQL injection vulnerability (line 45)**
- Risk: Attacker can extract entire database by manipulating vendor_name parameter
- Fix:
```python
  # Use parameterized query
  query = "SELECT * FROM vendors WHERE name = %s"
  result = db.execute(query, (vendor_name,))
```

### HIGH

**Missing rate limiting (line 102)**
- Risk: API endpoint can be abused to exhaust Claude token budget
- Fix:
```python
  @rate_limit(calls=10, period=60)
  def score_vendor(vendor_name: str):
      ...
```

## Compliance Review

### CRITICAL

**PII accessed without audit trail (line 78)**
- Regulation: GDPR Art. 30 (Records of processing activities)
- Risk: Cannot demonstrate compliance in regulatory audit
- Fix:
```python
  audit_log.record(
      event="pii_access",
      user_id=current_user.id,
      data_accessed="vendor_contact_email",
      purpose="risk_scoring"
  )
```
```

---

## Features

- **Multi-pass Review**: Security, compliance, logic, and performance checks
- **CLI Interface**: Easy-to-use command-line tool
- **CI/CD Integration**: Fail builds with critical issues
- **Structured Output**: Markdown reports and JSON data
- **Configurable**: Custom categories and thresholds

## Configuration

Create a `.env` file based on `.env.example`:

```bash
ANTHROPIC_API_KEY=your_api_key_here
```

Override settings in `config.yaml`:

```yaml
model:
  name: "claude-sonnet-4-20250514"
  max_tokens: 4000
  temperature: 0.0

review:
  enabled_categories:
    - security
    - logic
    - performance
    - compliance
  fail_on_critical: true
  fail_on_high: false
```

## Project Structure

```
code-review-agent/
├── code_review_agent/
│   ├── agent.py              # Core review orchestration
│   ├── cli.py                # CLI interface
│   ├── config.py             # Configuration management
│   ├── models.py             # Data models (Pydantic)
│   ├── parsers.py            # Claude response parsing
│   ├── prompts/              # Review prompts by category
│   ├── utils/                # Helper utilities
│   └── tests/                # Test suite
├── config.yaml               # Default configuration
├── setup.py                  # Package setup
├── requirements.txt          # Production dependencies
├── requirements-dev.txt      # Development dependencies
└── README.md                 # Documentation
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=code_review_agent

# Format code
black code_review_agent tests

# Check linting
flake8 code_review_agent tests

# Type checking
mypy code_review_agent
```

## License

MIT License - see LICENSE file for details

## Contributing

See CONTRIBUTING.md for guidelines
