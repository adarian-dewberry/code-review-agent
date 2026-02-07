# Development Guide

Complete guide for contributing to Code Review Agent.

## Table of Contents

- [Setup](#setup)
- [Running Tests](#running-tests)
- [Code Quality](#code-quality)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Debugging](#debugging)
- [Troubleshooting](#troubleshooting)

---

## Setup

### Clone & Install

```bash
# Clone repo
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install with dev dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install
```

### Prerequisites

- Python 3.11+
- Git
- pip

### Verify Installation

```bash
# Test CLI
code-review review --help

# Test imports
python -c "from code_review_agent import CodeReviewAgent; print('✅ Installation OK')"

# Run tests
pytest --collect-only
```

---

## Running Tests

### All tests
```bash
pytest
```

### With coverage
```bash
pytest --cov=code_review_agent --cov-report=html
```

### Integration tests (calls real API)
```bash
pytest -m integration
```

### Specific Test File

```bash
pytest code_review_agent/tests/test_agent.py -v
```

### Specific Test Function

```bash
pytest code_review_agent/tests/test_agent.py::TestSecurityReview::test_detects_sql_injection -v
```

### Unit tests only (no API calls)

```bash
pytest -m "not integration"
```

---

## Code Quality

### Format Code with Black

```bash
# Format all files
black code_review_agent/

# Check without modifying
black code_review_agent/ --check

# Format specific file
black code_review_agent/agent.py
```

### Lint with Flake8

```bash
# Check all files
flake8 code_review_agent/

# Check specific file
flake8 code_review_agent/agent.py

# Show statistics
flake8 code_review_agent/ --statistics
```

### Type Check with Mypy

```bash
# Check all files
mypy code_review_agent/

# Check specific file
mypy code_review_agent/agent.py

# Generate report
mypy code_review_agent/ --html mypy-report
```

### All Quality Checks

```bash
# Run all checks
black code_review_agent/ && flake8 code_review_agent/ && mypy code_review_agent/

# Or use a script
./scripts/quality-check.sh
```

---

## Project Structure

```
code-review-agent/
├── code_review_agent/           # Main package
│   ├── __init__.py              # Package exports
│   ├── agent.py                 # Core review orchestration (200 lines)
│   ├── cli.py                   # CLI interface (100 lines)
│   ├── config.py                # Configuration management (60 lines)
│   ├── models.py                # Data models (150 lines)
│   ├── parsers.py               # Claude response parsing (200 lines)
│   ├── prompts/                 # Review prompts
│   │   ├── security.md          # Security review guidelines
│   │   ├── logic.md             # Logic review guidelines
│   │   ├── performance.md       # Performance review guidelines
│   │   └── compliance.md        # Compliance review guidelines
│   ├── utils/                   # Utilities
│   │   ├── __init__.py
│   │   └── logging.py           # Structured logging
│   └── tests/                   # Test suite
│       ├── __init__.py
│       ├── test_agent.py        # Agent tests
│       ├── test_parsers.py      # Parser tests
│       ├── test_integration.py  # Integration tests
│       ├── fixtures/
│       │   └── sample_code.py   # Test data
│
├── .github/
│   └── workflows/
│       └── code-review.yml      # GitHub Actions workflow
│
├── .vscode/                     # VS Code configuration
│   ├── settings.json            # Editor settings
│   └── launch.json              # Debug configurations
│
├── config.yaml                  # Default configuration
├── setup.py                     # Package setup
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
├── pytest.ini                   # Pytest configuration
├── mypy.ini                     # Type checking config
├── .flake8                      # Linting config
├── .gitignore                   # Git exclusions
├── README.md                    # Project documentation
├── CONTRIBUTING.md              # Contribution guidelines
├── CI_CD_GUIDE.md               # CI/CD integration guide
└── LICENSE                      # MIT License
```

### Key Files Explained

**agent.py** (~200 lines)
- `CodeReviewAgent` class
- `review()` method - main entry point
- Four review passes (security, logic, performance, compliance)
- Claude API integration

**parsers.py** (~200 lines)
- `ReviewParser` class
- `parse()` - main parsing method
- `_split_by_severity()` - split Claude response
- `_parse_issues()` - extract individual issues
- `_parse_issue_block()` - parse single issue

**models.py** (~150 lines)
- `Severity` enum
- `Issue` model
- `ReviewCategory` model
- `ReviewResult` model with `to_markdown()` method

**config.py** (~60 lines)
- `ModelConfig` - LLM settings
- `ReviewConfig` - review behavior
- `Config` - main configuration class

**cli.py** (~100 lines)
- `main()` - CLI entry point
- Argument parsing
- File vs stdin handling
- Output formatting

---

## Contributing

### Workflow

1. **Fork the repository**
   ```bash
   # On GitHub: Click "Fork"
   git clone https://github.com/YOUR_USERNAME/code-review-agent.git
   cd code-review-agent
   ```

2. **Create feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes**
   ```bash
   # Edit files, write tests
   vim code_review_agent/agent.py
   vim code_review_agent/tests/test_agent.py
   ```

4. **Run quality checks**
   ```bash
   black code_review_agent/
   flake8 code_review_agent/
   mypy code_review_agent/
   pytest code_review_agent/tests/
   ```

5. **Commit with clear message**
   ```bash
   git add .
   git commit -m "feat: add TypeScript support"
   ```

6. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   # On GitHub: Click "Create Pull Request"
   ```

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```bash
git commit -m "feat(parser): add JSON output support"
git commit -m "fix(agent): handle empty prompt responses"
git commit -m "docs: update README with examples"
git commit -m "test(cli): add argument parsing tests"
```

### What to Contribute

#### Good First Issues
- [ ] Add TypeScript code review support
- [ ] Improve response parser for edge cases
- [ ] Add caching layer (avoid re-reviewing unchanged files)
- [ ] Write additional test cases
- [ ] Improve documentation

#### Medium Issues
- [ ] Add Go/Rust/Java support
- [ ] Implement review result caching
- [ ] Add custom rule configuration
- [ ] Create VSCode extension
- [ ] Add configuration validation

#### Hard Issues
- [ ] Multi-language support (AST parsing)
- [ ] Machine learning-based issue ranking
- [ ] Review result trending/metrics
- [ ] Distributed review across multiple instances

---

## Debugging

### VS Code Debug Mode

1. **Set breakpoint** in code
   - Click line number to add red dot

2. **Run debugger**
   - Press F5 or click "Run and Debug"
   - Select configuration from dropdown

3. **Available Configurations**
   - `Python: Review File` - Debug CLI on current file
   - `Python: Review with Stdin` - Debug stdin input
   - `Python: Run Pytest` - Debug tests
   - `Python: Debug Agent` - Debug agent directly

### Command Line Debugging

```bash
# Add debug logging to config
export PYTHONPATH=.
python -m pdb -c continue code_review_agent/cli.py review test.py

# Or use print statements (pytest will show them)
def test_something():
    result = agent.review(code)
    print(f"DEBUG: {result}")  # Will print during test
    assert result.summary.critical_count == 0

# Run with output
pytest -s -v code_review_agent/tests/test_agent.py
```

### Inspect Variables

```python
# In code_review_agent/agent.py
def review(self, code: str, file_path: Optional[str] = None) -> ReviewResult:
    categories = {}
    # Add breakpoint here
    import pdb; pdb.set_trace()
    
    for category in self.config.review.enabled_categories:
        # Now you can inspect variables in debugger
        pass
```

### Test-Driven Debugging

```bash
# Create test that reproduces bug
pytest code_review_agent/tests/test_agent.py::test_bug -v

# Add breakpoint in test
# Press F5 to debug

# Fix code until test passes
```

---

## Troubleshooting

### ImportError: No module named 'code_review_agent'

```bash
# Make sure you installed in development mode
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH=.
python -m code_review_agent.cli review test.py
```

### ModuleNotFoundError: No module named 'anthropic'

```bash
# Install dependencies
pip install -e ".[dev]"

# Or manually
pip install anthropic>=0.40.0
```

### ANTHROPIC_API_KEY not found

```bash
# Set environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Verify it's set
echo $ANTHROPIC_API_KEY

# Or use .env file
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
source .env
```

### Tests fail with "rate limit" error

```bash
# Anthropic API rate limit
# Wait a minute or:
# - Reduce max_tokens in config.yaml
# - Run unit tests only: pytest -m "not integration"
```

### Mypy errors with type hints

```bash
# Some type issues are expected (library incompleteness)
# Ignore specific errors:
mypy code_review_agent/ --ignore-missing-imports

# Or add ignores to code:
from anthropic import Anthropic  # type: ignore
```

### Pre-commit hook failing

```bash
# Pre-commit hook runs code review on staged files
# If it fails:

# Option 1: Fix the issue
code-review review path/to/file.py
# Then fix issues and re-stage

# Option 2: Skip pre-commit
git commit --no-verify

# Option 3: Disable pre-commit
pre-commit uninstall
```

### Code Review Agent hanging

```bash
# If CLI hangs while waiting for response:

# Kill the process
Ctrl+C

# Check API status
# https://status.anthropic.com/

# Check network connection
curl https://api.anthropic.com/

# Increase timeout (in code_review_agent/agent.py):
response = self.client.messages.create(
    # ...
    timeout=60  # Add this
)
```

---

## Performance Tips

### Speed Up Development

```bash
# Skip integration tests (avoid API calls)
pytest -m "not integration"

# Run only changed test file
pytest code_review_agent/tests/test_agent.py

# Use pytest-watch for auto-rerun
pytest-watch

# Increase code coverage cache
pytest --cache-clear
```

### Optimize Code Review

```yaml
# In config.yaml, reduce for faster local testing:
model:
  max_tokens: 2000  # vs 4000
  
review:
  enabled_categories:
    - security      # Test only security first
```

### Profile Code

```bash
# Find bottlenecks
python -m cProfile -s cumtime code_review_agent/cli.py review test.py | head -20

# Memory profiling
pip install memory-profiler
python -m memory_profiler code_review_agent/cli.py review test.py
```

---

## Quick Reference

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Test
pytest                          # All tests
pytest -v                       # Verbose
pytest --cov                    # With coverage
pytest -m "not integration"     # Skip API calls

# Quality
black code_review_agent/        # Format
flake8 code_review_agent/       # Lint
mypy code_review_agent/         # Type check

# Debug
code-review review test.py      # Test CLI
python -m code_review_agent.cli review test.py  # Direct

# Cleanup
rm -rf .pytest_cache .mypy_cache __pycache__
```

---

## Resources

- [Anthropic API Docs](https://docs.anthropic.com/)
- [Pydantic Docs](https://docs.pydantic.dev/)
- [Pytest Docs](https://docs.pytest.org/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [Flake8 Linter](https://flake8.pycqa.org/)
- [Mypy Type Checker](https://mypy.readthedocs.io/)

---

## Getting Help

1. Check existing [GitHub Issues](https://github.com/adarian-dewberry/code-review-agent/issues)
2. Search [Discussions](https://github.com/adarian-dewberry/code-review-agent/discussions)
3. Read [CONTRIBUTING.md](CONTRIBUTING.md)
4. Ask in Pull Request comments

---

Happy coding! 🚀
