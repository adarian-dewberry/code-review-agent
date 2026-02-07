# Contributing to Code Review Agent

Thank you for your interest in contributing! Here are some guidelines:

## Development Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Code Standards

- Follow PEP 8 style guide
- Use type hints for all functions
- Write tests for new features
- Maintain >80% code coverage

## Before Submitting

1. **Format Code**: `black code_review_agent tests`
2. **Lint**: `flake8 code_review_agent tests`
3. **Type Check**: `mypy code_review_agent`
4. **Test**: `pytest --cov=code_review_agent`

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Reporting Issues

Please include:
- Python version
- OS and version
- Steps to reproduce
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
