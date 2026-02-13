# Contributing to Code Review Agent

Thanks for considering a contribution. This project is a solo effort
right now, but thoughtful contributions are welcome.

---

## Ways to contribute

- **Bug reports:** Found something broken? Open an issue.
- **Feature ideas:** Have a suggestion? I'd love to hear it.
- **Documentation:** Typos, clarifications, examples.
- **Test cases:** New vulnerable code samples for the test corpus.
- **Code:** Bug fixes, improvements, new features.

---

## Development setup

```bash
# Clone and set up
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## Code standards

Nothing too strict, but please:

- Follow PEP 8 style guide
- Use type hints for functions
- Write tests for new features
- Keep functions focused and readable

---

## Before submitting

```bash
# Format
black code_review_agent tests

# Lint
flake8 code_review_agent tests

# Type check
mypy code_review_agent

# Test
pytest --cov=code_review_agent
```

Don't worry if you can't run all of these. I'll help clean things
up during review.

---

## Pull request process

1. Fork the repository
2. Create a branch (`git checkout -b feature/your-idea`)
3. Make your changes
4. Commit with a clear message
5. Push and open a PR

I'll review within a few days. If it's a larger change, consider
opening an issue first to discuss the approach.

---

## Contributing test cases

The test corpus in `examples/` is small. Contributions welcome:

1. Add a new vulnerable code file
2. Document the vulnerability in comments
3. Include CWE and OWASP references
4. Make sure it's synthetic (no real credentials or production code)

See [EVALS.md](EVALS.md) for context on how tests are used.

---

## Reporting issues

When filing a bug, please include:

- Python version (`python --version`)
- OS and version
- Steps to reproduce
- What you expected vs. what happened
- Any error messages

---

## Security issues

For security vulnerabilities, please email hello@adariandewberry.ai
instead of opening a public issue. See [SECURITY.md](SECURITY.md).

---

## Code of conduct

Be kind. Be constructive. We're all here to learn and build
something useful.

---

## License

By contributing, you agree that your contributions will be
licensed under the MIT License.

---

## Questions?

Open an issue or reach out. Happy to help.
