# Code Review Agent

An automated code review tool powered by Claude AI. Reviews code for security, performance, logic, and compliance issues.

## Features

- **Automated Code Review**: Analyzes code using Claude AI
- **Multiple Review Types**: Security, performance, logic, and compliance checks
- **CLI Interface**: Easy-to-use command-line tool
- **Structured Reporting**: Clear, actionable findings

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/code-review-agent.git
cd code-review-agent

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Review a single file
code-review-agent review path/to/file.py

# Review with specific type
code-review-agent review path/to/file.py --type security
```

## Configuration

Create a `.env` file based on `.env.example`:

```bash
ANTHROPIC_API_KEY=your_api_key_here
```

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=code_review_agent
```

## Code Quality

```bash
# Format code
black code_review_agent tests

# Check linting
flake8 code_review_agent tests

# Type checking
mypy code_review_agent
```

## Project Structure

- `code_review_agent/` - Main package
  - `agent.py` - Core review agent
  - `cli.py` - Command-line interface
  - `config.py` - Configuration management
  - `models.py` - Data models
  - `parsers.py` - Response parsing
  - `prompts/` - Review prompts for different categories
  - `utils/` - Utility functions
  - `tests/` - Test suite

## License

MIT License - see LICENSE file for details

## Contributing

See CONTRIBUTING.md for guidelines
