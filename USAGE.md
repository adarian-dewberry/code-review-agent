# Usage Guide

This document covers CLI usage, configuration options, and common workflows
for Frankie (Code Review Agent).

---

## Web interface

The easiest way to use Frankie is through the web demo:

https://huggingface.co/spaces/adarian-dewberry/code-review-agent

Paste your code, select review options, and click Analyze.

---

## CLI usage

Use `frankie` (preferred). The legacy `code-review` command still works.

### Basic review

```bash
frankie review path/to/code.py
```

### Review from stdin

```bash
cat myfile.py | frankie review --stdin
```

### Review git changes

```bash
git diff main | frankie review --stdin
```

### CI/CD mode

Fail the build if critical issues are found:

```bash
frankie review --ci-mode path/to/code.py
```

### SDL Multi-Agent mode

Enable full STRIDE/DREAD threat modeling:

```bash
python security_squad.py --file app.py --sdl-full
```

---

## Configuration

### Environment variables

```bash
# Required
ANTHROPIC_API_KEY=your_api_key_here

# Optional rate limiting
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW=60
```

### config.yaml

Create a `config.yaml` file to customize behavior:

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

  # Exclude patterns (glob-style)
  exclude_patterns:
    - "*.min.js"
    - "node_modules/**"
    - ".env"
```

---

## Review categories

| Category | What it checks |
|----------|----------------|
| **Security** | Injection, auth issues, crypto failures, unsafe patterns |
| **Compliance** | GDPR, CCPA, data exposure, audit requirements |
| **Logic** | Edge cases, error handling, control flow issues |
| **Performance** | N+1 queries, memory leaks, inefficient patterns |

---

## Verdict meanings

| Verdict | Meaning |
|---------|---------|
| **PASS** | No concerning patterns detected with high confidence |
| **REVIEW REQUIRED** | Potential risk depending on context |
| **BLOCK** | High-confidence, high-impact issues found |

---

## Example vulnerable code

The `examples/` directory contains intentionally vulnerable code for testing:

| File | Vulnerability |
|------|---------------|
| `sql_injection.py` | CWE-89 SQL injection patterns |
| `prompt_injection.py` | LLM prompt injection (OWASP LLM01) |
| `gdpr_violation.py` | GDPR compliance violations |
| `hardcoded_secrets.py` | CWE-798 hardcoded credentials |
| `path_traversal.py` | CWE-22 path traversal |

```bash
# Test with an example
cat examples/sql_injection.py
# Paste into the web UI or pipe to CLI
```

---

## Output formats

### Web UI

The web interface shows:
- Visual verdict card
- Findings grouped by severity
- Suggested fixes
- Audit JSON export

### CLI

The CLI outputs:
- Markdown-formatted findings
- Exit code based on severity (for CI/CD)

### JSON export

Click "Export Audit JSON" to download a structured decision record
suitable for compliance documentation.

---

## Large file handling

Very large files may be chunked or summarized depending on size limits.

When this occurs, the tool surfaces a warning so you understand the scope
of the analysis.

For best results, review focused files or diffs rather than entire codebases.

---

## Common workflows

### Daily development

1. Write or paste AI-generated code
2. Run through Frankie
3. Address critical findings before committing

### Pre-commit hook

```bash
# In .pre-commit-config.yaml
- repo: local
  hooks:
    - id: code-review
      name: Frankie
      entry: frankie review
      language: system
      types: [python]
```

### CI/CD integration

```yaml
# GitHub Actions example
- name: Security Review
  run: |
    frankie review --ci-mode src/
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed CI/CD setup.
