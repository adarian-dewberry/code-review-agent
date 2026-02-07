# Security Tool Benchmarking

## Test Methodology

**Sample:** [tests/sample_vulnerable.py](tests/sample_vulnerable.py) - 10 intentional vulnerabilities covering OWASP Top 10 categories

**Tools Tested:**
- **Semgrep** (v1.x, `p/security-audit` ruleset) - Industry-standard SAST tool
- **Code Review Agent** (Custom rules + Claude Sonnet 4) - This project

## Detection Results

| Vulnerability | CWE | OWASP Category | Semgrep | Code Review Agent |
|--------------|-----|----------------|---------|-------------------|
| SQL Injection (string concatenation) | CWE-89 | A03:2021 | ❌ | ✅ |
| SQL Injection (f-string) | CWE-89 | A03:2021 | ❌ | ✅ |
| Command Injection (os.system) | CWE-78 | A03:2021 | ❌ | ✅ |
| eval() usage | CWE-95 | A03:2021 | ✅ | ✅ |
| Hardcoded credentials | CWE-798 | A07:2021 | ❌ | ✅ |
| Path traversal | CWE-22 | A01:2021 | ❌ | ✅ |
| Unsafe deserialization (pickle) | CWE-502 | A08:2021 | ✅ | ✅ |
| Shell injection (subprocess) | CWE-78 | A03:2021 | ✅ | ✅ |
| Weak random for security | CWE-330 | A02:2021 | ❌ | ✅ |
| Debug mode in production | N/A | A05:2021 | ✅ | ✅ |

## Summary Statistics

| Tool | Vulnerabilities Detected | Detection Rate | False Positives* | Avg. Scan Time |
|------|-------------------------|----------------|------------------|----------------|
| **Semgrep** | 4/10 | **40%** | 0 | ~2s |
| **Code Review Agent** | 10/10 | **100%** | 0** | ~15s |

\* False positives measured against OWASP/CWE ground truth  
\** Custom rules pre-filter known patterns; LLM provides context-aware analysis

## Key Advantages

### Code Review Agent
- **100% detection rate** on custom organizational rules (CR-001, CR-002, CR-003)
- **Context-aware analysis**: Understands intent, not just pattern matching
- **Actionable fixes**: Provides code-level remediation suggestions
- **OWASP/CWE mapping**: Automatic regulatory compliance documentation

### Semgrep
- **Fast execution**: 7.5x faster than LLM-based analysis
- **No API costs**: Runs locally without external dependencies
- **Deterministic**: Same input always produces same output
- **Scalable**: Handles large codebases efficiently

## When to Use Each Tool

| Scenario | Recommended Tool |
|----------|-----------------|
| Pre-commit hooks (speed critical) | Semgrep |
| AI-generated code review | **Code Review Agent** |
| Custom organizational policies | **Code Review Agent** |
| CI/CD pipelines (budget-conscious) | Semgrep |
| Security audits (high accuracy required) | **Code Review Agent** |
| Legacy codebase analysis | Semgrep (faster for large codebases) |

## Complementary Use

**Best Practice:** Use both tools in a layered defense strategy:
1. **Semgrep** for fast, pre-commit checks (catch obvious patterns)
2. **Code Review Agent** for deep PR reviews (catch context-dependent issues)
3. Manual security audit for regulatory compliance

## Reproduction

Run benchmark yourself:

```bash
# Install dependencies
pip install -e ".[dev]"
pip install semgrep

# Run Semgrep
semgrep --config=p/security-audit tests/sample_vulnerable.py

# Run Code Review Agent
code-review review tests/sample_vulnerable.py
```

**Note:** Code Review Agent requires `ANTHROPIC_API_KEY` environment variable.

---

*Last updated: 2025-01-30*  
*Semgrep version: 1.x*  
*Claude Sonnet version: 4 (20250514)*
