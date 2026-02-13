# Security Policy

This document describes how to report security vulnerabilities
and what to expect from the process.

---

## Reporting a vulnerability

If you discover a security issue in Code Review Agent, please
report it privately rather than opening a public issue.

**Email:** hello@adariandewberry.ai

**What to include:**

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

**Response timeline:**

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgment | 48 hours |
| Severity assessment | 5 business days |
| Fix timeline communicated | 10 business days |
| Public disclosure | After fix deployed |

---

## Scope

The following are in scope for security reports:

- Code execution vulnerabilities
- Prompt injection attacks
- Authentication or authorization bypasses
- Information disclosure
- Denial of service
- Cross-site scripting (XSS) in the web interface
- Unsafe handling of user input

**Out of scope:**

- Issues in upstream dependencies (report to the dependency maintainer)
- Social engineering attacks
- Physical access attacks
- Issues requiring already-compromised API keys

---

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x | Yes |
| 0.1.x | Security fixes only |
| < 0.1 | No |

---

## Security design principles

Code Review Agent follows these security principles:

1. **Defense in depth:** Multiple layers of input validation and
   output sanitization.

2. **Least privilege:** The application requests only necessary
   permissions and API scopes.

3. **Secure defaults:** Rate limiting, input size limits, and
   output sanitization are enabled by default.

4. **Transparency:** All security-relevant decisions are logged
   and auditable.

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed threat analysis.

---

## Known limitations

- **LLM outputs are probabilistic.** The model may miss some
  vulnerabilities or produce false positives. Human review
  remains essential.

- **No secrets scanning.** Code Review Agent does not scan for
  hardcoded secrets or credentials. Use dedicated tools like
  truffleHog or GitLeaks.

- **Network boundary.** The application sends code to OpenAI
  (or your configured provider) for analysis. Do not submit
  code you cannot share with your model provider.

See [PRIVACY.md](PRIVACY.md) for data handling details.

---

## Acknowledgments

We appreciate responsible disclosure. Contributors who report
valid security issues will be acknowledged here (with permission).

---

## Related documentation

- [THREAT_MODEL.md](THREAT_MODEL.md) - Detailed threat analysis
- [PRIVACY.md](PRIVACY.md) - Data handling and privacy
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
