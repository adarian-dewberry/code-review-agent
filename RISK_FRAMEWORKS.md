# Risk Frameworks Reference

This document maps Code Review Agent's detection capabilities
to industry-standard security frameworks.

---

## OWASP Top 10:2025

The OWASP Top 10 represents the most critical web application
security risks. Code Review Agent maps findings to these categories.

| ID | Category | Coverage | Notes |
|----|----------|----------|-------|
| A01:2025 | Broken Access Control | Partial | Detects obvious authz issues in code |
| A02:2025 | Cryptographic Failures | Good | Weak algorithms, hardcoded keys |
| A03:2025 | Injection | Strong | SQL, command, LDAP, XPath, etc. |
| A04:2025 | Insecure Design | Limited | Requires context beyond code |
| A05:2025 | Security Misconfiguration | Partial | Debug flags, default creds in code |
| A06:2025 | Vulnerable Components | None | Use SCA tools for dependencies |
| A07:2025 | Auth Failures | Partial | Obvious auth bugs in code |
| A08:2025 | Data Integrity Failures | Partial | Deserialization, unsigned data |
| A09:2025 | Logging Failures | Limited | Missing logging patterns |
| A10:2025 | SSRF | Good | URL construction patterns |

**Recommendation:** Pair Code Review Agent with:
- SCA tools for A06 (Dependabot, Snyk)
- DAST for A04, A05 (OWASP ZAP)
- Manual review for A04

---

## OWASP Top 10 for LLM Applications:2025

This framework addresses risks specific to applications using
large language models. It's relevant both to Code Review Agent
as a tool and to code it reviews that uses LLMs.

| ID | Category | Self-Assessment | Detection |
|----|----------|-----------------|-----------|
| LLM01 | Prompt Injection | Mitigated | Can detect in reviewed code |
| LLM02 | Insecure Output Handling | Mitigated | Can detect in reviewed code |
| LLM03 | Training Data Poisoning | N/A | Not applicable |
| LLM04 | Model Denial of Service | Mitigated (rate limits) | N/A |
| LLM05 | Supply Chain | Partial | N/A |
| LLM06 | Sensitive Info Disclosure | Documented | Can detect patterns |
| LLM07 | Insecure Plugin Design | N/A | Can review plugin code |
| LLM08 | Excessive Agency | Mitigated (advisory only) | N/A |
| LLM09 | Overreliance | Documented | N/A |
| LLM10 | Model Theft | N/A | N/A |

### How we address LLM risks

**LLM01 - Prompt Injection:**
- User code treated as data, not instructions
- Strong delimiters in prompts
- Multi-agent verification (SDL mode)
- See [THREAT_MODEL.md](THREAT_MODEL.md#t1-prompt-injection-via-submitted-code)

**LLM02 - Insecure Output Handling:**
- Model output sanitized before rendering
- No raw HTML in output
- Markdown safe mode

**LLM06 - Sensitive Info Disclosure:**
- Clear warnings about secrets in documentation
- No code stored after processing
- Users control deployment

**LLM08 - Excessive Agency:**
- Tool is advisory only
- No automated actions (no auto-commits, no deployments)
- Human must act on findings

**LLM09 - Overreliance:**
- Documentation emphasizes human review
- Confidence scores encourage skepticism
- Limitations clearly stated

---

## CWE (Common Weakness Enumeration)

Code Review Agent maps findings to CWE identifiers where possible.

### Frequently detected CWEs

| CWE | Name | Example |
|-----|------|---------|
| CWE-89 | SQL Injection | `f"SELECT * FROM users WHERE id={id}"` |
| CWE-79 | Cross-site Scripting | `innerHTML = userInput` |
| CWE-78 | OS Command Injection | `os.system(f"ping {host}")` |
| CWE-22 | Path Traversal | `open(f"/data/{filename}")` |
| CWE-327 | Broken Crypto | `hashlib.md5(password)` |
| CWE-502 | Deserialization | `pickle.loads(data)` |
| CWE-918 | SSRF | `requests.get(user_url)` |
| CWE-798 | Hardcoded Credentials | `password = "admin123"` |
| CWE-259 | Hard-coded Password | Similar to CWE-798 |
| CWE-330 | Insufficient Randomness | `random.random()` for security |

### CWE accuracy

CWE mapping is best-effort. The LLM infers the appropriate CWE
based on the vulnerability pattern. Accuracy is approximately
85% on the synthetic test set.

For authoritative CWE information: [cwe.mitre.org](https://cwe.mitre.org)

---

## CVE (Common Vulnerabilities and Exposures)

Code Review Agent does not check for specific CVEs. It analyzes
code patterns, not known vulnerability databases.

For CVE checking, use:
- Dependabot
- Snyk
- OWASP Dependency-Check
- Trivy

---

## NIST Cybersecurity Framework

Code Review Agent supports several NIST CSF functions:

| Function | Category | Support |
|----------|----------|---------|
| Identify | Asset Management | Code inventory via review |
| Protect | Data Security | Detects data exposure patterns |
| Detect | Anomalies | Identifies vulnerability patterns |
| Respond | Analysis | Provides findings for response |
| Recover | N/A | Not applicable |

---

## SDL (Security Development Lifecycle)

Code Review Agent's SDL mode implements a multi-agent review
inspired by Microsoft's SDL phases:

| SDL Phase | Agent | Focus |
|-----------|-------|-------|
| Threat Modeling | Threat Scout | Attack surface analysis |
| Static Analysis | Code Auditor | Vulnerability detection |
| Compliance | Compliance Checker | Policy adherence |
| Risk Assessment | Risk Assessor | Severity and blast radius |
| Final Review | Final Reviewer | Synthesis and verdict |

---

## Using framework mappings

### In audit reports

Exported decision records include OWASP and CWE references:

```json
{
  "decision_drivers": [
    {
      "finding_id": "F-001",
      "title": "SQL Injection",
      "cwe": "CWE-89",
      "owasp": "A03:2025"
    }
  ]
}
```

### For compliance

When reporting to compliance teams:

1. Export the audit record
2. Reference the OWASP/CWE mappings
3. Document the human review decision
4. Note any override rationale

### For remediation

Use framework references to:

1. Find authoritative remediation guidance
2. Link to organizational policies
3. Prioritize by framework category
4. Track coverage across the organization

---

## Framework version tracking

| Framework | Version | Last Updated |
|-----------|---------|--------------|
| OWASP Top 10 | 2025 | 2025 |
| OWASP LLM Top 10 | 2025 | 2025 |
| CWE | 4.13+ | Ongoing |
| NIST CSF | 2.0 | 2024 |

---

## Related documentation

- [THREAT_MODEL.md](THREAT_MODEL.md) - Security analysis
- [EVALS.md](EVALS.md) - Evaluation methodology
- [DESIGN_NOTES.md](DESIGN_NOTES.md) - Architecture decisions
