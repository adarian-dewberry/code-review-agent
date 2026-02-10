# Security Review Policies (v1.0.0)

> **Governance-Ready AI Code Review**  
> Version: 1.0.0 | Updated: 2026-02-09 | Owner: Adarian Dewberry

---

## Quick Reference: Enforcement Rules

| Rule ID | Description | Trigger Condition | Action |
|---------|-------------|-------------------|--------|
| **BR-001** | Block merge on critical vulnerabilities | CRITICAL @ ≥0.8 confidence | ❌ Fail CI, block PR merge |
| **BR-002** | Block merge on high severity | HIGH @ ≥0.95 confidence | ❌ Fail CI, block PR merge |
| **RR-001** | Require human review | HIGH @ ≥0.7 confidence | ⚠️ Warning comment, require approval |
| **WARN-001** | Warning comment | MEDIUM @ ≥0.6 confidence | 💡 Informational comment |

---

## Configuration via Environment Variables

```yaml
env:
  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  BLOCK_THRESHOLD: "critical:0.8,high:0.95"
  REVIEW_THRESHOLD: "high:0.7"
```

CLI usage:
```bash
code-review review app.py --block-threshold "critical:0.8,high:0.95"
```

---

## Executive Summary

The **Code Review Agent Policy v1** provides a structured governance framework that maps AI-driven security detections to industry standards including **OWASP Top 10**, **CWE**, and the **NIST AI Risk Management Framework**. Every "BLOCK" decision is grounded in verifiable risk metrics and produces an audit-ready justification record.

---

## 1. Purpose and Scope

### 1.1 Purpose

This policy enforces a "Security-First" approach to the Software Development Lifecycle (SDLC). The Agent evaluates all submitted code against established security frameworks to prevent the introduction of high-impact vulnerabilities into production environments.

### 1.2 Scope

This policy applies to:
- All code submitted for automated review
- AI-generated code from tools like GitHub Copilot, ChatGPT, Claude
- Human-written code requiring security validation
- Code destined for production, staging, or shared environments

### 1.3 Exclusions

This policy does NOT replace:
- Professional security audits (pentesting, red team exercises)
- Legal compliance reviews (GDPR DPIAs, HIPAA assessments)
- Human code review for business logic and architecture decisions

---

## 2. Audit Criteria (Detection Logic)

### 2.1 Block Rules (Automatic BLOCK Verdict)

The Agent triggers a **BLOCK** status for any finding meeting these criteria:

| Rule ID | Category | Trigger Condition | Standards Mapping |
|---------|----------|-------------------|-------------------|
| BR-001 | CRITICAL Severity | Confidence ≥ 0.8 | CWE Top 25, OWASP A01-A10 |

### 2.2 Review Rules (REVIEW_REQUIRED Verdict)

| Rule ID | Category | Trigger Condition | Standards Mapping |
|---------|----------|-------------------|-------------------|
| RR-001 | HIGH Severity | Confidence ≥ 0.7 | CWE, OWASP |
| RR-002 | CRITICAL Severity | Confidence < 0.8 | CWE, OWASP |

---

## 3. Vulnerability Categories

### 3.1 Injection Flaws

| CWE | Name | Detection Pattern | Risk Level |
|-----|------|-------------------|------------|
| CWE-89 | SQL Injection | Unparameterized queries, string concatenation with user input | CRITICAL |
| CWE-78 | OS Command Injection | Unsanitized input in `subprocess`, `os.system` | CRITICAL |
| CWE-79 | Cross-Site Scripting (XSS) | Unescaped user input in HTML output | HIGH |
| CWE-94 | Code Injection | Dynamic code execution with `eval()`, `exec()` | CRITICAL |

**OWASP Mapping:** A03:2021 – Injection

### 3.2 AI-Specific Risks

| Category | Detection Pattern | Risk Level | Framework |
|----------|-------------------|------------|-----------|
| Prompt Injection | Direct string interpolation in LLM prompts | CRITICAL | NIST AI RMF |
| Instruction Override | User input without instruction hierarchy | HIGH | OWASP LLM Top 10 |
| Model Manipulation | Unvalidated prompt construction | MEDIUM | ISO/IEC 42001 |

**Standards:** NIST AI RMF (Govern, Map, Measure, Manage), OWASP LLM Top 10 (LLM01: Prompt Injection)

### 3.3 Broken Access Control

| CWE | Name | Detection Pattern | Risk Level |
|-----|------|-------------------|------------|
| CWE-798 | Hardcoded Credentials | API keys, passwords in source code | CRITICAL |
| CWE-200 | Information Exposure | Excessive data in responses (`SELECT *`) | MEDIUM |
| CWE-284 | Improper Access Control | Missing authentication checks | HIGH |

**OWASP Mapping:** A01:2021 – Broken Access Control

### 3.4 Resource Management

| CWE | Name | Detection Pattern | Risk Level |
|-----|------|-------------------|------------|
| CWE-772 | Missing Resource Release | Unclosed database connections, file handles | MEDIUM |
| CWE-400 | Resource Exhaustion | Unbounded loops, missing limits | MEDIUM |
| CWE-404 | Improper Resource Shutdown | Missing `finally` blocks, context managers | LOW |

**OWASP Mapping:** A05:2021 – Security Misconfiguration

---

## 4. Risk Rating Methodology

### 4.1 Severity Levels

| Level | Definition | Response Time | Example |
|-------|------------|---------------|---------|
| CRITICAL | Immediate exploitation possible | Block deployment | SQL Injection with direct DB access |
| HIGH | Exploitation requires minimal effort | Review within 24h | Hardcoded API keys |
| MEDIUM | Exploitation requires specific conditions | Review within 7 days | Excessive data exposure |
| LOW | Minor security improvement | Address in next sprint | Missing input validation |

### 4.2 Confidence Scoring

| Score | Meaning | Action |
|-------|---------|--------|
| 0.9 - 1.0 | Definite vulnerability | Automatic BLOCK |
| 0.7 - 0.89 | High probability | REVIEW_REQUIRED |
| 0.5 - 0.69 | Possible issue | Flag for human review |
| < 0.5 | Low confidence | Informational only |

### 4.3 Blast Radius Analysis

Every HIGH/CRITICAL finding includes impact estimation across three dimensions:

| Dimension | Values | Description |
|-----------|--------|-------------|
| **Technical Scope** | function → module → service → cross-service | How far can exploitation spread? |
| **Data Scope** | none → internal → customer → pii → regulated | What data is at risk? |
| **Organizational Scope** | single-team → multi-team → external-customers → regulators | Who is affected? |

**Example:**
```
SQL Injection in get_user():
- Technical: service (full database access)
- Data: pii (users table contains PII)
- Organizational: external-customers (data breach notification required)
```

---

## 5. Decision Accountability

### 5.1 Decision Record Schema

Every verdict generates an audit-ready JSON record:

```json
{
  "schema_version": "1.0",
  "decision_id": "D-20260207-014d",
  "timestamp_utc": "2026-02-07T05:47:50.922Z",
  "verdict": "BLOCK",
  "policy": {
    "policy_version": "v1",
    "block_rules": [
      {
        "rule_id": "BR-001",
        "description": "Block if any CRITICAL with confidence >= 0.8",
        "triggered": true
      }
    ]
  },
  "decision_drivers": [
    {
      "finding_id": "F-001",
      "title": "SQL Injection via String Formatting",
      "severity": "CRITICAL",
      "confidence": 1.0,
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "location": "get_user():2",
      "why_it_matters": [
        "Allows arbitrary SQL execution",
        "Could expose entire users table",
        "Common attack vector"
      ]
    }
  ],
  "override": {
    "allowed": true,
    "status": "none",
    "approver": null,
    "justification": null
  }
}
```

### 5.2 Override Workflow

BLOCK decisions may be overridden with:

1. **Approver:** Named individual with authority (e.g., Security Lead)
2. **Justification:** Written rationale explaining why risk is acceptable
3. **Expiration:** Optional time-bound override (e.g., "valid until 2026-03-01")
4. **Audit Trail:** All overrides logged with timestamp and approver

---

## 6. Remediation Requirements

### 6.1 BLOCK Resolution

Before a BLOCK can be converted to PASS:

1. **Technical Fix:** Implementation of secure coding pattern
2. **Validation:** Re-scan of corrected code
3. **Documentation:** Brief note on fix applied (optional)

### 6.2 Secure Coding Patterns

| Vulnerability | Insecure Pattern | Secure Pattern |
|---------------|------------------|----------------|
| SQL Injection | `f"SELECT * FROM users WHERE id = {user_id}"` | `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))` |
| Prompt Injection | `f"User says: {user_input}"` | Structured prompting with instruction hierarchy |
| Hardcoded Secrets | `API_KEY = "sk-..."` | `API_KEY = os.getenv("API_KEY")` |
| Resource Leak | `conn = db.connect()` | `with db.connect() as conn:` |

---

## 7. Compliance Mapping

### 7.1 Regulatory Frameworks

| Framework | Relevant Controls | Agent Coverage |
|-----------|-------------------|----------------|
| **SOC 2** | CC6.1 (Logical Access), CC7.2 (System Monitoring) | Policy-based blocking, audit trails |
| **ISO 27001** | A.14.2 (Secure Development) | Automated security review |
| **GDPR** | Art. 32 (Security of Processing) | PII exposure detection |
| **PCI-DSS** | Req. 6.5 (Secure Coding) | Injection, auth bypass detection |
| **HIPAA** | §164.312 (Technical Safeguards) | Data exposure controls |

### 7.2 AI Governance Frameworks

| Framework | Relevant Requirements | Agent Coverage |
|-----------|----------------------|----------------|
| **NIST AI RMF** | GOVERN 1.3, MAP 3.1 | Policy versioning, risk categorization |
| **ISO/IEC 42001** | 6.1.4, 8.4 | AI-specific risk detection |
| **EU AI Act** | Art. 9 (Risk Management) | Prompt injection detection |
| **OWASP LLM Top 10** | LLM01-LLM10 | AI vulnerability patterns |

---

## 8. Limitations and Disclaimers

### 8.1 What This Policy Does NOT Cover

- **Business Logic Errors:** The agent detects security patterns, not domain-specific logic flaws
- **Architecture Decisions:** Microservices design, database schema, API design are out of scope
- **Performance Optimization:** Beyond security-relevant performance issues
- **Legal Advice:** Findings are technical; consult legal counsel for compliance decisions

### 8.2 False Positive/Negative Rates

- **False Positives:** Expected rate < 10% for CRITICAL findings
- **False Negatives:** LLM-based detection may miss novel attack patterns
- **Recommendation:** Always combine with human review for critical systems

### 8.3 Model Limitations

- **Context Window:** Large files may be truncated, potentially missing vulnerabilities
- **Training Cutoff:** May not recognize very recent vulnerability patterns
- **Prompt Dependency:** Detection quality depends on prompt engineering

---

## 9. Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-02-07 | Initial policy framework | Adarian Dewberry |

---

## 10. References

- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [ISO/IEC 42001:2023 AI Management Systems](https://www.iso.org/standard/81230.html)

---

**Document Control**

- **Classification:** Public
- **Review Cycle:** Quarterly
- **Next Review:** 2026-05-07
- **Owner:** Adarian Dewberry
- **Contact:** [GitHub](https://github.com/adarian-dewberry) | [LinkedIn](https://linkedin.com/in/adariandewberry)
