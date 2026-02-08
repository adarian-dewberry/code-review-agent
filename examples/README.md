# Examples: Vulnerable Code Samples

This directory contains intentionally vulnerable code samples for testing Code Review Agent.

**⚠️ WARNING: These files contain security vulnerabilities by design. Do NOT use this code in production.**

## Files

### OWASP Top 10:2025

| File | Vulnerability | OWASP | Expected Verdict |
|------|---------------|-------|------------------|
| `sql_injection.py` | SQL Injection (CWE-89) | A03:2025 | 🚫 BLOCK |
| `path_traversal.py` | Path Traversal (CWE-22) | A01:2025 | 🚫 BLOCK |
| `hardcoded_secrets.py` | Hardcoded Credentials (CWE-798) | A01:2025 | 🚫 BLOCK |
| `weak_cryptography.py` | Broken Crypto (CWE-327) | A02:2025 | 🚫 BLOCK |
| `ssrf_vulnerability.py` | Server-Side Request Forgery (CWE-918) | A10:2025 | 🚫 BLOCK |

### OWASP Top 10 for LLM Applications:2025

| File | Vulnerability | LLM Top 10 | Expected Verdict |
|------|---------------|------------|------------------|
| `prompt_injection.py` | Prompt Injection | LLM01:2025 | 🚫 BLOCK |
| `llm_insecure_output.py` | Insecure Output Handling | LLM02:2025 | 🚫 BLOCK |
| `llm_excessive_agency.py` | Excessive Agency | LLM08:2025 | 🚫 BLOCK |

### Compliance

| File | Vulnerability | Framework | Expected Verdict |
|------|---------------|-----------|------------------|
| `gdpr_violation.py` | GDPR Non-compliance | Articles 5, 30, 32 | ⚠️ REVIEW_REQUIRED |

## Usage

1. Open [Code Review Agent](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)
2. Copy the contents of any file
3. Paste into the code editor
4. Click "Analyze My Code"
5. Review the findings

## Expected Results

Each file documents:
- The vulnerability type
- Expected findings (severity, confidence)
- Attack vectors
- Proper remediation

## Adding New Examples

When adding new vulnerable code samples:

1. Create a new `.py` file with a descriptive name
2. Include a module docstring explaining:
   - What vulnerability exists
   - Expected findings
   - Attack vector
   - Remediation approach
3. Keep code minimal (10-30 lines)
4. Update this README with the new file

## Testing

Use these examples to verify Code Review Agent catches:
- All OWASP Top 10:2025 vulnerabilities
- AI-specific risks (OWASP LLM Top 10:2025)
- Compliance issues (GDPR, CCPA)
- Logic bugs and performance issues

## Framework Coverage

### OWASP Top 10:2025 Coverage

| Category | Example File |
|----------|--------------|
| A01 - Broken Access Control | `path_traversal.py`, `hardcoded_secrets.py` |
| A02 - Cryptographic Failures | `weak_cryptography.py` |
| A03 - Injection | `sql_injection.py` |
| A10 - SSRF | `ssrf_vulnerability.py` |

### OWASP LLM Top 10:2025 Coverage

| Category | Example File |
|----------|--------------|
| LLM01 - Prompt Injection | `prompt_injection.py` |
| LLM02 - Insecure Output Handling | `llm_insecure_output.py` |
| LLM08 - Excessive Agency | `llm_excessive_agency.py` |
