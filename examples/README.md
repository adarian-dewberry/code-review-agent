# Examples: Vulnerable Code Samples

This directory contains intentionally vulnerable code samples for testing Code Review Agent.

**⚠️ WARNING: These files contain security vulnerabilities by design. Do NOT use this code in production.**

## Files

| File | Vulnerability | Expected Verdict |
|------|---------------|------------------|
| `sql_injection.py` | SQL Injection (CWE-89) | 🚫 BLOCK |
| `prompt_injection.py` | LLM Prompt Injection (LLM01) | 🚫 BLOCK |
| `gdpr_violation.py` | GDPR Non-compliance | ⚠️ REVIEW_REQUIRED |
| `hardcoded_secrets.py` | Hardcoded Credentials (CWE-798) | 🚫 BLOCK |
| `path_traversal.py` | Path Traversal (CWE-22) | 🚫 BLOCK |

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
- All OWASP Top 10 vulnerabilities
- AI-specific risks (prompt injection)
- Compliance issues (GDPR, CCPA)
- Logic bugs and performance issues
