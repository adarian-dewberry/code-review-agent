# Evaluation Methodology

This document describes how Code Review Agent is evaluated,
the limitations of current benchmarks, and how to interpret results.

---

## Purpose

Evaluation serves two goals:

1. **Validate detection capability:** Does the tool catch the
   vulnerabilities it claims to catch?

2. **Track regression:** Do changes to prompts or models affect
   detection rates?

Evaluation is NOT meant to prove the tool is perfect. LLMs are
probabilistic, and results will vary.

---

## Current approach

### Test corpus

The current evaluation uses a small synthetic test set of
intentionally vulnerable code samples covering:

| Category | Files | Examples |
|----------|-------|----------|
| SQL Injection | 3 | String formatting, f-strings, concatenation |
| XSS | 2 | Reflected, stored |
| Command Injection | 2 | os.system, subprocess |
| Path Traversal | 2 | File reads, includes |
| Insecure Crypto | 2 | Weak hashing, hardcoded keys |
| SSRF | 1 | URL fetching |
| Deserialization | 1 | Pickle loads |

Total: ~15 synthetic examples

See [examples/](examples/) for the test files.

### Methodology

For each test file:

1. Submit to Code Review Agent
2. Check if the known vulnerability is identified
3. Record severity and confidence scores
4. Verify correct CWE/OWASP mapping

Results are recorded manually and compared across model versions.

---

## Current results

**Last evaluated:** 2025-06  
**Model:** gpt-4.1-mini  
**Mode:** SDL (multi-agent)

| Metric | Result |
|--------|--------|
| Detection rate (synthetic) | 95-100% |
| False positive rate | ~5% (1-2 per run) |
| Correct severity assignment | ~90% |
| Correct CWE mapping | ~85% |

These results are on a small, synthetic test set designed to
contain obvious vulnerabilities. Real-world performance will vary.

---

## Interpreting results

### What "100% detection" means

When the README mentions high detection rates, this refers to
synthetic test cases, not:
- Real-world code with subtle bugs
- Business logic vulnerabilities
- Issues requiring runtime context
- Vulnerabilities in dependencies

### What affects accuracy

| Factor | Impact |
|--------|--------|
| Code complexity | Complex code may confuse the model |
| Language | Some languages are better covered |
| Context | Isolated snippets lack surrounding code |
| Model version | Different models perform differently |
| Prompt changes | Prompt updates affect behavior |

---

## Limitations

### Synthetic vs. real-world

The test corpus contains intentionally obvious vulnerabilities.
Real codebases have:
- More subtle bugs
- More context
- Business logic that affects severity
- False leads and red herrings

### Model variability

LLM outputs are non-deterministic. Running the same test twice
may produce different results. We mitigate this by:
- Running multiple passes
- Averaging results
- Noting variance in reports

### No adversarial testing

Current evals do not include:
- Prompt injection attempts
- Adversarial code designed to evade detection
- Obfuscated vulnerabilities

This is a known gap.

---

## Planned improvements

### Near term

- [ ] Expand test corpus to 50+ examples
- [ ] Add real-world samples (anonymized)
- [ ] Automate evaluation runs
- [ ] Track results over time

### Future

- [ ] Adversarial test cases
- [ ] Cross-model comparison
- [ ] Community-contributed test cases
- [ ] Third-party audit

---

## Reproducing evaluations

To run the evaluation yourself:

```bash
# Clone the repository
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent

# Set up environment
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_api_key_here

# Review each example
for file in examples/*.py; do
  frankie review "$file"
done
```

Compare the output to the expected vulnerabilities documented
in each example file's comments.

---

## Benchmark claims policy

When discussing performance:

1. **Be specific:** "95% on synthetic SQL injection examples"
   not "95% accurate"

2. **Acknowledge limits:** All claims include caveats about
   test set size and real-world variation

3. **No guarantees:** Detection rates are informational,
   not contractual

4. **Human review required:** Results are advisory, not
   definitive security assessments

---

## Contributing test cases

We welcome contributions to the test corpus:

1. Submit a PR with a new vulnerable code sample
2. Document the expected vulnerability in comments
3. Include CWE and OWASP references
4. Avoid real production code or credentials

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Related documentation

- [README.md](README.md) - Project overview
- [DESIGN_NOTES.md](DESIGN_NOTES.md) - Architecture decisions
- [THREAT_MODEL.md](THREAT_MODEL.md) - Security analysis
