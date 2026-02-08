---
title: Code Review Agent
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: gradio
sdk_version: "5.9.1"
python_version: "3.10"
app_file: app.py
pinned: false
license: mit
---

# Code Review Agent

Judgment-aware AI code review for security, compliance, and reliability.

![Python](https://img.shields.io/badge/python-3.10+-FAF8F4?style=flat&logo=python&logoColor=2A2926)
![Status](https://img.shields.io/badge/status-active-CD8F7A?style=flat)
![License](https://img.shields.io/badge/license-MIT-DCCCB3?style=flat)

---

## ✨ Screenshot

<p align="center">
  <img src="docs/screenshot.png" alt="Code Review Agent UI" width="800">
</p>

*Premium security console with verdict cards, severity counters, and audit-ready output.*

---

## Who this is for

| Persona | What you get |
|---------|--------------|
| **Developers** | Catch vulns early, get actionable fixes with context |
| **Security / AppSec** | OWASP/CWE mapping, deterministic structure, exportable findings |
| **Audit / Compliance** | Audit-ready verdicts, decision trails, policy versioning |
| **Engineering Managers** | Severity counts, blast radius, outcome summaries |
| **Learners** | Plain-language explanations, "why it matters" for every finding |

---

## What this is

Code Review Agent is a CLI and web-based tool that reviews code with an emphasis on
security, compliance, and operational risk.

Instead of returning opaque pass or fail results, it explains what it finds,
how confident it is, and why it matters. The goal is to support good decisions,
not replace human judgment.

This project is intended as a decision-support tool and learning resource,
not a drop-in replacement for secure development practices.

---

## Why I built this

Most AI code review tools focus on speed and coverage.

I wanted to explore a different question.

How should AI systems surface risk and uncertainty in workflows where mistakes
have real consequences?

This project treats AI output as decision support. It prioritizes clarity,
confidence, and explainability over automation for its own sake.

---

## Why people use this

People use Code Review Agent for different reasons.

- **Security and GRC engineers** use it to surface potential risk with
  clear reasoning and audit-friendly output.

- **Developers and DevOps teams** use it as a second set of eyes that
  explains *why* something might be risky, not just that it is.

- **AI practitioners** use it to understand how prompt handling,
  data exposure, and system design can introduce subtle risk.

- **Learners** use it to build intuition around secure patterns and
  decision-making without being overwhelmed.

The tool is designed to be useful even when the answer is
"this depends," not just when something is obviously wrong.

---

## Design principles

- **Judgment-aware**  
  Severity and confidence are treated as separate signals.

- **Human-in-the-loop**  
  The tool supports review, escalation, and override instead of auto-enforcement.

- **Audit-ready**  
  Findings and verdicts are structured so decisions can be explained later.

- **Risk-focused**  
  Issues are evaluated based on potential impact and blast radius, not just syntax.

- **Calm UX**  
  The interface is designed to feel supportive and clear, not alarming.

---

## How it works

The agent runs multiple passes over the code and looks at:

- Security patterns like injection and unsafe usage
- Compliance and data exposure risks
- Logic and reliability issues
- Performance considerations

Findings are grouped by root cause and presented with evidence,
suggested fixes, and an overall verdict:

**PASS**, **REVIEW REQUIRED**, or **BLOCK**.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Gradio Web UI                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │ Code     │  │ Review   │  │ Verdict  │  │ Export   │       │
│   │ Input    │→ │ Mode     │→ │ Card     │→ │ (JSON/MD)│       │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Analysis Engine                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │ Rate     │→ │ LRU      │→ │ Claude   │→ │ Finding  │       │
│   │ Limiter  │  │ Cache    │  │ API      │  │ Parser   │       │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│   Policy Engine: Block/Review rules, CWE/OWASP mapping          │
│   Blast Radius: Technical scope, Data scope, Org scope          │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Structured Output                            │
│   • Verdict + Decision ID      • Findings table                 │
│   • Severity counters          • Audit JSON                     │
│   • Top fixes                  • Confidence scores              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Try it

**Web demo**  
https://huggingface.co/spaces/adarian-dewberry/code-review-agent

**CLI**
```bash
code-review-agent review path/to/code.py
```

---

## Example output

### Verdict Card
```
┌─────────────────────────────────────────────────────┐
│ ⚠️  REVIEW REQUIRED                                 │
│                                                     │
│ Human review recommended                            │
│ Some patterns could become risky depending on usage │
│                                                     │
│ ┌────────┬────────┬────────┬────────┐              │
│ │ 0      │ 2      │ 1      │ 0      │              │
│ │Critical│ High   │ Medium │ Low    │              │
│ └────────┴────────┴────────┴────────┘              │
│                                                     │
│ 📊 3 findings · 📁 1 file · 🎯 High confidence      │
└─────────────────────────────────────────────────────┘
Decision ID: D-20260207-a1b2 · Policy: v2
```

### Top Fixes
1. **SQL Injection via f-string** · HIGH · `get_user():2` · A03:2025
2. **Prompt Injection Risk** · HIGH · `chat():2` · LLM01:2025  
3. **Missing Input Validation** · MEDIUM · `get_user():2` · CWE-20

---

## Risk frameworks

Code Review Agent maps findings to current industry standards:

- **OWASP Top 10:2025** for application security risks
- **OWASP Top 10 for LLM Applications:2025** for generative AI risks
- **CWE** identifiers for specific weakness patterns

It also includes agent-specific checks for tool use, prompt boundaries, and
action integrity. These mappings are guidance, not guarantees, and results
should be reviewed in context.

For detailed framework mapping, see [RISK_FRAMEWORKS.md](RISK_FRAMEWORKS.md).

---

## Early benchmark results

> These are early results on a small synthetic set and are not a comprehensive evaluation.

| Tool | Detection Rate | Notes |
|------|:-------------:|-------|
| Code Review Agent | 10/10 | Synthetic OWASP patterns |
| Semgrep | 4/10 | Same test set |
| ChatGPT | ~7/10 | Higher false positive rate |

For methodology and limitations, see [EVALS.md](EVALS.md).

---

## What this tool is not

- A replacement for human code review
- A legal or compliance determination engine
- A guarantee of zero risk

---

## Data handling and security

Code Review Agent processes untrusted input and interacts with external AI
model providers.

### Trust & Safety

| Aspect | How it's handled |
|--------|------------------|
| **Code storage** | Your code is not stored. Processed in memory only. |
| **Secrets** | Never submit real secrets. Use placeholders if needed. |
| **API calls** | Code is sent to Anthropic's Claude API for analysis. |
| **Caching** | LRU cache for performance. In-memory only, not persisted. |
| **Rate limiting** | Built-in protection against API abuse. |
| **Audit trail** | Decision IDs and policy versions for traceability. |

### Limitations

- Results depend on AI model capabilities and may miss edge cases
- False positives and false negatives are possible
- This is a decision-support tool, not a guarantee of security

If you are interested in how security, privacy, and evaluation are handled,
see the following documents:

- [Security policy](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Privacy overview](PRIVACY.md)
- [Evaluation notes](EVALS.md)

**Do not submit secrets or sensitive production data.**

---

## Documentation

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | CLI usage, configuration, common workflows |
| [API.md](API.md) | API endpoints and integration |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Docker, HF Spaces, environment setup |
| [DESIGN_NOTES.md](DESIGN_NOTES.md) | Architecture and decision rationale |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [ROADMAP.md](ROADMAP.md) | Planned features |

---

## Project structure

```
code-review-agent/
├── app.py                # Gradio web UI
├── examples/             # Sample vulnerable code
├── docs/                 # Additional documentation
├── config.yaml           # Default configuration
└── requirements.txt      # Dependencies
```

---

## License

This project is licensed under the MIT License.

It is provided as a learning and decision-support tool and does not
guarantee security, compliance, or correctness in production systems.

See [LICENSE](LICENSE) for full text.

---

Created by Adarian Dewberry.
