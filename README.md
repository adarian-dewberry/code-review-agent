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

<div align="center">

# 🐺 Frankie - AI Security Code Review Agent

### *Learn secure code patterns through AI-powered review*

[![v2.0 Homelab Edition](https://img.shields.io/badge/v2.0-Homelab%20Edition-brightgreen.svg)](RELEASE_NOTES.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Gradio 5.x](https://img.shields.io/badge/gradio-5.x-orange.svg)](https://gradio.app/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![HuggingFace Space](https://img.shields.io/badge/%F0%9F%A4%97-HuggingFace%20Space-yellow)](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)

**Multi-pass security review • OWASP 2025 mapping • Blast radius analysis • Audit-ready JSON**

[🚀 Live Demo](https://huggingface.co/spaces/adarian-dewberry/code-review-agent) • [📖 Documentation](USAGE.md) • [🛡️ Policies](POLICIES.md) • [📋 Release Notes](RELEASE_NOTES.md)

---

</div>

## 🎯 Key Features

- **Multi-Pass Security Analysis** – Three-stage review (summary → detailed findings → fixes) with confidence scoring
- **OWASP 2025 Alignment** – Findings mapped to OWASP Top 10 and CWE categories for compliance tracking
- **Blast Radius Analysis** – Impact assessment showing which systems/data could be affected by each vulnerability
- **Audit-Ready JSON** – Structured decision records with 30-day retention for governance and compliance
- **Frankie the Wolf** – Interactive mascot that guides you through reviews with real-time status updates
- **AI-Assisted Coding Friendly** – Built specifically for developers using GitHub Copilot and Claude

## What This Project Is

This is an **assistive security code review tool** designed for developers working with AI-assisted coding. It helps surface common security risks without requiring deep security expertise, while producing structured outputs that security and governance teams can audit and document.

It does not replace secure development practices, human code review, or professional security assessment. It is meant to support them.

## Why This Exists

I noticed something: a lot of developers write insecure code not because they don't care, but because they don't understand *why* something is insecure or how to fix it. They're vibing, learning as they go, trying to build things. That's not a failure—that's normal.

I wanted to build a tool that **explains** instead of just warns. That shows reasoning. That admits uncertainty. That helps you learn *why* something matters, not just that it's "bad."

I also wanted to understand: how does AI actually help with this? What does a learning-focused code review look like? So I built Frankie to explore those questions.

## Who This Is For

This tool is designed to be usable by people with different backgrounds, roles, and experience levels.

If you are a developer using Copilot or other AI tools and want help understanding potential security issues, this is for you. If you are a junior or mid-level engineer learning what common security risks look like, this is for you. If you are a senior engineer or reviewer who wants a second set of eyes before review, this is for you. If you work in security, AppSec, or governance and need structured artifacts that support risk discussions and documentation, this is also for you.

You do not need to be a security expert to use this tool, and it does not assume that you are.

## What It Does

The reviewer analyzes code for common security risks, including authentication and authorization issues, injection vulnerabilities, insecure handling of secrets, unsafe file or system operations, and patterns commonly mapped to OWASP Top 10 and CWE categories.

Findings are returned with a clear explanation of what the issue is, why it matters, and suggestions for how it could be addressed. The intent is to make security feedback understandable and actionable, not overwhelming.

## How It Works

At a high level, the tool follows a simple flow. Code is provided as input, the code is analyzed using an AI-driven review process, findings are normalized into a consistent structure, and results are returned as both human-readable feedback and structured JSON output.

The structured output can be reviewed by people, consumed by other tools, or stored for later reference.

## Quick Start

**Fastest Way (Docker - 30 seconds):**

```bash
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent
docker-compose up
# Open http://localhost:7860
```

**CLI Mode:**

```bash
# Install
pip install -r requirements.txt

# Review code
frankie review app.py
frankie review --confidence-threshold 0.8 src/

# From pipeline
git diff | frankie review --stdin
```

**Windows (PowerShell):**

```powershell
.\frankie.ps1 review app.py
.\frankie.ps1 docker  # or docker-compose up
```

👉 **For detailed setup guides:** [HOMELAB_SETUP.md](HOMELAB_SETUP.md) (Docker, local Python, platform-specific)

See [examples/](examples/) for code review examples and integration patterns.

**Web demo:** https://huggingface.co/spaces/adarian-dewberry/code-review-agent

## 🛠️ Tech Stack

**Frontend & UI**
- Gradio 5.x – Interactive web interface with custom CSS/JS
- Custom animations – Frankie mascot state machine with CSS transitions

**AI & Analysis**
- Anthropic Claude Sonnet 4 – Multi-pass security analysis with structured outputs
- Pydantic 2.0 – Schema validation and type safety for findings

**CI/CD & Governance**
- GitHub Actions – Automated security reviews with configurable thresholds
- JSON artifact retention – 30-day audit trail with structured decision records

**Infrastructure**
- HuggingFace Spaces – Live demo deployment with Python 3.10
- Docker support – Containerized deployment with health checks

## Features

- AI-assisted security code review with plain-language explanations
- Detection of common vulnerability classes aligned with OWASP and CWE
- Structured JSON decision records for traceability
- Human-readable output for developers
- Designed to work alongside AI-assisted coding workflows
- Flexible enough for local use, CI, or review pipelines

This tool is not intended to replace secure development practices or human review. It is meant to support them.

## Governance-Friendly Outputs

In addition to developer-facing feedback, the tool produces structured decision records in JSON format. These may include the type of risk identified, severity and reasoning, references to relevant security categories, and analysis context.

These outputs are designed to support security reviews, audit evidence collection, and AI governance workflows. They do not determine compliance on their own. Instead, they provide transparent artifacts that teams can use as part of broader risk management and governance processes.

## Use Responsibly

This tool is an **assistive signal, not an authority**. It:

- Does **not** guarantee code is secure or compliant
- Should **not** be the sole basis for security decisions  
- Must be reviewed by humans and considered alongside architecture and threat models
- Can surface useful insights but may miss issues or misinterpret context

Use it to **support** conversations about risk, not replace professional judgment.

## Design Principles

This project is guided by a few simple principles. It should be inclusive by default and usable by developers at different skill levels. It should focus on improving outcomes, not assigning blame. It should produce outputs that are explainable, reviewable, and reusable. It should reflect how people actually build software today, especially with AI in the loop.

## 🔧 Technical Challenges & Solutions

**Challenge 1: Making Frankie Visible Across Platforms**
- **Problem:** Fixed overlay positioning broke mobile layouts and felt intrusive
- **Solution:** Refactored to inline container with CSS state machine, `display: block` inline override, and flex-based centering
- **Result:** Smooth animations work across desktop/mobile, 2-second auto-hide for better UX

**Challenge 2: Enterprise-Ready Governance Without Security Theater**
- **Problem:** Most security tools either lack audit trails or overwhelm users with false positives
- **Solution:** Configurable thresholds (`BLOCK_THRESHOLD`, `REVIEW_THRESHOLD`), tool error vs security finding differentiation, structured JSON artifacts
- **Result:** Teams can tune sensitivity, CI doesn't block on tool failures, governance teams get 30-day audit history

**Challenge 3: Balancing AI Confidence with Developer Trust**
- **Problem:** AI can be confidently wrong; users need to understand reasoning without wading through jargon
- **Solution:** Three-pass review architecture (summary → detailed → fixes), confidence scores with clear thresholds, plain-language explanations with OWASP mapping
- **Result:** Developers understand *why* something is flagged, security teams can trace decisions back to standards

## Documentation

Additional documentation is available in the `docs` directory, including configuration options, output schema details, benchmark methodology, and development notes.

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | **CLI Reference** – Commands, flags, output formats, and common workflows for local use |
| [POLICIES.md](POLICIES.md) | **Governance Rules** – BR/RR/WARN policies with confidence thresholds and CI integration examples |
| [CHANGELOG.md](CHANGELOG.md) | **Release History** – Version notes from v1.0.0 including Frankie system, governance features |
| [API.md](API.md) | **Integration Guide** – REST endpoints, authentication, webhook examples for CI pipelines |
| [DEPLOYMENT.md](DEPLOYMENT.md) | **Infrastructure** – Docker Compose, HuggingFace Spaces, environment variables, health checks |
| [CONTRIBUTING.md](CONTRIBUTING.md) | **Development Guide** – How to contribute detection logic, tests, examples, or documentation |

## Contributing

Contributions are welcome. If you are interested in improving detection logic, documentation, examples, or governance alignment, please open an issue or pull request. The goal is to keep this project useful, approachable, and grounded in real workflows.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for full text.

---

Created by Adarian Dewberry.
