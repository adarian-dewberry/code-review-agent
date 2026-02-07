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

# 🛡️ Code Review Agent

### **Catch Security Flaws Before They Ship**

*AI-Powered Multi-Pass Code Review with **OWASP/CWE Mapping**, **Blast Radius Analysis**, and **Audit-Ready Verdicts***

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Gradio](https://img.shields.io/badge/gradio-5.x-orange.svg)](https://gradio.app/)
[![Live Demo](https://img.shields.io/badge/🚀_Try_Live_Demo-Hugging%20Face-yellow.svg)](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)

**[🎯 Try It Now](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)** · **[📖 Documentation](docs/)** · **[🛣️ Roadmap](ROADMAP.md)** · **[🤝 Contribute](CONTRIBUTING.md)**

</div>

---

## 🔥 Why This Exists

### The Problem

Every day, developers push code with hidden vulnerabilities:

- **SQL injection** slips through when Claude writes `f"SELECT * FROM users WHERE id={user_id}"`
- **API keys** get hardcoded because "I'll fix it later"
- **GDPR violations** sneak in when logging PII "for debugging"
- **Prompt injection** appears in LLM apps without proper input sanitization

Traditional linters catch syntax errors. **They miss the security issues that cost companies millions.**

### The Solution

**Code Review Agent** is your AI-powered security gate:

```
Your Code → Multi-Pass Analysis → Actionable Findings → Audit-Ready Verdict
             ├── Security (OWASP)
             ├── Compliance (GDPR/CCPA)
             ├── LLM Safety (Prompt Injection)
             └── Best Practices
```

**One paste. Instant findings. No security expertise required.**

### The Story Behind It

This project started when I watched a junior developer accidentally push database credentials to a public GitHub repo. By the time we noticed, the credentials had been scraped by bots. We rotated everything, but the question lingered: *Why did our code review process miss this?*

Existing tools either:
- Required expertise to interpret (Semgrep rules, SonarQube dashboards)
- Gave vague advice without actionable fixes
- Missed LLM-specific vulnerabilities entirely

**Code Review Agent bridges that gap** — professional-grade security analysis, accessible to everyone.

---

## 👀 See It In Action

### Live Demo

**[🚀 Try the Live Demo on Hugging Face Spaces](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)**

*No signup required. Paste code, get results in seconds.*

### Sample Review

<details>
<summary>📸 Click to see example output</summary>

**Input Code:**
```python
def get_user(user_id):
    return db.execute(f"SELECT * FROM users WHERE id={user_id}")
```

**Agent Output:**
```
🚫 VERDICT: BLOCK

CRITICAL FINDINGS:
┌─────────────────────────────────────────────────────────────┐
│ 🔴 SQL Injection via String Formatting                      │
│                                                             │
│ Location: get_user():1                                      │
│ Confidence: 100%                                            │
│ CWE-89 | OWASP A03:2021                                     │
│                                                             │
│ Why It Matters:                                             │
│ • Allows arbitrary SQL execution                            │
│ • Could expose entire users table                           │
│ • Common attack vector                                      │
│                                                             │
│ Fix:                                                        │
│ return db.execute("SELECT * FROM users WHERE id=?", (id,))  │
└─────────────────────────────────────────────────────────────┘
```

</details>

---

## 🎯 Use Cases

| Scenario | How Code Review Agent Helps |
|----------|----------------------------|
| **Daily Development** | Paste AI-generated code, get instant security feedback |
| **CI/CD Pipeline** | Fail builds with critical vulnerabilities before production |
| **Code Review Prep** | Pre-scan your PR before requesting human review |
| **Compliance Audits** | Generate audit-ready JSON with CWE/OWASP mappings |
| **Learning Security** | Educational findings explain *why* issues matter |
| **LLM App Development** | Detect prompt injection vulnerabilities in AI apps |

---

## ⚡ Quick Start

### Option 1: Use the Live Demo (Recommended)

**[🚀 Try Now on Hugging Face](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)** — no installation required!

### Option 2: Run Locally

```bash
# Clone the repo
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY=your_key_here

# Launch the app
python app.py
```

Open `http://localhost:7860` and start reviewing!

### Try Sample Vulnerable Code

Test the agent with our intentionally vulnerable examples:

```bash
# Copy any file from examples/ and paste into the app
cat examples/sql_injection.py
```

See [examples/README.md](examples/README.md) for all sample files.

---

## 🎯 Example Output: Decision Record

Every review generates an **audit-ready decision record**:

```json
{
  "schema_version": "1.0",
  "decision_id": "D-20260207-014d",
  "timestamp_utc": "2026-02-07T05:47:50.922Z",
  "verdict": "BLOCK",
  "policy": {
    "policy_version": "v1",
    "block_rules": [
      {"rule_id": "BR-001", "description": "Block if any CRITICAL with confidence >= 0.8", "triggered": true}
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
      "location": "get_user():2"
    }
  ]
}
```

---

## 🆚 How This Is Different

| Capability | Code Review Agent | ChatGPT/Claude | SonarQube | Semgrep |
|------------|:----------------:|:--------------:|:---------:|:-------:|
| **LLM Prompt Injection Detection** | ✅ | ❌ | ❌ | ❌ |
| **GDPR/CCPA Compliance Mapping** | ✅ | ❌ | ❌ | ❌ |
| **Confidence Scoring (0-100%)** | ✅ | ❌ | ❌ | ❌ |
| **Blast Radius Analysis** | ✅ | ❌ | ❌ | ❌ |
| **Audit-Ready JSON Export** | ✅ | ❌ | ✅ | ✅ |
| **CWE/OWASP Tagging** | ✅ | ⚠️ | ✅ | ✅ |
| **Natural Language Rules** | ✅ | ✅ | ❌ | ❌ |
| **No Installation Required** | ✅ | ✅ | ❌ | ❌ |
| **Actionable Code Fixes** | ✅ | ⚠️ | ✅ | ⚠️ |

### Benchmark Results

We tested 10 intentional vulnerabilities (OWASP Top 10 patterns):

| Tool | Detection Rate | False Positives | Scan Time |
|------|:-------------:|:---------------:|:---------:|
| **Code Review Agent** | **100% (10/10)** | 0 | ~15s |
| Semgrep | 40% (4/10) | 0 | ~2s |
| ChatGPT | ~70% | High | ~30s |

**What only Code Review Agent caught:**
- ✅ Hardcoded credentials in config objects
- ✅ Path traversal with weak filtering
- ✅ Prompt injection in LLM chains
- ✅ GDPR violations (missing consent, excessive logging)

**Full benchmark details:** [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

---

## �️ What Gets Detected

### Security Vulnerabilities (OWASP Top 10)
| Category | Examples |
|----------|----------|
| **A01: Broken Access Control** | Missing auth checks, privilege escalation |
| **A02: Cryptographic Failures** | Weak hashing, hardcoded keys, insecure random |
| **A03: Injection** | SQL, command, XPath, LDAP, prompt injection |
| **A07: Auth Failures** | Weak passwords, session issues |
| **A09: Logging Failures** | Missing audit trails, sensitive data in logs |

### Compliance Issues
| Framework | Examples |
|-----------|----------|
| **GDPR** | Missing consent, excessive data collection, no retention policy |
| **CCPA** | Missing privacy notices, no opt-out mechanism |
| **HIPAA** | Unencrypted PHI, missing audit logs |
| **PCI-DSS** | Plaintext card data, weak encryption |

### LLM-Specific Risks
| Risk | Examples |
|------|----------|
| **LLM01: Prompt Injection** | User input directly in prompts |
| **LLM02: Insecure Output** | Unvalidated model responses |
| **LLM06: Sensitive Data** | PII in training data, logs |

---

## 🗺️ Roadmap

| Phase | Features | Status |
|-------|----------|--------|
| **v0.2** (Current) | Gradio UI, HF Spaces, Blast Radius, Audit JSON | ✅ Released |
| **v0.3** | Multi-language (TypeScript, Go, Rust) | 🚧 Q1 2026 |
| **v0.4** | VS Code Extension, GitHub Action | 📋 Q2 2026 |
| **v0.5** | Custom Rules, Team Dashboards | 📋 Q3 2026 |
| **v1.0** | Enterprise API, SSO, SIEM Integration | 📋 2026 |

**Full roadmap:** [ROADMAP.md](ROADMAP.md)

---

## 📡 API Reference

### Review Endpoint

```bash
curl -X POST "https://adarian-dewberry-code-review-agent.hf.space/api/review" \
  -H "Content-Type: application/json" \
  -d '{"data": ["def get_user(id): return db.execute(f\"SELECT * FROM users WHERE id={id}\")", true, true, false, false, "app.py"]}'
```

### Health Check

```bash
curl "https://adarian-dewberry-code-review-agent.hf.space/api/health"
```

**Rate Limits:** 10 requests per 60 seconds (configurable via `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`)

---

## 🔮 Advanced Features

### Blast Radius Analysis

Every finding estimates how far impact can propagate:

| Dimension | Values |
|-----------|--------|
| **Technical Scope** | function → module → service → cross-service |
| **Data Scope** | none → internal → customer → pii → regulated |
| **Organizational Scope** | single-team → multi-team → external → regulators |

### SDL Multi-Agent Security Squad

Enable enterprise-grade threat modeling:

```bash
python security_squad.py --file app.py --sdl-full
```

**Docs:** [docs/SDL_MULTI_AGENT.md](docs/SDL_MULTI_AGENT.md)

---

## 🚀 Deployment Options

### Hugging Face Spaces (Recommended)

1. Fork this repo to your GitHub
2. Create a new Space at [huggingface.co/spaces](https://huggingface.co/spaces)
3. Choose **Gradio** SDK, connect your repo
4. Add `ANTHROPIC_API_KEY` in Settings → Secrets
5. Deploy!

### Docker

```bash
docker build -t code-review-agent .
docker run -e ANTHROPIC_API_KEY=your_key -p 7860:7860 code-review-agent
```

---

## ⚠️ Important Disclaimers

> **This tool does NOT replace professional security audits or legal compliance reviews.**

- AI models may produce false positives/negatives
- Your code is sent to Anthropic's Claude API
- No guarantee of regulatory compliance
- Always validate findings manually

**Read full disclaimer:** [DISCLAIMER.md](DISCLAIMER.md)

---

## 🔧 Configuration

Create a `.env` file:

```bash
ANTHROPIC_API_KEY=your_api_key_here
```

Optional `config.yaml`:

```yaml
model:
  name: "claude-sonnet-4-20250514"
  max_tokens: 4000

review:
  enabled_categories:
    - security
    - logic
    - performance
    - compliance
  fail_on_critical: true
```

---

## 🔒 Security Methodology

### OWASP Top 10 (2021) Coverage

All categories detected:
- **A01** – Broken Access Control
- **A02** – Cryptographic Failures  
- **A03** – Injection
- **A04** – Insecure Design
- **A05** – Security Misconfiguration
- **A06** – Vulnerable Components
- **A07** – Auth Failures
- **A08** – Software Integrity Failures
- **A09** – Logging Failures
- **A10** – SSRF

### Risk Levels

| Level | Description |
|-------|-------------|
| **CRITICAL** | Exploitable immediately, regulatory violation |
| **HIGH** | Significant security impact, compliance gap |
| **MEDIUM** | Defense-in-depth concern, best practices |
| **LOW** | Theoretical risk, hardening recommendation |

---

## 📁 Project Structure

```
code-review-agent/
├── app.py                    # Gradio web UI
├── examples/                 # Sample vulnerable code
│   ├── sql_injection.py
│   ├── prompt_injection.py
│   ├── gdpr_violation.py
│   ├── hardcoded_secrets.py
│   └── path_traversal.py
├── docs/                     # Documentation
├── config.yaml               # Default configuration
├── requirements.txt          # Dependencies
├── POLICIES.md               # GRC policy framework
├── ROADMAP.md                # Feature roadmap
├── CONTRIBUTING.md           # Contribution guide
└── LICENSE                   # MIT license
```

---

## 🛠️ Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=code_review_agent

# Format code
black .

# Type checking
mypy .
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick start:**
1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a PR

---

## 📜 License

**MIT License** — Free to use, modify, and distribute with attribution.

See [LICENSE](LICENSE) for full text.

---

<div align="center">

**Built with 🛡️ by developers, for developers**

**[🚀 Try Live Demo](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)** · **[⭐ Star on GitHub](https://github.com/adarian-dewberry/code-review-agent)** · **[🐛 Report Bug](https://github.com/adarian-dewberry/code-review-agent/issues)**

</div>
