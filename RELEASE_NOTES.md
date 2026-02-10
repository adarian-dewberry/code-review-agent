# 🐕 Frankie v2.0 - Homelab Edition

**Release Date:** February 10, 2026

---

## 🎯 What's New in v2.0

Frankie v2.0 is what I built after wanting to understand how AI can help people write more secure code—without judgment or shame. I kept seeing posts about new developers using insecure patterns not because they didn't care, but because they didn't know better. So I built a tool that explains *why* something matters and *how* to fix it, paired with the infrastructure to run it locally and learn from it.

### **🏠 Homelab-First Design**

- **Docker Compose One-Liner:** `docker-compose up` → Frankie runs locally in 30 seconds
- **Zero Docker Experience Required:** Platform-specific guides for Windows, Mac, Linux, and NAS systems
- **PowerShell Native Support:** Windows users get `.\frankie.ps1` (no WSL, no bash)
- **Multi-Language Ready:** Python, Node.js, Go, Bash clients included

### **🔐 What I Learned Building This**

- **Trivy Container Scanning:** Understanding what vulnerabilities live in dependencies (not just code)
- **SBOM Generation:** How compliance teams actually track what's in your software
- **Confidence Thresholding:** Tuning to reduce noise so you focus on what matters
- **Structured JSON Output:** Building auditability into reviews, not as an afterthought

### **🐕 The Frankie CLI (Rebranded)**

```bash
# Use 'frankie' command (or 'code-review' for backward compatibility)
frankie review app.py                              # Single file
frankie review src/ --confidence-threshold 0.8   # Directory with tuning
frankie docker                                    # Auto-containerize
.\frankie.ps1 review app.py                       # Windows native

# From pipeline/CI
git diff | frankie review --stdin
frankie review --ci-mode app.py                   # Fail build on critical
```

### **📊 Developer Experience**

- **Interactive Mascot (Frankie):** Real-time scanning animations in Gradio UI
- **Plain-Language Findings:** No security jargon; explains "why it matters" + "how to fix it"
- **OWASP/CWE Mapping:** Every finding links to industry standards
- **Blast Radius Analysis:** Shows which systems/data could be affected

### **🔧 Integration Everywhere**

| Language | Integration | Example |
|----------|-------------|---------|
| **Python** | Direct import | `from code_review_agent.agent import CodeReviewAgent` |
| **Node.js** | REST client | `node frankie-client.js app.js` |
| **Bash** | Wrapper script | `./frankie-wrapper.sh local app.py` |
| **PowerShell** | Native script | `.\frankie.ps1 review app.py` |
| **Go** | HTTP client | Standard lib `net/http` |
| **GitHub** | Actions workflow | Pre-built with Trivy + SBOM |
| **GitLab** | CI pipeline | `.gitlab-ci.yml` template |

---

## 📋 Full Changelog

### ✨ New Features

- **`frankie` CLI Command** - Memorable, on-brand CLI (vs generic "code-review")
- **PowerShell Wrapper (`frankie.ps1`)** - Windows homelab native support
- **`--confidence-threshold` Flag** - SecOps teams tune sensitivity: `frankie review --confidence-threshold 0.85`
- **Dockerfile** - Production-ready containerization with health checks
- **docker-compose.yml** - One-liner local deployment (Gradio on :7860)
- **HOMELAB_SETUP.md** - Beginner-friendly setup guide (Windows/Mac/Linux/NAS)
- **INTEGRATION_GUIDE.md** - Multi-language client examples + CI/CD templates
- **Trivy Container Scanning** - GitHub Actions auto-scans Frankie Docker image
- **SBOM Generation** - CycloneDX artifacts for compliance (90-day retention)
- **Node.js Client Example** - `examples/frankie-client.js` for REST API
- **Bash Wrapper Script** - `examples/frankie-wrapper.sh` for local/Docker/CI modes

### 🔄 Enhancements

- Enhanced CLI help text with real-world examples
- Improved error messages for common setup issues
- Added entry point aliases (`frankie` + `code-review`)
- GitHub Actions workflow now includes container vulnerability scanning
- LICENSE file explicitly linked in README for open-source visibility

### 🐛 Bug Fixes

- Fixed UTF-8 BOM encoding issue in requirements.txt
- Improved stdin handling for pipeline operations
- Better error handling for Docker mount path resolution

---

---

## 🎯 Who This Is For

**Individual developers** learning to recognize security patterns  
**Students** studying OWASP/CWE without expensive tools  
**Self-taught coders** who want to understand their code better  
**Anyone curious** about what AI can (and can't) do for code review  

**Not for:** Teams looking for a managed solution, organizations wanting vendor support, people looking to replace professional code review  

---

## 📊 By the Numbers

- **8** integration examples (Python, Node.js, Go, Bash, PowerShell, GitHub, GitLab, API)
- **3** platforms supported (Docker, Local, Web)
- **4** documentation guides (HOMELAB, INTEGRATION, USAGE, DEPLOYMENT)
- **2** container scanning integrations (Trivy + SBOM)
- **90 days** of artifact retention for compliance

---

## 🚀 Getting Started

### **Fastest Path (Docker)**
```bash
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent
docker-compose up
# Open http://localhost:7860
```

### **Local Path (Python)**
```bash
git clone ...
cd code-review-agent
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
frankie review app.py
```

### **Windows Native**
```powershell
.\frankie.ps1 review app.py
.\frankie.ps1 docker    # or use Docker
```

See [HOMELAB_SETUP.md](HOMELAB_SETUP.md) for full guides.

---

## 📚 Documentation

| Doc | Purpose |
|-----|---------|
| [HOMELAB_SETUP.md](HOMELAB_SETUP.md) | Platform guides + troubleshooting |
| [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) | Multi-language clients + CI/CD |
| [USAGE.md](USAGE.md) | CLI reference + config options |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [POLICIES.md](POLICIES.md) | Governance rules (BR/RR/WARN) |

---

## 🔮 What's Coming in v2.1

**Metrics & Dashboards:**
- `--collect-metrics` flag to track your security improvements
- `~/.frankie/dashboard.html` with trend analysis (7d, 30d, 90d)
- Optional anonymous aggregation ("compare yours to similar projects")

This is the **differentiator** vs SonarQube:
- Sonar: "You have 45 issues" 
- Frankie: "You went from 8 critical to 2. Here's your learning dashboard."

---

---

## 🎯 What Makes This Different

Most security tools make you feel bad. "45 issues found!" Shame. Alarm. I wanted to build something that **explains** instead. Shows the reasoning. Breaks it down. Admits uncertainty. Helps you learn instead of making you panic.

---

## � What's Next

**v2.1 (Next Week):** Local metrics dashboard  
I want to see if we can track *your* learning. Did you fix the same type of issue twice? Are you getting more confident with certain patterns? The metrics aren't about shaming—they're about visibility into your own growth.

**v2.2 (Q1):** Deeper integration with your workflow  
Maybe pre-commit hooks. Maybe IDE plugins. Whatever helps this feel natural, not intrusive.

---

## 💭 Why I Built This

I wanted to understand:
- How does AI actually help people write secure code?
- Can we make security concepts accessible without dumbing them down?
- What would help a beginner learn without overwhelming them?

I couldn't find a tool that did all three. So I built one. This is my exploration of those questions.
