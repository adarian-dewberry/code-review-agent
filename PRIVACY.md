# Privacy Policy

This document describes how Code Review Agent handles data,
what is sent to external services, and your options for control.

---

## Data flow overview

```
┌──────────────┐     ┌───────────────────┐     ┌───────────────┐
│  Your Code   │ ──► │ Code Review Agent │ ──► │ Model Provider│
│              │     │   (processing)    │     │ (OpenAI, etc.)│
└──────────────┘     └───────────────────┘     └───────────────┘
                              │
                              ▼
                     ┌───────────────────┐
                     │  Your Browser     │
                     │  (results shown)  │
                     └───────────────────┘
```

---

## What data is collected

### Code you submit

When you submit code for review, the following is processed:

| Data | Purpose | Retention |
|------|---------|-----------|
| Source code | Sent to model for analysis | Not stored after response |
| Filename | Context for language detection | Not stored |
| Review options | Determines which checks to run | Not stored |

### Audit records

If you export an audit record:

| Data | Purpose | Retention |
|------|---------|-----------|
| Findings summary | Compliance documentation | User-controlled |
| Verdict | Decision record | User-controlled |
| Timestamps | Audit trail | User-controlled |

Audit records are generated on-demand and returned to your browser.
They are not stored server-side.

---

## What is sent to model providers

When code is submitted for review, it is sent to your configured
model provider (OpenAI by default) for analysis.

**Sent to provider:**
- The code you submit
- System prompts (review instructions)
- Your configured model preference

**Not sent to provider:**
- Your IP address (directly)
- Browser information
- Any local files not explicitly submitted

### Provider data policies

| Provider | Data Policy |
|----------|-------------|
| OpenAI | [openai.com/policies/privacy-policy](https://openai.com/policies/privacy-policy) |
| Azure OpenAI | [azure.microsoft.com/privacy](https://azure.microsoft.com/en-us/explore/trusted-cloud/privacy) |

**Important:** Review your provider's data retention and training
policies. Some providers may retain API inputs for abuse monitoring
or model improvement unless you opt out.

---

## What is NOT collected

Code Review Agent does not:

- Create user accounts
- Track users across sessions
- Store submitted code after processing
- Use analytics or tracking scripts
- Collect telemetry by default
- Sell or share data with third parties

---

## Local deployment

For maximum privacy, deploy Code Review Agent locally:

```bash
git clone https://github.com/dewberryadarian/code-review-agent.git
cd code-review-agent
pip install -r requirements.txt
python app.py
```

With local deployment:
- Code never leaves your network (except to the model provider)
- No server-side logging
- Full control over configuration

---

## Secrets and sensitive data

**Warning:** Code Review Agent does not scan for secrets.

If you submit code containing API keys, passwords, or other
credentials, they will be sent to the model provider.

**Recommendations:**
- Use `.gitignore` to exclude sensitive files
- Run secrets scanners before code review
- Use environment variables for credentials
- Consider local deployment for sensitive codebases

---

## Caching

When caching is enabled (default), identical code submissions
may return cached results without calling the model provider.

| Setting | Behavior |
|---------|----------|
| `ENABLE_CACHE=true` | Hash of code stored with results |
| `ENABLE_CACHE=false` | No caching, every request calls provider |
| `CACHE_TTL=3600` | Cache entries expire after 1 hour |

Cache is stored in memory and cleared on restart.

---

## Logging

Default logging includes:
- Request timestamps
- Error messages
- Rate limit events

Default logging does NOT include:
- Submitted code content
- Full model responses
- User identifiers

For production, configure `LOG_LEVEL` appropriately:

```bash
LOG_LEVEL=WARNING  # Minimal logging
LOG_LEVEL=INFO     # Standard logging
LOG_LEVEL=DEBUG    # Verbose (may include sensitive data)
```

---

## Compliance notes

### GDPR

- No personal data is collected beyond IP for rate limiting
- No data is stored persistently
- No cross-border data transfer (your provider choice applies)

### SOC 2

- Audit logging available
- Rate limiting and access controls in place
- See [THREAT_MODEL.md](THREAT_MODEL.md) for security controls

### HIPAA

Code Review Agent is not designed for HIPAA-regulated data.
Do not submit protected health information.

---

## Your rights

You can:
- Use local deployment for full control
- Disable caching to prevent any storage
- Export audit records for your compliance needs
- Delete any exported data at your discretion

---

## Changes to this policy

This policy may be updated as features change. Significant
changes will be noted in release notes.

Last updated: 2025-06

---

## Questions

For privacy questions, contact: privacy@adariandewberry.com

---

## Related documentation

- [SECURITY.md](SECURITY.md) - Security policies
- [THREAT_MODEL.md](THREAT_MODEL.md) - Threat analysis
- [DEPLOYMENT.md](DEPLOYMENT.md) - Self-hosting options
