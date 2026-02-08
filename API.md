# API Reference

This document describes the API endpoints available when running
Code Review Agent as a web service.

---

## Base URL

**Hugging Face Spaces:**  
`https://adarian-dewberry-code-review-agent.hf.space`

**Local development:**  
`http://localhost:7860`

---

## Endpoints

### POST /api/review

Review code for security and compliance issues.

**Request:**

```bash
curl -X POST "https://adarian-dewberry-code-review-agent.hf.space/api/review" \
  -H "Content-Type: application/json" \
  -d '{
    "data": [
      "def get_user(id): return db.execute(f\"SELECT * FROM users WHERE id={id}\")",
      true,
      true,
      false,
      false,
      "app.py"
    ]
  }'
```

**Parameters (in order):**

| Index | Type | Description |
|-------|------|-------------|
| 0 | string | Code to review |
| 1 | boolean | Enable security checks |
| 2 | boolean | Enable compliance checks |
| 3 | boolean | Enable logic checks |
| 4 | boolean | Enable performance checks |
| 5 | string | Filename context (optional) |

**Response:**

```json
{
  "data": [
    "",
    "<div>...verdict HTML...</div>",
    "## What we found\n\n**SQL Injection**..."
  ]
}
```

---

### GET /api/health

Health check endpoint for monitoring and uptime verification.

**Request:**

```bash
curl "https://adarian-dewberry-code-review-agent.hf.space/api/health"
```

**Response:**

```json
{
  "status": "healthy",
  "version": "0.2.2",
  "schema_version": "1.0",
  "timestamp": "2026-02-07T05:47:50.922Z",
  "components": {
    "api_key": "configured",
    "cache": {
      "status": "healthy",
      "hit_rate": "45.2%",
      "size": 12
    },
    "rate_limiter": {
      "status": "healthy",
      "limit": "10/60s"
    }
  }
}
```

---

### POST /api/export_audit

Export the last audit record as JSON.

**Request:**

```bash
curl -X POST "https://adarian-dewberry-code-review-agent.hf.space/api/export_audit"
```

**Response:**

Returns the structured decision record from the most recent review.

---

## Rate limits

| Tier | Limit | Window |
|------|-------|--------|
| Default | 10 requests | 60 seconds |

Rate limits are applied per IP address.

**Configuration:**

```bash
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW=60
```

When rate limited, the API returns HTTP 429 with a Retry-After header.

---

## Response codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Invalid request format |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

## Decision record schema

The audit export follows this structure:

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
      "owasp": "A03:2025",
      "location": "get_user():2"
    }
  ]
}
```

---

## Integration examples

### Python

```python
import requests

response = requests.post(
    "https://adarian-dewberry-code-review-agent.hf.space/api/review",
    json={
        "data": [
            "def vulnerable(): pass",
            True,  # security
            True,  # compliance
            False, # logic
            False, # performance
            "example.py"
        ]
    }
)

result = response.json()
print(result["data"][2])  # Markdown findings
```

### JavaScript

```javascript
const response = await fetch(
  "https://adarian-dewberry-code-review-agent.hf.space/api/review",
  {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      data: ["def vulnerable(): pass", true, true, false, false, "example.py"]
    })
  }
);

const result = await response.json();
console.log(result.data[2]);
```

---

## Webhooks and callbacks

Webhook support is planned for v0.4. For now, poll the API or use
the web interface for interactive review.
