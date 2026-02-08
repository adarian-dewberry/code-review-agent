# Deployment Guide

This document covers deployment options for Code Review Agent.

---

## Quick start

The fastest way to try Code Review Agent is through the hosted
Hugging Face Space:

👉 [adarian-dewberry-code-review-agent.hf.space](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)

For private or production use, continue below.

---

## Local development

### Prerequisites

- Python 3.10 or later
- An OpenAI API key (or compatible provider)

### Setup

```bash
git clone https://github.com/dewberryadarian/code-review-agent.git
cd code-review-agent

python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

pip install -r requirements.txt
```

### Environment variables

Create a `.env` file or export these directly:

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW=60
```

### Run

```bash
python app.py
```

Open `http://localhost:7860` in your browser.

---

## Docker

### Build

```bash
docker build -t code-review-agent .
```

### Run

```bash
docker run -p 7860:7860 \
  -e OPENAI_API_KEY=sk-... \
  -e OPENAI_MODEL=gpt-4.1-mini \
  code-review-agent
```

### Docker Compose

```yaml
version: '3.8'
services:
  code-review-agent:
    build: .
    ports:
      - "7860:7860"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - OPENAI_MODEL=gpt-4.1-mini
      - RATE_LIMIT_REQUESTS=10
      - RATE_LIMIT_WINDOW=60
    restart: unless-stopped
```

Run with:

```bash
docker-compose up -d
```

---

## Hugging Face Spaces

Code Review Agent is designed to run on Hugging Face Spaces.

### Deploy your own Space

1. Fork or duplicate the Space:
   👉 [huggingface.co/spaces/adarian-dewberry/code-review-agent](https://huggingface.co/spaces/adarian-dewberry/code-review-agent)

2. Go to Settings > Repository secrets

3. Add your secrets:
   - `OPENAI_API_KEY` (required)
   - `OPENAI_MODEL` (optional, defaults to gpt-4.1-mini)

4. The Space will rebuild automatically

### Hardware requirements

The default CPU tier works well. GPU is not required since
inference happens through the OpenAI API.

| Tier | Notes |
|------|-------|
| CPU Basic | Sufficient for most use cases |
| CPU Upgrade | Better for higher traffic |

---

## Environment reference

### Required

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Your OpenAI API key |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_MODEL` | `gpt-4.1-mini` | Model to use for analysis |
| `OPENAI_API_BASE` | (OpenAI default) | Custom API endpoint |
| `RATE_LIMIT_REQUESTS` | `10` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window size in seconds |
| `ENABLE_CACHE` | `true` | Enable response caching |
| `CACHE_TTL` | `3600` | Cache TTL in seconds |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Reverse proxy

If running behind nginx or another reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name code-review.example.com;

    location / {
        proxy_pass http://localhost:7860;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;
    }
}
```

The long timeout accommodates LLM response times.

---

## CI/CD integration

### GitHub Actions

```yaml
name: Security Review

on:
  pull_request:
    paths:
      - '**.py'
      - '**.js'

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed
        run: |
          echo "files=$(git diff --name-only origin/main...HEAD | tr '\n' ' ')" >> $GITHUB_OUTPUT

      - name: Review code
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          pip install -r requirements.txt
          for file in ${{ steps.changed.outputs.files }}; do
            python cli.py "$file" --ci-mode
          done
```

### GitLab CI

```yaml
security-review:
  stage: test
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - git diff --name-only origin/main...HEAD | xargs -I {} python cli.py {} --ci-mode
  variables:
    OPENAI_API_KEY: $OPENAI_API_KEY
  only:
    - merge_requests
```

---

## Health checks

### Kubernetes liveness probe

```yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 7860
  initialDelaySeconds: 30
  periodSeconds: 10
```

### Docker healthcheck

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s \
  CMD curl -f http://localhost:7860/api/health || exit 1
```

---

## Scaling

Code Review Agent is stateless by default. You can run multiple
instances behind a load balancer.

**Caching:** The built-in cache is per-instance. For shared caching
across instances, use Redis:

```bash
CACHE_BACKEND=redis
REDIS_URL=redis://localhost:6379/0
```

**Rate limiting:** Per-instance by default. For distributed rate
limiting, configure Redis as the backend.

---

## Monitoring

### Prometheus metrics

Metrics are exposed at `/metrics` when enabled:

```bash
ENABLE_METRICS=true
METRICS_PORT=9090
```

### Logging

Logs follow structured JSON format when `LOG_FORMAT=json`:

```json
{
  "timestamp": "2026-02-07T05:47:50.922Z",
  "level": "INFO",
  "message": "Review completed",
  "decision_id": "D-20260207-014d",
  "verdict": "BLOCK"
}
```

---

## Troubleshooting

### Common issues

**"API key not configured"**  
Set `OPENAI_API_KEY` in your environment or .env file.

**Timeout errors**  
Increase `proxy_read_timeout` if behind a reverse proxy.
LLM calls can take 10-30 seconds for large files.

**Rate limited by OpenAI**  
Reduce `RATE_LIMIT_REQUESTS` or upgrade your OpenAI plan.

**Out of memory on HF Spaces**  
Large files may exhaust memory. Consider the CPU Upgrade tier.

---

## Next steps

- [USAGE.md](USAGE.md) - CLI and configuration options
- [API.md](API.md) - API endpoints and integration
- [SECURITY.md](SECURITY.md) - Security policies
