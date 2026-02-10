# 🔗 Integration Guide

Use **Frankie** in your existing workflows, CI/CD pipelines, and across different programming languages.

---

## 📚 Quick Links

- [CLI Usage](#-cli-usage)
- [Python Integration](#-python-integration)
- [Node.js/JavaScript](#-nodejs--javascript)
- [Bash/Shell Scripts](#-bashshell-scripts)
- [Go Integration](#-go-integration)
- [GitHub Actions](#-github-actions)
- [GitLab CI](#-gitlab-ci)
- [Pre-commit Hooks](#-pre-commit-hooks)
- [Docker](#-docker)
- [REST API](#-rest-api)

---

## 🖥️ CLI Usage

### Basic Review

```bash
# Single file
frankie review app.py

# Entire directory
frankie review src/

# From stdin (git diff)
git diff | frankie review --stdin

# CI mode (fails on critical issues)
frankie review --ci-mode app.py

# With custom config
frankie review --config config.yaml app.py
```

### Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY="your-api-key"

# Optional - governance thresholds
export BLOCK_THRESHOLD="critical:0.8,high:0.95"
export REVIEW_THRESHOLD="high:0.7"

# Optional - rate limiting
export RATE_LIMIT_REQUESTS=10
export RATE_LIMIT_WINDOW=60
```

---

## 🐍 Python Integration

### Direct Import

```python
from code_review_agent.agent import CodeReviewAgent
from code_review_agent.config import Config

# Initialize
config = Config()
agent = CodeReviewAgent(config)

# Review code
findings = agent.review_code(
    code="def foo(x): return eval(x)",
    filename="app.py"
)

# Process results
for finding in findings:
    print(f"{finding.severity}: {finding.title}")
    print(f"  {finding.explanation}")
```

### Using CLI Programmatically

```python
import subprocess
import json

def review_with_frankie(file_path):
    result = subprocess.run(
        ["frankie", "review", file_path, "--format", "json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        raise Exception(result.stderr)

findings = review_with_frankie("app.py")
print(f"Found {len(findings)} issues")
```

---

## 📦 Node.js / JavaScript

### Using the REST API (Frankie Web UI)

See [examples/frankie-client.js](examples/frankie-client.js):

```bash
# Review a JavaScript file
node examples/frankie-client.js src/app.js

# Review from stdin
cat src/utils.js | node examples/frankie-client.js
```

### npm Package Wrapper

Create `package.json`:

```json
{
  "name": "my-project",
  "scripts": {
    "review": "node frankie-client.js",
    "review:ci": "node frankie-client.js && echo 'Review passed'"
  }
}
```

Usage:

```bash
npm run review src/app.js
npm run review < git-diff.patch
```

### Direct HTTP Client

```javascript
const https = require('https');

async function reviewCode(code, filename) {
  const data = JSON.stringify({
    data: [code, true, true, false, false, filename]
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 7860,
      path: '/api/review',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Usage
reviewCode(myCode, 'app.js').then(results => {
  console.log(JSON.stringify(results, null, 2));
});
```

---

## 🔧 Bash/Shell Scripts

### Simple Wrapper

See [examples/frankie-wrapper.sh](examples/frankie-wrapper.sh):

```bash
chmod +x examples/frankie-wrapper.sh

# Docker mode
./examples/frankie-wrapper.sh docker src/

# Local mode
./examples/frankie-wrapper.sh local src/main.py

# CI mode
./examples/frankie-wrapper.sh ci src/

# From stdin
git diff | ./examples/frankie-wrapper.sh stdin
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
echo "🐕 Running Frankie on staged files..."

STAGED_PYTHON_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')

if [ -z "$STAGED_PYTHON_FILES" ]; then
    exit 0
fi

FAILED=0
for file in $STAGED_PYTHON_FILES; do
    if ! frankie review --ci-mode "$file" > /dev/null; then
        echo "❌ $file: Review found critical issues"
        FAILED=1
    fi
done

exit $FAILED
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### Git Diff Review

```bash
#!/bin/bash
# Review only changed lines

BRANCH=${1:-main}
echo "🐕 Reviewing changes vs $BRANCH..."

git diff "$BRANCH"...HEAD | frankie review --stdin

if [ $? -eq 0 ]; then
    echo "✅ All changes reviewed"
else
    echo "❌ Issues found"
    exit 1
fi
```

---

## 🚀 Go Integration

### HTTP Client Example

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type ReviewRequest struct {
	Data []interface{} `json:"data"`
}

func reviewCode(code, filename string) (map[string]interface{}, error) {
	req := ReviewRequest{
		Data: []interface{}{
			code,
			true,  // security
			true,  // compliance
			false, // logic
			false, // performance
			filename,
		},
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(
		"http://localhost:7860/api/review",
		"application/json",
		bytes.NewBuffer(body),
	)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &result)

	return result, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <file.go>")
		os.Exit(1)
	}

	data, _ := os.ReadFile(os.Args[1])
	results, err := reviewCode(string(data), os.Args[1])

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))
}
```

Compile and run:

```bash
go run main.go app.go
```

---

## ⚙️ GitHub Actions

### Basic Workflow

```yaml
name: Frankie Review

on:
  pull_request:
    branches: [main]

jobs:
  frankie:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install Frankie
        run: pip install -e .
      
      - name: Review changed files
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          git diff origin/${{ github.base_ref }}...HEAD --name-only | \
          grep '\.py$' | \
          xargs -I {} frankie review --ci-mode {}
```

### With Docker

```yaml
name: Frankie Review (Docker)

on:
  pull_request:

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t frankie-review .
      
      - name: Review code
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          docker run -e ANTHROPIC_API_KEY \
            -v $PWD:/repo \
            frankie-review frankie review /repo
      
      - name: Container vulnerability scan (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: frankie-review
          format: sarif
          output: trivy.sarif
      
      - name: Upload scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: trivy.sarif
```

### With SBOM Generation

```yaml
- name: Generate SBOM
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: frankie-review
    format: cyclonedx
    output: sbom.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
    retention-days: 90
```

---

## 📋 GitLab CI

### Basic Pipeline

```yaml
stages:
  - review

code_review:
  stage: review
  image: python:3.10
  script:
    - pip install -e .
    - |
      git diff $CI_MERGE_REQUEST_DIFF_BASE_SHA...HEAD --name-only | \
      grep '\.py$' | \
      xargs -I {} frankie review --ci-mode {}
  only:
    - merge_requests
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

### Docker Pipeline

```yaml
code_review_docker:
  stage: review
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t frankie-review .
    - docker run -e ANTHROPIC_API_KEY -v $CI_PROJECT_DIR:/repo frankie-review frankie review /repo
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

---

## 🪝 Pre-commit Hooks

### Setup

1. Install pre-commit: `pip install pre-commit`

2. Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: frankie-review
        name: Frankie Security Review
        entry: frankie review
        language: system
        types: [python]
        stages: [commit]
        verbose: true
```

3. Install hook:

```bash
pre-commit install
```

4. Test:

```bash
git commit -m "test"  # Frankie will auto-review staged files
```

---

## 🐳 Docker

### CLI in Container

```bash
# Build
docker build -t frankie-review .

# Review file
docker run \
  -e ANTHROPIC_API_KEY="your-key" \
  -v /path/to/code:/repo:ro \
  frankie-review frankie review /repo/app.py

# Interactive
docker run -it \
  -e ANTHROPIC_API_KEY="your-key" \
  -v $PWD:/repo \
  frankie-review /bin/bash
```

### docker-compose

See [docker-compose.yml](../docker-compose.yml) for web UI setup:

```bash
docker-compose up
```

Access at `http://localhost:7860`

---

## 🌐 REST API

### Endpoints

Base URL: `http://localhost:7860` (Gradio)

#### POST /api/review

Review code via HTTP:

```bash
curl -X POST http://localhost:7860/api/review \
  -H "Content-Type: application/json" \
  -d '{
    "data": [
      "def foo(x): return eval(x)",
      true,
      true,
      false,
      false,
      "app.py"
    ]
  }'
```

**Parameters** (in order):
1. `code` (string) - Code to review
2. `security` (boolean) - Enable security checks
3. `compliance` (boolean) - Enable compliance checks
4. `logic` (boolean) - Enable logic checks
5. `performance` (boolean) - Enable performance checks
6. `filename` (string) - File name for context

**Response:**

```json
{
  "summary": "...",
  "detailed_findings": [...],
  "suggested_fixes": [...],
  "audit_record": {...}
}
```

### Python HTTP Client

```python
import requests
import json

def review(code, filename="code.py"):
    resp = requests.post(
        "http://localhost:7860/api/review",
        json={
            "data": [code, True, True, False, False, filename]
        }
    )
    return resp.json()

findings = review("x = eval(input())", "app.py")
print(json.dumps(findings, indent=2))
```

---

## 🔒 Security Notes

1. **Local Use Only** - Frankie API is not authenticated
   - Only use internally or behind authentication proxy
   - Never expose publicly to internet

2. **API Key Safety**
   - Use environment variables, not hardcoded
   - Rotate keys regularly
   - Limit API key permissions in Anthropic console

3. **Data Privacy**
   - Code is sent to Anthropic Claude API
   - Review your privacy policy and terms
   - Don't review proprietary/sensitive code with public Anthropic API

---

## 📝 Configuration

See [config.yaml](../config.yaml) for full options:

```yaml
model:
  name: "claude-sonnet-4-20250514"
  max_tokens: 4000
  temperature: 0.0

review:
  enabled_categories:
    - security
    - compliance
    - logic
    - performance

  fail_on_critical: true
  fail_on_high: false
  
  exclude_patterns:
    - "*.min.js"
    - "node_modules/**"
    - ".env"
```

---

## 📚 Additional Resources

- [CLI Reference](USAGE.md)
- [Homelab Setup](HOMELAB_SETUP.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Policies & Governance](POLICIES.md)
- [Contributing](CONTRIBUTING.md)

---

## 💬 Questions?

Open an issue: https://github.com/adarian-dewberry/code-review-agent/issues

Happy integrating! 🐕
