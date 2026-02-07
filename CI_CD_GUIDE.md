# CI/CD Integration Guide

Complete guide for integrating Code Review Agent into your CI/CD pipeline.

## Supported Platforms

- ✅ GitHub Actions (recommended)
- ✅ GitLab CI
- ✅ Local Git Hooks (pre-commit)
- ✅ Any platform supporting shell commands

---

## 1. GitHub Actions (Recommended)

### Setup

1. **Add API Key Secret**
   ```
   Settings > Secrets and variables > Actions > New repository secret
   Name: ANTHROPIC_API_KEY
   Value: sk-ant-... (from console.anthropic.com)
   ```

2. **Workflow File**
   The file `.github/workflows/code-review.yml` is already configured. It will:
   - Run on all pull requests to `main` and `develop`
   - Review all changed Python files
   - Post results as PR comment
   - Fail if critical issues found

3. **Configure Branch Protection** (Optional)
   ```
   Settings > Branches > Branch protection rules
   Check: "Require status checks to pass before merging"
   Select: "Code Review / Automated Code Review"
   ```

### Features

- 📋 Automatic file detection
- 💬 PR comments with results
- ❌ Fail on critical issues
- ⚡ Caching for faster builds
- 🔄 Works with forks

### Example Workflow Output

```
✅ No Python files changed in this PR
```

or

```
## Code Review Results

### 📄 Reviewing: `src/agent.py`
✅ Passed

### 📄 Reviewing: `src/utils.py`
❌ Critical issues found

# Code Review Report
**File:** `src/utils.py`
## Summary
- **Recommendation:** `DO_NOT_MERGE`
- **Critical Issues:** 1
```

---

## 2. GitLab CI

### Setup

1. **Add API Key**
   ```
   Settings > CI/CD > Variables > Add variable
   Key: ANTHROPIC_API_KEY
   Value: sk-ant-...
   ```

2. **Pipeline Configuration**
   The file `.gitlab-ci.yml` is configured. It will:
   - Run on all merge requests
   - Review changed Python files
   - Fail if critical issues found

### Features

- 🎯 Runs on merge requests only
- ⚡ Parallel execution support
- 📊 Integration with GitLab UI
- 🔔 Automatic notifications

---

## 3. Local Git Hooks (Pre-commit)

### Setup

**Option A: Using pre-commit framework** (recommended)

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files

# Update hooks
pre-commit autoupdate
```

The `.pre-commit-config.yaml` file is configured to:
- Run on Python files before commit
- Block commits with critical issues
- Allow override with `--no-verify`

**Option B: Manual hook**

```bash
# Copy hook script
cp pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Hook will run automatically on `git commit`
```

### Features

- 🚀 Catch issues before push
- ⚡ Runs on staged files only
- 🔧 Easy to customize
- 💰 Saves API calls

---

## 4. Generic Shell Integration

### Run on Any CI/CD Platform

```bash
#!/bin/bash
# Review all Python files in pull request

# Get changed files
git diff origin/$BASE_BRANCH --name-only --diff-filter=d | grep '\.py$' > /tmp/changed.txt

# Review each file
while read file; do
  code-review review "$file" --ci-mode || exit 1
done < /tmp/changed.txt
```

### Environment Variables Required

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## 5. Configuration

### Model Settings

Edit `config.yaml`:

```yaml
model:
  name: "claude-sonnet-4-20250514"  # Model to use
  max_tokens: 4000                   # Max response length
  temperature: 0.0                   # Deterministic (0.0) or creative (1.0)
```

### Review Settings

```yaml
review:
  enabled_categories:
    - security        # Enable security review
    - logic          # Enable logic review
    - performance    # Enable performance review
    - compliance     # Enable compliance review
  
  fail_on_critical: true   # Fail CI if critical issues
  fail_on_high: false      # Don't fail on high (optional)
  
  max_issues_per_category: 20  # Limit output
```

### Disable Review for Specific Files

Add to `config.yaml`:

```yaml
# Patterns to skip
skip_patterns:
  - "**/migrations/*"
  - "**/generated/*"
  - "**/*.pb2.py"
```

---

## 6. Command Reference

### Local Review

```bash
# Review single file
code-review review src/agent.py

# Review from stdin (git diff)
git diff origin/main | code-review review --stdin

# CI mode (fail on issues)
code-review review src/agent.py --ci-mode

# JSON output
code-review review src/agent.py --format json

# Custom config
code-review review src/agent.py --config custom.yaml
```

### GitHub Actions Only

```bash
# Skip workflow for specific commit
git commit -m "message [skip ci]"

# Force re-run
# Use "Re-run jobs" button in GitHub Actions tab
```

---

## 7. Troubleshooting

### Workflow Not Running

```bash
# Check if file exists
test -f .github/workflows/code-review.yml

# Check syntax
cat .github/workflows/code-review.yml

# Verify branch protection doesn't block
# Settings > Branches > Branch protection rules
```

### API Key Errors

```bash
# Check secret exists (GitHub)
# Settings > Secrets and variables > Actions

# Test locally
export ANTHROPIC_API_KEY=sk-ant-...
code-review review test.py

# Verify key format
echo $ANTHROPIC_API_KEY | head -c 20
# Should start with: sk-ant-
```

### Too Many API Calls

```yaml
# In config.yaml, optimize:
model:
  max_tokens: 2000  # Reduce from 4000
  
review:
  enabled_categories:
    - security      # Remove unnecessary categories
    - compliance
```

### Rate Limiting

```bash
# Add delay between reviews
for file in $(git diff --name-only); do
  code-review review "$file" || true
  sleep 2  # Wait 2 seconds between files
done
```

---

## 8. Best Practices

### 1. Start Permissive

```yaml
fail_on_critical: false  # Allow reviews to settle in
fail_on_high: false
```

Then gradually tighten:

```yaml
fail_on_critical: true
fail_on_high: false  # After 1 week
```

### 2. Review Before Merging

Always review locally before pushing:

```bash
git checkout feature-branch
code-review review --stdin < <(git diff origin/main)
```

### 3. Document Exceptions

```python
# code-review: ignore-security
# Reason: This is safe because...
unsafe_operation()
```

### 4. Monitor Metrics

```bash
# Count issues by severity
code-review review . --format json | grep -o '"severity":"[^"]*"' | sort | uniq -c
```

---

## 9. Cost Optimization

### Estimate API Usage

- **Per review**: ~1,000 tokens = $0.0015
- **Per PR**: ~3 files = $0.0045
- **Per month**: ~100 PRs = $0.45

### Reduce Costs

```yaml
# Option 1: Smaller model responses
model:
  max_tokens: 2000  # vs 4000

# Option 2: Fewer review categories
review:
  enabled_categories:
    - security      # Most critical only
    - compliance

# Option 3: Review only certain file types
# In CI: git diff | grep '\.py$'
```

---

## 10. Examples

### Example 1: GitHub Actions + Branch Protection

```bash
# Setup branch protection to require review
1. Enable GitHub Actions workflow
2. Settings > Branches > Branch protection
3. Require "Code Review / Automated Code Review" check
4. Now all PRs must pass before merge ✅
```

### Example 2: Local Pre-commit Hook

```bash
# Setup automatic review before commit
pre-commit install

# Now each commit is reviewed
git commit -m "fix: update agent"
# 🔍 Running Code Review Agent...
# ✅ All files passed code review
```

### Example 3: GitLab with Merge Request Approvals

```bash
# Setup MR to require review pass
1. Enable `.gitlab-ci.yml`
2. Project > Merge requests > Approvals
3. Require pipeline to pass
4. Now MRs need code review approval ✅
```

---

## 11. Advanced Configuration

### Custom Failure Conditions

```python
# In CLI or config
if critical_count > 0 or high_count > 5:
    sys.exit(1)
```

### Skip Review for Drafts

```bash
# GitHub: Draft PR
# Workflow: Add check for isDraft
if: ${{ !github.event.pull_request.draft }}
```

### Selective Review

```bash
# Only review changed lines (not entire file)
git diff origin/main > /tmp/changes.diff
code-review review --diff /tmp/changes.diff
```

---

## Support

For issues:

1. Check [GitHub Issues](https://github.com/adariandewberry/code-review-agent/issues)
2. Review configuration: `config.yaml`
3. Test locally: `code-review review test.py --format json`
4. Check API key: `echo $ANTHROPIC_API_KEY`
