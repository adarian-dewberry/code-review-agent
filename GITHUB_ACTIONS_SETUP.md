# GitHub Actions Setup Guide

## 1. Add Secret to GitHub Repository

1. Go to your repository settings: `Settings > Secrets and variables > Actions`
2. Click "New repository secret"
3. Name: `ANTHROPIC_API_KEY`
4. Value: Your Anthropic API key (from https://console.anthropic.com/)
5. Click "Add secret"

## 2. Workflow File

The workflow file `.github/workflows/code-review.yml` will:

- Trigger on every pull request to `main` and `develop` branches
- Install Python 3.11 and code-review-agent
- Review all changed Python files
- Fail the PR if critical issues are found
- Post results as a PR comment

## 3. How It Works

```
Pull Request Created
         ↓
   Workflow Triggered
         ↓
   Install Dependencies
         ↓
   Get Changed Python Files
         ↓
   Run Code Review on Each File
         ↓
   Comment Results on PR
         ↓
   Fail/Pass Based on Critical Issues
```

## 4. Configuration

To customize the review behavior:

1. Edit `config.yaml` to change:
   - Model and token settings
   - Review categories to enable/disable
   - Failure conditions (fail_on_critical, fail_on_high)

2. Commit changes to trigger workflow update

## 5. Example Workflow Output

### PR Comment:
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
- **High Issues:** 2
```

## 6. Troubleshooting

### Workflow not running?
- Check that `.github/workflows/code-review.yml` exists
- Verify branch protection rules don't block workflow
- Check repository Actions are enabled

### API key not found?
- Verify secret name is `ANTHROPIC_API_KEY`
- Check secret is set in correct repository (not organization)
- Regenerate key if needed at console.anthropic.com

### Too many API calls?
- Reduce `max_tokens` in `config.yaml`
- Disable unnecessary review categories
- Use `fail_on_high: false` to avoid excessive reviews

## 7. Disabling for Specific PRs

Add a label to skip review:

```bash
git label add "skip-review" <PR_number>
```

Or modify workflow to check labels before running.

## 8. Local Development

Run code review locally before committing:

```bash
# Review single file
code-review review src/agent.py

# Review git diff
git diff origin/main | code-review review --stdin

# CI mode (exit with error on critical issues)
code-review review src/agent.py --ci-mode
```

## 9. Integration with Branch Protection

1. Go to `Settings > Branches > Branch protection rules`
2. Select branch (e.g., `main`)
3. Under "Require status checks to pass before merging"
4. Search for `Code Review / Automated Code Review`
5. Check the box to require this check
6. Click "Create"

Now all PRs must pass code review before merging!
