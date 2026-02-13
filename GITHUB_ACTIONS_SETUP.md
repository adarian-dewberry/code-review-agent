# GitHub Actions Setup Guide

This is a quick-start guide for GitHub Actions. For comprehensive CI/CD setup across multiple platforms, see [CI_CD_GUIDE.md](CI_CD_GUIDE.md).

## Quick Setup

### 1. Add API Key Secret

1. Go to your repository settings: `Settings > Secrets and variables > Actions`
2. Click "New repository secret"
3. Name: `ANTHROPIC_API_KEY`
4. Value: Your Anthropic API key (from https://console.anthropic.com/)
5. Click "Add secret"

### 2. Deploy Workflow

The workflow file `.github/workflows/code-review.yml` is pre-configured and will:
- Run on pull requests to `main` and `develop` branches
- Review all changed Python files
- Post results as PR comments
- Block merging if critical issues found

See [CI_CD_GUIDE.md > GitHub Actions](CI_CD_GUIDE.md#1-github-actions-recommended) for detailed configuration and customization options.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Workflow not running | Verify `.github/workflows/code-review.yml` exists; check if Actions are enabled in Settings |
| API key not found | Confirm secret name is exactly `ANTHROPIC_API_KEY`; check it's set in current repo (not org) |
| Too many API calls | Reduce review scope in config, disable unnecessary categories, or increase token limits |
| Skip review for specific PRs | Add a label or modify workflow condition |

## Advanced Configuration

For branch protection, caching, multi-platform CI/CD, custom workflows, and detailed API configuration, see [CI_CD_GUIDE.md](CI_CD_GUIDE.md).
