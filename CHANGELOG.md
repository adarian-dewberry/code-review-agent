# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-02-09

### Added
- **Frankie Mascot System**: AI-powered code review with animated Alaskan Malamute mascot
  - Inline loading state (Scanning → Found → Hidden)
  - Southern phrases rotation ("Frankie's catchin' the scent...", "He's a thorough boy, sugar!")
  - Breathing and tail-wag animations with synced head tilts
  - Mobile-responsive design with proper breakpoints (768px, 480px)
  - Accessibility features: aria-live, prefers-reduced-motion, safe-area-insets
  - Auto-hides after 2 seconds when results appear

- **Code Review Analysis**
  - Multi-pass OWASP 2025 mapping with CWE references
  - Blast radius analysis for impact assessment
  - Confidence scoring system (Critical/High/Medium/Low)
  - Audit-ready JSON/Markdown exports
  - Review modes: Quick (security), Deep (security + compliance), Compliance (full)

- **User Interface**
  - Light/Dark mode with high contrast text
  - Responsive two-panel layout (code input on left, results on right)
  - Verdict card with visual confidence indicators
  - Tabbed results (Overview, Fixes, Audit)
  - Example code for quick start
  - Mobile-optimized experience

- **Repo Hygiene**
  - GitHub Actions workflows (CI/CD)
  - Pre-commit hooks (ruff, mypy, formatting)
  - Comprehensive test suite
  - Type hints throughout codebase
  - Security scanning integration

### Changed
- Refactored Frankie from fixed overlay modal to inline results panel
  - Eliminates floating card in empty space
  - Results flow more naturally below loading state
  - Cleaner UX with less layout disruption

### Fixed
- Mobile layout overflow and proper scaling
- Text contrast in light and dark modes
- Details/summary element visibility
- GitHub Actions versions updated to latest (v6 for checkout/setup-python, v5 for cache, v8 for github-script)

### Deprecated
- Removed file download components (use JSON display with copy functionality)

## [0.1.0] - Initial Development

### Added
- Initial codebase structure
- Security Squad agent for code analysis
- Gradio web interface
- HuggingFace Space deployment
