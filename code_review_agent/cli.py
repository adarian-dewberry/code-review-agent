"""
Command-line interface for code review agent.

Usage:
    code-review review path/to/file.py
    git diff | code-review review --stdin
    code-review review --ci-mode path/to/file.py
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from .agent import CodeReviewAgent
from .config import Config
from .models import ReviewRecommendation


def main():
    """Main CLI entry point."""
    
    parser = argparse.ArgumentParser(
        description="Automated code review for AI-powered development",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Review a file
  code-review review path/to/code.py
  
  # Review from stdin (git diff)
  git diff main | code-review review --stdin
  
  # CI/CD mode (exits with error if critical issues)
  code-review review --ci-mode path/to/code.py
  
  # Custom config
  code-review review --config config.yaml path/to/code.py
        """
    )
    
    parser.add_argument(
        "command",
        choices=["review"],
        help="Command to run"
    )
    
    parser.add_argument(
        "file_path",
        nargs="?",
        help="Path to file to review (omit if using --stdin)"
    )
    
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read code from stdin instead of file"
    )
    
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="CI/CD mode: exit with error code if critical/high issues found"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to config file (default: config.yaml)"
    )
    
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)"
    )
    
    parser.add_argument(
        "--sdl-mode",
        action="store_true",
        help="Enable SDL Multi-Agent Security Squad (SAST+DAST+SCA+SDL Champion)"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config.load(args.config)
    
    # Get code to review
    if args.stdin:
        code = sys.stdin.read()
        file_path = None
    elif args.file_path:
        file_path = Path(args.file_path)
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        code = file_path.read_text()
    else:
        print("Error: Must provide file path or --stdin", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    # Data privacy warning
    if config.review.warn_before_sending and not args.ci_mode:
        print(
            "⚠️  DATA PRIVACY WARNING ⚠️\n"
            "Your code will be sent to Anthropic's Claude API for analysis.\n"
            "Ensure your code does not contain:\n"
            "  • Hardcoded secrets or API keys\n"
            "  • PII (personally identifiable information)\n"
            "  • Proprietary business logic you cannot share\n"
            "  • Other sensitive data\n"
            "\nFor more information, visit: https://www.anthropic.com/privacy\n",
            file=sys.stderr
        )
    
    # Run review
    agent = CodeReviewAgent(config, enable_security_squad=args.sdl_mode)
    result = agent.review(code, str(file_path) if file_path else None)
    
    # Output results
    if args.format == "markdown":
        print(result.to_markdown())
    elif args.format == "json":
        print(result.model_dump_json(indent=2))
    
    # CI mode: exit with error if issues found
    if args.ci_mode:
        if config.review.fail_on_critical and result.summary.critical_count > 0:
            sys.exit(1)
        if config.review.fail_on_high and result.summary.high_count > 0:
            sys.exit(1)
    
    # Normal mode: exit with error only if DO_NOT_MERGE
    if result.summary.recommendation == ReviewRecommendation.DO_NOT_MERGE:
        sys.exit(1)


if __name__ == "__main__":
    main()
