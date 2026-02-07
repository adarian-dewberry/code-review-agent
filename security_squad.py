"""CLI entrypoint for SDL Multi-Agent Security Squad.

Usage:
  python security_squad.py --file app.py --sdl-full
"""

import argparse
import os
import sys
from pathlib import Path

from code_review_agent.security_squad import SecuritySquad


def main() -> int:
    parser = argparse.ArgumentParser(description="SDL Multi-Agent Security Squad (SAST+DAST+SCA+SDL Champion)")
    parser.add_argument("--file", required=True, help="Path to the file to analyze")
    parser.add_argument("--sdl-full", action="store_true", help="Run full SDL analysis (SAST+DAST+SCA+SDL Champion)")
    parser.add_argument(
        "--output", choices=["markdown", "json"], default="markdown", help="Output format (default: markdown)"
    )
    args = parser.parse_args()

    if not args.sdl_full:
        print("Error: --sdl-full is required for full SDL analysis", file=sys.stderr)
        return 1

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY is not set. Set it to run SDL Champion analysis.", file=sys.stderr)
        return 1

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return 1

    code = file_path.read_text(encoding="utf-8")
    squad = SecuritySquad(api_key=api_key)
    result = squad.analyze(code, str(file_path))

    if args.output == "json":
        import json

        print(json.dumps(result, indent=2, default=str))
    else:
        print(result.get("threat_report", "No report generated"))
        sdl_status = result.get("sdl_status", {})
        if sdl_status:
            print("\nSDL Phase Status:")
            print(f"- Current Phase: {sdl_status.get('current_phase', 'Unknown')}")
            print(f"- Recommendation: {sdl_status.get('recommendation', 'N/A')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
