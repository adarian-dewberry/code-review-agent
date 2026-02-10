#!/bin/bash
# Bash wrapper for Frankie CLI
# 
# Usage:
#   ./frankie-wrapper.sh review /path/to/code.py
#   git diff | ./frankie-wrapper.sh review --stdin
#   ./frankie-wrapper.sh docker /repo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_IMAGE="frankie-review:latest"
API_KEY="${ANTHROPIC_API_KEY}"

print_usage() {
    cat << EOF
🐕 Frankie - AI Code Review Wrapper

Usage:
    frankie-wrapper.sh docker <path>     Build and run in Docker
    frankie-wrapper.sh local <path>      Run locally (requires Python 3.10+)
    frankie-wrapper.sh stdin             Review code from stdin
    frankie-wrapper.sh ci <path>         CI/CD mode (strict checking)

Examples:
    ./frankie-wrapper.sh local src/main.py
    git diff | ./frankie-wrapper.sh stdin
    ./frankie-wrapper.sh docker .
EOF
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker not found. Install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python 3 not found. Install Python 3.10+: https://www.python.org/downloads/"
        exit 1
    fi
}

run_docker() {
    local target_path="${1:-.}"
    
    check_docker
    
    if [ ! -d "$target_path" ]; then
        echo "❌ Path not found: $target_path"
        exit 1
    fi
    
    echo "🐳 Building Docker image..."
    docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"
    
    echo "🐕 Running Frankie in Docker..."
    docker run --rm \
        -v "$(cd "$target_path" && pwd)":/repo:ro \
        -e "ANTHROPIC_API_KEY=$API_KEY" \
        "$DOCKER_IMAGE" \
        frankie review /repo
}

run_local() {
    local target_path="${1:-.}"
    
    check_python
    
    if [ ! -f "$target_path" ]; then
        echo "❌ File not found: $target_path"
        exit 1
    fi
    
    if [ -z "$API_KEY" ]; then
        echo "❌ ANTHROPIC_API_KEY not set"
        exit 1
    fi
    
    echo "🐕 Running Frankie locally..."
    cd "$SCRIPT_DIR"
    
    # Create venv if not exists
    if [ ! -d "venv" ]; then
        echo "📦 Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate venv
    source venv/bin/activate
    
    # Install deps
    pip install -q -r requirements.txt
    
    # Run review
    ANTHROPIC_API_KEY="$API_KEY" frankie review "$target_path"
}

run_stdin() {
    check_python
    
    if [ -z "$API_KEY" ]; then
        echo "❌ ANTHROPIC_API_KEY not set"
        exit 1
    fi
    
    echo "🐕 Reading code from stdin..."
    cd "$SCRIPT_DIR"
    
    # Create venv if not exists
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -q -r requirements.txt
    
    ANTHROPIC_API_KEY="$API_KEY" frankie review --stdin
}

run_ci() {
    local target_path="${1:-.}"
    
    echo "🔒 CI/CD Mode: Strict checking enabled"
    echo "⚠️  Build will fail on critical/high-confidence issues"
    
    check_python
    
    if [ -z "$API_KEY" ]; then
        echo "❌ ANTHROPIC_API_KEY not set"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -q -r requirements.txt
    
    # Run with CI mode
    ANTHROPIC_API_KEY="$API_KEY" \
    BLOCK_THRESHOLD="critical:0.8,high:0.95" \
    REVIEW_THRESHOLD="high:0.7" \
    frankie review --ci-mode "$target_path"
}

# Main
if [ $# -eq 0 ]; then
    print_usage
    exit 0
fi

COMMAND="$1"
shift

case "$COMMAND" in
    docker)
        run_docker "$@"
        ;;
    local)
        run_local "$@"
        ;;
    stdin)
        run_stdin
        ;;
    ci)
        run_ci "$@"
        ;;
    help)
        print_usage
        ;;
    *)
        echo "❌ Unknown command: $COMMAND"
        print_usage
        exit 1
        ;;
esac
