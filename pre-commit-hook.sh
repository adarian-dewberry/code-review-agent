#!/bin/bash
# Local pre-commit hook script
# Copy to: .git/hooks/pre-commit
# Make executable: chmod +x .git/hooks/pre-commit

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Running Code Review Agent...${NC}"

# Get staged Python files
PYTHON_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)

if [ -z "$PYTHON_FILES" ]; then
    echo -e "${GREEN}✅ No Python files to review${NC}"
    exit 0
fi

echo -e "${YELLOW}📋 Reviewing:${NC}"
echo "$PYTHON_FILES"
echo ""

FAILED=0

for file in $PYTHON_FILES; do
    if [ -f "$file" ]; then
        echo -e "${YELLOW}🔎 $file${NC}"
        
        if code-review review "$file" --ci-mode > /tmp/review.log 2>&1; then
            echo -e "${GREEN}✅ Passed${NC}"
        else
            echo -e "${RED}❌ Failed - Critical issues found${NC}"
            cat /tmp/review.log
            FAILED=1
        fi
        echo ""
    fi
done

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All files passed code review${NC}"
    exit 0
else
    echo -e "${RED}❌ Code review failed. Fix issues or use:${NC}"
    echo "    git commit --no-verify"
    exit 1
fi
