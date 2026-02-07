#!/bin/bash
# Setup Hugging Face Space remote for local deployment
# Usage: source setup-hf-remote.sh

if [ -z "$HF_TOKEN" ]; then
    echo "❌ Error: HF_TOKEN environment variable not set"
    echo "Please set your Hugging Face token:"
    echo "  export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxx"
    exit 1
fi

# Remove old remote if it exists
git remote remove hf 2>/dev/null

# Add HF Space remote
git remote add hf https://adarian-dewberry:${HF_TOKEN}@huggingface.co/spaces/adarian-dewberry/code-review-agent

echo "✅ HF Space remote added successfully"
echo "   Remote: hf"
echo "   URL: https://huggingface.co/spaces/adarian-dewberry/code-review-agent"
echo ""
echo "To deploy: git push hf main"
