#!/bin/bash

# Pre-validation script
# Developed by: ditikrushnaroutray
# Date: 2026-04-03

# Check for required tools
REQUIRED_TOOLS=(git curl jq)
for TOOL in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$TOOL" &> /dev/null; then
        echo "$TOOL is required but not installed. Please install it and try again."
        exit 1
    fi
done

# Example validation checks
# 1. Check if the repository is clean
if [[ -n "
$(git status --porcelain)
" ]]; then
    echo "Repository is not clean. Please commit or stash your changes."
    exit 1
fi

# 2. Check for specific files
REQUIRED_FILES=("README.md" "main.py")
for FILE in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$FILE" ]]; then
        echo "$FILE not found! Please ensure all required files are present."
        exit 1
    fi
done

# 3. Check if the latest changes from the main branch are integrated
git fetch origin
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse "origin/main")
if [ "$LOCAL" != "$REMOTE" ]; then
    echo "Your branch is behind 'origin/main'. Please merge the latest changes and try again."
    exit 1
fi

echo "All pre-validation checks passed!"