#!/usr/bin/env bash
set -euo pipefail

REPO_URL=$(git remote get-url origin)
OWNER_REPO=${REPO_URL#https://github.com/}
OWNER_REPO=${OWNER_REPO%.git}

WIKI_URL="https://github.com/${OWNER_REPO}.wiki.git"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "Cloning wiki: $WIKI_URL"
if ! git clone "$WIKI_URL" "$WORKDIR"; then
  echo "Error: Wiki repository not found. Ensure the repo's Wiki is enabled and that you have push access." >&2
  echo "You can enable Wiki with: gh repo edit ${OWNER_REPO} --enable-wiki" >&2
  exit 1
fi

rsync -a --delete docs/wiki/ "$WORKDIR"/
cd "$WORKDIR"
git add .
if git diff --cached --quiet; then
  echo "No wiki changes to publish."
  exit 0
fi
git commit -m "wiki: sync from docs/wiki"
git push origin HEAD
echo "Wiki published: https://github.com/${OWNER_REPO}/wiki"

