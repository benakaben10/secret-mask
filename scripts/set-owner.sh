#!/bin/sh
# Point the module path and docs at the real GitHub repository. Usage: scripts/set-owner.sh owner/repo
set -eu
REPO=${1:?usage: scripts/set-owner.sh owner/repo}
case "$REPO" in */*) ;; *) echo "expected owner/repo" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."
OLD=$(sed -n 's/^module //p' go.mod)
NEW="github.com/$REPO"
OWNER=${REPO%/*}
# Go sources, go.mod, Dockerfile, docs: module path, then remaining OWNER/secret-mask references (ghcr, URLs).
for f in $(git ls-files 2>/dev/null || find . -type f -not -path './.git/*'); do
  case "$(basename "$f")" in *.go|go.mod|Dockerfile|*.md|*.sh|*.yml) ;; *) continue ;; esac
  sed -i.bak -e "s#$OLD#$NEW#g" -e "s#ghcr.io/OWNER/#ghcr.io/$OWNER/#g" -e "s#github.com/OWNER/secret-mask#$NEW#g" "$f" && rm -f "$f.bak"
done
echo "module path: $OLD -> $NEW"
