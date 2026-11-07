#!/bin/sh
# Move the project to another GitHub repository: rewrites the Go module path and the
# github.com / ghcr.io references. Usage: scripts/set-owner.sh owner/repo
set -eu
REPO=${1:?usage: scripts/set-owner.sh owner/repo}
case "$REPO" in */*) ;; *) echo "expected owner/repo" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."
OLD=$(sed -n 's/^module //p' go.mod)   # github.com/<old-owner>/<old-repo>
OLD_REPO=${OLD#github.com/}
OLD_OWNER=${OLD_REPO%/*}
NEW_OWNER=${REPO%/*}
for f in $(git ls-files 2>/dev/null || find . -type f -not -path './.git/*'); do
  [ "$f" = scripts/set-owner.sh ] && continue
  case "$(basename "$f")" in *.go|go.mod|Dockerfile|*.md|*.sh|*.yml) ;; *) continue ;; esac
  sed -i.bak -e "s#github.com/$OLD_REPO#github.com/$REPO#g" -e "s#ghcr.io/$OLD_OWNER/#ghcr.io/$NEW_OWNER/#g" "$f" && rm -f "$f.bak"
done
echo "github.com/$OLD_REPO -> github.com/$REPO"
