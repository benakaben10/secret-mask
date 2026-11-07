#!/bin/sh
# Install the secret-mask read hook and MCP server into a project's Claude Code config.
#
#   scripts/install-claude-hooks.sh [project-dir]                    # uses secret-mask on PATH
#   scripts/install-claude-hooks.sh --docker IMAGE [project-dir]     # runs secret-mask from a container
#   scripts/install-claude-hooks.sh --user                           # hook for every project (~/.claude)
#
# After it runs, Claude Code calls `secret-mask hook` before Read/Grep and refuses files that still contain
# unmasked secrets until the user runs `secret-mask mask` in a terminal.
set -eu

IMAGE=""
SCOPE=project
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) IMAGE=${2:?--docker needs an image}; shift 2 ;;
    --user) SCOPE=user; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) break ;;
  esac
done
DIR=$(cd "${1:-.}" && pwd)

if [ -n "$IMAGE" ]; then
  command -v docker >/dev/null 2>&1 || { echo "docker is not installed" >&2; exit 1; }
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
  # The project is mounted at the same path so file paths in hook input resolve inside the container.
  CMD="docker run --rm -i -u $(id -u):$(id -g) -v $DIR:$DIR -w $DIR -e CLAUDE_PROJECT_DIR=$DIR $IMAGE"
  mkdir -p "$HOME/.claude"
  docker run --rm -u "$(id -u):$(id -g)" -v "$DIR:$DIR" -w "$DIR" \
    -v "$HOME/.claude:/home/user/.claude" -e HOME=/home/user "$IMAGE" \
    setup --scope "$SCOPE" --command "$CMD" "$DIR"
else
  command -v secret-mask >/dev/null 2>&1 || {
    echo "secret-mask is not on PATH: download a release binary, or use --docker IMAGE" >&2
    exit 1
  }
  secret-mask setup --scope "$SCOPE" "$DIR"
fi

cat <<EOF

Next steps:
  1. secret-mask check $DIR          # anything unmasked?
  2. secret-mask mask $DIR           # mask it (asks for a password, or set SECRET_MASK_PASSWORD)
  3. Restart Claude Code in $DIR so it loads the hook and the MCP server.
EOF
