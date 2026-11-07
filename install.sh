#!/bin/sh
# One-line installer for secret-mask: downloads the release binary, verifies it against SHA256SUMS,
# installs it and configures every detected coding agent (`secret-mask install`).
#
#   curl -fsSL https://raw.githubusercontent.com/benakaben10/secret-mask/master/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --dir /usr/local/bin --clients claude,codex
#
# Options:
#   --dir PATH         install directory (default: ~/.local/bin)
#   --version TAG      release to install, e.g. v1.2.0 (default: latest)
#   --clients LIST     configure only these agents (claude, codex, gemini, cursor, vscode, copilot)
#   --no-hooks         configure agents without the read-blocking hooks
#   --skip-config      install the binary only, no agent configuration
#
# Environment: SECRET_MASK_DOWNLOAD_URL overrides the release download URL (HTTPS, or http://localhost
# for tests).
set -eu

# Everything runs from main, called on the last line, so a truncated `curl | sh` download runs nothing.
main() {
  REPO=benakaben10/secret-mask
  DIR="$HOME/.local/bin"
  VERSION=latest
  CLIENTS=""
  NO_HOOKS=false
  SKIP_CONFIG=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) DIR=${2:?--dir needs a path}; shift 2 ;;
      --dir=*) DIR=${1#--dir=}; shift ;;
      --version) VERSION=${2:?--version needs a tag}; shift 2 ;;
      --version=*) VERSION=${1#--version=}; shift ;;
      --clients) CLIENTS=${2:?--clients needs a list}; shift 2 ;;
      --clients=*) CLIENTS=${1#--clients=}; shift ;;
      --no-hooks) NO_HOOKS=true; shift ;;
      --skip-config) SKIP_CONFIG=true; shift ;;
      -h|--help) sed -n '2,17p' "$0" 2>/dev/null || echo "see https://github.com/$REPO#install"; exit 0 ;;
      *) echo "install.sh: unknown option '$1' (see --help)" >&2; exit 2 ;;
    esac
  done

  if [ "$VERSION" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
  BASE=${SECRET_MASK_DOWNLOAD_URL:-$BASE}
  case "$BASE" in
    https://*) ;;
    http://localhost[:/]* | http://127.0.0.1[:/]*) ;;
    *) echo "error: refusing non-HTTPS download URL: $BASE" >&2; exit 1 ;;
  esac

  case "$(uname -s)" in
    Darwin) OS=darwin ;;
    Linux) OS=linux ;;
    MINGW* | MSYS* | CYGWIN*) OS=windows ;;
    *) echo "error: unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) ARCH=arm64 ;;
    x86_64 | amd64)
      ARCH=amd64
      # A Rosetta shell reports x86_64 on Apple silicon.
      if [ "$OS" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then ARCH=arm64; fi
      ;;
    *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  EXT=""
  [ "$OS" = windows ] && EXT=.exe
  if [ "$OS" = windows ] && [ "$ARCH" != amd64 ]; then
    echo "error: no windows/$ARCH build" >&2
    exit 1
  fi
  ASSET="secret-mask_${OS}_${ARCH}${EXT}"
  DEST="$DIR/secret-mask$EXT"

  echo "secret-mask installer"
  echo "  release: $VERSION ($ASSET)"
  echo "  target:  $DEST"

  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  download "$BASE/$ASSET" "$TMP/$ASSET"
  download "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"

  # The checksum is mandatory: no published digest, no install.
  EXPECTED=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f { print tolower($1) }' "$TMP/SHA256SUMS")
  case "$EXPECTED" in
    *[!0-9a-f]* | "") echo "error: no valid SHA-256 for $ASSET in SHA256SUMS" >&2; exit 1 ;;
  esac
  if [ "${#EXPECTED}" -ne 64 ]; then
    echo "error: SHA256SUMS lists more than one digest for $ASSET" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{ print tolower($1) }')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP/$ASSET" | awk '{ print tolower($1) }')
  else
    echo "error: sha256sum or shasum is needed to verify the download" >&2
    exit 1
  fi
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: CHECKSUM MISMATCH for $ASSET" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
  fi
  echo "Checksum verified."

  chmod 755 "$TMP/$ASSET"
  if [ "$OS" = darwin ]; then
    xattr -d com.apple.quarantine "$TMP/$ASSET" >/dev/null 2>&1 || true
  fi
  "$TMP/$ASSET" version >/dev/null 2>&1 || { echo "error: the downloaded binary does not run here" >&2; exit 1; }

  # Copy next to the target, then rename: a running binary is never overwritten in place.
  mkdir -p "$DIR"
  cp "$TMP/$ASSET" "$DIR/.secret-mask.$$"
  mv -f "$DIR/.secret-mask.$$" "$DEST"
  echo "Installed: $("$DEST" version)"

  if [ "$SKIP_CONFIG" = true ]; then
    echo "Skipping agent configuration (--skip-config). Run '$DEST install' later."
  else
    echo ""
    set -- install
    [ -n "$CLIENTS" ] && set -- "$@" --clients "$CLIENTS"
    [ "$NO_HOOKS" = true ] && set -- "$@" --no-hooks
    "$DEST" "$@"
  fi

  case ":$PATH:" in
    *":$DIR:"*) ;;
    *)
      echo ""
      echo "NOTE: $DIR is not on your PATH. Add it to your shell profile:"
      echo "  export PATH=\"$DIR:\$PATH\""
      ;;
  esac
}

download() {
  if command -v curl >/dev/null 2>&1; then
    case "$1" in
      https://*) curl -fsSL --proto '=https' --proto-redir '=https' -o "$2" "$1" ;;
      *) curl -fsS --noproxy '*' -o "$2" "$1" ;;
    esac
  elif command -v wget >/dev/null 2>&1; then
    case "$1" in
      https://*) wget -q --https-only -O "$2" "$1" ;;
      *) wget -q --no-proxy --max-redirect=0 -O "$2" "$1" ;;
    esac
  else
    echo "error: curl or wget is required" >&2
    return 1
  fi || { echo "error: download failed: $1" >&2; return 1; }
}

main "$@"
