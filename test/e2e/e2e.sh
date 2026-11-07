#!/bin/sh
# End-to-end test of a secret-mask binary (POSIX sh + busybox). Usage: e2e.sh /path/to/secret-mask
# Runs the same way against a release binary or inside the Docker image (see Makefile: make e2e).
set -eu
SM=${1:?usage: e2e.sh /path/to/secret-mask}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PASS=0
FAIL=0
PW="e2e-password-123"

ok() { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; [ -f "$W/out" ] && sed 's/^/        /' "$W/out"; }

# run <want-exit> <description> <cmd...>: output goes to $W/out
run() {
  want=$1 desc=$2
  shift 2
  set +e
  "$@" >"$W/out" 2>&1
  got=$?
  set -e
  if [ "$got" = "$want" ]; then ok "$desc"; else bad "$desc (exit $got, want $want)"; fi
}
has() { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3: '$2' not in $1"; fi; }
hasnt() { if grep -qF -- "$2" "$1"; then bad "$3: '$2' found in $1"; else ok "$3"; fi; }
hook() { printf '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"%s","tool_input":{"file_path":"%s"}}' "$P" "$1" | CLAUDE_PROJECT_DIR=$P "$SM" hook; }

# Secrets are assembled here so this script never contains a detectable secret.
AWS="AKIA""QYLPMN5HHHFPZAM2"
GH="ghp_""8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"
P=$W/project
mkdir -p "$P/config" "$P/docs"
printf 'AWS_ACCESS_KEY_ID=%s\nGITHUB_TOKEN=%s\nPORT=8080\n' "$AWS" "$GH" >"$P/.env"
printf '{"github":{"token":"%s"},"timeout":30}\n' "$GH" >"$P/config/app.json"
printf '# API\nNo secrets here.\n' >"$P/docs/README.md"
cp -R "$P" "$W/original"

echo "== secret-mask e2e: $SM"
run 0 "version" "$SM" version
has "$W/out" "(gitleaks v8." "version reports the embedded gitleaks"

echo "-- detection (no password needed)"
run 4 "check finds unmasked secrets" "$SM" check "$P"
has "$W/out" "3 unmasked secret(s)" "check counts every occurrence"
hasnt "$W/out" "$AWS" "check never prints secret values"

echo "-- AI agent guard rails before masking"
run 0 "hook runs" hook "$P/.env"
has "$W/out" '"permissionDecision":"deny"' "hook blocks reading .env"
has "$W/out" "secret-mask mask $P" "hook tells the user what to run"
hasnt "$W/out" "$GH" "hook never prints secret values"
run 0 "hook on a clean file" hook "$P/docs/README.md"
if [ -s "$W/out" ]; then bad "hook allows a clean file (no output)"; else ok "hook allows a clean file (no output)"; fi
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_secrets","arguments":{}}}' >"$W/mcp.in"
run 0 "mcp server" sh -c "\"$SM\" mcp --dir \"$P\" <\"$W/mcp.in\""
has "$W/out" '"name":"check_secrets"' "mcp lists check_secrets"
has "$W/out" '3 unmasked secret(s)' "mcp check_secrets reports leaks"
hasnt "$W/out" '"name":"restore' "mcp does not expose restore"

echo "-- mask"
run 1 "mask without a password (no env, no terminal) fails" env -u SECRET_MASK_PASSWORD "$SM" mask "$P"
run 2 "mask rejects a short password" env SECRET_MASK_PASSWORD=short "$SM" mask "$P"
run 0 "mask with SECRET_MASK_PASSWORD" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$P"
has "$W/out" "Masked 3 occurrence(s) in 2 file(s); the vault holds 2 secret(s)" "mask summary"
hasnt "$P/.env" "$AWS" ".env no longer contains the AWS key"
hasnt "$P/config/app.json" "$GH" "app.json no longer contains the token"
has "$P/.env" "__SECRET_MASK_" ".env has placeholders"
has "$P/SECRET_MASK_AI_GUIDE.md" "You MUST NOT" "AI guide written"
hasnt "$P/.secret-mask.vault" "$GH" "vault does not contain plaintext"

echo "-- after masking"
run 0 "check is clean" "$SM" check "$P"
run 0 "hook on masked .env" hook "$P/.env"
if [ -s "$W/out" ]; then bad "hook allows the masked file"; else ok "hook allows the masked file"; fi
run 0 "status" "$SM" status "$P"
has "$W/out" "missing: 0" "status: all placeholders present"
run 0 "re-mask finds nothing new" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$P"
has "$W/out" "Masked 0" "re-mask is a no-op"

echo "-- an AI edits the masked project"
TOKEN=$(grep -o '__SECRET_MASK_[0-9a-f]*__' "$P/config/app.json")
printf 'GITHUB_TOKEN=%s\n' "$TOKEN" >"$P/config/moved.env"
printf 'LOG_LEVEL=debug\n' >>"$P/.env"
cp "$P/.env" "$W/env.before"
run 1 "restore with a wrong password fails" env SECRET_MASK_PASSWORD=wrong-password "$SM" restore "$P"
has "$W/out" "wrong password" "wrong password reported"
if cmp -s "$P/.env" "$W/env.before"; then ok "nothing written with a wrong password"; else bad "files changed on wrong password"; fi
sed -i 's/__SECRET_MASK_/__secret_mask_/' "$P/.env"
run 3 "status detects an altered placeholder" "$SM" status "$P"
run 3 "restore refuses with an altered placeholder" env SECRET_MASK_PASSWORD=$PW "$SM" restore "$P"
if grep -q "__secret_mask_" "$P/.env"; then ok "nothing restored while a placeholder is missing"; else bad "restore wrote files"; fi
sed -i 's/__secret_mask_/__SECRET_MASK_/' "$P/.env"
run 0 "restore with the right password" env SECRET_MASK_PASSWORD=$PW "$SM" restore "$P"
has "$P/.env" "$AWS" ".env secret restored"
has "$P/.env" "LOG_LEVEL=debug" "the AI's other edit is kept"
has "$P/config/moved.env" "$GH" "placeholder moved to another file is restored"
has "$W/out" "edited since masking" "restore reports edited files"

echo "-- exact round trip"
rm -rf "$W/rt" && cp -R "$W/original" "$W/rt"
run 0 "mask copy" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$W/rt"
run 0 "restore --clean" env SECRET_MASK_PASSWORD=$PW "$SM" restore --clean "$W/rt"
if diff -r "$W/original" "$W/rt" >"$W/out" 2>&1; then ok "restored tree is byte-identical to the original"; else bad "round trip differs"; fi

echo "-- Claude Code setup"
run 0 "setup" "$SM" setup "$P"
has "$P/.claude/settings.json" '"command": "secret-mask hook"' "hook installed"
has "$P/.claude/settings.json" '"matcher": "Read|Grep|NotebookRead"' "hook matcher"
has "$P/.mcp.json" '"secret-mask"' "MCP server registered"
run 0 "setup again" "$SM" setup "$P"
has "$W/out" "nothing changed" "setup is idempotent"

echo "== $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
