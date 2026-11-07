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
cp -R "$P" "$W/masked"
run 5 "mask with another vault refuses (no double masking)" env SECRET_MASK_PASSWORD=$PW "$SM" mask --vault "$W/other.vault" "$P"
has "$W/out" "already masked with another vault" "double masking explained"
if [ ! -e "$W/other.vault" ] && diff -r "$W/masked" "$P" >/dev/null; then ok "refused mask wrote nothing"; else bad "refused mask changed files"; fi
mv "$P/.secret-mask.vault" "$W/vault.bak"
run 5 "mask without the vault refuses" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$P"
if [ ! -e "$P/.secret-mask.vault" ]; then ok "no second vault created"; else bad "a second vault was created"; fi
mv "$W/vault.bak" "$P/.secret-mask.vault"

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
has "$P/.claude/settings.json" '"matcher": "Read|Grep|NotebookRead|Bash|mcp__.*"' "hook matcher"
has "$P/.mcp.json" '"secret-mask"' "MCP server registered"
run 0 "setup again" "$SM" setup "$P"
has "$W/out" "nothing changed" "setup is idempotent"

echo "-- install for coding agents"
H=$W/home
mkdir -p "$H/.codex" "$H/.gemini"
run 0 "install detects agents" env HOME=$H "$SM" install
has "$W/out" "Codex CLI:" "Codex detected"
has "$W/out" "Gemini CLI:" "Gemini detected"
hasnt "$W/out" "Cursor:" "Cursor not detected"
has "$H/.codex/config.toml" "[mcp_servers.secret-mask]" "Codex MCP server"
has "$H/.codex/hooks.json" "hook --client codex" "Codex hook"
has "$H/.gemini/settings.json" "hook --client gemini" "Gemini hook"
has "$H/.gemini/GEMINI.md" "secret-mask:start" "Gemini instructions"
run 0 "install again" env HOME=$H "$SM" install
hasnt "$W/out" "(updated)" "install is idempotent"
printf '{"tool_name":"Bash","cwd":"%s","tool_input":{"command":"cat .env"}}' "$W/original" >"$W/codex.in"
run 0 "codex hook" sh -c "\"$SM\" hook --client codex <\"$W/codex.in\""
has "$W/out" '"permissionDecision":"deny"' "codex hook blocks cat of a leaky file"
printf '{"hook_event_name":"beforeReadFile","file_path":"%s/.env","workspace_roots":["%s"]}' "$W/original" "$W/original" >"$W/cursor.in"
run 0 "cursor hook" sh -c "\"$SM\" hook --client cursor <\"$W/cursor.in\""
has "$W/out" '"permission":"deny"' "cursor hook blocks a leaky read"
run 0 "uninstall" env HOME=$H "$SM" uninstall
if [ -z "$(find "$H" -type f)" ]; then ok "uninstall removes every file it wrote"; else find "$H" -type f >"$W/out"; bad "uninstall left files"; fi

if command -v git >/dev/null 2>&1; then
  echo "-- git pre-commit protection"
  G=$W/repo
  rm -rf "$G" && cp -R "$W/original" "$G"
  export GIT_AUTHOR_NAME=e2e GIT_AUTHOR_EMAIL=e2e@example.com GIT_COMMITTER_NAME=e2e GIT_COMMITTER_EMAIL=e2e@example.com
  git -C "$G" init -q
  run 0 "protect" "$SM" protect --command "$SM" "$G"
  has "$G/.git/hooks/pre-commit" "pre-commit --mode block" "pre-commit hook installed"
  git -C "$G" add -A
  run 1 "commit with secrets is blocked" git -C "$G" commit -qm leak
  has "$W/out" "commit blocked" "the hook explains why"
  hasnt "$W/out" "$AWS" "the hook never prints secret values"
  if git -C "$G" rev-parse -q --verify HEAD >/dev/null; then bad "nothing committed"; else ok "nothing committed"; fi
  run 0 "protect --mode mask" "$SM" protect --mode mask --command "$SM" "$G"
  run 0 "commit masks and re-stages" env SECRET_MASK_PASSWORD=$PW git -C "$G" commit -qm masked
  git -C "$G" show HEAD:.env >"$W/committed"
  hasnt "$W/committed" "$AWS" "the committed .env has no secret"
  has "$W/committed" "__SECRET_MASK_" "the committed .env has placeholders"
  run 0 "protect --remove" "$SM" protect --remove "$G"
  if [ -e "$G/.git/hooks/pre-commit" ]; then bad "hook removed"; else ok "hook removed"; fi
else
  echo "-- git pre-commit protection: skipped (no git in this environment)"
fi

echo "-- detection rules"
run 0 "rules lists the rules in use" "$SM" rules "$W/original"
has "$W/out" "secret-mask-password-unquoted" "secret-mask password rules are active"
has "$W/out" "aws-access-token" "gitleaks rules are active"
run 0 "rules --id shows a rule in full" "$SM" rules --id secret-mask-url-password "$W/original"
has "$W/out" '"secretGroup": 1' "rule details"
PWP=$W/passwords
mkdir -p "$PWP/config"
printf 'DB_PASSWORD=Admin@123\nREDIS_PASSWORD=${REDIS_PASSWORD}\n' >"$PWP/.env"
printf 'db:\n  url: postgres://app:Dbpass-77@db:5432/app\n' >"$PWP/config/app.yaml"
printf '<settings><db.password>XmlPass99</db.password></settings>\n' >"$PWP/config/app.xml"
run 4 "self-chosen passwords are detected" "$SM" check "$PWP"
has "$W/out" "3 unmasked secret(s)" "three passwords; the \${VAR} reference is not one"
run 0 "passwords are masked" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$PWP"
hasnt "$PWP/.env" "Admin@123" ".env password masked"
has "$PWP/.env" 'REDIS_PASSWORD=${REDIS_PASSWORD}' "variable reference left alone"
has "$PWP/config/app.yaml" "postgres://app:__SECRET_MASK_" "only the password part of the URL is masked"
C=$W/custom
mkdir -p "$C"
printf 'service acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\n' >"$C/notes.txt"
run 0 "custom format unknown to the default rules" "$SM" check "$C"
printf '%s\n' '[extend]' 'useDefault = true' '[[rules]]' 'id = "acme-token"' \
  "regex = '''\\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\\b'''" 'keywords = ["acme_"]' >"$C/.gitleaks.toml"
run 4 "a custom rule in .gitleaks.toml detects it" "$SM" check "$C"
has "$W/out" "acme-token" "custom rule id reported"
printf 'notes.txt:acme-token:1\n' >"$C/.gitleaksignore"
run 0 ".gitleaksignore suppresses a finding" "$SM" check "$C"

echo "-- MCP: agent workflow and rule tools"
M=$W/mcp
mkdir -p "$M"
printf 'DB_PASSWORD=Admin@123\nSERVICE_TOKEN=acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\n' >"$M/.env"
# mcp <tool> <arguments-json>: one tool call against $M, output in $W/out
mcp() {
  printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" >"$W/mcp.in"
  run 0 "mcp $1" sh -c "\"$SM\" mcp --dir \"$M\" <\"$W/mcp.in\""
}
mcp next_steps '{}'
has "$W/out" "NOT SAFE" "next_steps: not safe before masking"
has "$W/out" "secret-mask mask $M" "next_steps gives the user the mask command"
hasnt "$W/out" "Admin@123" "next_steps never shows values"
mcp list_rules '{"source":"secret-mask"}'
has "$W/out" "secret-mask-password-quoted" "list_rules shows the password rules"
mcp get_rule '{"id":"aws-access-token"}'
has "$W/out" "keywords" "get_rule returns the full rule"
mcp test_rule '{"regex":"\\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\\b","sample":"T=acme_xx_AAAAbbbbCCCCddddEEEEffff","scan_project":true}'
has "$W/out" "acme_xx_AAAAbbbbCCCCddddEEEEffff" "test_rule shows the sample match"
has "$W/out" ".env:2" "test_rule shows project locations"
hasnt "$W/out" "acme_pr_Q7xT2" "test_rule never shows project values"
mcp add_rule '{"id":"acme-token","regex":"\\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\\b","keywords":["acme_"]}'
has "$W/out" "Added rule" "add_rule writes the rule"
has "$M/.gitleaks.toml" "useDefault = true" "default rules stay on"
mcp add_rule '{"id":"aws-access-token","regex":"x(y)"}'
has "$W/out" "already exists" "add_rule cannot replace a rule"
run 0 "user masks (password rule + new rule)" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$M"
has "$W/out" "Masked 2 occurrence(s)" "both secrets masked"
mcp next_steps '{}'
has "$W/out" "STATE: SAFE" "next_steps: safe after masking"
has "$W/out" "secret-mask restore $M" "next_steps tells how to unseal"
run 0 "user unseals" env SECRET_MASK_PASSWORD=$PW "$SM" restore --clean "$M"
has "$M/.env" "Admin@123" "real values back"

echo "-- local development: tell real secrets from dev values, allowlist the dev ones"
D=$W/devproject
mkdir -p "$D/test/fixtures"
printf 'DATABASE_URL=postgres://app:Devpass-123@localhost:5432/app\nPROD_DB_PASSWORD=Pr0d-S3cret!\nLOCAL_ADMIN_PASSWORD=localdev-admin1\n' >"$D/.env"
printf 'DB_PASSWORD=Fixture-Pass1\n' >"$D/test/fixtures/db.env"
printf 'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: Compose-Pass9\n' >"$D/docker-compose.dev.yml"
run 4 "dev values are detected like any password" "$SM" check "$D"
has "$W/out" "5 unmasked secret(s)" "five findings before allowlisting"
M_SAVE=$M
M=$D
mcp review_findings '{}'
M=$M_SAVE
has "$W/out" "postgres://app:«redacted»@localhost" "review_findings shows the line with the value redacted"
has "$W/out" "may be a local-dev value" "localhost URL flagged as possibly dev"
has "$W/out" "looks like a REAL credential" "production password flagged as real"
has "$W/out" "test/fixtures/db.env:secret-mask-password-unquoted:1" "exact .gitleaksignore entry offered"
hasnt "$W/out" "Pr0d-S3cret" "review_findings never shows values"
printf '%s\n' '[extend]' 'useDefault = true' '' '[[allowlists]]' 'description = "local dev and test files"' \
  "paths = ['''^docker-compose\\.dev\\.yml\$''', '''^test/fixtures/''']" '' '[[allowlists]]' \
  'description = "local dev database"' 'targetRules = ["secret-mask-url-password"]' 'regexTarget = "line"' \
  "regexes = ['''@(?:localhost|127\\.0\\.0\\.1|db)[:/]''']" '' '[[allowlists]]' \
  'description = "shared dev passwords"' 'stopwords = ["localdev"]' >"$D/.gitleaks.toml"
run 4 "with the documented dev allowlists only the real secret is left" "$SM" check "$D"
has "$W/out" "1 unmasked secret(s)" "one finding left"
has "$W/out" ".env:2" "the production password"
printf '.env:secret-mask-password-unquoted:2\n' >"$D/.gitleaksignore"
run 0 ".gitleaksignore allowlists one finding" "$SM" check "$D"

echo "-- shell completion"
for SH in bash zsh; do
  run 0 "completion $SH" "$SM" completion $SH
  cp "$W/out" "$W/completion.$SH"
  has "$W/completion.$SH" "protect" "$SH script completes the commands"
  if command -v $SH >/dev/null 2>&1; then
    run 0 "$SH accepts the script" $SH -n "$W/completion.$SH"
  fi
done
if command -v bash >/dev/null 2>&1; then
  run 0 "bash completes --clients values" bash -c ". '$W/completion.bash'; COMP_WORDS=(secret-mask install --clients co); COMP_CWORD=3; _secret_mask; echo \"\${COMPREPLY[*]}\""
  has "$W/out" "codex copilot" "bash suggests the matching clients"
fi
run 0 "completion --install zsh" env HOME="$W/chome" SHELL=/bin/zsh "$SM" completion --install
has "$W/chome/.zshrc" "completion zsh" "zsh startup file loads it"
run 0 "completion --uninstall zsh" env HOME="$W/chome" "$SM" completion --uninstall zsh
if [ -e "$W/chome/.zshrc" ]; then bad "uninstall removes the block"; else ok "uninstall removes the block"; fi

echo "-- secret, token and API key rules"
K=$W/keys
mkdir -p "$K/config" "$K/src" "$K/k8s"
printf 'CLIENT_SECRET=mysecret1\nTOKEN_LIMIT=1000\nGITHUB_TOKEN=%s\n' "$GH" >"$K/.env"
printf '{"internalAuthorization": {"svc-a1b2-c3d4-client": "3f2a9c1e-1b2c-4d5e-8f90-123456789abc"}}\n' >"$K/config/auth.json"
printf 'fetch("https://v6.exchangerate-api.com/v6/0123456789abcdef0123/latest/USD")\n' >"$K/src/rates.js"
printf 'spec:\n  secretName: db-credentials\n  tokenTtl: 3600\n' >"$K/k8s/app.yaml"
run 4 "low-entropy secrets, client maps and URL keys are detected" "$SM" check "$K"
has "$W/out" "4 unmasked secret(s)" "four findings; references and settings are not secrets"
has "$W/out" ".env:3  github-pat" "a token found by two rules is reported once, under the specific rule"
has "$W/out" "secret-mask-client-credential-map" "client credential map"
has "$W/out" "secret-mask-exchangerate-api-key" "API key in a URL path"

echo "-- reveal: real values, for the user's terminal only"
R=$W/reveal
rm -rf "$R" && cp -R "$W/original" "$R"
run 0 "mask a copy" env SECRET_MASK_PASSWORD=$PW "$SM" mask "$R"
run 1 "reveal refuses without a terminal" env SECRET_MASK_PASSWORD=$PW "$SM" reveal "$R"
has "$W/out" "interactive terminal" "reason given"
hasnt "$W/out" "$AWS" "nothing revealed"
if command -v script >/dev/null 2>&1 && script --version 2>/dev/null | grep -q util-linux; then
  run 1 "reveal refuses inside a coding agent" sh -c "printf '%s\n' '$PW' | CLAUDECODE=1 script -qec '$SM reveal $R' /dev/null"
  has "$W/out" "inside a coding agent" "agent environment detected"
  run 0 "reveal in a terminal shows values and locations" sh -c "printf '%s\n' '$PW' | script -qec '$SM reveal $R' /dev/null"
  has "$W/out" ".env:1  aws-access-token  __SECRET_MASK_" "file, line, rule and placeholder"
  has "$W/out" "$AWS" "the real value"
else
  echo "-- reveal in a terminal: skipped (needs util-linux script)"
fi

echo "-- hooks: reveal, other MCP servers, session start"
printf '{"tool_name":"Bash","cwd":"%s","tool_input":{"command":"secret-mask reveal ."}}' "$R" >"$W/h.in"
run 0 "hook on secret-mask reveal" sh -c "\"$SM\" hook <\"$W/h.in\""
has "$W/out" '"permissionDecision":"deny"' "an agent may not run reveal"
printf '{"tool_name":"mcp__codebase-memory-mcp__index_repository","cwd":"%s","tool_input":{"repo_path":"%s"}}' "$W/original" "$W/original" >"$W/h.in"
run 0 "hook on another MCP server's indexer" sh -c "\"$SM\" hook <\"$W/h.in\""
has "$W/out" '"permissionDecision":"deny"' "indexing a project with unmasked secrets is blocked"
printf '{"tool_name":"mcp__codebase-memory-mcp__index_repository","cwd":"%s","tool_input":{"repo_path":"%s"}}' "$R" "$R" >"$W/h.in"
run 0 "hook on the indexer after masking" sh -c "\"$SM\" hook <\"$W/h.in\""
if [ -s "$W/out" ]; then bad "indexing a masked project is allowed"; else ok "indexing a masked project is allowed"; fi
printf '{"hook_event_name":"SessionStart","cwd":"%s"}' "$W/original" >"$W/h.in"
run 0 "session start" sh -c "\"$SM\" hook <\"$W/h.in\""
has "$W/out" "BEFORE anything else" "the agent is told to mask first"
has "$W/out" "additionalContext" "as session context"

echo "-- upgrade"
run 0 "upgrade prints the command" "$SM" upgrade --version v9.9.9
has "$W/out" "install.sh | sh -s -- --dir" "upgrade keeps the install directory"
has "$W/out" "--version v9.9.9" "upgrade pins a release"
INSTALLER=${SECRET_MASK_INSTALLER:-$(dirname "$0")/../../install.sh}
if command -v httpd >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && [ -f "$INSTALLER" ]; then
  case "$(uname -m)" in aarch64 | arm64) A=arm64 ;; *) A=amd64 ;; esac
  REL=$W/release
  mkdir -p "$REL" "$W/ubin" "$W/uhome/.claude"
  cp "$SM" "$REL/secret-mask_linux_$A"
  (cd "$REL" && sha256sum "secret-mask_linux_$A" >SHA256SUMS)
  httpd -f -p 127.0.0.1:18080 -h "$REL" &
  HTTPD=$!
  sleep 1
  # An "old release" that only answers `version`.
  printf '#!/bin/sh\necho "secret-mask v0.0.1 (gitleaks old)"\n' >"$W/ubin/secret-mask"
  chmod 755 "$W/ubin/secret-mask"
  run 0 "install.sh upgrades in place" env HOME="$W/uhome" PATH="$W/ubin:$PATH" SECRET_MASK_DOWNLOAD_URL=http://127.0.0.1:18080 sh "$INSTALLER" --clients claude
  has "$W/out" "Upgraded: v0.0.1 ->" "old and new versions reported"
  has "$W/out" "Claude Code:" "agent configuration refreshed"
  run 0 "upgraded binary runs" "$W/ubin/secret-mask" version
  has "$W/out" "(gitleaks v8." "the old binary was replaced"
  echo "0000000000000000000000000000000000000000000000000000000000000000  secret-mask_linux_$A" >"$REL/SHA256SUMS"
  run 1 "install.sh refuses a checksum mismatch" env HOME="$W/uhome" PATH="$W/ubin:$PATH" SECRET_MASK_DOWNLOAD_URL=http://127.0.0.1:18080 sh "$INSTALLER" --skip-config
  has "$W/out" "CHECKSUM MISMATCH" "mismatch reported"
  run 1 "install.sh refuses plain HTTP to another host" env SECRET_MASK_DOWNLOAD_URL=http://example.com sh "$INSTALLER"
  kill "$HTTPD"
else
  echo "-- install.sh upgrade: skipped (needs httpd, curl and install.sh)"
fi

echo "== $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
