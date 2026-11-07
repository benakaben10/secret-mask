#!/bin/sh
# Guided demo of every secret-mask feature on a sample API project: detection (including self-chosen
# passwords), detection rules, AI agent setup and workflow (block, next_steps, review_findings), allowlists for
# local development, masking, unsealing, the "never mask twice" rule, git protection and upgrades.
# Usage: demo.sh /path/to/secret-mask [workdir]      (make demo runs it in a container with git)
set -eu
SM=${1:?usage: demo.sh /path/to/secret-mask [workdir]}
W=${2:-$(mktemp -d)}
P=$W/api-project
export SECRET_MASK_PASSWORD="demo-password-2026"
export HOME=$W/home GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.com GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.com

step() { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
say() { printf '\033[2m%s\033[0m\n' "$*"; }
show() { printf '\033[33m$ %s\033[0m\n' "$*"; sh -c "$*" || true; }
# mcp TOOL ARGS-JSON: what an AI agent gets from the secret-mask MCP server
mcp() {
  printf '\033[35m[agent → MCP] %s %s\033[0m\n' "$1" "$2"
  printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" |
    "$SM" mcp --dir "$P" | tail -n 1 | sed -e 's/.*"text":"//' -e 's/","type":"text"}\].*//' -e 's/\\n/\n/g' \
      -e 's/\\"/"/g' -e 's/\\u003c/</g' -e 's/\\u003e/>/g' -e 's/\\u0026/\&/g' -e 's/\\\\/\\/g'
}
read_hook() { # read_hook FILE: the JSON Claude Code sends before its Read tool
  printf '\033[35m[agent] Read %s\033[0m\n' "$1"
  printf '{"tool_name":"Read","cwd":"%s","tool_input":{"file_path":"%s"}}' "$P" "$1" | CLAUDE_PROJECT_DIR=$P "$SM" hook |
    sed -e 's/.*"permissionDecisionReason":"//' -e 's/"}}$//' -e 's/\\n/\n/g'
}

# Demo secrets are assembled at run time (fake values in real formats).
AWS_ID="AKIA""QYLPMN5HHHFPZAM2"
SLACK="xoxb-""2918374650-5829104736281-Kq8Lm3Np7Rt2Vx9Zb4Cd6Fh1"
GH="ghp_""8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"

rm -rf "$W/home" "$P" && mkdir -p "$W/home/.claude" "$P/config" "$P/k8s" "$P/src" "$P/test/fixtures"
cat >"$P/.env" <<EOF
APP_PORT=8080
AWS_ACCESS_KEY_ID=$AWS_ID
SLACK_BOT_TOKEN=$SLACK
DB_PASSWORD=Admin@2024
LOCAL_DATABASE_URL=postgres://dev:devpass123@localhost:5432/orders
EOF
cat >"$P/config/app.json" <<EOF
{
  "service": "orders-api",
  "github": { "token": "$GH", "org": "acme" },
  "smtp": { "password": "Mail-Pass-77" }
}
EOF
cat >"$P/k8s/deployment.yaml" <<EOF
env:
  - name: GITHUB_TOKEN
    value: "$GH"
EOF
printf 'DB_PASSWORD=fixture-pass-1\n' >"$P/test/fixtures/db.env"
printf 'notes: service token acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\n' >"$P/config/notes.yaml"
printf 'package main\n\nfunc main() {}\n' >"$P/src/main.go"

step "1. A project with secrets, including passwords people chose themselves"
show "$SM version"
show "cat $P/.env"

step "2. Check before letting anyone in (no password needed; values are never printed)"
show "$SM check $P"
say "DB_PASSWORD=Admin@2024 is caught by secret-mask's password rules; gitleaks alone looks for random tokens."

step "3. The detection rules in use"
show "$SM rules --source secret-mask $P"
show "$SM rules $P | head -4"

step "4. Set up the coding agents found on this machine (here: Claude Code)"
show "$SM install"
show "cat $HOME/.claude/settings.json"

step "5. The agent starts a task: the hook blocks the read, next_steps says what to ask the user"
read_hook "$P/.env"
mcp next_steps '{}'

step "6. Real secret or local-dev value? The agent cannot see values; review_findings helps it ask you"
mcp review_findings '{}'

step "7. You decide: the localhost URL and the test fixture are dev-only, so you allowlist them"
cat >"$P/.gitleaks.toml" <<'EOF'
[extend]
useDefault = true

[[allowlists]]
description = "local dev and test files"
paths = ['''^test/fixtures/''']

[[allowlists]]
description = "local dev database"
targetRules = ["secret-mask-url-password"]
regexTarget = "line"
regexes = ['''@(?:localhost|127\.0\.0\.1)[:/]''']
EOF
show "cat $P/.gitleaks.toml"
show "$SM check $P"

step "8. An in-house token format the rules miss: the agent drafts a rule, tests it, adds it"
mcp test_rule '{"regex":"\\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\\b","keywords":["acme_"],"sample":"token: acme_xx_AAAAbbbbCCCCddddEEEEffff","scan_project":true}'
mcp add_rule '{"id":"acme-token","description":"ACME internal token","regex":"\\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\\b","keywords":["acme_"]}'

step "9. You mask the project (password from SECRET_MASK_PASSWORD here, or prompted)"
show "$SM mask $P"
show "cat $P/.env"
show "cat $P/config/app.json"

step "10. Now the agent may work"
read_hook "$P/.env" && say "(empty = allowed)"
mcp next_steps '{}'

step "11. The agent edits the project, keeping placeholders (it moves the Slack token)"
TOKEN=$(sed -n 's/^SLACK_BOT_TOKEN=//p' "$P/.env")
sed -i '/SLACK_BOT_TOKEN/d' "$P/.env"
printf 'APP_LOG_LEVEL=debug\n' >>"$P/.env"
printf 'SLACK_BOT_TOKEN=%s\n' "$TOKEN" >"$P/config/slack.env"
show "cat $P/config/slack.env"
show "$SM status $P"

step "12. Never mask twice: with the vault gone (or another --vault), mask refuses (exit 5)"
show "mv $P/.secret-mask.vault $W/vault.bak && $SM mask $P; echo exit=\$?; mv $W/vault.bak $P/.secret-mask.vault"

step "13. Commits: block staged secrets, or mask them on the way in"
G=$W/repo
rm -rf "$G" && mkdir -p "$G" && git -C "$G" init -q
printf 'API_TOKEN=%s\n' "$GH" >"$G/.env"
show "$SM protect --command $SM $G"
show "git -C $G add .env && git -C $G commit -qm 'add config'; echo exit=\$?"
show "$SM protect --mode mask --command $SM $G"
show "git -C $G commit -qm 'add config' && git -C $G --no-pager show HEAD:.env"

step "14. You unseal: the real values come back, edits and moved placeholders included"
show "$SM restore --dry-run $P"
show "$SM restore $P"
show "cat $P/.env $P/config/slack.env"

step "15. Upgrading to a new release"
show "$SM upgrade"

step "16. Shell completion for bash and zsh"
show "$SM completion --install bash && tail -4 $HOME/.bashrc"

step "Done"
say "Workdir: $W   Use cases: demo/USE_CASES.md"
