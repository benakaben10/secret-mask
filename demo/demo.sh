#!/bin/sh
# Guided demo: an API project with leaked secrets is protected for AI agents, edited, then restored.
# Usage: demo.sh /path/to/secret-mask [workdir]      (make demo runs it inside the Docker image)
set -eu
SM=${1:?usage: demo.sh /path/to/secret-mask [workdir]}
W=${2:-$(mktemp -d)}
P=$W/api-project
export SECRET_MASK_PASSWORD="demo-password-2026"

step() { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
say() { printf '\033[2m%s\033[0m\n' "$*"; }
show() { printf '\033[33m$ %s\033[0m\n' "$*"; sh -c "$*" || true; }

# Demo secrets are assembled at run time (fake values in real formats).
AWS_ID="AKIA""QYLPMN5HHHFPZAM2"
SLACK="xoxb-""2918374650-5829104736281-Kq8Lm3Np7Rt2Vx9Zb4Cd6Fh1"
GH="ghp_""8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"

rm -rf "$P" && mkdir -p "$P/config" "$P/k8s" "$P/src"
cat >"$P/.env" <<EOF
APP_PORT=8080
AWS_ACCESS_KEY_ID=$AWS_ID
SLACK_BOT_TOKEN=$SLACK
EOF
cat >"$P/config/app.json" <<EOF
{
  "service": "orders-api",
  "github": { "token": "$GH", "org": "acme" },
  "slack": { "token": "$SLACK" }
}
EOF
cat >"$P/k8s/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: GITHUB_TOKEN
              value: "$GH"
EOF
printf 'package main\n\nfunc main() {}\n' >"$P/src/main.go"

step "1. An API project with secrets committed in config"
show "$SM version"
show "cat $P/.env"

step "2. Check before letting an AI agent in (no password needed)"
show "$SM check $P"

step "3. Install the Claude Code guard rails (read hook + MCP server)"
show "$SM setup $P"
show "cat $P/.claude/settings.json"

step "4. The agent tries to read .env -> the hook blocks it"
say "(this is the JSON Claude Code sends to the PreToolUse hook)"
show "printf '{\"tool_name\":\"Read\",\"cwd\":\"$P\",\"tool_input\":{\"file_path\":\"$P/.env\"}}' | CLAUDE_PROJECT_DIR=$P $SM hook"

step "5. The user masks the project (password from SECRET_MASK_PASSWORD, or prompted / --ask)"
show "$SM mask $P"
show "cat $P/.env"
show "cat $P/config/app.json"
show "sed -n '1,12p' $P/SECRET_MASK_AI_GUIDE.md"

step "6. Now the agent may read it"
show "printf '{\"tool_name\":\"Read\",\"cwd\":\"$P\",\"tool_input\":{\"file_path\":\"$P/.env\"}}' | CLAUDE_PROJECT_DIR=$P $SM hook && echo '(no output = allowed)'"
show "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"masking_status\",\"arguments\":{}}}' | $SM mcp --dir $P"

step "7. The agent edits the project, keeping placeholders as the guide says"
say "moves the Slack token into a new file and adds a setting"
TOKEN=$(grep -o 'SLACK_BOT_TOKEN=__SECRET_MASK_[0-9a-f]*__' "$P/.env" | cut -d= -f2)
sed -i '/SLACK_BOT_TOKEN/d' "$P/.env"
printf 'APP_LOG_LEVEL=debug\n' >>"$P/.env"
printf 'SLACK_BOT_TOKEN=%s\n' "$TOKEN" >"$P/config/slack.env"
show "cat $P/config/slack.env"
show "$SM status $P"

step "8. The user restores the real values"
show "$SM restore $P"
show "cat $P/.env $P/config/slack.env"

step "Done"
say "Workdir: $W"
