# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository). We aim to acknowledge reports within 5 working days.

## Scope

In scope: vault confidentiality/integrity, restore correctness, the Claude Code hook failing open, and any
path where a secret value reaches tool output (CLI `check`, hook messages, MCP results).

Out of scope: secrets gitleaks does not detect (report those to [gitleaks](https://github.com/gitleaks/gitleaks)),
weak user-chosen passwords, and agents reading files through tools the hook does not cover (e.g. shell commands).
