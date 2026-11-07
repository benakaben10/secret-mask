# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository). We aim to acknowledge reports within 5 working days.

## Scope

In scope: vault confidentiality/integrity, restore correctness, an agent hook failing open, `secret-mask reveal`
running without the user's terminal, and any path where a secret value reaches tool output (CLI `check`, hook
messages, MCP results).

Out of scope: secrets no rule detects (report missed formats as an issue, or to
[gitleaks](https://github.com/gitleaks/gitleaks) for its rules), weak user-chosen passwords, shell commands that
build file paths at run time (the hooks read commands best-effort), and MCP servers that index in the
background without a tool call.

## Automated checks

CodeQL, govulncheck, gosec, a secret scan, dependency review and OpenSSF Scorecard run in GitHub Actions
(`.github/workflows/security.yml`, `scorecard.yml`); results are in the Security tab.
