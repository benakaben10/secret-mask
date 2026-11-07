# secret-mask

Mask the secrets in a project before AI agents (or anyone) see it, and restore them exactly afterwards.

- **Detects** secrets with [gitleaks](https://github.com/gitleaks/gitleaks), embedded as a library: one
  static binary, no external tools. Your `.gitleaks.toml` and `.gitleaksignore` are honored.
- **Masks** every occurrence with a stable placeholder such as `__SECRET_MASK_8656926daa6d6f8c__`; the same
  value gets the same placeholder everywhere.
- **Encrypts** the originals into `.secret-mask.vault` with your password (AES-256-GCM, PBKDF2-SHA256 600k).
- **Restores** byte-for-byte, even if placeholders were moved to other files, while keeping other edits.
- **Guards AI agents**: a Claude Code hook blocks reading files that still contain unmasked secrets, an MCP
  server gives agents read-only checks, and `SECRET_MASK_AI_GUIDE.md` tells them never to alter placeholders.

## Install

**Binary** — download `secret-mask_<os>_<arch>` from the
[latest release](https://github.com/OWNER/secret-mask/releases/latest), check it against `SHA256SUMS`,
make it executable and put it on `PATH`. Builds: linux/darwin (amd64, arm64), windows/amd64.

**Docker** (linux/amd64, linux/arm64)

```sh
docker run --rm -it -u "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/OWNER/secret-mask:latest check
```

**Go**: `go install github.com/OWNER/secret-mask/cmd/secret-mask@latest`

**From source** (needs only Docker): `make binaries` → `dist/`, `make image` → `secret-mask:dev`.

## Use

```sh
secret-mask check  .        # exit 4 if anything is unmasked (no password)
secret-mask mask   .        # mask + write .secret-mask.vault and SECRET_MASK_AI_GUIDE.md
secret-mask status .        # every placeholder still present? (no password)
secret-mask restore .       # put the real values back
secret-mask restore --clean .   # ...and delete the vault and guide
```

The password comes from `$SECRET_MASK_PASSWORD` (or `--password-env NAME`); if it is empty you are prompted
on the terminal. `--ask` always prompts. A new vault asks twice and needs at least 8 characters. Running
`mask` again adds new secrets to the same vault (same password).

| Exit code | Meaning |
|---|---|
| 0 | ok |
| 1 | error (wrong password, I/O, …) |
| 2 | bad usage |
| 3 | placeholders missing or altered (`status`, `restore`) — nothing was restored |
| 4 | `check` found unmasked secrets |

Useful flags: `--config` (gitleaks config; default `$GITLEAKS_CONFIG`, then `<dir>/.gitleaks.toml`, then the
built-in rules), `--dry-run`, `--vault`, `--guide`, `restore --force` (restore what is present even if some
placeholders are gone).

## AI agents

```sh
scripts/install-claude-hooks.sh .                      # secret-mask on PATH
scripts/install-claude-hooks.sh --docker IMAGE .       # run it from a container
scripts/install-claude-hooks.sh --user                 # hook for all projects
```

or directly `secret-mask setup [--scope user] [--command CMD] .`. This merges into existing config:

- `.claude/settings.json` — a `PreToolUse` hook (`Read|Grep|NotebookRead`) running `secret-mask hook`. If the
  target still has unmasked secrets the read is **denied** and the agent is told to ask the user to run
  `secret-mask mask` themselves (it needs their password). Any error also denies (fail closed).
- `.mcp.json` — the `secret-mask` MCP server (`secret-mask mcp`) with read-only tools `check_secrets`,
  `masking_status` and `masking_guide`. There is deliberately no mask/restore tool: those need the password
  and stay with the user. Tool results never include secret values.

Limits: the hook covers Claude Code's file-reading tools; a shell command (`cat`, …) is not inspected, so
keep secrets masked whenever an agent works in the tree.

## Security notes

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).


- The vault keeps a plaintext manifest (placeholder ids, rule ids, file paths — no values) so `status` works
  without the password; it is authenticated, so editing it makes the vault fail to open.
- Committing the vault is up to you: it is encrypted, but its strength is your password's.
- Masking rewrites files atomically and preserves their permissions. Binary files and symlinks are skipped;
  a secret that gitleaks found only after decoding (e.g. base64) is reported as skipped.

## Development

Only Docker is needed:

```sh
make test       # go vet + unit/integration tests
make e2e        # end-to-end against the linux binary and the image
make demo       # guided walkthrough
make scan       # Trivy scan of the image
```

Layout: `cmd/secret-mask` (entrypoint), `internal/` — `cli` (commands), `detect` (embedded gitleaks), `mask`
(placeholders, mask/restore), `vault` (encryption), `guide` (AI rules), `hook` (Claude Code hook), `mcp`
(stdio MCP server), `setup` (config wiring), `fsutil`, `version`.

## License

[MIT](LICENSE). Embeds [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
