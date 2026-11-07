# secret-mask

Mask the secrets in a project before AI agents (or anyone) see it, and restore them exactly afterwards.

- **Detects** secrets with [gitleaks](https://github.com/gitleaks/gitleaks), embedded as a library: one
  static binary, no external tools. Your `.gitleaks.toml` and `.gitleaksignore` are honored.
- **Masks** every occurrence with a stable placeholder such as `__SECRET_MASK_8656926daa6d6f8c__`; the same
  value gets the same placeholder everywhere.
- **Encrypts** the originals into `.secret-mask.vault` with your password (AES-256-GCM, PBKDF2-SHA256 600k).
- **Restores** byte-for-byte, even if placeholders were moved to other files, while keeping other edits.
- **Guards AI agents** (Claude Code, Codex, Gemini CLI, Cursor, VS Code / Copilot): `secret-mask install` adds
  a hook that blocks reading files that still contain unmasked secrets, an MCP server with read-only checks,
  and a skill telling them never to alter placeholders.

## Install

**One line** (macOS, Linux; Windows via Git Bash) — downloads the release binary, verifies it against
`SHA256SUMS`, installs it to `~/.local/bin` and runs `secret-mask install` to set up your coding agents:

```sh
curl -fsSL https://raw.githubusercontent.com/benakaben10/secret-mask/master/install.sh | sh
```

Options (after `sh -s --`): `--dir PATH`, `--version vX.Y.Z`, `--clients claude,codex`, `--no-hooks`,
`--skip-config` (binary only). Re-running it updates the binary and the agent configuration.

**Binary** — download `secret-mask_<os>_<arch>` from the
[latest release](https://github.com/benakaben10/secret-mask/releases/latest), check it against `SHA256SUMS`,
make it executable and put it on `PATH`. Builds: linux/darwin (amd64, arm64), windows/amd64.

**Docker** (linux/amd64, linux/arm64)

```sh
docker run --rm -it -u "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/benakaben10/secret-mask:latest check
```

**Go**: `go install github.com/benakaben10/secret-mask/cmd/secret-mask@latest`

**From source** (needs only Docker): `make binaries` → `dist/`, `make image` → `secret-mask:dev`.

## Use

```sh
secret-mask check  .        # exit 4 if anything is unmasked (no password)
secret-mask mask   .        # mask + write .secret-mask.vault and SECRET_MASK_AI_GUIDE.md
secret-mask status .        # every placeholder still present? (no password)
secret-mask restore .       # put the real values back
secret-mask restore --clean .   # ...and delete the vault and guide
secret-mask protect .       # git pre-commit hook: no commit with unmasked secrets
```

Step-by-step scenarios (sharing with an AI agent, CI, commits, recovery…): [demo/USE_CASES.md](demo/USE_CASES.md).

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
| 5 | `mask` refused: the tree is already masked with another vault — nothing was written |

A tree is never masked twice. Running `mask` again with the same vault only masks new secrets; existing
placeholders are never touched. If the tree holds placeholders that the vault does not know (the vault was
deleted or moved, or `--vault` points elsewhere), `mask` stops with exit 5 before asking for a password:
masking again would bury the old placeholders under a second vault. Restore with the original vault first.

Useful flags: `--config` (gitleaks config; default `$GITLEAKS_CONFIG`, then `<dir>/.gitleaks.toml`, then the
built-in rules), `--dry-run`, `--vault`, `--guide`, `restore --force` (restore what is present even if some
placeholders are gone).

## Git commits

```sh
secret-mask protect [dir]               # --mode block (default): refuse commits that stage unmasked secrets
secret-mask protect --mode mask [dir]   # mask the staged secrets and re-stage the files, then commit
secret-mask protect --remove [dir]      # take the hook out again
```

`protect` finds the git repository containing `dir` (default: the current directory; it must be inside a work
tree) and adds a block to its `pre-commit` hook (`git rev-parse --git-path hooks`, so `core.hooksPath` is
honored). An existing shell hook keeps its content; the block goes right after the shebang so it runs first.
A hook in another language is left alone and you are shown the line to add.

On each commit the hook runs `secret-mask pre-commit`, which scans the **staged** content (what will be
committed, not the work tree):

- `block`: the commit is refused with the files, lines and rule ids (never the values) and the command to run.
- `mask`: the secrets are masked in the work tree with the vault of the repository root (created or extended;
  the password comes from `$SECRET_MASK_PASSWORD` or the terminal), the files are staged again and the commit
  goes on. A file whose work tree differs from what is staged is not masked (re-staging it would also commit
  your unstaged changes): the commit is refused instead. The "never mask twice" rule applies: placeholders of
  another vault stop the commit (exit 5). The vault is not staged for you; commit it or keep it safe.
- Any error (no password, scan failure, `secret-mask` not found) blocks the commit. `git commit --no-verify`
  skips the hook.

## AI agents

```sh
secret-mask install                       # every detected agent
secret-mask install --clients claude,codex --dry-run
secret-mask install --no-hooks            # MCP, skill and instructions only
secret-mask uninstall                     # remove everything install wrote
```

`install` detects the agents on this machine and merges into their user configuration (existing settings are
kept, re-running is a no-op, `uninstall` removes only what secret-mask wrote):

| Agent (`--clients`) | MCP server | Read-blocking hook | Skill / instructions |
|---|---|---|---|
| Claude Code (`claude`) | `~/.claude.json` | `PreToolUse` `Read\|Grep\|NotebookRead` in `~/.claude/settings.json` | `~/.claude/skills/secret-mask` |
| Codex CLI (`codex`) | `$CODEX_HOME/config.toml` | `PreToolUse` `Bash` in `$CODEX_HOME/hooks.json` | `AGENTS.md` block, `~/.agents/skills/secret-mask` |
| Gemini CLI (`gemini`) | `~/.gemini/settings.json` | `BeforeTool` (`read_file`, `read_many_files`, searches, shell) | `~/.gemini/GEMINI.md` block |
| Cursor (`cursor`) | `~/.cursor/mcp.json` | `beforeReadFile`, `beforeShellExecution` in `~/.cursor/hooks.json` | `~/.cursor/skills/secret-mask` |
| VS Code Copilot (`vscode`) | `Code/User/mcp.json` | `PreToolUse` in `~/.copilot/hooks/secret-mask.json` | `~/.copilot/skills/secret-mask` |
| Copilot CLI (`copilot`) | `~/.copilot/mcp-config.json` | (shared with VS Code) | (shared with VS Code) |

- **Hook** (`secret-mask hook --client <agent>`): if what the agent is about to read still has unmasked
  secrets, the call is **denied** and the agent is told to ask the user to run `secret-mask mask` themselves
  (it needs their password). Any error also denies (fail closed). Shell commands are read best-effort: files
  named in the command, globs, and the directory of recursive searches (`rg`, `grep -r`) are checked;
  variables and generated paths are not. Codex users trust the new hook once with `/hooks`.
- **MCP server** (`secret-mask mcp`): read-only tools `check_secrets`, `masking_status`, `masking_guide`.
  There is deliberately no mask/restore tool: those need the password and stay with the user. Tool results
  never include secret values.
- **Skill and instructions** tell the agent to keep placeholders byte-for-byte, check before reading
  config files and leave masking to the user. A skill file you wrote yourself is never overwritten
  (`--force` replaces it).
- The configs call this executable by its absolute path; `--command "docker run --rm -i IMAGE"` writes another
  command. JSON files with comments (JSONC) are reported and must be edited by hand.

**Claude Code plugin** (MCP server, hook and skill; needs `secret-mask` on `PATH`). Use either the plugin or
`install --clients claude`, not both:

```sh
claude plugin marketplace add benakaben10/secret-mask
claude plugin install secret-mask@secret-mask
```

**One project only** (Claude Code): `secret-mask setup [--command CMD] .` writes `.claude/settings.json` and
`.mcp.json` in the project, or `scripts/install-claude-hooks.sh [--docker IMAGE] .`.

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
(placeholders, mask/restore), `vault` (encryption), `guide` (AI rules), `hook` (agent hooks), `mcp`
(stdio MCP server), `setup` (agent config: `install`/`uninstall`, skill in `setup/skill`), `gitrepo` (staged
content, pre-commit hook), `fsutil`, `version`.
`plugin/` is the Claude Code plugin (its `SKILL.md` must equal `internal/setup/skill/SKILL.md`; a test checks).

## License

[MIT](LICENSE). Embeds [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
