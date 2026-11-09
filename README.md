# secret-mask

[![ci](https://github.com/benakaben10/secret-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/benakaben10/secret-mask/actions/workflows/ci.yml)
[![security](https://github.com/benakaben10/secret-mask/actions/workflows/security.yml/badge.svg)](https://github.com/benakaben10/secret-mask/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/benakaben10/secret-mask/badge)](https://scorecard.dev/viewer/?uri=github.com/benakaben10/secret-mask)
[![Go Report Card](https://goreportcard.com/badge/github.com/benakaben10/secret-mask)](https://goreportcard.com/report/github.com/benakaben10/secret-mask)
[![release](https://img.shields.io/github/v/release/benakaben10/secret-mask)](https://github.com/benakaben10/secret-mask/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/benakaben10/secret-mask)](go.mod)
[![license](https://img.shields.io/github/license/benakaben10/secret-mask)](LICENSE)

Mask the secrets in a project before AI agents (or anyone) see it, and restore them exactly afterwards.

- **Detects** secrets with [gitleaks](https://github.com/gitleaks/gitleaks), embedded as a library (one
  static binary, no external tools), plus strict rules for passwords people choose themselves. Your
  `.gitleaks.toml` and `.gitleaksignore` are honored.
- **Masks** every occurrence with a stable placeholder such as `__SECRET_MASK_8656926daa6d6f8c__`; the same
  value gets the same placeholder everywhere.
- **Encrypts** the originals into `.secret-mask.vault` with your password (AES-256-GCM, PBKDF2-SHA256 600k).
- **Restores** byte-for-byte, even if placeholders were moved to other files, while keeping other edits.
- **Guards AI agents** (Claude Code, Codex, Gemini CLI, Cursor, VS Code / Copilot): `secret-mask install` adds
  a hook that blocks reading files that still contain unmasked secrets, an MCP server that tells the agent what
  to ask you (mask first, unseal at the end) and lets it read and add detection rules, and a skill with the rules.
- **Guards commits**: `secret-mask protect` adds a git pre-commit hook that refuses, or masks, staged secrets.

## Install

**One line** (macOS, Linux; Windows via Git Bash) — downloads the release binary, verifies it against
`SHA256SUMS`, installs it to `~/.local/bin` and runs `secret-mask install` to set up your coding agents:

```sh
curl -fsSL https://raw.githubusercontent.com/benakaben10/secret-mask/master/install.sh | sh
```

Options (after `sh -s --`): `--dir PATH`, `--version vX.Y.Z`, `--clients claude,codex`, `--no-hooks`,
`--skip-config` (binary only).

**Upgrade**: run the same line again. An existing `secret-mask` on `PATH` is replaced in place (agent configs
and git hooks call it by that path), the old and new versions are printed, and the agent configuration is
refreshed (new skill text, hook commands). `secret-mask upgrade` prints the exact command for the current
installation (`--version vX.Y.Z` to pin one); the binary itself never downloads anything. Other installs:
`go install …@latest`, `docker pull …:latest`, and for the plugin
`claude plugin marketplace update secret-mask && claude plugin update secret-mask@secret-mask`.

**Shell completion** (bash, zsh): commands, flags, agents for `--clients`, modes, rule sources, paths.

```sh
secret-mask completion --install          # for $SHELL; or: --install bash | --install zsh
secret-mask completion --uninstall zsh    # take it out again
eval "$(secret-mask completion zsh)"      # or load it yourself (zsh: after compinit)
```

`--install` adds a marked block to `~/.bashrc` or `~/.zshrc` that loads the script from this executable, so it
follows upgrades.

**Binary** — download `secret-mask_<os>_<arch>` from the
[latest release](https://github.com/benakaben10/secret-mask/releases/latest), check it against `SHA256SUMS`,
make it executable and put it on `PATH`. Builds: linux/darwin (amd64, arm64), windows/amd64.

**Verify a release** (from v0.3.2). The release workflow signs `SHA256SUMS` with Sigstore (keyless: the
certificate names the workflow and the tag) and publishes SLSA build provenance for every binary and for the
image. `install.sh` checks the signature by itself when `cosign` is installed.

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/benakaben10/secret-mask/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS                       # then the binary against the list
gh attestation verify secret-mask_linux_amd64 --repo benakaben10/secret-mask   # build provenance
cosign verify ghcr.io/benakaben10/secret-mask:latest \
  --certificate-identity-regexp '^https://github.com/benakaben10/secret-mask/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

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
secret-mask reveal  .       # the real value behind each placeholder, with its location (your terminal only)
secret-mask protect .       # git pre-commit hook: no commit with unmasked secrets
secret-mask rules .         # the detection rules in use
secret-mask upgrade         # how to upgrade to a new release
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

## Detection rules

```sh
secret-mask rules .                           # every rule in use, with its source
secret-mask rules --source secret-mask .      # gitleaks | secret-mask | project
secret-mask rules --id aws-access-token .     # one rule in full (regex, keywords, allowlists)
secret-mask rules --json .                    # everything, including the global allowlists
```

Every scan (`check`, `mask`, the agent hooks, the MCP server, `pre-commit`) uses the same rules:

1. **gitleaks' built-in rules** (222 in gitleaks v8.30.1, compiled into the binary; source:
   [config/gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)). They find
   provider tokens (AWS, GitHub, Slack, OpenAI, Stripe, private keys, JWTs…) and, with `generic-api-key`,
   random-looking values assigned to `key`/`token`/`secret`/`password` names.
2. **secret-mask's rules** ([internal/detect/rules.toml](internal/detect/rules.toml)). They catch secrets
   people choose themselves (`Admin@123`, `CLIENT_SECRET=mysecret1`), which have too little entropy for
   gitleaks, and a few formats it misses. They are strict on purpose (a value in `.env.example` is caught too);
   only obvious non-values are skipped: `$VAR`, `${VAR}`, `$(cmd)`, `{{ template }}`, `<placeholder>`, `***`,
   `xxxx`, `true`/`null`, `changeme`, numbers for token settings, and keys that name a reference or a setting
   (`secretName`, `existingSecret`, `secretKeyRef`, `tokenTtl`, `token_expiry`, `keyFile`, `publicKey`,
   `password_length`…).

   | Rule id | Finds |
   |---|---|
   | `secret-mask-password-quoted` | `password = "…"`, `"db_password": "…"`, `--password='…'` in any file |
   | `secret-mask-password-unquoted` | `DB_PASSWORD=…`, `password: …`, `export PGPASSWORD=…` in config files (`.env*`, `*.yaml`, `*.ini`, `*.properties`, `*.toml`, `*.conf`, shell scripts, Dockerfiles, compose files…) |
   | `secret-mask-url-password` | the password of `scheme://user:password@host` (only that part is masked) |
   | `secret-mask-connection-string-password` | `Server=…;User Id=…;Password=…;` |
   | `secret-mask-xml-password` | `<password>…</password>`, `<db.password>…</db.password>` |
   | `secret-mask-secret-quoted` | `client_secret = "…"`, `"apiKey": "…"`, `token: '…'` in any file, any entropy (`secret`, `token`, `api key`, `access key`, `private key`, `auth key`, `credential`) |
   | `secret-mask-secret-unquoted` | `CLIENT_SECRET=…`, `api_key: …` in config files, any entropy |
   | `secret-mask-client-credential-map` | a UUID secret mapped from a client id in JSON (`"svc-a1b2-c3d4": "3f2a9c1e-…"`) |
   | `secret-mask-exchangerate-api-key` | the API key in `exchangerate-api.com/v6/<key>/…` URLs |

   A value found by several rules (a GitHub token named `GITHUB_TOKEN`) is one finding, reported under the most
   specific rule.

3. **The project's rules**: the first of `--config FILE`, `$GITLEAKS_CONFIG`, `<project>/.gitleaks.toml`.

A project config with `[extend] useDefault = true` keeps the gitleaks rules; without it, only its own rules
and secret-mask's run. secret-mask's rules are always added unless the config defines a rule with the same id
(which replaces it) or lists the id in `[extend] disabledRules`.

### Writing a rule

Add it to `.gitleaks.toml` in the project root:

```toml
[extend]
useDefault = true                      # keep the built-in rules
disabledRules = ["generic-api-key"]    # optional: turn off a noisy rule

# An in-house token: the whole match is the secret.
[[rules]]
id = "acme-internal-token"
description = "ACME internal service token"
regex = '''\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\b'''
keywords = ["acme_"]

# A password inside a DSN: only capture group 1 is the secret (and gets masked).
[[rules]]
id = "acme-db-password"
regex = '''postgres://[^:\s]+:([^@\s]{8,})@'''
secretGroup = 1
keywords = ["postgres://"]
[[rules.allowlists]]
regexes = ['''^changeme''']            # values of this rule to ignore
```

| Field | Meaning |
|---|---|
| `id` | name shown in findings and used in `.gitleaksignore` |
| `regex` | Go RE2 syntax (no lookahead/lookbehind) |
| `secretGroup` | capture group that holds the secret. Unset: the first non-empty group, else the whole match |
| `keywords` | lowercase strings; the regex only runs on files containing one of them (speed) |
| `entropy` | minimum Shannon entropy of the secret: 3–4 filters out words, 0 (unset) keeps self-chosen passwords |
| `path` | only files whose project-relative path (`config/app.yaml`, forward slashes) matches |
| `[[rules.allowlists]]` | exceptions for this rule: `regexes` (on the secret, or `regexTarget = "match"` / `"line"`), `paths`, `stopwords` |

What secret-mask adds to the gitleaks rules: **the capture group decides what is replaced by a placeholder**.
A regex that matches `password=...` without a group would replace the whole `password=...` and break the
file; always put the value in a group.

Try it before relying on it:

```sh
secret-mask rules --id acme-db-password .   # loaded as expected?
secret-mask check .                          # finds what it should (exit 4), nothing else?
secret-mask mask --dry-run .                 # what would be masked
```

Agents do the same through MCP: `list_rules` / `get_rule` read every rule, `test_rule` runs a draft on a
sample (and, with `scan_project`, reports project locations without values), `add_rule` appends it to
`.gitleaks.toml`. `add_rule` only adds new ids: it cannot replace, disable or allowlist an existing rule.

### Mock, test, example and CI values: the `fake-` prefix

Every config (built-in or project) includes this global allowlist from
[internal/detect/rules.toml](internal/detect/rules.toml):

```toml
[[allowlists]]
description = "Fake values in examples, CI and tests: always start with fake- (or fakesecret-), never real credentials"
regexes = ['''^fake(?:secret)?-''']
```

A value that starts with `fake-` or `fakesecret-` is never reported nor masked, by any rule, in any project.
Use it for every credential that only exists for tests:

| Where | Example |
|---|---|
| unit tests, mocks, stubs | `DB_PASSWORD=fake-db-password` in `.env.test` |
| integration and e2e tests, local docker-compose | `POSTGRES_PASSWORD: fake-postgres` |
| CI jobs (throwaway service containers) | `MYSQL_ROOT_PASSWORD=fake-mysql-root` |
| examples and docs | `.env.example` with `API_KEY=fake-api-key` |

How to tell a test value from a real one:

- **Test value** (rename it `fake-…`): it lives in a test, spec, mock, fixture, example, e2e or CI file, or points
  to `localhost`, a local Docker service or `example.com`, and works nowhere but a developer's machine or a
  throwaway CI container.
- **Real credential** (mask it): anything a shared environment accepts: production, staging, a shared dev
  server, a SaaS account, a personal token. A real value renamed `fake-…` is still real, and is now exposed.

Two limits:

- Only the start of the detected value counts. Provider formats (`ghp_…`, `AKIA…`, `sk_live_…`) are detected
  by their own shape, so `fake-ghp_…` is still reported: write fake values that do not imitate a provider
  (`fake-github-token`), or allowlist them below.
- The allowlist cannot be turned off. Do not give the prefix to anything that must stay secret.

Agents follow the same convention: the MCP instructions, `review_findings`, the skill and
`SECRET_MASK_AI_GUIDE.md` tell them to start every mock, test, example or CI value they write with `fake-`, and
to suggest the rename to the user for test values they find.

### Local development: allowlists

For values that cannot be renamed `fake-…`: a value that only works on the developer's machine (a local Docker database, a test fixture, an example file)
need not be masked. Allowlist it, in the narrowest way that fits:

| Need | Where | Example |
|---|---|---|
| One finding | `.gitleaksignore` (project root) | `docker-compose.dev.yml:secret-mask-password-unquoted:4` |
| Whole dev/test files | `[[allowlists]] paths` in `.gitleaks.toml` | `'''^docker-compose\.dev\.yml$'''`, `'''^test/fixtures/'''` |
| Local URLs of one rule | `targetRules` + `regexTarget = "line"` | `'''@(?:localhost\|127\.0\.0\.1\|db)[:/]'''` |
| Known dev values | `stopwords` | `["devpass", "localdev"]` |

```toml
[extend]
useDefault = true

[[allowlists]]
description = "local dev and test files"
paths = ['''^docker-compose\.dev\.yml$''', '''^test/fixtures/''']

[[allowlists]]
description = "local dev database"
targetRules = ["secret-mask-url-password"]
regexTarget = "line"
regexes = ['''@(?:localhost|127\.0\.0\.1|db)[:/]''']

[[allowlists]]
description = "shared dev passwords"
stopwords = ["localdev"]
```

- `.gitleaksignore` lines are `file:rule:line` (the output of `secret-mask check`). They stop matching when
  the line moves; add them again then.
- Paths are matched against the project-relative path, so `^test/` means the project's own `test/` folder.
- An allowlisted value is never masked: agents can read it and it can be committed. Never allowlist a value
  that works anywhere but your machine (shared dev servers included).
- Agents tell the two apart with the MCP tool `review_findings`: each finding with its line, the value
  replaced by «redacted», a hint (real credential vs. local-dev/test value) and these allowlist lines ready to
  copy. The decision and the edit stay with you.

## See the real values (your terminal only)

```sh
secret-mask reveal .                         # every placeholder: file:line, rule, placeholder, real value
secret-mask reveal --file config/app.json .  # one file
secret-mask reveal --id 8656926daa6d6f8c .   # one placeholder
```

```
.env:2  aws-access-token  __SECRET_MASK_e39bd706e19a4914__  AKIA…
config/app.json:3  github-pat  __SECRET_MASK_e9cbe5f120495218__  ghp_…
(missing)  slack-bot-token  __SECRET_MASK_d546f3e8ee66a712__  xoxb-…  masked in: .env
```

`reveal` is for you, not for AI agents:

- it runs only when stdin and stdout are an interactive terminal (not in a pipe, a script or an agent's shell);
- it always asks for the password on the terminal; `$SECRET_MASK_PASSWORD` is ignored;
- it refuses to run when a coding agent's environment is detected (`CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`…);
- no MCP tool exposes it, the agent hooks deny any shell command that runs it, and the skill forbids asking you
  for its output.

## Run before other MCP servers (indexers, code graphs)

Tools such as codebase-memory-mcp's `index_repository` copy the project's source, secrets included, into their
own database. secret-mask has to come first:

- **Tool calls are covered.** The Claude Code hook matches `mcp__.*` (Codex: `Bash|mcp__.*`, Cursor:
  `beforeMCPExecution`, Copilot: every tool). A call of another MCP server is checked like a read: the paths
  in its arguments (`path`, `repo_path`, `root`, `files`…) are scanned, and an indexer called without a path
  (`index`, `ingest`, `scan`, `embed`, `sync`, `upload`, `build`…) scans the whole project. With unmasked
  secrets the call is denied. All matching hooks run and a single deny stops the call, so their order does
  not matter.
- **Session start.** A `SessionStart` hook (Claude Code, Codex) tells the agent, when the project has unmasked
  secrets, to deal with them before anything else: no indexing, no graph, no reading until you have masked.
  The skill and instructions say the same.
- **Background indexing is not a tool call.** A server that indexes by itself (codebase-memory-mcp
  `auto_index`, `auto_watch`, its daemon) cannot be stopped by any hook. Mask the project **before** opening an
  agent session on it, keep `auto_index` off (its default) for projects with secrets, and if a project was
  indexed while unmasked, delete that index (codebase-memory-mcp `delete_project`) and index again after
  masking. Listing secret files in `.cbmignore` also keeps them out.

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
| Claude Code (`claude`) | `~/.claude.json` | `PreToolUse` `Read\|Grep\|NotebookRead\|Bash\|mcp__.*` and `SessionStart` in `~/.claude/settings.json` | `~/.claude/skills/secret-mask` |
| Codex CLI (`codex`) | `$CODEX_HOME/config.toml` | `PreToolUse` `Bash\|mcp__.*` and `SessionStart` in `$CODEX_HOME/hooks.json` | `AGENTS.md` block, `~/.agents/skills/secret-mask` |
| Gemini CLI (`gemini`) | `~/.gemini/settings.json` | `BeforeTool` (`read_file`, `read_many_files`, searches, shell) | `~/.gemini/GEMINI.md` block |
| Cursor (`cursor`) | `~/.cursor/mcp.json` | `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution` in `~/.cursor/hooks.json` | `~/.cursor/skills/secret-mask` |
| VS Code Copilot (`vscode`) | `Code/User/mcp.json` | `PreToolUse` in `~/.copilot/hooks/secret-mask.json` | `~/.copilot/skills/secret-mask` |
| Copilot CLI (`copilot`) | `~/.copilot/mcp-config.json` | (shared with VS Code) | (shared with VS Code) |

- **Hook** (`secret-mask hook --client <agent>`): if what the agent is about to read still has unmasked
  secrets, the call is **denied** and the agent is told to ask the user to run `secret-mask mask` themselves
  (it needs their password). Any error also denies (fail closed). Shell commands are read best-effort: files
  named in the command, globs, and the directory of recursive searches (`rg`, `grep -r`) are checked;
  variables and generated paths are not. Codex users trust the new hook once with `/hooks`.
- **MCP server** (`secret-mask mcp`). There is deliberately no mask/restore tool: those need the password and
  stay with the user. Tool results never include secret values from project files.

  | Tool | What the agent gets |
  |---|---|
  | `next_steps` | where the project stands and the exact commands to give the user: mask before any work, restore ("unseal") at the end |
  | `check_secrets` | unmasked secrets in a file or directory (rule ids and locations) |
  | `review_findings` | each finding's line with the value «redacted», a hint (real credential vs. local-dev/test value) and the allowlist lines the user can add |
  | `masking_status` | every placeholder still present? (`missing` must be 0 before finishing) |
  | `masking_guide` | the content of `SECRET_MASK_AI_GUIDE.md`: the rules for editing a masked project |
  | `list_rules`, `get_rule` | every detection rule in use, in full |
  | `test_rule` | a draft rule run on a sample, and on the project (locations only) |
  | `add_rule` | appends a new rule to `.gitleaks.toml` (the only tool that writes; cannot change existing rules) |

- **Workflow the agent follows** (skill, instructions, hook message): at the start of a task it calls
  `next_steps`. Unmasked secrets: it stops and asks you to run `secret-mask mask <project>` (your password, which
  it never sees), and continues only after you confirm and the check passes. A finding that may be a dev value:
  it shows you `review_findings` and you choose between masking and allowlisting. In a masked project it reads
  `SECRET_MASK_AI_GUIDE.md` in full before any other file (the MCP instructions, `next_steps`, the session-start
  hook and the skill all make this mandatory). Mock, test, example and CI values it writes start with `fake-`.
  At the end it checks
  `masking_status` and tells you how to unseal: `secret-mask restore <project>` (`--dry-run` to preview,
  `--clean` to drop the vault).
- **Skill and instructions** carry that workflow and the placeholder rules. A skill file you wrote yourself is never overwritten
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
- Agents cannot change detection through MCP except by adding rules. An agent with a file-editing tool could
  still edit `.gitleaks.toml` or `.gitleaksignore`; the skill forbids it, and reviewing changes to those files
  is worth a rule in your code review.
- Masking rewrites files atomically and preserves their permissions. Binary files and symlinks are skipped;
  a secret that gitleaks found only after decoding (e.g. base64) is reported as skipped.

## Development

Every push and pull request runs [ci](.github/workflows/ci.yml) (tests, end-to-end, Trivy image scan) and
[security](.github/workflows/security.yml): CodeQL (`security-extended`), `govulncheck` (known vulnerabilities
reachable from the code, standard library included), `gosec`, a secret scan of the repository with
secret-mask itself ([.gitleaks.toml](.gitleaks.toml) skips the fixtures that hold fake secrets on
purpose) and, on pull requests, dependency review. [OpenSSF Scorecard](.github/workflows/scorecard.yml)
grades the supply chain weekly. Findings appear under the repository's Security tab; Dependabot keeps Go
modules, the Docker base images and the actions up to date.

Only Docker is needed:

```sh
make test       # go vet + unit/integration tests
make e2e        # end-to-end against the linux binary and the image
make demo       # guided walkthrough
make scan       # Trivy scan of the image
```

Layout: `cmd/secret-mask` (entrypoint), `internal/` — `cli` (commands), `detect` (embedded gitleaks), `mask`
(placeholders, mask/restore; `detect/rules.toml` holds the password rules), `vault` (encryption), `guide` (AI rules), `hook` (agent hooks), `mcp`
(stdio MCP server), `setup` (agent config: `install`/`uninstall`, skill in `setup/skill`), `gitrepo` (staged
content, pre-commit hook), `fsutil`, `version`.
`plugin/` is the Claude Code plugin (its `SKILL.md` must equal `internal/setup/skill/SKILL.md`; a test checks).

## License

[MIT](LICENSE). Embeds [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
