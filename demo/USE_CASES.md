# secret-mask use cases

Each case below covers when it applies, the commands to run and what you will see. Run `make demo` to see
every case live against a sample project (`demo/demo.sh`; it needs only Docker).

| # | Situation | Main command |
|---|---|---|
| 1 | Are there secrets in this tree? | `secret-mask check` |
| 2 | Let an AI agent (or a contractor) work on a project with secrets | `mask` → work → `restore` |
| 3 | New secrets appear after masking | `mask` again (same vault) |
| 4 | Make coding agents unable to read unmasked secrets | `secret-mask install` |
| 5 | The agent moved or broke a placeholder | `status`, `restore` |
| 6 | Never commit a secret | `secret-mask protect` |
| 7 | Fail a CI pipeline on leaked secrets | `secret-mask check` (exit 4) |
| 8 | See the rules, add one for an in-house secret format | `secret-mask rules`, `.gitleaks.toml`, MCP `add_rule` |
| 9 | Run without installing a binary | Docker image |
| 10 | The vault is gone, or the tree was masked elsewhere | exit 5, recovery |
| 11 | Local development: dev-only values that need not be masked | `review_findings`, allowlists |
| 12 | Install, upgrade to a new release | `install.sh`, `secret-mask upgrade` |
| 13 | Tab completion in bash or zsh | `secret-mask completion --install` |

Exit codes used throughout: `0` ok, `1` error, `2` bad usage, `3` placeholders missing or altered, `4`
unmasked secrets found, `5` already masked with another vault (refused).

---

## 1. Check a tree for secrets

**When:** before sharing a repository, zipping a project, or opening it in an AI tool. No password is needed and
nothing is changed.

```sh
secret-mask check .              # whole tree
secret-mask check config/app.json
```

```
2 unmasked secret(s):
  .env:2  aws-access-token
  config/app.json:3  github-pat
```

- Exit `4` when something is unmasked, `0` when clean. Only file, line and rule id are printed, **never the
  value**.
- Besides gitleaks' token rules, secret-mask's password rules catch values people chose themselves
  (`DB_PASSWORD=Admin@123`, `postgres://app:Dbpass-77@db/app`, `<password>…</password>`). `${VAR}`,
  `{{ template }}` and `<placeholder>` values are not reported.
- Placeholders (`__SECRET_MASK_…__`) are not counted, so a masked tree checks clean.

## 2. Mask, let someone work, restore

**When:** an AI agent, a contractor or a support engineer needs the code but must not see the credentials.

```sh
export SECRET_MASK_PASSWORD='a long passphrase'    # or let it prompt; --ask always prompts
secret-mask mask .
```

```
Masked 3 occurrence(s) in 2 file(s); the vault holds 2 secret(s).
  .env                1
  config/app.json     2
Vault:    ./.secret-mask.vault
AI guide: ./SECRET_MASK_AI_GUIDE.md
Restore:  secret-mask restore .
```

- Every secret is replaced in place, e.g. `AWS_ACCESS_KEY_ID=__SECRET_MASK_8656926daa6d6f8c__`. The same value
  gets the same placeholder in every file.
- The originals are encrypted in `.secret-mask.vault` (AES-256-GCM, key from your password). A new vault asks
  for the password twice and needs at least 8 characters.
- `SECRET_MASK_AI_GUIDE.md` tells AI agents to keep placeholders exactly as they are.
- `--dry-run` shows what would be masked without writing anything.

Then hand the tree over. When the work is done:

```sh
secret-mask restore .            # real values back; other edits are kept
secret-mask restore --clean .    # ...and delete the vault and the guide
```

- Restore is byte-for-byte: a file nobody touched is identical to the original.
- Edits made in the meantime are kept, and placeholders moved to other files are restored where they now are.
- A wrong password changes nothing (exit `1`).

> There is no password recovery. Without the password the vault cannot be opened and the secrets stay masked.

## 3. New secrets after masking

**When:** you masked a project, then someone added a new key.

```sh
secret-mask mask .               # same vault, same password
```

- Only the new secret is masked; existing placeholders are never touched. A value already in the vault gets
  its existing placeholder.
- Nothing new: `Masked 0 occurrence(s)`, and the files are not rewritten.

## 4. Guard coding agents

**When:** you use Claude Code, Codex CLI, Gemini CLI, Cursor, VS Code Copilot or Copilot CLI and want them
**unable** to read a file that still has a real secret.

```sh
secret-mask install --dry-run     # see what would be written
secret-mask install               # every agent detected on this machine
secret-mask install --clients claude,codex
```

```
Claude Code:
  mcp:          ~/.claude.json (created)
  hook:         ~/.claude/settings.json (updated)
  skill:        ~/.claude/skills/secret-mask/SKILL.md (created)
Codex CLI:
  mcp:          ~/.codex/config.toml (updated)
  hook:         ~/.codex/hooks.json (created)
  ...
Restart your coding agents to load secret-mask.
Codex CLI: review and trust the new hook with /hooks.
```

What each agent gets:

- **Hook:** before a read, secret-mask scans the target. If it holds an unmasked secret, the read is **denied** and
  the agent is told to ask you to run `secret-mask mask`. Errors also deny. For Codex (which reads through
  its shell) and Cursor shell commands, files named in the command are checked, as are globs and the
  directory of a recursive `rg` / `grep -r`.
- **MCP server:** `next_steps`, `check_secrets`, `review_findings`, `masking_status`, `masking_guide`, and the
  rule tools `list_rules`, `get_rule`, `test_rule`, `add_rule`. There is no mask or restore tool: those need
  your password.
- **Skill / instructions:** the workflow below, and the placeholder rules.

What the agent sees when it tries to read `.env` too early:

```
BLOCKED by secret-mask: 1 unmasked secret(s) found; this content must not be read until it is masked.
  .env: line 2 (aws-access-token)
Stop the task and ask the user to run this themselves in a terminal (it needs their password), then retry:
  secret-mask mask /work/api
Continue only after the user confirms. When the work is done, tell them the real values come back with:
  secret-mask restore /work/api
```

After `secret-mask mask`, the same read is allowed: the agent works on placeholders.

The workflow the agent follows with you:

1. **Start of the task:** it calls `next_steps`. With unmasked secrets it stops and tells you, word for word:

   ```
   This project has unmasked secrets. Please mask them in your own terminal (it needs your password,
   which I must never see):
       secret-mask mask /work/api
   Choose a password of at least 8 characters and keep it: it is the only way to get the real values back.
   Tell me when it is done.
   ```

   It continues only after you confirm and `next_steps` reports `STATE: SAFE`.
2. **A finding may be a dev value:** it shows you `review_findings` and you decide (case 11).
3. **End of the task:** it checks `masking_status` (`missing: 0`) and tells you how to unseal:

   ```
   secret-mask status /work/api             # missing must be 0
   secret-mask restore --dry-run /work/api  # preview
   secret-mask restore /work/api            # put the real values back
   secret-mask restore --clean /work/api    # ...and delete the vault and the AI guide
   ```

Variants:

| Need | Command |
|---|---|
| MCP, skill and instructions, but no blocking hooks | `secret-mask install --no-hooks` |
| Run secret-mask from Docker in the configs | `secret-mask install --command "docker run --rm -i IMAGE"` |
| One project only, Claude Code | `secret-mask setup .` (writes `.claude/settings.json`, `.mcp.json`) |
| Claude Code plugin instead of `install` | `claude plugin marketplace add benakaben10/secret-mask` then `claude plugin install secret-mask@secret-mask` |
| Remove everything | `secret-mask uninstall` |

- Your own settings and hooks are kept, and re-running `install` changes nothing. `uninstall` removes only
  what secret-mask wrote.
- A skill file you wrote yourself is not overwritten (`--force` replaces it).
- JSON configs with comments (JSONC) are reported, not rewritten: add the entry by hand.
- Limit: a command that builds a path at run time (`cat $FILE`, a script) cannot be seen by the hook. Keep
  secrets masked whenever an agent works in the tree.

## 5. A placeholder was moved or broken

**When:** an agent (or a person) edited the masked tree and you want to know whether restore will work.

```sh
secret-mask status .
```

- `missing: 0` means every placeholder is still somewhere in the tree. Moving it to another file is fine.
- Exit `3` lists the placeholders that are gone or altered (re-cased, quoted differently, truncated).
  `restore` then refuses and **writes nothing**:

```sh
secret-mask restore .            # exit 3: put the exact placeholders back first
secret-mask restore --force .    # or restore what is present; the missing values stay in the vault
```

- A placeholder that is not in this vault is left as is and reported as a warning.

## 6. Never commit a secret

**When:** a repository must never receive a credential, whoever commits.

```sh
secret-mask protect .                 # block mode (default)
secret-mask protect --mode mask .     # mask mode
secret-mask protect --remove .        # take it out
```

`protect` finds the git repository containing the directory, including from a subdirectory, and adds a block
to its `pre-commit` hook. On every commit it scans the **staged** content, which is what will be committed;
the work tree is not what counts.

**Block mode:** the commit is refused.

```
$ git commit -m "add config"
secret-mask: commit blocked, 1 unmasked secret(s) in staged files:
  .env:1  aws-access-token
Mask them, stage the result and commit again:
  secret-mask mask /work/api && git add .env
(To commit anyway, at your own risk: git commit --no-verify)
```

**Mask mode:** the staged secrets are masked, the files are staged again and the commit goes on.

```
$ SECRET_MASK_PASSWORD=... git commit -m "add config"
secret-mask: 1 unmasked secret(s) staged; masking them before the commit.
Masked 1 occurrence(s) in 1 file(s); the vault holds 1 secret(s).
secret-mask: masked and re-staged 1 file(s). .secret-mask.vault is not staged: commit it or keep it safe.
```

| Situation | Result |
|---|---|
| Secret only in an unstaged file | commit allowed (it is not committed) |
| Clean staged version, secret added after `git add` | commit allowed; the next `git add` is checked |
| Mask mode, file partly staged (`git add -p`) | refused: re-staging would also commit your unstaged lines |
| Mask mode, no password (GUI client, no terminal) | refused: set `SECRET_MASK_PASSWORD` |
| Mask mode, placeholders of another vault in the tree | refused, exit 5 (see case 10) |
| An existing shell `pre-commit` hook | kept; the secret-mask block runs first |
| A `pre-commit` hook in another language | left alone; the line to add is printed |
| `secret-mask` not found when the hook runs | refused (fails closed) |

## 7. CI pipeline

**When:** a pull request must not bring a secret in.

```yaml
- name: Secrets
  run: secret-mask check .        # exit 4 fails the job; values are never printed
```

or, without installing anything:

```yaml
- run: docker run --rm -v "$PWD:/work" ghcr.io/benakaben10/secret-mask:latest check
```

## 8. Detection rules: see them, add one

**When:** you want to know what is detected, or you have a secret format the rules miss (an in-house token).

```sh
secret-mask rules .                          # every rule: 222 gitleaks, 5 secret-mask, your project's
secret-mask rules --source secret-mask .     # the password rules
secret-mask rules --id aws-access-token .    # one rule in full
```

Add a rule to `.gitleaks.toml` in the project root (put the secret value in a capture group: only that part is
masked):

```toml
[extend]
useDefault = true

[[rules]]
id = "acme-token"
description = "ACME internal token"
regex = '''\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\b'''
keywords = ["acme_"]
```

Then `secret-mask check .` finds it (exit 4) and `secret-mask mask .` masks it. The README's "Detection rules"
section lists every field.

An AI agent can do it for you through MCP: `test_rule` runs a draft on a sample (the matched value is shown,
since the sample is yours) and on the project (locations only); `add_rule` appends it to `.gitleaks.toml`.
`add_rule` only adds new ids: it cannot replace, disable or allowlist an existing rule. The secrets the new rule
finds must then be masked by you.

All rules (gitleaks, secret-mask, yours) are used by `check`, `mask`, the agent hooks, the MCP server and
`pre-commit`. Disable a secret-mask rule with `[extend] disabledRules = ["secret-mask-password-quoted"]`.

## 9. Docker, no install

```sh
docker run --rm -it -u "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/benakaben10/secret-mask:latest check
docker run --rm -it -u "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/benakaben10/secret-mask:latest mask
```

- `-u` keeps your file ownership; `-it` lets it prompt for the password (or pass `-e SECRET_MASK_PASSWORD`).
- The image has no git, so use a native binary for `protect`.

## 10. The vault is gone, or the tree was masked elsewhere

**When:** the tree holds placeholders that the current vault does not know. Typical causes: the vault was deleted
or not copied along, `--vault` points to another file, or someone else masked the tree.

```
$ secret-mask mask .
error: refusing to mask: 2 placeholder(s) are not in this vault, so this tree was already masked with another vault:
  .env: __SECRET_MASK_99b1edfbc7ba44ff__
  config/app.json: __SECRET_MASK_29a87bf2731aac92__
restore it with the vault that masked it (or pass that vault with --vault) before masking again
```

- Exit `5`, raised **before** any password prompt; nothing is written and no second vault is created. Masking
  again would bury the old placeholders under a second vault, and restoring would then need two vaults and
  two passwords.
- **Fix:** find the original vault and run `secret-mask restore --vault /path/to/that.vault .`, then mask again
  if needed.
- The same rule applies to `pre-commit --mode mask`: the commit is refused.

## 11. Local development: dev-only values

**When:** some findings are not real credentials: the password of the local Docker database, a test fixture, an
example file. They can stay visible, but only you can say so.

The agent cannot see the values. `review_findings` (MCP) shows it each finding with the value redacted and a
hint, which it explains to you:

```
3. .env:4  rule secret-mask-password-unquoted
   line: DB_PASSWORD=«redacted»
   hint: looks like a REAL credential: mask it
4. .env:5  rule secret-mask-url-password
   line: LOCAL_DATABASE_URL=postgres://dev:«redacted»@localhost:5432/orders
   hint: may be a local-dev value (points to localhost / a local host); ask the user
   allowlist just this finding: add to .gitleaksignore the line  .env:secret-mask-url-password:5
```

You decide, finding by finding. A real credential (production, staging, shared service, personal token), or
any doubt: mask it. A dev-only value: allowlist it yourself, in the narrowest way that fits:

| Need | Add |
|---|---|
| One finding | the `file:rule:line` line to `.gitleaksignore` |
| Whole dev/test files | an `[[allowlists]]` with `paths` |
| Local URLs of one rule | an `[[allowlists]]` with `targetRules`, `regexTarget = "line"` and `regexes` |
| Known dev values | an `[[allowlists]]` with `stopwords` |

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
stopwords = ["devpass"]
```

Then `secret-mask check .`: only the real secrets are left, and `mask` masks only those. Paths are relative to
the project root. An allowlisted value is never masked: agents can read it and it can be committed. The agent
never edits these files itself.

## 12. Install and upgrade

```sh
curl -fsSL https://raw.githubusercontent.com/benakaben10/secret-mask/master/install.sh | sh
```

The installer downloads the release binary for your OS, refuses it unless it matches `SHA256SUMS`, installs it
(default `~/.local/bin`) and runs `secret-mask install` for your agents.

**Upgrade:** run the same line again.

```
  target:  /home/me/.local/bin/secret-mask (installed: v0.2.0)
Checksum verified.
Upgraded: v0.2.0 -> v0.3.0
Claude Code:
  skill:        ~/.claude/skills/secret-mask/SKILL.md (updated)
```

- The binary is replaced **in place**, so the agent configs and git hooks that call it by path keep working.
- The agent configuration is refreshed: new skill text, new hook commands.
- `--version v0.2.0` installs (or goes back to) a given release; `--skip-config` only replaces the binary.
- `secret-mask upgrade` prints the exact command for the current installation. The binary itself never
  downloads anything.
- Plugin users: `claude plugin marketplace update secret-mask && claude plugin update secret-mask@secret-mask`.

## 13. Tab completion

```sh
secret-mask completion --install          # bash or zsh, from $SHELL
secret-mask completion --install zsh
secret-mask completion --uninstall zsh
```

It adds a marked block to `~/.bashrc` or `~/.zshrc` that loads the script from the installed binary, so it
follows upgrades. Commands, flags, agent names for `--clients`, `--mode block|mask`, rule sources and paths
complete. To load it yourself instead: `eval "$(secret-mask completion zsh)"` (zsh: after `compinit`).
