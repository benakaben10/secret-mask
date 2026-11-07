---
name: secret-mask
description: "Work safely in projects whose secrets are masked by secret-mask. Use when a file contains __SECRET_MASK_<16 hex>__ placeholders, when a read is BLOCKED by secret-mask, before reading .env, config, credential or deployment files, when the user mentions masking, unmasking, unsealing, restoring, allowlisting or protecting secrets, when a finding may be a local-dev or test value, or when a kind of secret should be detected that is not."
---
<!-- managed by secret-mask: `secret-mask install` overwrites this file and `secret-mask uninstall` removes it -->

# secret-mask

secret-mask replaces the secrets of a project with placeholders such as `__SECRET_MASK_8656926daa6d6f8c__` and
keeps the originals in an encrypted vault (`.secret-mask.vault`). Only the user can mask and restore
("unseal"): both need their password, which you must never see.

## Workflow with the user

1. **Start of a task, before anything else:** call the `next_steps` MCP tool (server `secret-mask`), or run
   `secret-mask check <project>` (exit 4 = unmasked secrets). Do it before indexing the project or building a
   code graph with another MCP server (codebase-memory-mcp `index_repository` and the like), and before reading
   files: those tools copy the source, secrets included. The hooks block them while secrets are unmasked.
2. **Unmasked secrets:** stop the task. Do not read those files in any way. Tell the user to run, in their own
   terminal:

   ```sh
   secret-mask mask <project>
   ```

   For a new vault they choose a password of at least 8 characters and must keep it; for an existing vault
   they use the same password. Wait until they confirm, then check again (`next_steps`) and continue only when
   it reports SAFE.
3. **Work** on the masked files, keeping placeholders exactly as written (rules below).
4. **End of the task:** call `masking_status`: `missing` must be 0. Then tell the user how to unseal:

   ```sh
   secret-mask status <project>             # missing must be 0
   secret-mask restore --dry-run <project>  # preview
   secret-mask restore <project>            # real values back (their password)
   secret-mask restore --clean <project>    # ...and delete the vault and the AI guide
   ```

   Remind them that after restoring the files hold real secrets again: mask before the next AI session, and
   commit only masked files (`secret-mask protect` enforces it with a pre-commit hook).

## Real secret or local-dev value?

Not every finding is a real credential: a local Docker database password, a test fixture or an example file
may be safe for anyone to see. You cannot read the value, so call `review_findings`: it shows each finding's
line with the value replaced by «redacted», a hint (real credential vs. local-dev/test value) and the exact
allowlist the user can add. Explain the choice to the user and let them decide:

- **Real or unsure** (production, staging, shared services, personal tokens): mask it (step 2).
- **Local-dev or test value**: the user allowlists it, by adding a `file:rule:line` line to `.gitleaksignore`,
  or an `[[allowlists]]` block (paths, `targetRules` + `regexTarget = "line"`, `stopwords`) to `.gitleaks.toml`.
  `review_findings` prints these ready to copy. Allowlisted values are never masked: agents can read them and
  they can be committed.

Never edit `.gitleaksignore` or the allowlists of `.gitleaks.toml` yourself, and never suggest allowlisting a
value that works anywhere but the developer's own machine.

## Rules

1. Keep every `__SECRET_MASK_<16 hex>__` placeholder byte-for-byte: same characters, case, underscores, and the
   same quoting around it. Moving or copying it together with its setting is fine.
2. Never replace a placeholder with a real-looking, example or empty value, never re-encode it, never invent
   new placeholders, and never try to reconstruct the original secret.
3. Never edit or delete `.secret-mask.vault` or `SECRET_MASK_AI_GUIDE.md`.
4. Never run `secret-mask mask`, `secret-mask restore` or `secret-mask reveal` yourself, never ask for the
   password, never ask the user to paste a secret or the output of `secret-mask reveal` (it prints the real
   values and is for the user's eyes only).

## When a read is BLOCKED by secret-mask

The hook found unmasked secrets in what you tried to read. Do not read the file another way (cat, grep, an
editor, a script). Follow step 2 above: give the user the mask command from the message and wait.

## Placeholders went missing

`masking_status` lists them. Put each back exactly where it was. Only if that is impossible, tell the user that
`secret-mask restore --force <project>` restores the rest and leaves the missing values in the vault.

## Detection rules

`list_rules` (filter with `query`, `source`; `details=true` for regexes) and `get_rule` show every rule in use:
gitleaks' built-in rules, secret-mask's password rules and the project's `.gitleaks.toml`. To detect a new kind
of secret: write a Go RE2 regex with the secret value in a capture group, try it with `test_rule` on a sample
with a fake value, then add it with `add_rule` (it appends to `.gitleaks.toml` and cannot change or disable
existing rules). Secrets the new rule finds must then be masked by the user (step 2).
