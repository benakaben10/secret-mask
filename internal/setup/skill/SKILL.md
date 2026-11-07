---
name: secret-mask
description: "Work safely in projects whose secrets are masked by secret-mask. Use when a file contains __SECRET_MASK_<16 hex>__ placeholders, when a read is BLOCKED by secret-mask, before reading .env, config, credential or deployment files, or when the user mentions masking, unmasking, restoring or protecting secrets."
---
<!-- managed by secret-mask: `secret-mask install` overwrites this file and `secret-mask uninstall` removes it -->

# secret-mask

secret-mask replaces the secrets of a project with placeholders such as `__SECRET_MASK_8656926daa6d6f8c__` and
keeps the originals in an encrypted vault (`.secret-mask.vault`). Only the user can mask and restore: both need
their password.

## Rules

1. Keep every `__SECRET_MASK_<16 hex>__` placeholder byte-for-byte: same characters, case, underscores, and the
   same quoting around it. Moving or copying it together with its setting is fine.
2. Never replace a placeholder with a real-looking, example or empty value, never re-encode it, never invent
   new placeholders, and never try to reconstruct the original secret.
3. Never edit or delete `.secret-mask.vault` or `SECRET_MASK_AI_GUIDE.md`.
4. Never run `secret-mask mask` or `secret-mask restore` yourself, never ask for the password, and never ask the
   user to paste a secret.

## Before reading secrets-prone files

Call the `check_secrets` MCP tool (server `secret-mask`) for the file or directory, or run
`secret-mask check <path>` (exit 4 means unmasked secrets). If anything is unmasked, stop and ask the user to
run `secret-mask mask <project>` in their own terminal, then continue.

## When a read is BLOCKED by secret-mask

The hook found unmasked secrets in what you tried to read. Do not read the file another way (cat, grep, an
editor, a script). Tell the user which files were reported and ask them to run `secret-mask mask <project>`;
retry after they confirm.

## Before finishing a task

Call `masking_status` (or run `secret-mask status`): `missing` must be 0. If a placeholder went missing, put it
back exactly where it was. `masking_guide` lists which files hold placeholders.
