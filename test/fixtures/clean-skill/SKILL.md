---
name: markdown-formatter
description: Formats and lints Markdown files, fixing heading levels and list spacing.
---

# Markdown Formatter

Use this skill when the user asks to tidy up a Markdown document.

## Steps

1. Read the target `.md` file.
2. Normalize heading levels so they never skip (h1 → h2 → h3).
3. Ensure a single blank line between blocks.
4. Wrap long lines at 100 characters where it does not break links.
5. Show the user a diff and ask before writing changes.

## Notes

- Never modify code fences.
- Preserve the document's front matter exactly.
