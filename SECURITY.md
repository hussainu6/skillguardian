# Security Policy

## Reporting a vulnerability in skill-safe

If you find a security issue in skill-safe itself (for example, a way to make the
scanner execute code from a file it is scanning, or a crafted input that causes a
crash), please report it privately:

- Use **GitHub → Security → "Report a vulnerability"** (private advisory), or
- Open a minimal issue asking for a private channel — do **not** post exploit
  details publicly first.

We aim to acknowledge within a few days.

## Reporting a malicious *public* skill or plugin

If skill-safe helps you find a malicious component published somewhere public,
please practice responsible disclosure:

1. **Report it to the platform** hosting it (GitHub, the registry, the author)
   first, privately.
2. **Do not open a public issue that names and shames** the author before they've
   had a chance to respond — mistakes and compromised accounts happen.
3. When you write it up, **defang** the example: fake endpoints, placeholder
   secrets, no working payload.

The goal is a safer ecosystem, not a pillory.

## Scope

skill-safe performs **static text analysis only**. It does not execute the files
it scans and does not start MCP servers. A clean report is a fast first filter,
not a guarantee of safety.
