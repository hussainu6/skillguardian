# Test fixtures

These are **inert test inputs** for skill-safe's rule engine. The files under
`malicious-skill/` deliberately contain the *textual patterns* the scanner is
supposed to flag (fake endpoints, example placeholders, non-functional snippets)
so the test suite can assert each rule fires.

Nothing here is a working payload:

- URLs point at `example.com` / RFC-5737 documentation IP ranges.
- "Secrets" are obvious placeholders, not real values.
- Command snippets are illustrative strings, not wired to run.

Do not "fix" these files — the tests depend on the patterns being present.
