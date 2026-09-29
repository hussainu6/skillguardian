# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-29

### Added

- **Configuration file** `.skillguardianrc.json` (found at or above the scan
  path): `disable` rules, a default `failOn`, and a `minSeverity` filter.
- **Inline suppression** comments: `skillguardian-ignore [RULES]` on or above a
  line, and `skillguardian-ignore-file` for a whole file.
- New flags: `--min-severity`, `--no-suppress`, `--no-config`.
- Three more rules: `SS014` insecure `http://` endpoint, `SS015` hardcoded API
  key/token (masked in output, skips placeholders), `SS016` auto-running
  install/lifecycle hook that executes a command.
- `docs/FINDINGS.md` — a real-world precision-tuning write-up.
- Architecture diagram in the README.

### Changed

- Major false-positive reduction after scanning four large public repos:
  `SS001` no longer flags emoji zero-width joiners, `SS003` requires a real
  `eval(`/`exec(` call on decoded/fetched input, `SS014` ignores XML/schema
  namespaces, `SS002` requires a read verb, `SS008` requires action-paired
  urgency. Critical flags across the test corpus fell ~14× with no loss of true
  detections.

## [0.1.2] - 2026-09-29

### Added

- Three new detection rules:
  - `SS011` — reads the system clipboard (can capture passwords, 2FA codes, tokens).
  - `SS012` — installs a possible typosquatted package, using Damerau edit-distance
    against a list of commonly-squatted packages (catches `expres`, `loadsh`,
    `reqeusts`, and multiple packages on one install line).
  - `SS013` — overbroad filesystem access (recursive home reads, `**` globs).

## [0.1.1] - 2026-09-29

### Changed

- Renamed the package to **skillguardian** (npm blocked `skill-safe` as too
  similar to an existing package). CLI command, GitHub Action, and docs updated;
  detection engine and behavior are unchanged.
- Added a project banner and `repository`/`homepage`/`bugs` metadata so the npm
  page links back to the repo and renders the banner.

## [0.1.0] - 2026-09-29

Initial release.

### Added

- CLI `skillguardian` that scans a file or directory for AI agent skills, plugins,
  and MCP configs.
- 10 built-in detection rules (`SS001`–`SS010`) covering hidden Unicode, secret
  access, remote/dynamic execution, obfuscation, data egress, instruction
  override, disabled guardrails, false authority, destructive commands, and the
  read-secrets-and-exfiltrate combination.
- A–F grading with a 0–100 risk score per component and overall.
- Reporters: terminal, JSON, SARIF 2.1.0 (GitHub code scanning), and Markdown.
- Composite GitHub Action (`hussainu6/skillguardian`) with SARIF upload.
- Programmatic API: `scan()`, `discover()`, `scanComponents()`, reporters, rules.
- Test suite and CI across Node 20/22/24.
