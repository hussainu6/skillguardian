# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

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
