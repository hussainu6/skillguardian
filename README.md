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

**[Why](#why)** · **[Install](#install)** · **[Usage](#usage)** · **[Rules](#what-it-detects)** · **[Config & suppression](#configuration--suppression)** · **[GitHub Action](#github-action)** · **[API](#programmatic-api)** · **[Limitations](#limitations)** · **[Contributing](#contributing)**

## Why

An AI agent skill is just a text file the agent *obeys*. A plugin or MCP server extends what the agent can do. You copy them from GitHub, gists, and registries and drop them straight into Claude Code, Cursor, and other agents — usually without reading every line.

That's a supply chain, and it has the same problem every supply chain has: **a malicious or careless component can turn your agent against you** — reading your `.env`, piping a remote script into your shell, or quietly telling the agent to skip its safety checks.

`skillguardian` reads those files the way an attacker would and flags the patterns that matter, in **one command, with zero config, no account, and no data leaving your machine.**

```bash
npx skillguardian ./path-to-skill
```

<div align="center">

<img src="https://raw.githubusercontent.com/hussainu6/skillguardian/main/assets/demo.svg" alt="skillguardian scanning a malicious skill and grading it F" width="720">

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
| `--ignore` | Skip paths matching globs, e.g. `--ignore "vendor/**,*.min.js"` | none |
| `--min-severity` | Hide findings below this severity | — |
| `skillguardian rules` | List every rule | |
| `skillguardian badge` | Print a README grade badge | |

```bash
skillguardian ./skills                       # scan a folder of skills
skillguardian . -f sarif -o skillguardian.sarif # SARIF for GitHub code scanning
skillguardian . --fail-on critical           # only fail on critical findings
skillguardian . -f json | jq '.grade'        # pipe into your own tooling
skillguardian badge .                        # -> [![skillguardian: A](…)](…)
```

**Exit codes:** `0` clean or under threshold · `1` findings at/above `--fail-on` · `2` usage error.

## How it works

<div align="center">
<img src="https://raw.githubusercontent.com/hussainu6/skillguardian/main/assets/architecture.svg" alt="skillguardian pipeline: discover components, apply 22 rules, grade A–F, report" width="820">
</div>

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
| `SS011` | Reads the system clipboard (passwords, 2FA codes, tokens) | 🟨 medium |
| `SS012` | Installs a possible typosquatted package (`expres`, `reqeusts`) | 🟧 high |
| `SS013` | Overbroad filesystem access (recursive home reads, `**` globs) | 🟨 medium |
| `SS014` | Uses an insecure `http://` endpoint (non-localhost) | 🟨 medium |
| `SS015` | Hardcoded API key or token (OpenAI, GitHub, AWS, Stripe, JWT…) | 🟧 high |
| `SS016` | Auto-running hook executes a command (install / `SessionStart` / `PreToolUse`) | 🟧 high |
| `SS017` | Reverse or bind shell (`/dev/tcp`, `nc -e`, `socat EXEC`) | 🟥 critical |
| `SS018` | Reads browser / OS credential stores (`Login Data`, `key4.db`, keychain) | 🟧 high |
| `SS019` | Accesses a crypto wallet or seed phrase (`wallet.dat`, keystore, mnemonic) | 🟧 high |
| `SS020` | Installs a persistence mechanism (shell rc, cron, launchd, Run key) | 🟧 high |
| `SS021` | Obfuscated / download-and-run PowerShell (`-enc`, hidden, `IEX` download) | 🟧 high |
| `SS022` | Clears history or covers tracks (`history -c`, wipes event logs) | 🟨 medium |

`SS010` is the one that matters most: it fires only when a *single component* both touches secrets and has a network egress path. Skills that look innocent rule-by-rule get caught by the combination.

These rules were tuned against real public repositories to keep false positives low — see [**docs/FINDINGS.md**](docs/FINDINGS.md) for that write-up.

## Capability analysis & cross-skill risks

A finding tells you a pattern is present. A **capability** tells you what authority installing a component grants your agent — `secrets`, `filesystem`, `network`, `exec`, `persistence`, `control`, `evasion`. skillguardian summarizes the capability surface of each component so you can answer the question that actually matters: *what new power does this give the agent, and can those powers combine?*

That composition is the dangerous part. `SS010` already flags a single component that **both** reads secrets and reaches the network. But the same chain can hide across **two separate skills** — one reads your `.env`, another (installed later, looks unrelated) has network access. Each grades fine alone; together they're an exfiltration path. skillguardian raises that as a scan-level **cross-skill risk**:

```
Cross-skill risks (capabilities combined across separate components)
    COMPOSED  SX01 Composed exfiltration risk (secrets + network across skills)
      · 🔑 secrets in env-reader        (SS002)
      · 🌐 network in diagnostics-uploader (SS005)
```

Static scanning can't prove safety, but it can establish a **minimum trust threshold** — a capability budget — before an agent is handed filesystem, credential, or network access.

> This feature was built from [dev.to](https://dev.to/hussainu6/your-ai-agent-installs-skills-like-npm-packages-but-nobodys-scanning-them-1gm1) feedback on exactly this: the real boundary is capability composition, not any single skill.

## Configuration & suppression

Tune skillguardian without touching code:

```jsonc
// .skillguardianrc.json (found at or above the scan path)
{
  "disable": ["SS008"],   // turn rules off
  "failOn": "high",        // default CI threshold
  "minSeverity": "low"     // hide anything quieter than this
}
```

Silence a reviewed, accepted finding right where it lives:

```md
<!-- skillguardian-ignore SS005 -->   suppress one rule on the next/this line
# skillguardian-ignore                 suppress all rules on this line
<!-- skillguardian-ignore-file -->     suppress the whole file (top of file)
```

CLI flags always win over the config file; run `--no-config` or `--no-suppress` to ignore either.

## Show your grade

If your skills pass, say so. `skillguardian badge` prints a Markdown badge for the scanned path:

```bash
skillguardian badge .
```

[![skillguardian: A](https://img.shields.io/badge/skillguardian-A-brightgreen)](https://github.com/hussainu6/skillguardian)

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

## Limitations

`skillguardian` is a **static, pattern-based** scanner. It reads files as text and matches known-dangerous shapes; it does **not** execute anything it scans, and it never starts your MCP servers.

That means:

- ✅ Fast, offline, safe to run on untrusted files, no account.
- ⚠️ It catches known patterns, not novel or heavily obfuscated attacks. A clean report is **not** a guarantee — it's a fast first filter that removes the obvious and the careless.
- ⚠️ Some rules (like `SS008`) are *signals*, not proof. A real vendor skill may legitimately trip them.

Use it as one layer. Still read skills you grant real power to.

## How it compares

| | skillguardian | Hand review | Enterprise agent scanners |
| --- | :---: | :---: | :---: |
| Cost | Free, MIT | Your time | Paid / account |
| Setup | `npx`, zero config | — | Sign-up + token |
| Runs offline | ✅ | ✅ | Often phones home |
| Catches the obvious & careless | ✅ | Depends on attention | ✅ |
| Catches novel, targeted attacks | ⚠️ not alone | ✅ if careful | ✅ |
| CI + README badge | ✅ | — | Varies |

skillguardian's job is to be the cheap, always-on first gate so human review and heavier tooling spend their attention where it matters.

## Contributing

New detection rules are the most valuable contribution. A rule is one small file that exports a `Rule`; see [`src/rules/`](src/rules/) and [CONTRIBUTING.md](CONTRIBUTING.md). Found a pattern in the wild? Open an issue with a **defanged** example.

Found something malicious in a *public* skill? Please **don't** name-and-shame — see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[MIT](LICENSE) © Uzair Hussain
