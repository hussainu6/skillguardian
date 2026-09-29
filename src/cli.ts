#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { discover } from "./discover.js";
import { RULES } from "./rules/index.js";
import { renderJson } from "./reporters/json.js";
import { renderMarkdown } from "./reporters/markdown.js";
import { renderSarif } from "./reporters/sarif.js";
import { renderTerminal } from "./reporters/terminal.js";
import { scanComponents } from "./scanner.js";
import type { Severity } from "./types.js";

const VERSION = "0.1.2";

interface Args {
  path: string;
  format: "terminal" | "json" | "sarif" | "markdown";
  output?: string;
  failOn: Severity | "never";
  only?: string[];
  skip?: string[];
  command: "scan" | "rules" | "help" | "version";
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function parseArgs(argv: string[]): Args {
  const args: Args = { path: ".", format: "terminal", failOn: "high", command: "scan" };
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case "rules":
        args.command = "rules";
        break;
      case "-h":
      case "--help":
        args.command = "help";
        break;
      case "-v":
      case "--version":
        args.command = "version";
        break;
      case "-f":
      case "--format":
        args.format = argv[++i] as Args["format"];
        break;
      case "-o":
      case "--output":
        args.output = argv[++i];
        break;
      case "--fail-on":
        args.failOn = argv[++i] as Args["failOn"];
        break;
      case "--only":
        args.only = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
        break;
      case "--skip":
        args.skip = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
        break;
      default:
        if (a === "scan") break;
        if (a.startsWith("-")) {
          process.stderr.write(`Unknown option: ${a}\n`);
          process.exit(2);
        }
        positional.push(a);
    }
  }
  if (positional[0]) args.path = positional[0];
  return args;
}

const HELP = `
skillguardian v${VERSION} — security scanner for AI agent skills, plugins & MCP configs

USAGE
  skillguardian [scan] [path] [options]
  skillguardian rules
  skillguardian --help

ARGUMENTS
  path                 File or directory to scan (default: current directory)

OPTIONS
  -f, --format <fmt>   terminal | json | sarif | markdown   (default: terminal)
  -o, --output <file>  Write the report to a file instead of stdout
  --fail-on <sev>      Exit non-zero at this severity or worse:
                       critical | high | medium | low | never   (default: high)
  --only <ids>         Run only these rule ids (comma-separated), e.g. --only SS003,SS010
  --skip <ids>         Skip these rule ids
  -v, --version        Print version
  -h, --help           Show this help

EXAMPLES
  npx skillguardian                         Scan the current directory
  npx skillguardian ./skills                Scan a folder of skills
  npx skillguardian . -f sarif -o out.sarif Emit SARIF for GitHub code scanning
  npx skillguardian . --fail-on critical    Only fail CI on critical findings

Exit codes: 0 clean/under threshold · 1 findings at/above --fail-on · 2 usage error
`;

function listRules(): void {
  process.stdout.write(`\nskillguardian rules (${RULES.length})\n\n`);
  for (const r of RULES) {
    process.stdout.write(`  ${r.id}  [${r.severity.padEnd(8)}] ${r.title}\n`);
    process.stdout.write(`         ${r.description}\n`);
  }
  process.stdout.write("\n");
}

function render(report: import("./types.js").ScanReport, format: Args["format"]): string {
  switch (format) {
    case "json":
      return renderJson(report);
    case "sarif":
      return renderSarif(report);
    case "markdown":
      return renderMarkdown(report);
    case "terminal":
    default:
      return renderTerminal(report);
  }
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  if (args.command === "help") return void process.stdout.write(HELP);
  if (args.command === "version") return void process.stdout.write(`${VERSION}\n`);
  if (args.command === "rules") return listRules();

  const target = resolve(args.path);
  if (!existsSync(target)) {
    process.stderr.write(`Path not found: ${target}\n`);
    process.exit(2);
  }

  const components = discover(target);
  const report = scanComponents(components, args.path, { only: args.only, skip: args.skip });
  const rendered = render(report, args.format);

  if (args.output) {
    writeFileSync(args.output, rendered + "\n", "utf8");
    process.stdout.write(`Report written to ${args.output}\n`);
  } else {
    process.stdout.write(rendered + "\n");
  }

  if (args.failOn !== "never") {
    const limit = SEVERITY_ORDER[args.failOn];
    const tripped = report.components.some((c) =>
      c.findings.some((f) => SEVERITY_ORDER[f.severity] <= limit),
    );
    if (tripped) process.exit(1);
  }
}

main();
