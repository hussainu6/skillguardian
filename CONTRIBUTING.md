# Contributing to skill-safe

Thanks for helping make the AI agent ecosystem safer. The most useful
contributions are **new detection rules** and **real-world (defanged) examples**.

## Setup

```bash
git clone https://github.com/hussainu6/skill-safe
cd skill-safe
npm install
npm run build
npm test
```

## Writing a rule

A rule is one file in [`src/rules/`](src/rules/) that exports a `Rule`:

```ts
import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

export const myRule: Rule = {
  id: "SS0NN",                       // next free SS number
  title: "Short human title",
  severity: "high",                  // critical | high | medium | low | info
  description: "One line for `skill-safe rules`.",
  scan(component) {
    const matches = matchAll(component, /your-pattern/gi);
    return findingsFromMatches(
      myRule,
      matches,
      "Why this is a problem, one sentence.",
      "What the author should do instead.",
    );
  },
};
```

Then register it in [`src/rules/index.ts`](src/rules/index.ts).

### Rule guidelines

1. **One idea per rule.** Small rules are easier to tune and explain.
2. **Minimize false positives.** A noisy rule gets disabled and erodes trust. If a
   rule will fire on legitimate skills, score it `low` and say so in the message.
3. **Always give a remediation.** Every finding must tell the reader what to do.
4. **Add fixtures.** Put a defanged trigger in `test/fixtures/malicious-skill/`
   (or a new fixture) and assert it fires in `test/rules.test.js`. Make sure the
   clean fixture still grades `A`.
5. **Defang evidence.** Never let a rule echo raw payloads or control characters;
   `util.ts` handles this if you use the helpers.

## Reporting a pattern you found in the wild

Open an issue with:

- The **category** of attack (what it tries to do).
- A **defanged** minimal example (fake endpoints, placeholder secrets — see
  `test/fixtures/README.md`).
- Why current rules miss it.

Do **not** paste working payloads or point them at real infrastructure.

## Commit / PR

- Keep PRs focused; one rule or one fix per PR.
- `npm test` must pass. `npm run lint` must be clean.
- Reference the issue you're addressing.

By contributing you agree your work is licensed under the project's MIT license.
