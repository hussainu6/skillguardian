# What skillguardian finds in the wild

To tune skillguardian against real content — not just its own fixtures — I ran it
across four large public repositories and studied every category of flag. This
doc reports the aggregate result and, just as importantly, what the exercise
taught me about **false positives**.

> **Read this carefully:** a flag is *not* a confirmed vulnerability. All four
> repositories below are reputable and, as the numbers show, mostly clean. The
> remaining flags are overwhelmingly **advisory** — things worth a human glance,
> like example code that reads an environment variable, not evidence of malice.
> No confirmed vulnerability was found, and no repository is singled out.

## Corpus

| Repository | Type | Components scanned |
| --- | --- | --- |
| anthropics/skills | Agent skills | 68 |
| obra/superpowers | Agent skills | 60 |
| punkpeye/awesome-mcp-servers | MCP list | 2 |
| anthropics/claude-cookbooks | Example code | 112 |

A "component" is a directory of related text files (a skill folder, a doc set).
242 in total, ~335 Markdown files plus scripts and configs.

## Aggregate result (after precision tuning)

- **64% of components graded A** (156 of 242); 6% graded F (14).
- **38%** had at least one flag of any severity.
- Flags by severity: 80 critical · 40 high · 72 medium · 31 low.
- Most-fired rules: `SS010` (reads-secret **and** network, 69), `SS002`
  (reads a credential store, 58), `SS008` (pushy/authority language, 31),
  `SS007` (disabled guardrails, 17).

The `SS010` and `SS002` flags cluster in the **example-code** repository, where
sample scripts legitimately read an API key from the environment and call an
API. In that context it's expected behavior, not exfiltration — which is exactly
why skillguardian is meant for *skill/plugin/MCP definition* files, and why its
output is a first filter a human still reads.

## The real lesson: dogfooding cut false positives ~14×

The first run was noisy — **1,129 "critical" flags**. Reading the evidence
line-by-line, almost all of that was the scanner misreading ordinary content.
Fixing it dropped critical flags to **80** with no loss of true detections
(every fixture still grades correctly). The fixes:

| Rule | False positive found | Fix |
| --- | --- | --- |
| `SS001` | Zero-width joiners in **emoji sequences** counted as hidden text (840 hits in one list) | Only flag zero-width chars embedded in ASCII text |
| `SS003` | A case-insensitive pattern matched the word **"function"**; a bare backtick matched Markdown code-spans like `` `eval-audit.md` `` | Require an actual `eval(`/`exec(` **call** on decoded/fetched/interpolated input |
| `SS014` | **XML/schema namespace URIs** (`http://schemas.openxmlformats.org/…`, `http://www.w3.org/…`) flagged as insecure endpoints | Ignore known namespace/spec/license hosts and `xmlns`/DTD lines |
| `SS002` | Benign **mentions** ("set your `OPENAI_API_KEY`") flagged as secret access | Require a read/transmit verb on the line |
| `SS008` | Everyday prose ("you must consider…") flagged as pressure | Require urgency to be paired with a concrete action |

This is the honest value of a real-world pass: it made the tool trustworthy
enough that a green result means something.

## Reproduce it

```bash
# clone any skill/plugin/MCP repo, then:
npx skillguardian ./that-repo --fail-on never
```

skillguardian runs offline and never sends the scanned content anywhere. If you
find a genuinely malicious public component, please follow
[SECURITY.md](../SECURITY.md) — report it to the platform first, and defang any
example before writing it up.
