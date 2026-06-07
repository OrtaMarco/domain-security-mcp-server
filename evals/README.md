# Evaluations

`evaluation.xml` holds 10 question/answer pairs that test whether an LLM, given
**only** this MCP server's tools (no other context), can answer realistic
domain & email-security questions. They follow the MCP evaluation format:
read-only, independent, verifiable by direct string comparison, and **stable**
(answers don't drift over time).

## Why these answers are stable

Most questions target infrastructure that effectively never changes (Google's
`8.8.8.8` → `dns.google`, `google.com` → `pki.goog` CAA, `gmail.com` MTA-STS
enforce, `cloudflare.com` DNSSEC). The two email-header questions embed a
**fixed** header block in the prompt, so their answers are fully deterministic.

Each answer was verified by calling the server's tools directly before being
recorded here.

| # | Tool exercised | Answer |
|---|---|---|
| 1 | `reverse_dns` | dns.google |
| 2 | `dnssec_check` (negative case) | False |
| 3 | `caa_check` | pki.goog |
| 4 | `dmarc_check` | reject |
| 5 | `dnssec_check` (positive case) | True |
| 6 | `ip_geolocation` | US |
| 7 | `mta_sts_check` | True |
| 8 | `analyze_email_headers` (auth result) | fail |
| 9 | `analyze_email_headers` (transit math) | 30 |
| 10 | `whois_lookup` | MarkMonitor, Inc. |

## Quick functional check (no API key)

`npm run smoke` (→ `scripts/smoke-all.mjs`) calls all 19 tools over stdio and
asserts each returns `structuredContent` that validates against its
`outputSchema`. This is a deterministic build gate, not an LLM evaluation.

## Full LLM evaluation (needs an Anthropic API key)

Use the evaluation harness from the `mcp-builder` skill
(`reference/scripts/evaluation.py`). It launches this server over stdio, lets a
Claude agent answer each question using only the tools, and scores the answers:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# from the mcp-builder skill's scripts/ directory:
python evaluation.py \
  -t stdio \
  -c node \
  -a /absolute/path/to/domain-security-mcp-server/dist/index.js \
  -o report.md \
  /absolute/path/to/domain-security-mcp-server/evals/evaluation.xml
```

The report shows per-question pass/fail, tool-call counts, and the agent's
feedback on the tools — useful for spotting unclear descriptions or schemas.

Build first: `npm run build`.
