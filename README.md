# domain-security-mcp-server

> An [MCP](https://modelcontextprotocol.io) server that lets an AI agent audit the **email and domain security** of any domain — SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, DNS, TLS/SSL and WHOIS — in plain language. **No API keys required.**

[![MCP](https://img.shields.io/badge/MCP-server-blue)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Built on the **v2 MCP SDK**: the server speaks the **2026-07-28** protocol
revision and keeps accepting 2025-era clients (Claude Desktop, Claude Code,
Cursor) from the same factory — the era is negotiated per connection, so there
is nothing to configure on either side.

Ask Claude *"Is acme.com protected against email spoofing?"* and it runs a full
authentication audit and hands you a graded report with prioritised fixes —
instead of you pasting a domain into five different web tools.

```
> Is ortamarco.me protected against email spoofing?

  email_auth_audit(domain="ortamarco.me")

  Grade: A (95/100) · MX: present
  ✅ SPF ends in '-all' (hard fail). 3/10 DNS lookups.
  ✅ DMARC policy is enforced ('p=reject').
  ✅ DKIM key found for selector: google.
  Top recommendation: add a TLS-RPT record for delivery-failure reports.
```

---

## Why this exists

The email-security ecosystem is full of single-purpose web checkers (SPF here,
DMARC there, WHOIS somewhere else) and the few MCP equivalents are locked behind
paid API tokens. This server brings the whole **deliverability & domain-security
toolkit** to any MCP client, key-free, with one headline workflow tool that does
the synthesis for you.

It is the agent-facing companion to the network tools at
[ortamarco.me](https://ortamarco.me) and shares the same battle-tested core
(public-resolver DNS, host validation, timeouts).

## Tools

| Tool | What it does |
|---|---|
| **`email_auth_audit`** ⭐ | One-call SPF + DKIM + DMARC + MX audit → 0–100 score, A–F grade, prioritised fixes |
| `spf_check` | Parse SPF; recursively count DNS lookups vs the RFC 7208 limit of 10; flag `+all`/`?all` |
| `dmarc_check` | Parse DMARC policy (`p`, `sp`, `rua`, `pct`, `aspf`/`adkim`) with warnings |
| `dkim_check` | Probe `<selector>._domainkey` keys (supply selectors or use common ones) |
| `mta_sts_check` | Validate the `_mta-sts` TXT **and** the `.well-known/mta-sts.txt` policy + mode |
| `tls_rpt_check` | Check the `_smtp._tls` TLS-RPT record |
| `bimi_check` | Check the `default._bimi` BIMI record |
| `dnssec_check` | DS/DNSKEY presence + DNSSEC `AD` validation flag (via DoH) |
| `dns_lookup` | All record types (A/AAAA/CNAME/MX/NS/TXT/SOA) via public resolvers |
| `ssl_certificate` | TLS cert issuer, validity window, days-to-expiry, SANs, fingerprint |
| `whois_lookup` | Registrar, dates, name servers, status (raw port-43 WHOIS, IANA-resolved) |
| `reverse_dns` | PTR records for an IP |
| `ip_geolocation` | Offline IP geolocation + reverse DNS |
| `mx_lookup` | Mail servers (MX) with priority and resolved IPs |
| `caa_check` | Which CAs may issue TLS certificates (CAA records) |
| `blacklist_check` | IP/domain against open-access email DNSBLs |
| `dns_propagation` | Compare a record across 5 public resolvers worldwide |
| `analyze_email_headers` | Parse raw headers → SPF/DKIM/DMARC verdicts + Received hop chain with delays |

Every tool is **read-only**, declares an `outputSchema` and returns
`structuredContent` (validated by the SDK) alongside human-readable Markdown
(default) or JSON (`response_format="json"`), plus actionable error messages.

## Install

Requires **Node.js 20+** (the v2 SDK's floor).

```bash
git clone https://github.com/ortamarco/domain-security-mcp-server.git
cd domain-security-mcp-server
npm install
npm run build
```

## Use it with Claude Code

```bash
claude mcp add domain-security -- node /absolute/path/to/domain-security-mcp-server/dist/index.js
```

## Use it with Claude Desktop

Add to `claude_desktop_config.json` (see [`examples/`](./examples/claude_desktop_config.json)):

```json
{
  "mcpServers": {
    "domain-security": {
      "command": "node",
      "args": ["/absolute/path/to/domain-security-mcp-server/dist/index.js"]
    }
  }
}
```

Restart Claude Desktop, then ask: *"Audit the email security of stripe.com."*

## Self-host (HTTP transport)

The same server speaks stateless **Streamable HTTP** for remote/multi-client use
— handy behind a reverse proxy such as Coolify or Traefik. One endpoint serves
both protocol eras and there is no session state, so no `Mcp-Session-Id` header
is issued or expected.

```bash
TRANSPORT=http PORT=3000 npm start
# POST JSON-RPC to http://localhost:3000/mcp   ·   health at /healthz
```

Or with Docker:

```bash
docker build -t domain-security-mcp .
docker run -p 3000:3000 -e TRANSPORT=http domain-security-mcp
```

Set `ALLOWED_ORIGINS=https://your.app` to enable Origin-based DNS-rebinding
protection (leave empty when a trusted proxy already restricts access).

## Develop

```bash
npm run dev      # tsx watch (stdio)
npm run inspect  # open the MCP Inspector against the built server
npm run build     # type-check + emit dist/
npm run typecheck # type-check only
npm run smoke     # call all 19 tools on BOTH protocol eras and validate
                  # structuredContent against each tool's outputSchema
```

[`evals/`](./evals/) holds a 10-question LLM evaluation set (stable, verifiable)
and instructions for running it — see [`evals/README.md`](./evals/README.md).

## How it works

```
src/
├── index.ts        # transport selection (stdio | http), v2 SDK entry points
├── server.ts       # factory: registers every tool on one McpServer
├── core/           # pure logic, no MCP coupling — reusable & testable
│   ├── dns.ts      # public-resolver DNS + DoH client
│   ├── tls.ts      # certificate inspection
│   ├── whois.ts    # port-43 WHOIS with IANA/registrar referral
│   ├── http.ts     # security-header grading
│   ├── geoip.ts    # offline IP geolocation
│   └── email-auth.ts  # SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI/DNSSEC + scoring
└── tools/          # thin MCP wrappers (Zod schemas, descriptions, formatting)
```

The `core/` layer is deliberately free of any MCP types, so the exact same logic
powers both this server and the web tools on ortamarco.me.

## License

MIT © [Marco Orta](https://ortamarco.me)
