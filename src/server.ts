/**
 * Builds the MCP server instance and registers every tool.
 *
 * This is a **factory**, not a singleton: both v2 entry points (`serveStdio`
 * and `createMcpHandler`) take a factory and call it once per connection
 * (stdio) or once per request (HTTP), which is what lets one code path serve
 * both the 2026-07-28 revision and 2025-era clients. Either way the two
 * transports always expose the same API.
 */

import { McpServer } from "@modelcontextprotocol/server";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";
import { registerNetworkTools } from "./tools/network.js";
import { registerEmailTools } from "./tools/email.js";
import { registerWebTools } from "./tools/web.js";
import { registerExtraTools } from "./tools/extra.js";

const INSTRUCTIONS = `Domain & email security toolkit. Every tool is read-only and uses public DNS, TLS, WHOIS and HTTPS — no API keys, no side effects.

Guidance:
- To assess a domain's email security, start with \`email_auth_audit\` (it scores SPF + DKIM + DMARC + MX and lists fixes), then drill into \`spf_check\`, \`dmarc_check\`, \`dkim_check\`, \`mta_sts_check\`, \`tls_rpt_check\` or \`bimi_check\` for detail.
- DKIM selectors are undiscoverable: pass the domain's selector to \`dkim_check\` for a definitive answer; a miss on common selectors is inconclusive.
- For DNS/network questions use \`dns_lookup\`, \`mx_lookup\`, \`whois_lookup\`, \`ssl_certificate\`, \`dnssec_check\`, \`caa_check\`, \`dns_propagation\`, \`reverse_dns\` or \`ip_geolocation\`.
- \`blacklist_check\` queries only open-access DNSBLs; Spamhaus/Barracuda are excluded.
- All tools accept response_format='json' for structured output instead of the default markdown.`;

/**
 * Create a fully-registered server instance.
 *
 * Tool registration order is deliberate and stable: `tools/list` returns them
 * in this order on every connection, so a client that caches the list (see the
 * `cacheHints` below) never sees it shuffle.
 */
export function createServer(): McpServer {
  const server = new McpServer(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      capabilities: { tools: {} },
      instructions: INSTRUCTIONS,
      // The tool list is a compile-time constant here — no dynamic
      // registration, no feature flags — so on the 2026-07-28 revision we can
      // honestly advertise a real TTL instead of the SDK's conservative
      // `ttlMs: 0`. `public` is safe because the advertisement carries nothing
      // user-specific. 2025-era responses never carry these fields.
      cacheHints: {
        "tools/list": { ttlMs: 3_600_000, cacheScope: "public" },
        "server/discover": { ttlMs: 3_600_000, cacheScope: "public" },
      },
    },
  );

  registerEmailTools(server); // flagship + email/deliverability
  registerNetworkTools(server); // DNS / TLS / IP / WHOIS
  registerWebTools(server); // HTTP headers / DNSSEC
  registerExtraTools(server); // CAA / MX / DNSBL / propagation / email headers

  return server;
}
