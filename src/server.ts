/**
 * Builds the MCP server instance and registers every tool. Shared by both the
 * stdio and HTTP entry points so the two transports always expose the same API.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
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

export function createServer(): McpServer {
  const server = new McpServer(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    { instructions: INSTRUCTIONS },
  );

  registerEmailTools(server); // flagship + email/deliverability
  registerNetworkTools(server); // DNS / TLS / IP / WHOIS
  registerWebTools(server); // HTTP headers / DNSSEC
  registerExtraTools(server); // CAA / MX / DNSBL / propagation / email headers

  return server;
}
