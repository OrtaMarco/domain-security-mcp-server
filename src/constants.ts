/**
 * Shared constants for the domain-security MCP server.
 */

export const SERVER_NAME = "domain-security-mcp-server";
export const SERVER_VERSION = "1.0.0";

/**
 * Public DNS resolvers (Cloudflare, Google, Quad9). Used instead of the host's
 * /etc/resolv.conf so the server behaves identically in any environment
 * (containers, WSL, CI) where the system resolver may be missing or local-only.
 */
export const PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

/** Cloudflare DNS-over-HTTPS JSON endpoint — used for record types Node's
 *  resolver cannot query (DS, DNSKEY) and to read the DNSSEC `AD` flag. */
export const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/** Maximum size of any tool response, in characters, before truncation. */
export const CHARACTER_LIMIT = 25_000;

/** Default per-operation network timeout, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 8_000;

/** RFC 7208 §4.6.4 — an SPF record may trigger at most 10 DNS-querying terms. */
export const SPF_MAX_LOOKUPS = 10;

/**
 * Common DKIM selectors probed when the caller does not supply one. DKIM has no
 * discovery mechanism, so absence of these is NOT proof that DKIM is unconfigured.
 */
export const COMMON_DKIM_SELECTORS = [
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "k2",
  "dkim",
  "default",
  "mail",
  "smtp",
  "mandrill",
  "mailjet",
  "mailgun",
  "mxvault",
  "zoho",
  "amazonses",
  "fm1",
  "fm2",
  "fm3",
  "protonmail",
  "pm",
];
