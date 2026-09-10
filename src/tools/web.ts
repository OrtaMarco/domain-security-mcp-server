/**
 * Web-security tools: http_security_headers, dnssec_check.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { fail, respond, responseFormatField, statusLine } from "../format.js";
import { errMessage, validateHost, validateUrl } from "../core/validate.js";
import { analyzeSecurityHeaders } from "../core/http.js";
import { checkDnssec } from "../core/email-auth.js";
import { DnssecSchema, SecurityHeadersSchema } from "../schemas.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerWebTools(server: McpServer): void {
  const UrlInput = z.object({
    url: z.string().min(1).describe("URL or host to check, e.g. 'https://example.com'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "http_security_headers",
    {
      title: "HTTP Security Headers",
      description: `Fetch a URL and grade its HTTP security headers (HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP). Returns a 0–100 score, an A–F grade, and per-header notes.

Args:
  - url (string): URL or host to check (scheme defaults to https://).
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { url, final_url, status, grade, score, checks[{header, present, value, note}], missing[] }.

Example: "Grade the security headers on https://news.ycombinator.com" -> http_security_headers(url="https://news.ycombinator.com").
Errors: returns an error if the URL is invalid or the host is unreachable.`,
      inputSchema: UrlInput,
      outputSchema: SecurityHeadersSchema,
      annotations: READ_ONLY,
    },
    async ({ url, response_format }) => {
      const parsed = validateUrl(url);
      if (!parsed) return fail(`Error: '${url}' is not a valid http(s) URL.`);
      try {
        const report = await analyzeSecurityHeaders(parsed);
        return respond(report, response_format, () =>
          [
            `# Security headers — ${report.final_url}`,
            "",
            `**Grade: ${report.grade} (${report.score}/100)** · HTTP ${report.status}`,
            "",
            ...report.checks.map((c) => `${statusLine(c.present, c.header)} — ${c.note}`),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`Could not fetch ${parsed.toString()}: ${errMessage(err)}`);
      }
    },
  );

  const DomainInput = z.object({
    domain: z.string().min(1).describe("Domain to check, e.g. 'example.com'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "dnssec_check",
    {
      title: "DNSSEC Check",
      description: `Check whether a domain is protected by DNSSEC. Queries DS and DNSKEY records over DNS-over-HTTPS and reads the resolver's Authenticated Data (AD) flag to confirm the chain of trust validates.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { enabled, validated, ds_records, dnskey_records, findings[] }.

Example: "Is cloudflare.com DNSSEC-signed?" -> dnssec_check(domain="cloudflare.com").`,
      inputSchema: DomainInput,
      outputSchema: DnssecSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const result = await checkDnssec(host);
        return respond(result, response_format, () =>
          [
            `# DNSSEC — ${host}`,
            "",
            statusLine(result.enabled, "Signed (DS/DNSKEY present)"),
            statusLine(result.validated, "Chain of trust validates (AD flag)"),
            `\nDS records: ${result.ds_records} · DNSKEY records: ${result.dnskey_records}`,
            "",
            result.findings.map((f) => f.message).join("\n"),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`DNSSEC check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );
}
