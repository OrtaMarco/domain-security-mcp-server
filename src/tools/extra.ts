/**
 * Additional tools: CAA, MX, DNSBL blacklist, DNS propagation and email-header
 * analysis. Mirrors the ortamarco.me web tools so the agent and the site share
 * the same capabilities.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { isIP } from "node:net";
import * as z from "zod/v4";
import { ResponseFormat, fail, respond, responseFormatField } from "../format.js";
import { errMessage, validateHost } from "../core/validate.js";
import {
  analyzeBlacklist,
  analyzeCaa,
  analyzeDnsPropagation,
  mxLookup,
  type PropagationType,
} from "../core/net.js";
import { parseEmailHeaders } from "../core/email-headers.js";
import {
  BlacklistSchema,
  CaaSchema,
  HeadersAnalysisSchema,
  MxSchema,
  PropagationSchema,
} from "../schemas.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerExtraTools(server: McpServer): void {
  // --- caa_check -----------------------------------------------------------
  const DomainInput = z.object({
    domain: z.string().min(1).describe("Domain to query, e.g. 'example.com'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "caa_check",
    {
      title: "CAA Record Check",
      description: `Check a domain's CAA (Certification Authority Authorization) records — which CAs are allowed to issue TLS certificates for it. Absence means any CA may issue.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { found, issue[], issuewild[], iodef[] }.

Example: "Which CAs can issue certs for google.com?" -> caa_check(domain="google.com").`,
      inputSchema: DomainInput,
      outputSchema: CaaSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const r = await analyzeCaa(host);
        return respond(r, response_format, () =>
          [
            `# CAA — ${host}`,
            "",
            r.found
              ? `Authorized CAs: ${r.issue.join(", ") || "—"}${r.issuewild.length ? `\nWildcard: ${r.issuewild.join(", ")}` : ""}`
              : "No CAA record — any certificate authority may issue certificates for this domain.",
          ].join("\n"),
        );
      } catch (err) {
        return fail(`CAA check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // --- mx_lookup -----------------------------------------------------------
  server.registerTool(
    "mx_lookup",
    {
      title: "MX Lookup",
      description: `Look up a domain's mail servers (MX records) with priority and the IPs they resolve to.

Args:
  - domain (string): the domain to query.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: array of { exchange, priority, ips[] }.

Example: "What are the mail servers for github.com?" -> mx_lookup(domain="github.com").`,
      inputSchema: DomainInput,
      outputSchema: MxSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const records = await mxLookup(host);
        if (records.length === 0) return fail(`No MX records found for ${host}.`);
        return respond({ domain: host, records }, response_format, () =>
          [`# MX — ${host}`, "", ...records.map((r) => `- ${r.priority} ${r.exchange} (${r.ips.join(", ") || "no A"})`)].join("\n"),
        );
      } catch (err) {
        return fail(`MX lookup for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // --- blacklist_check -----------------------------------------------------
  const BlacklistInput = z.object({
    query: z.string().min(1).describe("An IPv4 address or a domain to check against DNSBLs."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "blacklist_check",
    {
      title: "DNSBL Blacklist Check",
      description: `Check whether an IPv4 address (or a domain's A records) appears on email DNS blocklists (DNSBLs). Only open-access lists are queried (SORBS, SpamCop, UCEPROTECT-1, DroneBL, s5h); Spamhaus and Barracuda refuse public-resolver queries and are excluded.

Args:
  - query (string): an IPv4 address or a domain.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { ips[], listedCount, checked, results[{ip, hits[{list, listed, reason}]}], note }.

Example: "Is 203.0.113.5 blacklisted?" -> blacklist_check(query="203.0.113.5").`,
      inputSchema: BlacklistInput,
      outputSchema: BlacklistSchema,
      annotations: READ_ONLY,
    },
    async ({ query, response_format }) => {
      const sanitized = query.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      const valid = isIP(sanitized) === 4 || validateHost(sanitized) !== null;
      if (!valid) return fail(`Error: '${query}' is not a valid IPv4 address or domain.`);
      try {
        const r = await analyzeBlacklist(sanitized);
        return respond(r, response_format, () => {
          const lines = [`# Blacklist — ${sanitized}`, ""];
          if (r.ips.length === 0) lines.push("Could not resolve any IP to check.");
          else lines.push(r.listedCount === 0 ? `✅ Clean — not listed on any of ${r.checked} lists.` : `❌ Listed ${r.listedCount} time(s).`);
          for (const res of r.results) {
            const listed = res.hits.filter((h) => h.listed);
            if (listed.length) lines.push(`\n${res.ip}: ${listed.map((h) => h.list).join(", ")}`);
          }
          lines.push(`\n_${r.note}_`);
          return lines.join("\n");
        });
      } catch (err) {
        return fail(`Blacklist check failed: ${errMessage(err)}`);
      }
    },
  );

  // --- dns_propagation -----------------------------------------------------
  const PropagationInput = z.object({
    domain: z.string().min(1).describe("Domain to check."),
    type: z.enum(["A", "AAAA", "CNAME", "MX", "NS", "TXT"]).default("A").describe("Record type (default 'A')."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "dns_propagation",
    {
      title: "DNS Propagation Check",
      description: `Compare a domain's DNS records across multiple public resolvers worldwide (Cloudflare, Google, Quad9, OpenDNS, AdGuard) to see whether a change has propagated.

Args:
  - domain (string): the domain to check.
  - type ('A'|'AAAA'|'CNAME'|'MX'|'NS'|'TXT'): record type (default 'A').
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { type, consistent, resolvers[{name, server, values[], error}] }.

Example: "Has the A record for example.com propagated?" -> dns_propagation(domain="example.com").`,
      inputSchema: PropagationInput,
      outputSchema: PropagationSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, type, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const r = await analyzeDnsPropagation(host, type as PropagationType);
        return respond(r, response_format, () =>
          [
            `# DNS propagation — ${host} (${type})`,
            "",
            r.consistent ? "✅ Propagated: all resolvers agree." : "⚠️ Propagating: resolvers disagree.",
            "",
            ...r.resolvers.map((x) => `- ${x.name} (${x.server}): ${x.error ? `error (${x.error})` : x.values.join(", ") || "no data"}`),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`DNS propagation check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // --- analyze_email_headers ----------------------------------------------
  const HeadersInput = z.object({
    headers: z.string().min(1).describe("The raw email headers to analyze (RFC 5322)."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "analyze_email_headers",
    {
      title: "Email Header Analyzer",
      description: `Parse raw email headers and report the SPF/DKIM/DMARC verdicts (from Authentication-Results), key fields (From, Subject, Date, Message-ID, Return-Path) and the Received hop chain with per-hop delays and total transit time.

Args:
  - headers (string): the raw email headers.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { auth{spf,dkim,dmarc}, fields{}, hops[{index,from,by,date,delaySec}], totalSec }.

Example: paste the headers from "Show original" in Gmail to trace a message's path and authentication.`,
      inputSchema: HeadersInput,
      outputSchema: HeadersAnalysisSchema,
      annotations: READ_ONLY,
    },
    async ({ headers, response_format }) => {
      try {
        const r = parseEmailHeaders(headers);
        return respond(r, response_format, () =>
          [
            `# Email header analysis`,
            "",
            `**Auth** — SPF: ${r.auth.spf ?? "?"} · DKIM: ${r.auth.dkim ?? "?"} · DMARC: ${r.auth.dmarc ?? "?"}`,
            "",
            ...Object.entries(r.fields).map(([k, v]) => `- **${k}**: ${v}`),
            "",
            `**Route** (${r.hops.length} hops${r.totalSec !== null ? `, ${r.totalSec}s total` : ""}):`,
            ...r.hops.map((h) => `${h.index}. ${h.from} → ${h.by}${h.delaySec !== null ? ` (+${h.delaySec}s)` : ""}`),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`Header analysis failed: ${errMessage(err)}`);
      }
    },
  );
}
