/**
 * Network/DNS tools: dns_lookup, reverse_dns, ip_geolocation, ssl_certificate,
 * whois_lookup. The first four are ported from the ortamarco.me tool backend.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { ResponseFormat, fail, respond, responseFormatField } from "../format.js";
import { resolveAllRecords, reverseDns, type NormalizedRecord } from "../core/dns.js";
import { inspectCertificate } from "../core/tls.js";
import { GEOIP_ATTRIBUTION, geolocateIp } from "../core/geoip.js";
import { lookupWhois } from "../core/whois.js";
import { errMessage, isPrivateHost, validateHost, validateIp } from "../core/validate.js";
import {
  CertificateSchema,
  DnsLookupSchema,
  IpInfoSchema,
  ReverseDnsSchema,
  WhoisSchema,
} from "../schemas.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

function renderDns(host: string, records: Record<string, NormalizedRecord[]>): string {
  const lines = [`# DNS records for ${host}`, ""];
  for (const [type, recs] of Object.entries(records)) {
    lines.push(`## ${type}`);
    for (const r of recs) {
      const pri = r.priority !== undefined ? ` (priority ${r.priority})` : "";
      lines.push(`- ${r.value}${pri}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function registerNetworkTools(server: McpServer): void {
  const DnsInput = z.object({
    domain: z.string().min(1).max(253).describe("Domain to query, e.g. 'example.com'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "dns_lookup",
    {
      title: "DNS Lookup",
      description: `Resolve all common DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA) for a domain in one call, using public resolvers (Cloudflare/Google/Quad9).

Args:
  - domain (string): the domain to query, e.g. "example.com".
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: a map of record type -> list of records. Each record has { type, host, value, priority? }.

Examples:
  - "What are the MX records for stripe.com?" -> dns_lookup(domain="stripe.com")
  - Use ssl_certificate for TLS details, whois_lookup for registration data.

Errors: returns an error if the domain is malformed or has no resolvable records.`,
      inputSchema: DnsInput,
      outputSchema: DnsLookupSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const records = await resolveAllRecords(host);
        if (Object.keys(records).length === 0) {
          return fail(`No DNS records found for ${host}. Check the domain is spelled correctly and registered.`);
        }
        return respond({ domain: host, records }, response_format, () => renderDns(host, records));
      } catch (err) {
        return fail(`Error resolving DNS for ${host}: ${errMessage(err)}`);
      }
    },
  );

  const IpInput = z.object({
    ip: z.string().min(1).max(45).describe("IPv4 or IPv6 address, e.g. '1.1.1.1'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "reverse_dns",
    {
      title: "Reverse DNS (PTR)",
      description: `Resolve the PTR (reverse DNS) records for an IP address — the hostname(s) the IP maps back to.

Args:
  - ip (string): IPv4 or IPv6 address.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { ip, hostnames: string[] }.

Example: "What hostname does 8.8.8.8 reverse to?" -> reverse_dns(ip="8.8.8.8").
Errors: returns an error if the IP is invalid or has no PTR record.`,
      inputSchema: IpInput,
      outputSchema: ReverseDnsSchema,
      annotations: READ_ONLY,
    },
    async ({ ip, response_format }) => {
      const addr = validateIp(ip);
      if (!addr) return fail(`Error: '${ip}' is not a valid IP address.`);
      try {
        const hostnames = await reverseDns(addr);
        if (hostnames.length === 0) return fail(`No PTR record is configured for ${addr}.`);
        return respond({ ip: addr, hostnames }, response_format, () =>
          [`# Reverse DNS for ${addr}`, "", ...hostnames.map((h) => `- ${h}`)].join("\n"),
        );
      } catch {
        return fail(`No PTR record is configured for ${addr}.`);
      }
    },
  );

  server.registerTool(
    "ip_geolocation",
    {
      title: "IP Geolocation",
      description: `Geolocate an IP address (country, region, city, coordinates, time zone) using the offline DB-IP Lite database, plus its reverse-DNS hostname. No external API.

Args:
  - ip (string): IPv4 or IPv6 address.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { ip, country_iso, country_name, region, city, latitude, longitude, time_zone, hostname }.

Example: "Where is 151.101.1.69 located?" -> ip_geolocation(ip="151.101.1.69").
Note: geolocation is approximate (city-level at best) and offline data may lag reality. The time zone is estimated from the coordinates.
Data: ${GEOIP_ATTRIBUTION}, licensed CC BY 4.0 — credit it when showing these results.`,
      inputSchema: IpInput,
      outputSchema: IpInfoSchema,
      annotations: READ_ONLY,
    },
    async ({ ip, response_format }) => {
      const addr = validateIp(ip);
      if (!addr) return fail(`Error: '${ip}' is not a valid IP address.`);
      try {
        const info = await geolocateIp(addr);
        return respond(info, response_format, () =>
          [
            `# IP ${addr}`,
            "",
            `- **Country**: ${info.country_name ?? "unknown"} (${info.country_iso ?? "—"})`,
            `- **City**: ${info.city ?? "—"}${info.region ? `, ${info.region}` : ""}`,
            `- **Coordinates**: ${info.latitude ?? "—"}, ${info.longitude ?? "—"}`,
            `- **Time zone**: ${info.time_zone ?? "—"}`,
            `- **Hostname**: ${info.hostname ?? "—"}`,
            "",
            `_${GEOIP_ATTRIBUTION}_`,
          ].join("\n"),
        );
      } catch (err) {
        return fail(`Error geolocating ${addr}: ${errMessage(err)}`);
      }
    },
  );

  const SslInput = z.object({
    domain: z.string().min(1).max(253).describe("Domain (or host) to inspect, e.g. 'example.com'."),
    port: z.number().int().min(1).max(65535).default(443).describe("TLS port (default 443)."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "ssl_certificate",
    {
      title: "SSL/TLS Certificate Inspector",
      description: `Inspect the TLS certificate served by a host: issuer, subject, validity window, days-until-expiry, SANs, serial and SHA-256 fingerprint. Flags expired or soon-to-expire certificates.

Args:
  - domain (string): host to connect to.
  - port (number): TLS port (default 443).
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: certificate fields plus { days_until_expiry, expired, expires_soon, trusted, hostname_matches, authorization_error }. An untrusted certificate (self-signed, unknown root, wrong host) is still inspected and reported, never silently passed.

Example: "When does github.com's certificate expire?" -> ssl_certificate(domain="github.com").
Errors: returns an error if the host is unreachable or serves no certificate.`,
      inputSchema: SslInput,
      outputSchema: CertificateSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, port, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      if (isPrivateHost(host)) {
        return fail(`Error: '${host}' is a private or reserved host; refusing to connect to it.`);
      }
      try {
        const cert = await inspectCertificate(host, port);
        return respond(cert, response_format, () => {
          const expiry = cert.expired
            ? "⚠️ EXPIRED"
            : cert.expires_soon
              ? `⚠️ expires in ${cert.days_until_expiry} days`
              : `${cert.days_until_expiry} days remaining`;
          return [
            `# TLS certificate for ${host}:${port}`,
            "",
            `- **Issued to**: ${cert.subject_common_name ?? "—"}`,
            `- **Issuer**: ${cert.issuer_organization ?? cert.issuer_common_name ?? "—"}`,
            `- **Valid**: ${cert.valid_from ?? "—"} → ${cert.valid_to ?? "—"}`,
            `- **Status**: ${expiry}`,
            `- **Trusted**: ${cert.trusted ? "✅ yes" : `❌ no — ${!cert.hostname_matches ? "the certificate does not cover this host" : cert.authorization_error ?? "the chain does not validate"}`}`,
            `- **SANs**: ${cert.subject_alt_names.slice(0, 12).join(", ") || "—"}`,
            `- **SHA-256**: ${cert.fingerprint_sha256 ?? "—"}`,
          ].join("\n");
        });
      } catch (err) {
        return fail(`Could not retrieve a certificate for ${host}:${port}: ${errMessage(err)}`);
      }
    },
  );

  const WhoisInput = z.object({
    domain: z.string().min(1).max(253).describe("Domain to look up, e.g. 'example.com'."),
    response_format: responseFormatField,
  });

  server.registerTool(
    "whois_lookup",
    {
      title: "WHOIS Lookup",
      description: `Look up domain registration data over the raw WHOIS protocol (port 43): registrar, creation/update/expiry dates, name servers and domain status. Resolves the correct WHOIS server via IANA and follows registrar referrals. No API key.

Args:
  - domain (string): the domain to look up.
  - response_format ('markdown' | 'json'): output format (default 'markdown'). JSON includes the raw WHOIS text.

Returns: { domain, registrar, created, updated, expires, name_servers[], status[], whois_server }.

Example: "Who is the registrar for openai.com and when does it expire?" -> whois_lookup(domain="openai.com").
Errors: returns an error if no WHOIS server answers (some ccTLDs restrict or rate-limit WHOIS).`,
      inputSchema: WhoisInput,
      outputSchema: WhoisSchema,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const info = await lookupWhois(host);
        if (response_format === ResponseFormat.JSON) {
          return respond(info, response_format, () => "");
        }
        return respond(info, response_format, () =>
          [
            `# WHOIS for ${host}`,
            "",
            `- **Registrar**: ${info.registrar ?? "—"}`,
            `- **Created**: ${info.created ?? "—"}`,
            `- **Updated**: ${info.updated ?? "—"}`,
            `- **Expires**: ${info.expires ?? "—"}`,
            `- **Name servers**: ${info.name_servers.join(", ") || "—"}`,
            `- **Status**: ${info.status.slice(0, 6).join(", ") || "—"}`,
            `- **WHOIS server**: ${info.whois_server ?? "—"}`,
          ].join("\n"),
        );
      } catch (err) {
        return fail(`WHOIS lookup for ${host} failed: ${errMessage(err)}`);
      }
    },
  );
}
