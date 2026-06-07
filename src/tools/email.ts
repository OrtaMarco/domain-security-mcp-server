/**
 * Email-authentication and deliverability tools: email_auth_audit (headline
 * workflow), spf_check, dmarc_check, dkim_check, mta_sts_check, tls_rpt_check,
 * bimi_check.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { fail, respond, responseFormatField } from "../format.js";
import { errMessage, validateHost, validateSelector } from "../core/validate.js";
import {
  auditEmailAuth,
  checkBimi,
  checkDkim,
  checkDmarc,
  checkMtaSts,
  checkSpf,
  checkTlsRpt,
  type Finding,
} from "../core/email-auth.js";
import {
  DkimSchema,
  DmarcSchema,
  EmailAuditSchema,
  MtaStsSchema,
  SpfSchema,
  TxtPolicySchema,
} from "../schemas.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const GLYPH: Record<Finding["severity"], string> = {
  error: "❌",
  warning: "⚠️",
  info: "ℹ️",
  ok: "✅",
};

function renderFindings(findings: Finding[]): string {
  return findings.map((f) => `${GLYPH[f.severity]} ${f.message}`).join("\n");
}

/** Validate + sanitise the optional DKIM selector list shared by two tools. */
function cleanSelectors(selectors: string[] | undefined): string[] {
  return (selectors ?? []).map(validateSelector).filter((s): s is string => s !== null);
}

export function registerEmailTools(server: McpServer): void {
  // -------------------------------------------------------------------------
  // Flagship: email_auth_audit
  // -------------------------------------------------------------------------
  const AuditInput = z.object({
    domain: z.string().min(1).describe("Domain to audit, e.g. 'example.com'."),
    dkim_selectors: z
      .array(z.string())
      .optional()
      .describe(
        "Optional DKIM selectors to check (e.g. ['google','selector1']). If omitted, a list of common provider selectors is probed.",
      ),
    response_format: responseFormatField,
  });

  server.registerTool(
    "email_auth_audit",
    {
      title: "Email Authentication Audit",
      description: `Headline tool. Audits a domain's email-authentication posture in one call — SPF, DKIM, DMARC and MX — then returns a 0–100 score, an A–F grade and a prioritised list of fixes. Use this first; reach for the per-record tools (spf_check, dmarc_check, dkim_check) only when you need the full detail of one mechanism.

Args:
  - domain (string): the domain to audit.
  - dkim_selectors (string[], optional): DKIM selectors to probe. If omitted, common provider selectors are tried (absence is then inconclusive).
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns (JSON):
  {
    "domain": string,
    "grade": "A".."F",
    "score": number,             // 0-100
    "has_mx": boolean,
    "mx_hosts": string[],
    "spf":  { found, record, all_qualifier, lookup_count, exceeds_lookup_limit, findings[] },
    "dmarc":{ found, policy, tags, findings[] },
    "dkim": { any_found, selectors[], findings[] },
    "top_recommendations": string[]
  }

Examples:
  - "Is example.com protected against email spoofing?" -> email_auth_audit(domain="example.com")
  - "Audit acme.com, our DKIM selector is 'k1'" -> email_auth_audit(domain="acme.com", dkim_selectors=["k1"])

Errors: returns an error only if the domain is malformed; missing records are reported as findings, not errors.`,
      inputSchema: AuditInput.shape,
      outputSchema: EmailAuditSchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, dkim_selectors, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const audit = await auditEmailAuth(host, cleanSelectors(dkim_selectors));
        return respond(audit, response_format, () =>
          [
            `# Email authentication audit — ${host}`,
            "",
            `**Grade: ${audit.grade} (${audit.score}/100)** · MX: ${audit.has_mx ? audit.mx_hosts.join(", ") : "none"}`,
            "",
            "## SPF",
            renderFindings(audit.spf.findings),
            audit.spf.record ? `\n\`${audit.spf.record}\`` : "",
            "",
            "## DMARC",
            renderFindings(audit.dmarc.findings),
            audit.dmarc.record ? `\n\`${audit.dmarc.record}\`` : "",
            "",
            "## DKIM",
            renderFindings(audit.dkim.findings),
            "",
            "## Top recommendations",
            audit.top_recommendations.length
              ? audit.top_recommendations.map((r, i) => `${i + 1}. ${r}`).join("\n")
              : "None — this domain is well configured. ✅",
          ].join("\n"),
        );
      } catch (err) {
        return fail(`Audit of ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  const DomainInput = z.object({
    domain: z.string().min(1).describe("Domain to check, e.g. 'example.com'."),
    response_format: responseFormatField,
  });

  // -------------------------------------------------------------------------
  // spf_check
  // -------------------------------------------------------------------------
  server.registerTool(
    "spf_check",
    {
      title: "SPF Record Check",
      description: `Fetch and analyse a domain's SPF record. Detects: missing/multiple records, the trailing 'all' qualifier (+all/?all/~all/-all), and counts DNS-querying terms recursively against the RFC 7208 limit of 10.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { found, record, multiple_records, all_qualifier, lookup_count, exceeds_lookup_limit, findings[] }.

Example: "Does sendgrid.net's SPF exceed the 10-lookup limit?" -> spf_check(domain="sendgrid.net").`,
      inputSchema: DomainInput.shape,
      outputSchema: SpfSchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const spf = await checkSpf(host);
        return respond(spf, response_format, () =>
          [
            `# SPF — ${host}`,
            "",
            spf.record ? `\`${spf.record}\`` : "_No SPF record._",
            spf.found ? `\nDNS lookups: ${spf.lookup_count} / 10` : "",
            "",
            renderFindings(spf.findings),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`SPF check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // -------------------------------------------------------------------------
  // dmarc_check
  // -------------------------------------------------------------------------
  server.registerTool(
    "dmarc_check",
    {
      title: "DMARC Record Check",
      description: `Fetch and parse a domain's DMARC record (_dmarc.<domain>). Reports the policy (p=), subdomain policy (sp=), reporting addresses (rua/ruf), pct and alignment (aspf/adkim), and warns on monitor-only or partial deployments.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { found, record, policy, tags{}, findings[] }.

Example: "What is paypal.com's DMARC policy?" -> dmarc_check(domain="paypal.com").`,
      inputSchema: DomainInput.shape,
      outputSchema: DmarcSchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const dmarc = await checkDmarc(host);
        return respond(dmarc, response_format, () =>
          [
            `# DMARC — ${host}`,
            "",
            dmarc.record ? `\`${dmarc.record}\`` : "_No DMARC record._",
            "",
            renderFindings(dmarc.findings),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`DMARC check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // -------------------------------------------------------------------------
  // dkim_check
  // -------------------------------------------------------------------------
  const DkimInput = z.object({
    domain: z.string().min(1).describe("Domain to check, e.g. 'example.com'."),
    selectors: z
      .array(z.string())
      .optional()
      .describe(
        "DKIM selectors to check (e.g. ['google']). If omitted, common provider selectors are probed — absence is then inconclusive.",
      ),
    response_format: responseFormatField,
  });

  server.registerTool(
    "dkim_check",
    {
      title: "DKIM Record Check",
      description: `Look up DKIM public keys at <selector>._domainkey.<domain>. Because DKIM selectors are arbitrary and undiscoverable, you should pass the selector(s) your mail provider uses for a definitive answer; otherwise a curated list of common selectors is probed and a miss is inconclusive.

Args:
  - domain (string): the domain to check.
  - selectors (string[], optional): DKIM selectors to probe.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { any_found, probed_selectors, selectors[{selector, found, record, key_type}], findings[] }.

Examples:
  - "Does acme.com publish a DKIM key for selector 'google'?" -> dkim_check(domain="acme.com", selectors=["google"])
  - "Find any DKIM keys for acme.com" -> dkim_check(domain="acme.com")`,
      inputSchema: DkimInput.shape,
      outputSchema: DkimSchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, selectors, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const dkim = await checkDkim(host, cleanSelectors(selectors));
        return respond(dkim, response_format, () =>
          [
            `# DKIM — ${host}`,
            "",
            ...dkim.selectors
              .filter((s) => s.found)
              .map((s) => `- **${s.selector}** (${s.key_type}): published`),
            "",
            renderFindings(dkim.findings),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`DKIM check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  // -------------------------------------------------------------------------
  // mta_sts_check / tls_rpt_check / bimi_check
  // -------------------------------------------------------------------------
  server.registerTool(
    "mta_sts_check",
    {
      title: "MTA-STS Check",
      description: `Check a domain's MTA-STS deployment: the _mta-sts TXT record AND the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt. Reports the enforcement mode (enforce/testing/none) and the listed MX hosts. MTA-STS forces TLS for inbound SMTP and blocks downgrade attacks.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { dns_record_found, policy_found, mode, policy{}, findings[] }.

Example: "Does gmail.com enforce MTA-STS?" -> mta_sts_check(domain="gmail.com").`,
      inputSchema: DomainInput.shape,
      outputSchema: MtaStsSchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const result = await checkMtaSts(host);
        return respond(result, response_format, () =>
          [
            `# MTA-STS — ${host}`,
            "",
            `- DNS record: ${result.dns_record_found ? "present" : "missing"}`,
            `- Policy file: ${result.policy_found ? `present (mode: ${result.mode ?? "?"})` : "missing"}`,
            "",
            renderFindings(result.findings),
          ].join("\n"),
        );
      } catch (err) {
        return fail(`MTA-STS check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  server.registerTool(
    "tls_rpt_check",
    {
      title: "TLS-RPT Check",
      description: `Check a domain's TLS-RPT record (_smtp._tls.<domain> TXT). TLS-RPT lets you receive reports about TLS delivery failures to your domain.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { found, record, findings[] }.

Example: "Does microsoft.com publish TLS-RPT?" -> tls_rpt_check(domain="microsoft.com").`,
      inputSchema: DomainInput.shape,
      outputSchema: TxtPolicySchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const result = await checkTlsRpt(host);
        return respond(result, response_format, () =>
          [`# TLS-RPT — ${host}`, "", result.record ? `\`${result.record}\`` : "_Not configured._", "", renderFindings(result.findings)].join("\n"),
        );
      } catch (err) {
        return fail(`TLS-RPT check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );

  server.registerTool(
    "bimi_check",
    {
      title: "BIMI Check",
      description: `Check a domain's BIMI record (default._bimi.<domain> TXT), which points to the brand logo (and optional VMC) displayed next to authenticated mail. BIMI requires an enforced DMARC policy to take effect.

Args:
  - domain (string): the domain to check.
  - response_format ('markdown' | 'json'): output format (default 'markdown').

Returns: { found, record, findings[] }.

Example: "Does cnn.com have BIMI set up?" -> bimi_check(domain="cnn.com").`,
      inputSchema: DomainInput.shape,
      outputSchema: TxtPolicySchema.shape,
      annotations: READ_ONLY,
    },
    async ({ domain, response_format }) => {
      const host = validateHost(domain);
      if (!host) return fail(`Error: '${domain}' is not a valid domain name.`);
      try {
        const result = await checkBimi(host);
        return respond(result, response_format, () =>
          [`# BIMI — ${host}`, "", result.record ? `\`${result.record}\`` : "_Not configured._", "", renderFindings(result.findings)].join("\n"),
        );
      } catch (err) {
        return fail(`BIMI check for ${host} failed: ${errMessage(err)}`);
      }
    },
  );
}
