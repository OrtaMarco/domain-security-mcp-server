/**
 * Smoke test: start the built server over stdio, call EVERY registered tool
 * through the real MCP protocol, and validate each answer's
 * `structuredContent` against that tool's own Zod output schema.
 *
 * It runs the whole battery **twice**, once per protocol era, because this
 * server is built on the v2 SDK and serves both from one factory:
 *
 *   1. `versionNegotiation: { mode: 'auto' }` → the 2026-07-28 revision
 *      (`getProtocolEra() === 'modern'`).
 *   2. no options at all → the 2025 `initialize` handshake (`'legacy'`),
 *      which is what Claude Desktop, Claude Code and Cursor speak today.
 *
 * A regression that only shows up on one era (a schema the modern codec
 * rejects, a tool that leans on session state) fails here rather than in
 * somebody's client.
 *
 *   npm run smoke
 *
 * Unlike a pure-computation server, almost every call here leaves the machine:
 * DNS, WHOIS, TLS and HTTPS against deliberately boring, long-lived domains
 * (google.com, cloudflare.com, github.com). Expect the run to take a couple of
 * minutes, and read a failure as "the network or that domain moved" before
 * suspecting the server. `analyze_email_headers` is the only offline call.
 */

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  BlacklistSchema,
  CaaSchema,
  CertificateSchema,
  DkimSchema,
  DmarcSchema,
  DnsLookupSchema,
  DnssecSchema,
  EmailAuditSchema,
  HeadersAnalysisSchema,
  IpInfoSchema,
  MtaStsSchema,
  MxSchema,
  PropagationSchema,
  ReverseDnsSchema,
  SecurityHeadersSchema,
  SpfSchema,
  TxtPolicySchema,
  WhoisSchema,
} from "../dist/schemas.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const RAW_HEADERS = [
  "Received: from a.com (a.com [1.2.3.4]) by b.com; Wed, 04 Jun 2026 10:00:00 +0000",
  "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
  "From: T <t@a.com>",
  "Subject: Hi",
].join("\n");

/**
 * One entry per call: the tool, its arguments, the schema its
 * `structuredContent` must satisfy, and a one-line signal to print.
 */
const CALLS = [
  {
    tool: "email_auth_audit",
    args: { domain: "github.com" },
    schema: EmailAuditSchema,
    signal: (s) => `grade=${s.grade} score=${s.score} mx=${s.has_mx}`,
  },
  {
    tool: "spf_check",
    args: { domain: "github.com" },
    schema: SpfSchema,
    signal: (s) => `found=${s.found} all=${s.all_qualifier ?? "-"} lookups=${s.lookup_count}`,
  },
  {
    tool: "dmarc_check",
    args: { domain: "google.com" },
    schema: DmarcSchema,
    signal: (s) => `found=${s.found} policy=${s.policy ?? "-"}`,
    expect: (s) => (s.found ? null : "google.com must publish a DMARC record"),
  },
  {
    tool: "dkim_check",
    args: { domain: "google.com", selectors: ["20230601"] },
    schema: DkimSchema,
    signal: (s) => `any_found=${s.any_found} probed=${s.probed_selectors}`,
  },
  {
    tool: "mta_sts_check",
    args: { domain: "gmail.com" },
    schema: MtaStsSchema,
    signal: (s) => `dns=${s.dns_record_found} policy=${s.policy_found} mode=${s.mode ?? "-"}`,
  },
  {
    tool: "tls_rpt_check",
    args: { domain: "google.com" },
    schema: TxtPolicySchema,
    signal: (s) => `found=${s.found}`,
  },
  {
    tool: "bimi_check",
    args: { domain: "cnn.com" },
    schema: TxtPolicySchema,
    signal: (s) => `found=${s.found}`,
  },
  {
    tool: "dns_lookup",
    args: { domain: "github.com" },
    schema: DnsLookupSchema,
    signal: (s) => `${Object.keys(s.records).join(", ")}`,
  },
  {
    tool: "reverse_dns",
    args: { ip: "8.8.8.8" },
    schema: ReverseDnsSchema,
    signal: (s) => s.hostnames.join(", ") || "(none)",
  },
  {
    tool: "ip_geolocation",
    args: { ip: "8.8.8.8" },
    schema: IpInfoSchema,
    signal: (s) => `${s.country_iso ?? "?"} ${s.city ?? ""}`.trim(),
  },
  {
    tool: "ssl_certificate",
    args: { domain: "cloudflare.com" },
    schema: CertificateSchema,
    signal: (s) => `${s.issuer_organization ?? "?"} expires in ${s.days_until_expiry ?? "?"}d`,
    expect: (s) => (s.expired ? "cloudflare.com should not be serving an expired certificate" : null),
  },
  {
    tool: "whois_lookup",
    args: { domain: "github.com" },
    schema: WhoisSchema,
    signal: (s) => `${s.registrar ?? "?"} (${s.name_servers.length} NS)`,
  },
  {
    tool: "http_security_headers",
    args: { url: "https://github.com" },
    schema: SecurityHeadersSchema,
    signal: (s) => `${s.status} grade=${s.grade} score=${s.score}`,
  },
  {
    tool: "dnssec_check",
    args: { domain: "cloudflare.com" },
    schema: DnssecSchema,
    signal: (s) => `enabled=${s.enabled} validated=${s.validated} ds=${s.ds_records}`,
    expect: (s) => (s.enabled ? null : "cloudflare.com must be DNSSEC-signed"),
  },
  {
    tool: "caa_check",
    args: { domain: "google.com" },
    schema: CaaSchema,
    signal: (s) => `found=${s.found} issue=[${s.issue.join(", ")}]`,
  },
  {
    tool: "mx_lookup",
    args: { domain: "github.com" },
    schema: MxSchema,
    signal: (s) => `${s.records.length} MX`,
    expect: (s) => (s.records.length > 0 ? null : "github.com must have MX records"),
  },
  {
    tool: "blacklist_check",
    args: { query: "8.8.8.8" },
    schema: BlacklistSchema,
    signal: (s) => `${s.listedCount} listed of ${s.checked} checked`,
  },
  {
    tool: "dns_propagation",
    args: { domain: "cloudflare.com", type: "A" },
    schema: PropagationSchema,
    signal: (s) => `consistent=${s.consistent} across ${s.resolvers.length} resolvers`,
  },
  {
    tool: "analyze_email_headers",
    args: { headers: RAW_HEADERS },
    schema: HeadersAnalysisSchema,
    signal: (s) => `spf=${s.auth.spf} dkim=${s.auth.dkim} dmarc=${s.auth.dmarc} hops=${s.hops.length}`,
    expect: (s) => (s.auth.spf === "pass" && s.hops.length === 1 ? null : "expected one hop with spf=pass"),
  },
];

async function connect(options) {
  const client = new Client({ name: "domain-security-smoke", version: "1.1.0" }, options);
  await client.connect(
    new StdioClientTransport({ command: "node", args: [join(ROOT, "dist", "index.js")], stderr: "ignore" }),
  );
  return client;
}

async function runEra(name, options) {
  console.log(`\n── ${name} era ${"─".repeat(Math.max(0, 44 - name.length))}`);
  const client = await connect(options);
  const era = client.getProtocolEra() ?? "(unreported)";
  console.log(`  negotiated era: ${era}`);

  const { tools } = await client.listTools();
  const registered = new Set(tools.map((t) => t.name));
  const planned = new Set(CALLS.map((c) => c.tool));
  console.log(`  registered tools: ${tools.length}`);

  let failed = 0;
  for (const name of registered) {
    if (!planned.has(name)) {
      console.log(`  ⚠️  ${name} is registered but not covered by this smoke test`);
      failed++;
    }
  }
  for (const name of planned) {
    if (!registered.has(name)) {
      console.log(`  ⚠️  ${name} is in the smoke test but NOT registered`);
      failed++;
    }
  }

  // Every tool must declare an outputSchema and be flagged read-only.
  for (const tool of tools) {
    if (!tool.outputSchema) {
      console.log(`  ❌ ${tool.name} declares no outputSchema`);
      failed++;
    }
    if (tool.annotations?.readOnlyHint !== true) {
      console.log(`  ❌ ${tool.name} is not annotated readOnlyHint: true`);
      failed++;
    }
  }

  let passed = 0;
  for (const call of CALLS) {
    const label = call.label ?? call.tool;
    const began = Date.now();
    try {
      const result = await client.callTool({ name: call.tool, arguments: call.args });
      const ms = Date.now() - began;

      if (result.isError) {
        console.log(`  ❌ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  error: ${(result.content?.[0]?.text ?? "").slice(0, 120)}`);
        failed++;
        continue;
      }
      if (!result.structuredContent) {
        console.log(`  ❌ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  no structuredContent returned`);
        failed++;
        continue;
      }

      const parsed = call.schema.safeParse(result.structuredContent);
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        console.log(
          `  ❌ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  schema mismatch at ${issue.path.join(".") || "(root)"}: ${issue.message}`,
        );
        failed++;
        continue;
      }

      const complaint = call.expect?.(parsed.data);
      if (complaint) {
        console.log(`  ❌ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  ${complaint}`);
        failed++;
        continue;
      }

      console.log(`  ✅ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  ${call.signal(parsed.data)}`);
      passed++;
    } catch (err) {
      const ms = Date.now() - began;
      console.log(`  ❌ ${label.padEnd(22)} ${String(ms).padStart(5)}ms  threw: ${String(err.message).slice(0, 160)}`);
      failed++;
    }
  }

  await client.close();
  console.log(`  ${passed} passed, ${failed} failed (of ${CALLS.length} calls)`);
  return { passed, failed, era };
}

const modern = await runEra("modern (2026-07-28)", { versionNegotiation: { mode: "auto" } });
const legacy = await runEra("legacy (2025 initialize)", undefined);

let failures = modern.failed + legacy.failed;
if (modern.era !== "modern") {
  console.log(`\n❌ auto negotiation landed on '${modern.era}', expected 'modern'`);
  failures++;
}
if (legacy.era !== "legacy") {
  console.log(`\n❌ the default client landed on '${legacy.era}', expected 'legacy'`);
  failures++;
}

console.log(
  `\n${modern.passed + legacy.passed} passed, ${failures} failed across both eras (${CALLS.length} calls each).`,
);
process.exit(failures > 0 ? 1 : 0);
