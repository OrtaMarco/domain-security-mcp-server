import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "node", args: ["dist/index.js"] });
const client = new Client({ name: "smoke-all", version: "1.0.0" });
await client.connect(transport);

const headers = "Received: from a.com (a.com [1.2.3.4]) by b.com; Wed, 04 Jun 2026 10:00:00 +0000\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nFrom: T <t@a.com>\nSubject: Hi";
const calls = [
  ["email_auth_audit", { domain: "github.com" }],
  ["spf_check", { domain: "github.com" }],
  ["dmarc_check", { domain: "google.com" }],
  ["dkim_check", { domain: "google.com", selectors: ["20230601"] }],
  ["mta_sts_check", { domain: "gmail.com" }],
  ["tls_rpt_check", { domain: "google.com" }],
  ["bimi_check", { domain: "cnn.com" }],
  ["dns_lookup", { domain: "github.com" }],
  ["reverse_dns", { ip: "8.8.8.8" }],
  ["ip_geolocation", { ip: "8.8.8.8" }],
  ["ssl_certificate", { domain: "github.com" }],
  ["whois_lookup", { domain: "github.com" }],
  ["http_security_headers", { url: "https://github.com" }],
  ["dnssec_check", { domain: "cloudflare.com" }],
  ["caa_check", { domain: "google.com" }],
  ["mx_lookup", { domain: "github.com" }],
  ["blacklist_check", { query: "8.8.8.8" }],
  ["dns_propagation", { domain: "cloudflare.com", type: "A" }],
  ["analyze_email_headers", { headers }],
];

let pass = 0, fail = 0;
for (const [name, args] of calls) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const hasSC = r.structuredContent !== undefined && r.structuredContent !== null;
    if (r.isError) { console.log(`✗ ${name}: isError`); fail++; }
    else if (!hasSC) { console.log(`✗ ${name}: NO structuredContent`); fail++; }
    else { console.log(`✓ ${name}: structuredContent ok (${Object.keys(r.structuredContent).length} keys)`); pass++; }
  } catch (e) {
    console.log(`✗ ${name}: THREW ${String(e.message).slice(0,120)}`); fail++;
  }
}
console.log(`\n${pass}/${calls.length} passed, ${fail} failed`);
await client.close();
process.exit(fail ? 1 : 0);
