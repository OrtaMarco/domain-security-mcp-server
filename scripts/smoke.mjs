// Smoke test: spawn the built server over stdio, list tools, and run a real audit.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/index.js"],
});
const client = new Client({ name: "smoke-test", version: "1.0.0" });
await client.connect(transport);

const { tools } = await client.listTools();
console.log(`\n✅ ${tools.length} tools registered:`);
console.log("   " + tools.map((t) => t.name).join(", "));

const domain = process.argv[2] ?? "ortamarco.me";
console.log(`\n▶ email_auth_audit(domain="${domain}")\n`);
const res = await client.callTool({
  name: "email_auth_audit",
  arguments: { domain },
});
console.log(res.content[0].text);

console.log("\n▶ dnssec_check(domain=\"cloudflare.com\")\n");
const dnssec = await client.callTool({
  name: "dnssec_check",
  arguments: { domain: "cloudflare.com" },
});
console.log(dnssec.content[0].text);

await client.close();
process.exit(0);
