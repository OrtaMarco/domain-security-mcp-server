/**
 * Deterministic unit tests for the logic the real-network smoke test cannot pin
 * down: input validation and the SSRF guard, offline geolocation, the SPF /
 * DMARC / DKIM analysers and the audit score, email-header parsing, and the
 * response helpers.
 *
 * No test touches the network. The DNS-backed analysers run against a fake
 * resolver installed on the shared `resolver` instance that every lookup in
 * `core/dns.ts` goes through; any name the fake does not know answers NXDOMAIN.
 *
 *   npm test
 */

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { Agent } from "undici";
import { Reader } from "mmdb-lib";

import { createGuardedLookup, safeFetch, readTextCapped } from "../dist/core/netguard.js";

import {
  validateHost,
  validateIp,
  validateSelector,
  isPrivateHost,
  validateUrl,
  withTimeout,
  errMessage,
} from "../dist/core/validate.js";
import { resolver } from "../dist/core/dns.js";
import { checkSpf, checkDmarc, checkDkim, auditEmailAuth } from "../dist/core/email-auth.js";
import { parseEmailHeaders } from "../dist/core/email-headers.js";
import { lookupLocation } from "../dist/core/geoip.js";
import { truncate, respond, fail, scoreToGrade, ResponseFormat } from "../dist/format.js";
import { CHARACTER_LIMIT, COMMON_DKIM_SELECTORS } from "../dist/constants.js";

// ---------------------------------------------------------------------------
// Fake DNS
// ---------------------------------------------------------------------------

let txt = {};
let mx = {};

function dnsError(code, host) {
  return Object.assign(new Error(`${code} ${host}`), { code });
}

resolver.resolveTxt = async (host) => {
  const records = txt[host.toLowerCase()];
  if (!records) throw dnsError("ENOTFOUND", host);
  return records.map((r) => (Array.isArray(r) ? r : [r]));
};
resolver.resolveMx = async (host) => {
  const records = mx[host.toLowerCase()];
  if (!records) throw dnsError("ENODATA", host);
  return records;
};
for (const method of ["resolve", "resolve4", "resolve6", "reverse"]) {
  resolver[method] = async (host) => {
    throw new Error(`unit tests must not reach real DNS (${method} ${host})`);
  };
}

beforeEach(() => {
  txt = {};
  mx = {};
});

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

test("validateHost strips scheme, path and trailing dot, and lowercases", () => {
  assert.equal(validateHost("  HTTPS://Example.COM/path?q=1 "), "example.com");
  assert.equal(validateHost("mail.example.co.uk."), "mail.example.co.uk");
});

test("validateHost rejects what is not a fully qualified domain name", () => {
  for (const bad of ["localhost", "1.2.3.4", "exa_mple.com", "-bad.com", "a..b.com", "", 42, null]) {
    assert.equal(validateHost(bad), null, `accepted ${String(bad)}`);
  }
  assert.equal(validateHost(`${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}.com`), null);
});

test("validateIp accepts IPv4 and IPv6 and nothing else", () => {
  assert.equal(validateIp(" 8.8.8.8 "), "8.8.8.8");
  assert.equal(validateIp("2001:4860:4860::8888"), "2001:4860:4860::8888");
  for (const bad of ["8.8.8", "999.1.1.1", "example.com", "", undefined]) {
    assert.equal(validateIp(bad), null, `accepted ${String(bad)}`);
  }
});

test("validateSelector accepts DKIM labels and rejects injection into the query name", () => {
  assert.equal(validateSelector("Selector1"), "selector1");
  assert.equal(validateSelector("s1.2024"), "s1.2024");
  for (const bad of ["", ".s1", "s1.", "s1 s2", "s1/../x", "a".repeat(65)]) {
    assert.equal(validateSelector(bad), null, `accepted ${bad}`);
  }
});

// ---------------------------------------------------------------------------
// SSRF guard
// ---------------------------------------------------------------------------

test("isPrivateHost blocks loopback, private, link-local and metadata IPv4", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0"]) {
    assert.equal(isPrivateHost(ip), true, `let through ${ip}`);
  }
});

test("isPrivateHost blocks shared, multicast, broadcast and reserved IPv4", () => {
  for (const ip of ["100.64.0.1", "100.127.255.254", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "198.18.0.1"]) {
    assert.equal(isPrivateHost(ip), true, `let through ${ip}`);
  }
});

test("isPrivateHost blocks IPv6 loopback, unique-local, link-local and site-local", () => {
  for (const ip of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1", "[::1]"]) {
    assert.equal(isPrivateHost(ip), true, `let through ${ip}`);
  }
});

test("isPrivateHost sees through IPv4 embedded in IPv6 (mapped and NAT64)", () => {
  for (const ip of ["::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "[::ffff:10.0.0.1]", "64:ff9b::a9fe:a9fe"]) {
    assert.equal(isPrivateHost(ip), true, `let through ${ip}`);
  }
  assert.equal(isPrivateHost("::ffff:8.8.8.8"), false);
});

test("isPrivateHost blocks local names, including a trailing dot", () => {
  for (const host of ["localhost", "LOCALHOST", "localhost.", "app.localhost", "printer.local", "db.internal", "127.0.0.1."]) {
    assert.equal(isPrivateHost(host), true, `let through ${host}`);
  }
});

test("isPrivateHost lets public addresses and names through", () => {
  for (const host of ["8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "github.com", "localhost.example.com"]) {
    assert.equal(isPrivateHost(host), false, `blocked ${host}`);
  }
});

test("validateUrl adds https, keeps http(s) only and refuses internal targets in any spelling", () => {
  assert.equal(validateUrl("example.com/x")?.href, "https://example.com/x");
  assert.equal(validateUrl("http://example.com")?.protocol, "http:");
  for (const bad of [
    "ftp://example.com",
    "file:///etc/passwd",
    "javascript://example.com/%0aalert(1)",
    "http://127.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://127.1/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
    "http://localhost./",
    "not a url at all",
  ]) {
    assert.equal(validateUrl(bad), null, `accepted ${bad}`);
  }
});

// ---------------------------------------------------------------------------
// Connect-time guard
// ---------------------------------------------------------------------------

/** A resolver stand-in: answers every name with the given addresses. */
function fakeResolve(addresses) {
  return (_host, _opts, cb) => cb(null, addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
}

function lookupOnce(lookup, host, options = {}) {
  return new Promise((resolve) => lookup(host, options, (err, address, family) => resolve({ err, address, family })));
}

test("guardedLookup refuses a name that resolves to any private address", async () => {
  const lookup = createGuardedLookup(fakeResolve(["93.184.216.34", "10.0.0.5"]));
  const { err } = await lookupOnce(lookup, "rebind.example");
  assert.equal(err?.code, "ESSRF");
  assert.match(err.message, /10\.0\.0\.5/);
});

test("guardedLookup hands back public addresses in the shape the caller asked for", async () => {
  const lookup = createGuardedLookup(fakeResolve(["93.184.216.34", "2606:2800:220:1::1"]));
  const single = await lookupOnce(lookup, "example.com");
  assert.deepEqual([single.err, single.address, single.family], [null, "93.184.216.34", 4]);
  const all = await lookupOnce(lookup, "example.com", { all: true });
  assert.equal(all.address.length, 2);
});

test("guardedLookup passes resolver errors through and refuses an empty answer", async () => {
  const failing = createGuardedLookup((_h, _o, cb) => cb(Object.assign(new Error("nx"), { code: "ENOTFOUND" })));
  assert.equal((await lookupOnce(failing, "nx.example")).err.code, "ENOTFOUND");
  const empty = createGuardedLookup(fakeResolve([]));
  assert.equal((await lookupOnce(empty, "empty.example")).err.code, "ESSRF");
});

/** A loopback HTTP server whose routes the test controls. */
async function localServer(routes) {
  const server = http.createServer((req, res) => (routes[req.url] ?? ((_q, r) => r.writeHead(404).end()))(req, res));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) };
}

test("safeFetch refuses to connect when a public-looking name resolves to loopback", async () => {
  const srv = await localServer({ "/": (_q, r) => r.end("internal") });
  const toLoopback = fakeResolve(["127.0.0.1"]);
  const guarded = new Agent({ connect: { lookup: createGuardedLookup(toLoopback) } });
  const open = new Agent({ connect: { lookup: toLoopback } });
  try {
    // Control: the same request over an unguarded dispatcher does reach the server.
    const control = await safeFetch(new URL(`http://app.example.test:${srv.port}/`), { maxRedirects: 0, dispatcher: open });
    assert.equal(await control.res.text(), "internal");
    await assert.rejects(
      safeFetch(new URL(`http://app.example.test:${srv.port}/`), { maxRedirects: 0, dispatcher: guarded }),
      (err) => (err.cause ?? err).code === "ESSRF",
    );
  } finally {
    await Promise.all([guarded.close(), open.close(), srv.close()]);
  }
});

test("safeFetch screens every redirect hop and never follows when maxRedirects is 0", async () => {
  const srv = await localServer({
    "/to-loopback": (_q, r) => r.writeHead(302, { location: "http://127.0.0.1/latest/meta-data/" }).end(),
    "/to-ftp": (_q, r) => r.writeHead(302, { location: "ftp://example.com/" }).end(),
  });
  const open = new Agent({ connect: { lookup: fakeResolve(["127.0.0.1"]) } });
  const base = `http://app.example.test:${srv.port}`;
  try {
    const held = await safeFetch(new URL(`${base}/to-loopback`), { maxRedirects: 0, dispatcher: open });
    assert.equal(held.res.status, 302);
    await held.res.body?.cancel();
    await assert.rejects(safeFetch(new URL(`${base}/to-loopback`), { maxRedirects: 3, dispatcher: open }), /private or reserved/);
    await assert.rejects(safeFetch(new URL(`${base}/to-ftp`), { maxRedirects: 3, dispatcher: open }), /non-HTTP/);
  } finally {
    await Promise.all([open.close(), srv.close()]);
  }
});

test("readTextCapped stops a body that is too large, declared or streamed", async () => {
  const srv = await localServer({
    "/declared": (_q, r) => r.writeHead(200, { "content-length": "100000" }).end("x".repeat(100000)),
    "/streamed": (_q, r) => {
      r.writeHead(200, { "transfer-encoding": "chunked" });
      for (let i = 0; i < 20; i++) r.write("y".repeat(10000));
      r.end();
    },
    "/small": (_q, r) => r.end("version: STSv1\nmode: enforce\n"),
  });
  const open = new Agent({ connect: { lookup: fakeResolve(["127.0.0.1"]) } });
  const get = (path) => safeFetch(new URL(`http://app.example.test:${srv.port}${path}`), { maxRedirects: 0, dispatcher: open });
  try {
    await assert.rejects((async () => readTextCapped((await get("/declared")).res, 64000))(), /over the 64000-byte limit/);
    await assert.rejects((async () => readTextCapped((await get("/streamed")).res, 64000))(), /exceeded the 64000-byte limit/);
    assert.match(await readTextCapped((await get("/small")).res, 64000), /mode: enforce/);
  } finally {
    await Promise.all([open.close(), srv.close()]);
  }
});

// ---------------------------------------------------------------------------
// HTTP transport defaults
// ---------------------------------------------------------------------------

async function freePort() {
  const probe = http.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function startHttpServer(env) {
  const port = await freePort();
  const base = { ...process.env };
  for (const key of ["HOST", "ALLOWED_HOSTS", "ALLOWED_ORIGINS", "MCP_AUTH_TOKEN"]) delete base[key];
  const child = spawn(process.execPath, [fileURLToPath(new URL("../dist/index.js", import.meta.url))], {
    env: { ...base, TRANSPORT: "http", PORT: String(port), ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let log = "";
  child.stderr.on("data", (c) => (log += c));
  for (let i = 0; i < 100 && !/running on http/.test(log); i++) await new Promise((r) => setTimeout(r, 50));
  return { port, log: () => log, stop: () => new Promise((r) => (child.once("exit", r), child.kill("SIGTERM"))) };
}

function post(port, headers = {}, body = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18", ...headers } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, type: res.headers["content-type"] ?? "", body: data }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("HTTP transport binds to loopback and rejects a foreign Host header by default", async () => {
  const srv = await startHttpServer({});
  try {
    assert.match(srv.log(), /http:\/\/127\.0\.0\.1:/);
    assert.equal((await post(srv.port)).status, 200);
    assert.equal((await post(srv.port, { host: "attacker.example" })).status, 403);
    assert.equal((await post(srv.port, { origin: "http://attacker.example" })).status, 403);
  } finally {
    await srv.stop();
  }
});

test("HTTP transport enforces MCP_AUTH_TOKEN and answers parse errors in JSON-RPC", async () => {
  const srv = await startHttpServer({ HOST: "127.0.0.1", MCP_AUTH_TOKEN: "s3cret-token" });
  try {
    assert.equal((await post(srv.port)).status, 401);
    assert.equal((await post(srv.port, { authorization: "Bearer wrong-token!" })).status, 401);
    assert.equal((await post(srv.port, { authorization: "Bearer s3cret-token" })).status, 200);
    const broken = await post(srv.port, { authorization: "Bearer s3cret-token" }, "{not json");
    assert.equal(broken.status, 400);
    assert.match(broken.type, /json/);
    assert.equal(JSON.parse(broken.body).error.code, -32700);
  } finally {
    await srv.stop();
  }
});

test("HTTP transport on a public bind warns when it has no Host allowlist or token", async () => {
  const srv = await startHttpServer({ HOST: "0.0.0.0" });
  try {
    assert.match(srv.log(), /without ALLOWED_HOSTS/);
    assert.match(srv.log(), /without MCP_AUTH_TOKEN/);
  } finally {
    await srv.stop();
  }
});

// ---------------------------------------------------------------------------
// Timeouts and errors
// ---------------------------------------------------------------------------

test("withTimeout rejects a promise that never settles, with the label in the message", async () => {
  await assert.rejects(withTimeout(new Promise(() => {}), 20, "slow-thing"), /Timeout after 20ms: slow-thing/);
});

test("withTimeout passes through a value or an error that arrives in time", async () => {
  assert.equal(await withTimeout(Promise.resolve(7), 1000, "fast"), 7);
  await assert.rejects(withTimeout(Promise.reject(new Error("boom")), 1000, "fast"), /boom/);
});

test("errMessage reads Error instances and stringifies anything else", () => {
  assert.equal(errMessage(new Error("x")), "x");
  assert.equal(errMessage("plain"), "plain");
  assert.equal(errMessage(404), "404");
});

// ---------------------------------------------------------------------------
// Offline geolocation (DB-IP Lite, no network)
// ---------------------------------------------------------------------------

/** The raw record straight from one of the two MMDB files, bypassing geoip.ts. */
async function rawDbipRecord(file, ip) {
  const path = createRequire(import.meta.url).resolve(`@ip-location-db/dbip-city-mmdb/${file}`);
  return new Reader(await readFile(path)).get(ip);
}

test("lookupLocation reads the IPv4 file and estimates the time zone from the coordinates", async () => {
  const loc = await lookupLocation("8.8.8.8");
  assert.equal(loc.country_iso, "US");
  assert.equal(loc.country_name, "United States");
  assert.equal(typeof loc.latitude, "number");
  assert.equal(typeof loc.longitude, "number");
  // Four decimals at most: the file's float32 noise does not leak into the output.
  assert.equal(loc.latitude, Math.round(loc.latitude * 1e4) / 1e4);
  assert.match(loc.time_zone ?? "", /^America\//);
});

test("lookupLocation asks the IPv6 file about IPv6, never the IPv4 one", async () => {
  // The IPv4 file answers an IPv6 query with the record of its first 32 bits.
  const ip = "2001:4860:4860::8888";
  const expected = await rawDbipRecord("dbip-city-ipv6.mmdb", ip);
  assert.ok(expected, "the IPv6 file should know Google's public resolver");
  const loc = await lookupLocation(ip);
  assert.equal(loc.country_iso, expected.country_code);
  assert.equal(loc.city, expected.city || undefined);
  assert.equal(loc.region, expected.state1 || undefined);
});

test("lookupLocation reads IPv4-mapped IPv6, dotted or hex, from the IPv4 file", async () => {
  const plain = await lookupLocation("8.8.8.8");
  assert.deepEqual(await lookupLocation("::ffff:8.8.8.8"), plain);
  assert.deepEqual(await lookupLocation("::FFFF:808:808"), plain);
  assert.deepEqual(await lookupLocation("0:0:0:0:0:ffff:8.8.8.8"), plain);
});

test("lookupLocation answers {} for private, unrouted and invalid addresses", async () => {
  for (const ip of ["192.168.1.1", "10.0.0.1", "::1", "not-an-ip", ""]) {
    assert.deepEqual(await lookupLocation(ip), {}, ip);
  }
});

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

const severities = (findings) => findings.map((f) => f.severity);

test("SPF ending in -all is ok, and ip4 terms cost no lookups", async () => {
  txt["example.com"] = ["v=spf1 ip4:192.0.2.0/24 -all"];
  const spf = await checkSpf("example.com");
  assert.equal(spf.found, true);
  assert.equal(spf.all_qualifier, "-");
  assert.equal(spf.lookup_count, 0);
  assert.deepEqual(severities(spf.findings), ["ok"]);
});

test("SPF qualifiers map to the right severity", async () => {
  const cases = { "+all": ["+", "error"], all: ["+", "error"], "?all": ["?", "warning"], "~all": ["~", "info"], "-ALL": ["-", "ok"] };
  for (const [term, [qualifier, severity]] of Object.entries(cases)) {
    txt["example.com"] = [`v=spf1 mx ${term}`];
    const spf = await checkSpf("example.com");
    assert.equal(spf.all_qualifier, qualifier, term);
    assert.equal(spf.findings[0].severity, severity, term);
  }
});

test("SPF does not read an include target like tall.com as the all mechanism", async () => {
  txt["example.com"] = ["v=spf1 include:tall.com"];
  txt["tall.com"] = ["v=spf1 ip4:192.0.2.1 -all"];
  const spf = await checkSpf("example.com");
  assert.equal(spf.all_qualifier, undefined);
  assert.equal(spf.findings[0].severity, "warning");
});

test("SPF without all but with redirect= is informational, not a warning", async () => {
  txt["example.com"] = ["v=spf1 redirect=_spf.example.net"];
  txt["_spf.example.net"] = ["v=spf1 ip4:192.0.2.1 -all"];
  const spf = await checkSpf("example.com");
  assert.equal(spf.findings[0].severity, "info");
  assert.equal(spf.lookup_count, 1);
});

test("two SPF records are a permerror, and non-SPF TXT records are ignored", async () => {
  txt["example.com"] = ["google-site-verification=abc", "v=spf1 -all", "v=spf1 mx -all"];
  const spf = await checkSpf("example.com");
  assert.equal(spf.multiple_records, true);
  assert.equal(spf.record, "v=spf1 -all");
  assert.ok(spf.findings.some((f) => f.severity === "error" && /Multiple SPF/.test(f.message)));
});

test("SPF counts nested includes and flags more than 10 lookups", async () => {
  const includes = Array.from({ length: 4 }, (_, i) => `include:i${i}.example.net`).join(" ");
  txt["example.com"] = [`v=spf1 ${includes} -all`];
  for (let i = 0; i < 4; i++) txt[`i${i}.example.net`] = ["v=spf1 a mx -all"]; // 1 + 2 each
  const spf = await checkSpf("example.com");
  assert.equal(spf.lookup_count, 12);
  assert.equal(spf.exceeds_lookup_limit, true);
  assert.ok(spf.findings.some((f) => /over the limit of 10/.test(f.message)));
});

test("SPF stops counting once a record is already far over the limit", async () => {
  const includes = Array.from({ length: 30 }, (_, i) => `include:i${i}.example.net`).join(" ");
  txt["example.com"] = [`v=spf1 ${includes} -all`];
  for (let i = 0; i < 30; i++) txt[`i${i}.example.net`] = ["v=spf1 a mx -all"];
  const spf = await checkSpf("example.com");
  assert.ok(spf.lookup_count > 10 && spf.lookup_count <= 16, `counted ${spf.lookup_count}`);
  assert.equal(spf.exceeds_lookup_limit, true);
});

test("SPF lookups at exactly 10 are within the limit", async () => {
  txt["example.com"] = [`v=spf1 ${Array.from({ length: 10 }, (_, i) => `a:h${i}.example.net`).join(" ")} -all`];
  const spf = await checkSpf("example.com");
  assert.equal(spf.lookup_count, 10);
  assert.equal(spf.exceeds_lookup_limit, false);
});

test("an SPF include cycle terminates", async () => {
  txt["a.example"] = ["v=spf1 include:b.example -all"];
  txt["b.example"] = ["v=spf1 include:a.example -all"];
  const spf = await checkSpf("a.example");
  assert.equal(spf.lookup_count, 2);
});

test("a domain with no SPF record is an error, not a crash", async () => {
  const spf = await checkSpf("nothing.example");
  assert.equal(spf.found, false);
  assert.deepEqual(severities(spf.findings), ["error"]);
});

// ---------------------------------------------------------------------------
// DMARC and DKIM
// ---------------------------------------------------------------------------

test("DMARC p=reject with rua is clean, and tag names are case-insensitive", async () => {
  txt["_dmarc.example.com"] = ["v=DMARC1; P=reject; RUA=mailto:d@example.com"];
  const dmarc = await checkDmarc("example.com");
  assert.equal(dmarc.policy, "reject");
  assert.equal(dmarc.tags.rua, "mailto:d@example.com");
  assert.deepEqual(severities(dmarc.findings), ["ok"]);
});

test("DMARC p=none, missing rua and pct under 100 each raise a warning", async () => {
  txt["_dmarc.example.com"] = ["v=DMARC1; p=none; pct=50"];
  const dmarc = await checkDmarc("example.com");
  assert.deepEqual(severities(dmarc.findings), ["warning", "warning", "warning"]);
});

test("DMARC without a p= tag is an error, and no record at all is an error", async () => {
  txt["_dmarc.example.com"] = ["v=DMARC1; rua=mailto:d@example.com"];
  assert.equal((await checkDmarc("example.com")).findings[0].severity, "error");
  const missing = await checkDmarc("nodmarc.example");
  assert.equal(missing.found, false);
  assert.deepEqual(severities(missing.findings), ["error"]);
});

test("DKIM with explicit selectors reports every selector and joins split TXT strings", async () => {
  txt["s1._domainkey.example.com"] = [["v=DKIM1; k=ed25519; ", "p=MCowBQYDK2VwAyEA"]];
  const dkim = await checkDkim("example.com", ["s1", "s2"]);
  assert.equal(dkim.any_found, true);
  assert.deepEqual(dkim.selectors.map((s) => [s.selector, s.found]), [["s1", true], ["s2", false]]);
  assert.equal(dkim.selectors[0].key_type, "ed25519");
});

test("DKIM default probe reports only hits, and a miss is a warning not an error", async () => {
  const miss = await checkDkim("example.com", []);
  assert.equal(miss.probed_selectors, COMMON_DKIM_SELECTORS.length);
  assert.equal(miss.findings[0].severity, "warning");
  txt["google._domainkey.example.com"] = ["v=DKIM1; p=MIIBIjAN"];
  const hit = await checkDkim("example.com", []);
  assert.deepEqual(hit.selectors.map((s) => s.selector), ["google"]);
  assert.equal(hit.selectors[0].key_type, "rsa");
});

test("DKIM with supplied selectors that all miss is an error", async () => {
  const dkim = await checkDkim("example.com", ["custom"]);
  assert.equal(dkim.findings[0].severity, "error");
});

// ---------------------------------------------------------------------------
// Audit score
// ---------------------------------------------------------------------------

test("a fully configured domain scores 100 / A with no recommendations", async () => {
  mx["example.com"] = [{ exchange: "mx2.example.com", priority: 20 }, { exchange: "mx1.example.com", priority: 10 }];
  txt["example.com"] = ["v=spf1 mx -all"];
  txt["_dmarc.example.com"] = ["v=DMARC1; p=reject; rua=mailto:d@example.com"];
  txt["s1._domainkey.example.com"] = ["v=DKIM1; p=MIIB"];
  const audit = await auditEmailAuth("example.com", ["s1"]);
  assert.equal(audit.score, 100);
  assert.equal(audit.grade, "A");
  assert.deepEqual(audit.mx_hosts, ["mx1.example.com", "mx2.example.com"]);
  assert.deepEqual(audit.top_recommendations, []);
});

test("a domain with nothing published scores 25 / F and gets the lock-down advice", async () => {
  const audit = await auditEmailAuth("bare.example", []);
  assert.equal(audit.score, 25);
  assert.equal(audit.grade, "F");
  assert.equal(audit.has_mx, false);
  assert.ok(audit.top_recommendations.some((r) => /never sends mail/.test(r)));
});

test("the audit subtracts each SPF and DMARC weakness once", async () => {
  mx["example.com"] = [{ exchange: "mx.example.com", priority: 10 }];
  txt["example.com"] = ["v=spf1 +all", "v=spf1 -all"];
  txt["_dmarc.example.com"] = ["v=DMARC1; p=none"];
  txt["s1._domainkey.example.com"] = ["v=DKIM1; p=MIIB"];
  const audit = await auditEmailAuth("example.com", ["s1"]);
  // +all −25, multiple records −15, p=none −15, no rua −5
  assert.equal(audit.score, 40);
  assert.equal(audit.top_recommendations.length, 4);
});

// ---------------------------------------------------------------------------
// Email headers
// ---------------------------------------------------------------------------

test("parseEmailHeaders unfolds headers and reads the auth verdicts", () => {
  const parsed = parseEmailHeaders(
    [
      "Authentication-Results: mx.example.net;",
      "\tspf=pass smtp.mailfrom=example.com;",
      "\tdkim=FAIL header.d=example.com",
      "Authentication-Results: other; dmarc=quarantine",
      "Subject: Folded",
      " subject line",
      "From: A <a@example.com>",
    ].join("\r\n"),
  );
  assert.deepEqual(parsed.auth, { spf: "pass", dkim: "fail", dmarc: "quarantine" });
  assert.equal(parsed.fields.Subject, "Folded subject line");
  assert.equal(parsed.fields.From, "A <a@example.com>");
});

test("parseEmailHeaders orders Received hops oldest first and measures the delays", () => {
  const parsed = parseEmailHeaders(
    [
      "Received: from relay.example.net by mx.example.org; Wed, 04 Jun 2026 10:00:30 +0000",
      "Received: from mail.example.com by relay.example.net; Wed, 04 Jun 2026 10:00:05 +0000",
      "Received: from laptop by mail.example.com; Wed, 04 Jun 2026 10:00:00 +0000",
    ].join("\n"),
  );
  assert.deepEqual(parsed.hops.map((h) => [h.index, h.from, h.by, h.delaySec]), [
    [1, "laptop", "mail.example.com", null],
    [2, "mail.example.com", "relay.example.net", 5],
    [3, "relay.example.net", "mx.example.org", 25],
  ]);
  assert.equal(parsed.totalSec, 30);
});

test("parseEmailHeaders survives garbage and unparseable dates", () => {
  const parsed = parseEmailHeaders("not a header\nReceived: from x by y; not a date\n\n");
  assert.deepEqual(parsed.auth, { spf: null, dkim: null, dmarc: null });
  assert.equal(parsed.hops[0].date, null);
  assert.equal(parsed.totalSec, null);
});

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

test("truncate leaves short text alone and caps long text with a pointer to json", () => {
  assert.equal(truncate("short"), "short");
  const long = truncate("x".repeat(CHARACTER_LIMIT + 10));
  assert.ok(long.startsWith("x".repeat(CHARACTER_LIMIT)));
  assert.match(long, /truncated 10 characters/);
});

test("respond attaches structuredContent in both formats and renders markdown or JSON", () => {
  const data = { a: 1 };
  const md = respond(data, ResponseFormat.MARKDOWN, () => "# A");
  assert.equal(md.content[0].text, "# A");
  assert.deepEqual(md.structuredContent, data);
  const json = respond(data, ResponseFormat.JSON, () => "unused");
  assert.deepEqual(JSON.parse(json.content[0].text), data);
  assert.equal(fail("nope").isError, true);
});

test("scoreToGrade boundaries", () => {
  assert.deepEqual([100, 90, 89, 80, 79, 70, 69, 60, 59, 0].map(scoreToGrade), ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]);
});
