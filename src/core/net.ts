/**
 * Network analysis core: CAA records, DNSBL blacklist checks, multi-resolver
 * DNS propagation and MX lookups. No API keys — DNS only.
 */

import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { DEFAULT_TIMEOUT_MS } from "../constants.js";
import { resolver } from "./dns.js";
import { errMessage, withTimeout } from "./validate.js";

// --- CAA -------------------------------------------------------------------

export interface CaaResult {
  domain: string;
  found: boolean;
  issue: string[];
  issuewild: string[];
  iodef: string[];
}

export async function analyzeCaa(domain: string): Promise<CaaResult> {
  let records: Awaited<ReturnType<typeof resolver.resolveCaa>> = [];
  try {
    records = await withTimeout(resolver.resolveCaa(domain), DEFAULT_TIMEOUT_MS, "caa");
  } catch {
    records = [];
  }
  const issue: string[] = [];
  const issuewild: string[] = [];
  const iodef: string[] = [];
  for (const r of records) {
    if (r.issue) issue.push(r.issue);
    if (r.issuewild) issuewild.push(r.issuewild);
    if (r.iodef) iodef.push(r.iodef);
  }
  return { domain, found: records.length > 0, issue, issuewild, iodef };
}

// --- DNSBL blacklist -------------------------------------------------------

// Open-access DNSBLs only. Spamhaus/Barracuda refuse public-resolver queries.
// SORBS is gone (its 127.0.0.2 test point answers NXDOMAIN), so it is not queried.
export const DNSBL_ZONES: { zone: string; name: string }[] = [
  { zone: "bl.spamcop.net", name: "SpamCop" },
  { zone: "dnsbl-1.uceprotect.net", name: "UCEPROTECT-1" },
  { zone: "dnsbl.dronebl.org", name: "DroneBL" },
  { zone: "all.s5h.net", name: "s5h.net" },
];

export interface BlacklistHit {
  list: string;
  zone: string;
  listed: boolean;
  reason: string | null;
  /** Set when the list could not be queried — then `listed: false` means "unknown", not "clean". */
  error: string | null;
}

export interface BlacklistResult {
  query: string;
  ips: string[];
  listedCount: number;
  checked: number;
  results: { ip: string; hits: BlacklistHit[] }[];
  note: string;
}

async function checkIpAgainstZones(ip: string): Promise<BlacklistHit[]> {
  if (isIP(ip) !== 4) return [];
  const reversed = ip.split(".").reverse().join(".");
  return Promise.all(
    DNSBL_ZONES.map(async ({ zone, name }): Promise<BlacklistHit> => {
      const host = `${reversed}.${zone}`;
      try {
        await withTimeout(resolver.resolve4(host), DEFAULT_TIMEOUT_MS, `dnsbl:${zone}`);
        let reason: string | null = null;
        try {
          const txt = await withTimeout(resolver.resolveTxt(host), 4000, `dnsbl-txt:${zone}`);
          reason = txt.map((p) => p.join("")).join(" ") || null;
        } catch {
          /* no TXT */
        }
        return { list: name, zone, listed: true, reason, error: null };
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        // NXDOMAIN / NODATA is the DNSBL's way of saying "not listed"; anything
        // else (timeout, SERVFAIL, refused) means the list did not answer.
        if (code === "ENOTFOUND" || code === "ENODATA") {
          return { list: name, zone, listed: false, reason: null, error: null };
        }
        return { list: name, zone, listed: false, reason: null, error: errMessage(err) };
      }
    }),
  );
}

export async function analyzeBlacklist(query: string): Promise<BlacklistResult> {
  let ips: string[] = [];
  if (isIP(query) === 4) {
    ips = [query];
  } else {
    try {
      ips = (await withTimeout(resolver.resolve4(query), DEFAULT_TIMEOUT_MS, "a")).slice(0, 2);
    } catch {
      ips = [];
    }
  }
  const results = await Promise.all(
    ips.map(async (ip) => ({ ip, hits: await checkIpAgainstZones(ip) })),
  );
  const listedCount = results.reduce((sum, r) => sum + r.hits.filter((h) => h.listed).length, 0);
  return {
    query,
    ips,
    listedCount,
    checked: DNSBL_ZONES.length,
    results,
    note: "Open-access lists only. Spamhaus and Barracuda block public-resolver queries and are excluded; verify those with registered access.",
  };
}

// --- MX --------------------------------------------------------------------

export interface MxRecord {
  exchange: string;
  priority: number;
  ips: string[];
}

export async function mxLookup(domain: string): Promise<MxRecord[]> {
  let mx: { exchange: string; priority: number }[] = [];
  try {
    mx = await withTimeout(resolver.resolveMx(domain), DEFAULT_TIMEOUT_MS, "mx");
  } catch {
    return [];
  }
  mx.sort((a, b) => a.priority - b.priority);
  return Promise.all(
    mx.map(async (r) => {
      let ips: string[] = [];
      try {
        ips = await withTimeout(resolver.resolve4(r.exchange), DEFAULT_TIMEOUT_MS, "mx-a");
      } catch {
        /* no A */
      }
      return { exchange: r.exchange, priority: r.priority, ips };
    }),
  );
}

// --- DNS propagation -------------------------------------------------------

const PROPAGATION_RESOLVERS: { name: string; server: string }[] = [
  { name: "Cloudflare", server: "1.1.1.1" },
  { name: "Google", server: "8.8.8.8" },
  { name: "Quad9", server: "9.9.9.9" },
  { name: "OpenDNS", server: "208.67.222.222" },
  { name: "AdGuard", server: "94.140.14.14" },
];

export type PropagationType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT";

export interface PropagationResolverResult {
  name: string;
  server: string;
  values: string[];
  error: string | null;
}

export interface PropagationResult {
  domain: string;
  type: PropagationType;
  consistent: boolean;
  resolvers: PropagationResolverResult[];
}

function recordToStrings(type: PropagationType, records: unknown): string[] {
  switch (type) {
    case "MX":
      return (records as { exchange: string; priority: number }[])
        .map((r) => `${r.priority} ${r.exchange}`)
        .sort();
    case "TXT":
      return (records as string[][]).map((parts) => parts.join("")).sort();
    default:
      return (records as string[]).map(String).sort();
  }
}

export async function analyzeDnsPropagation(
  domain: string,
  type: PropagationType,
): Promise<PropagationResult> {
  const resolvers = await Promise.all(
    PROPAGATION_RESOLVERS.map(async ({ name, server }): Promise<PropagationResolverResult> => {
      const r = new Resolver();
      r.setServers([server]);
      try {
        const records = await withTimeout(r.resolve(domain, type), DEFAULT_TIMEOUT_MS, `prop:${server}`);
        return { name, server, values: recordToStrings(type, records as unknown), error: null };
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        return { name, server, values: [], error: code ?? (err instanceof Error ? err.message : "error") };
      }
    }),
  );
  const ok = resolvers.filter((r) => !r.error);
  const fingerprints = new Set(ok.map((r) => r.values.join("|")));
  // Consistent only when at least one resolver answered and they all agree —
  // an all-errors result (NXDOMAIN/timeout) must NOT report "consistent".
  return { domain, type, consistent: ok.length > 0 && fingerprints.size === 1, resolvers };
}
