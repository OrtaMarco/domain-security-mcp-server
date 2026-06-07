/**
 * DNS resolution core.
 *
 * Uses a Resolver pinned to public servers (so behaviour is identical in any
 * environment) for the record types Node supports natively, plus a small
 * DNS-over-HTTPS client for the types it does not (DS, DNSKEY) and for reading
 * the DNSSEC `AD` flag.
 */

import { Resolver } from "node:dns/promises";
import { DEFAULT_TIMEOUT_MS, DOH_ENDPOINT, PUBLIC_DNS_SERVERS } from "../constants.js";
import { withTimeout } from "./validate.js";

export const resolver = new Resolver();
resolver.setServers(PUBLIC_DNS_SERVERS);

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "SOA";

export interface NormalizedRecord {
  type: DnsRecordType;
  host: string;
  value: string;
  priority?: number;
  extra?: Record<string, number>;
}

/** Resolve a single record type, returning [] on NODATA/NXDOMAIN rather than throwing. */
async function safeResolve<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await withTimeout(fn(), DEFAULT_TIMEOUT_MS, "dns");
  } catch {
    return null;
  }
}

/** TXT records, with each record's character-strings concatenated into one string. */
export async function resolveTxtStrings(host: string): Promise<string[]> {
  const records = await safeResolve(() => resolver.resolveTxt(host));
  if (!records) return [];
  return records.map((parts) => parts.join(""));
}

/** MX records sorted by ascending priority. */
export async function resolveMx(
  host: string,
): Promise<{ exchange: string; priority: number }[]> {
  const records = await safeResolve(() => resolver.resolveMx(host));
  if (!records) return [];
  return [...records].sort((a, b) => a.priority - b.priority);
}

/** A records (IPv4). */
export async function resolveA(host: string): Promise<string[]> {
  return (await safeResolve(() => resolver.resolve4(host))) ?? [];
}

/** Reverse DNS (PTR) for an IP address. Throws on failure so callers can distinguish. */
export async function reverseDns(ip: string): Promise<string[]> {
  return withTimeout(resolver.reverse(ip), DEFAULT_TIMEOUT_MS, "reverse");
}

/** Resolve every common record type for a domain in parallel. */
export async function resolveAllRecords(
  host: string,
): Promise<Record<string, NormalizedRecord[]>> {
  const types: DnsRecordType[] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"];
  const out: Record<string, NormalizedRecord[]> = {};

  await Promise.all(
    types.map(async (type) => {
      const records = await safeResolve(() => resolver.resolve(host, type));
      if (!records) return;
      const normalized = normalizeRecords(type, host, records as unknown);
      if (normalized.length) out[type] = normalized;
    }),
  );

  return out;
}

function normalizeRecords(
  type: DnsRecordType,
  host: string,
  records: unknown,
): NormalizedRecord[] {
  switch (type) {
    case "A":
    case "AAAA":
    case "NS":
    case "CNAME":
      return (records as string[]).map((value) => ({ type, host, value }));
    case "MX":
      return (records as { exchange: string; priority: number }[]).map((r) => ({
        type,
        host,
        value: r.exchange,
        priority: r.priority,
      }));
    case "TXT":
      return (records as string[][]).map((parts) => ({
        type,
        host,
        value: parts.join(""),
      }));
    case "SOA": {
      const r = records as {
        nsname: string;
        hostmaster: string;
        serial: number;
        refresh: number;
        retry: number;
        expire: number;
        minttl: number;
      };
      return [
        {
          type,
          host,
          value: `${r.nsname} ${r.hostmaster}`,
          extra: {
            serial: r.serial,
            refresh: r.refresh,
            retry: r.retry,
            expire: r.expire,
            minimum_ttl: r.minttl,
          },
        },
      ];
    }
  }
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS (for DS / DNSKEY / AD flag)
// ---------------------------------------------------------------------------

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number;
  /** Authenticated Data — true when the resolver DNSSEC-validated the answer. */
  AD: boolean;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

/**
 * Query Cloudflare DNS-over-HTTPS (JSON). `type` may be a name ("A", "DS") or a
 * numeric RR type (43 = DS, 48 = DNSKEY). Requests DNSSEC data (`do=true`).
 */
export async function dohQuery(
  name: string,
  type: string | number,
): Promise<DohResponse> {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}&do=true`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`DoH query failed with status ${res.status}`);
  return (await res.json()) as DohResponse;
}
