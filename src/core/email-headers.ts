/**
 * Email header analysis: parse raw RFC 5322 headers into authentication
 * verdicts, key fields and the Received hop chain with per-hop delays.
 * Pure string processing — no network.
 */

export interface Hop {
  index: number;
  from: string;
  by: string;
  date: string | null;
  delaySec: number | null;
}

export interface ParsedHeaders {
  auth: { spf: string | null; dkim: string | null; dmarc: string | null };
  fields: Record<string, string>;
  hops: Hop[];
  totalSec: number | null;
}

const SUMMARY_FIELDS = ["From", "To", "Subject", "Date", "Message-ID", "Return-Path"];

/** Unfold folded headers (continuation lines start with whitespace). */
function unfold(raw: string): string[] {
  const out: string[] = [];
  for (const line of raw.replace(/\r\n/g, "\n").split("\n")) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += " " + line.trim();
    else out.push(line);
  }
  return out;
}

export function parseEmailHeaders(raw: string): ParsedHeaders {
  const headers: { name: string; value: string }[] = [];
  for (const line of unfold(raw)) {
    const m = /^([!-9;-~]+):[ \t]?(.*)$/.exec(line);
    if (m) headers.push({ name: m[1]!, value: m[2]! });
  }

  const get = (name: string) =>
    headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? "";
  const fields: Record<string, string> = {};
  for (const f of SUMMARY_FIELDS) {
    const v = get(f);
    if (v) fields[f] = v;
  }

  const authRaw = headers
    .filter((h) => h.name.toLowerCase() === "authentication-results")
    .map((h) => h.value)
    .join("; ");
  const verdict = (re: RegExp): string | null => re.exec(authRaw)?.[1]?.toLowerCase() ?? null;
  const auth = {
    spf: verdict(/spf=(\w+)/i),
    dkim: verdict(/dkim=(\w+)/i),
    dmarc: verdict(/dmarc=(\w+)/i),
  };

  const received = headers
    .filter((h) => h.name.toLowerCase() === "received")
    .map((h) => h.value)
    .reverse();
  const times: (number | null)[] = [];
  const hops: Hop[] = received.map((value, i) => {
    const from = /from\s+([^\s;]+)/i.exec(value)?.[1] ?? "?";
    const by = /by\s+([^\s;]+)/i.exec(value)?.[1] ?? "?";
    const dateStr = value.includes(";") ? value.slice(value.lastIndexOf(";") + 1).trim() : "";
    const ms = dateStr ? Date.parse(dateStr) : NaN;
    times.push(Number.isNaN(ms) ? null : ms);
    return { index: i + 1, from, by, date: Number.isNaN(ms) ? null : new Date(ms).toISOString(), delaySec: null };
  });
  for (let i = 1; i < hops.length; i++) {
    const a = times[i - 1];
    const b = times[i];
    if (a != null && b != null) hops[i]!.delaySec = Math.max(0, Math.round((b - a) / 1000));
  }
  const valid = times.filter((t): t is number => t != null);
  const totalSec = valid.length >= 2 ? Math.max(0, Math.round((Math.max(...valid) - Math.min(...valid)) / 1000)) : null;

  return { auth, fields, hops, totalSec };
}
