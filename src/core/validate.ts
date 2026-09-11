/**
 * Input validation and timeout helpers.
 *
 * Ported and extended from the ortamarco.me network-tools backend
 * (src/pages/api/tools/_shared.ts).
 */

import { BlockList, isIP } from "node:net";
import { domainToASCII } from "node:url";

const HOST_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

const DKIM_SELECTOR_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;

/**
 * Validate and normalise a hostname/domain. Strips a leading scheme and a
 * trailing slash or dot, lowercases, converts an internationalised name to its
 * ASCII (punycode) form, and enforces a sane FQDN shape.
 * @returns the cleaned host, or null if invalid.
 */
export function validateHost(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const stripped = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
  const sanitized = /^[\x00-\x7f]*$/.test(stripped) ? stripped : domainToASCII(stripped);
  if (!HOST_RE.test(sanitized)) return null;
  return sanitized;
}

/** Validate an IPv4 or IPv6 address. @returns the address, or null if invalid. */
export function validateIp(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const sanitized = input.trim();
  if (isIP(sanitized) === 0) return null;
  return sanitized;
}

/** Validate a DKIM selector (the label to the left of `._domainkey`). */
export function validateSelector(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const sanitized = input.trim().toLowerCase();
  if (!DKIM_SELECTOR_RE.test(sanitized)) return null;
  return sanitized;
}

/**
 * Every address range that is not globally routable unicast: loopback, private,
 * shared (CGNAT), link-local (cloud metadata lives at 169.254.169.254),
 * documentation, benchmarking, multicast, reserved and broadcast — plus the IPv6
 * ranges that carry an IPv4 address inside (NAT64, 6to4, Teredo). IPv4-mapped
 * IPv6 (`::ffff:127.0.0.1`, `::ffff:7f00:1`) is checked against the IPv4 rules
 * by BlockList itself.
 */
const NON_PUBLIC = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::", 128], ["::1", 128], ["::", 96], ["64:ff9b::", 96], ["64:ff9b:1::", 48],
  ["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
  ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, "ipv6");
}

/** True if `ip` is a globally routable unicast address (and false for anything else, including non-IPs). */
export function isPublicIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 0) return false;
  return !NON_PUBLIC.check(ip, family === 4 ? "ipv4" : "ipv6");
}

/**
 * Reject loopback / private / link-local / cloud-metadata hosts to avoid SSRF
 * (a caller asking the server to reach internal services). This judges what a
 * name or literal *says*; the address a name actually resolves to is checked at
 * connect time by `guardedLookup` in `netguard.ts`.
 */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (h === "" || h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".home.arpa")) return true;
  if (isIP(h) !== 0) return !isPublicIp(h);
  return false;
}

/** Validate an http(s) URL and return its parsed form, or null. Blocks SSRF targets. */
export function validateUrl(input: unknown): URL | null {
  if (typeof input !== "string") return null;
  let raw = input.trim();
  // Only a bare host gets `https://` prepended; an explicit other scheme is refused
  // rather than turned into a URL whose host is the scheme name.
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw)) {
    if (!/^[^:/]+:\d+(?:[/?#]|$)/.test(raw)) return null;
  }
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (isPrivateHost(url.hostname)) return null;
    return url;
  } catch {
    return null;
  }
}

/** Reject a promise if it does not settle within `ms` milliseconds. */
export function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const id = setTimeout(
      () => reject(new Error(`Timeout after ${ms}ms: ${label}`)),
      ms,
    );
    promise.then(
      (value) => {
        clearTimeout(id);
        resolve(value);
      },
      (err) => {
        clearTimeout(id);
        reject(err);
      },
    );
  });
}

/** Normalise an unknown thrown value into a readable message. */
export function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
