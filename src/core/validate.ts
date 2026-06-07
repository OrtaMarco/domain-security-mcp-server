/**
 * Input validation and timeout helpers.
 *
 * Ported and extended from the ortamarco.me network-tools backend
 * (src/pages/api/tools/_shared.ts).
 */

import { isIP } from "node:net";
import { Resolver } from "node:dns/promises";
import { DEFAULT_TIMEOUT_MS, PUBLIC_DNS_SERVERS } from "../constants.js";

const HOST_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const DKIM_SELECTOR_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;

/**
 * Validate and normalise a hostname/domain. Strips a leading scheme and a
 * trailing slash, lowercases, and enforces a sane FQDN shape.
 * @returns the cleaned host, or null if invalid.
 */
export function validateHost(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const sanitized = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
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
 * Reject loopback / private / link-local / cloud-metadata hosts to avoid SSRF
 * (a caller asking the server to fetch internal services). Applied to every
 * user-supplied URL.
 */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (isIP(h) !== 0) {
    return (
      /^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(h) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
      h === "::1" ||
      h === "::" ||
      /^(fc|fd|fe80)/.test(h)
    );
  }
  return false;
}

/** Validate an http(s) URL and return its parsed form, or null. Blocks SSRF targets. */
export function validateUrl(input: unknown): URL | null {
  if (typeof input !== "string") return null;
  let raw = input.trim();
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

const ssrfResolver = new Resolver();
ssrfResolver.setServers(PUBLIC_DNS_SERVERS);

/**
 * SSRF guard for the tools that open a raw connection (TLS) or follow redirects
 * (HTTP) to a user-supplied host. `validateHost` only checks a name's *shape*,
 * so a public hostname that resolves to an internal IP (DNS rebinding) would
 * otherwise slip through. Returns true if `host` is — or resolves to — a
 * loopback / private / link-local / metadata address.
 */
export async function resolvesToPrivate(host: string): Promise<boolean> {
  if (isPrivateHost(host)) return true;
  if (isIP(host) !== 0) return false; // a public IP literal: nothing to resolve
  const ips: string[] = [];
  await Promise.all(
    (["resolve4", "resolve6"] as const).map(async (method) => {
      try {
        ips.push(
          ...(await withTimeout(ssrfResolver[method](host), DEFAULT_TIMEOUT_MS, `ssrf:${method}`)),
        );
      } catch {
        /* no record for this address family */
      }
    }),
  );
  return ips.some(isPrivateHost);
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
