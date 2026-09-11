/**
 * Connect-time SSRF guard.
 *
 * Checking a hostname's resolved addresses *before* connecting is not enough:
 * the check and the connection can resolve differently (DNS rebinding, a name
 * the public resolvers do not know but /etc/hosts or an internal DNS does). So
 * every outbound connection to a user-supplied host goes through
 * `guardedLookup`, which resolves with the same system resolver the socket
 * uses and refuses the connection if *any* returned address is not public.
 * IP literals never reach a lookup, so callers must still screen them with
 * `isPrivateHost` — which `validateUrl` and `assertPublicTarget` do.
 */

import { lookup as systemLookup, type LookupAddress, type LookupOptions } from "node:dns";
import { Agent, fetch as undiciFetch, type Response } from "undici";
import { DEFAULT_TIMEOUT_MS } from "../constants.js";
import { isPrivateHost, isPublicIp } from "./validate.js";

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

export type LookupFunction = (hostname: string, options: LookupOptions, callback: LookupCallback) => void;

export class SsrfError extends Error {
  readonly code = "ESSRF";
}

/** Build a `lookup` for net/tls/undici that only ever hands back public addresses. */
export function createGuardedLookup(resolve: typeof systemLookup = systemLookup): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err, [], undefined);
      const list = addresses as unknown as LookupAddress[];
      const blocked = list.find((a) => !isPublicIp(a.address));
      if (list.length === 0 || blocked) {
        const reason = blocked ? `it resolves to ${blocked.address}` : "it has no address";
        return callback(
          new SsrfError(`Refusing to connect to ${hostname}: ${reason}, which is private or reserved.`),
          [],
          undefined,
        );
      }
      if (options.all) callback(null, list);
      else callback(null, list[0]!.address, list[0]!.family);
    });
  };
}

export const guardedLookup = createGuardedLookup();

/** Throw if a host literal or name is obviously internal (the connect-time guard covers the rest). */
export function assertPublicTarget(host: string): void {
  if (isPrivateHost(host)) {
    throw new SsrfError(`Refusing to connect to ${host}: it is a private or reserved address.`);
  }
}

const dispatcher = new Agent({
  connect: { lookup: guardedLookup, timeout: DEFAULT_TIMEOUT_MS },
  headersTimeout: DEFAULT_TIMEOUT_MS,
  bodyTimeout: DEFAULT_TIMEOUT_MS,
});

export interface SafeFetchOptions {
  /** Maximum redirects to follow; 0 returns the 3xx response itself. */
  maxRedirects: number;
  headers?: Record<string, string>;
  /** Override the guarded dispatcher (tests). */
  dispatcher?: Agent;
}

/**
 * GET `start`, following redirects by hand so every hop is screened, over a
 * dispatcher whose connections pass through `guardedLookup`.
 */
export async function safeFetch(
  start: URL,
  { maxRedirects, headers = {}, dispatcher: via = dispatcher }: SafeFetchOptions,
): Promise<{ res: Response; finalUrl: string }> {
  let current = start;
  for (let hop = 0; ; hop++) {
    assertPublicTarget(current.hostname);
    const res = await undiciFetch(current, {
      method: "GET",
      redirect: "manual",
      headers,
      dispatcher: via,
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    const location = res.headers.get("location");
    if (res.status < 300 || res.status >= 400 || !location || maxRedirects === 0) {
      return { res, finalUrl: current.toString() };
    }
    await res.body?.cancel();
    if (hop >= maxRedirects) throw new Error(`Too many redirects (more than ${maxRedirects}).`);
    const next = new URL(location, current);
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      throw new Error("Refusing to follow a redirect to a non-HTTP(S) URL.");
    }
    current = next;
  }
}

/** Read a response body as UTF-8, refusing to buffer more than `maxBytes`. */
export async function readTextCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return "";
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body.cancel();
    throw new Error(`Response body is ${declared} bytes, over the ${maxBytes}-byte limit.`);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`Response body exceeded the ${maxBytes}-byte limit.`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
