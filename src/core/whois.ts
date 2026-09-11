/**
 * WHOIS lookups over the raw port-43 protocol (RFC 3912). No API key.
 *
 * Resolution strategy:
 *   1. Ask whois.iana.org which WHOIS server is authoritative for the TLD.
 *   2. Query that registry server for the domain.
 *   3. If the registry response refers to a registrar WHOIS server (thin model,
 *      e.g. .com/.net), follow that one hop for the richer record.
 */

import net from "node:net";
import { DEFAULT_TIMEOUT_MS } from "../constants.js";
import { assertPublicTarget, guardedLookup } from "./netguard.js";
import { validateHost, withTimeout } from "./validate.js";

const IANA_WHOIS = "whois.iana.org";

export interface WhoisInfo {
  domain: string;
  whois_server?: string;
  registrar?: string;
  created?: string;
  updated?: string;
  expires?: string;
  name_servers: string[];
  status: string[];
  registrant_org?: string;
  raw: string;
}

/** Cap on the raw record returned to the caller (the socket read is capped separately). */
const MAX_RAW_CHARS = 20_000;

/**
 * Send a single WHOIS query to `server:43` and return the raw text response.
 * The server name comes from IANA or from a registry's referral text, so it is
 * treated as untrusted: it must look like a hostname, and the connection goes
 * through the SSRF-guarded lookup under an overall deadline (the socket's own
 * timeout only measures inactivity, which a slow drip keeps resetting).
 */
function whoisQuery(query: string, server: string): Promise<string> {
  const host = validateHost(server);
  if (!host) return Promise.reject(new Error(`'${server}' is not a valid WHOIS server name.`));
  try {
    assertPublicTarget(host);
  } catch (err) {
    return Promise.reject(err);
  }
  return withTimeout(rawWhoisQuery(query, host), DEFAULT_TIMEOUT_MS * 2, `whois ${host}`);
}

function rawWhoisQuery(query: string, server: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: server, port: 43, lookup: guardedLookup }, () => {
      socket.write(`${query}\r\n`);
    });
    let data = "";
    socket.setTimeout(DEFAULT_TIMEOUT_MS);
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      data += chunk;
      if (data.length > 512_000) {
        socket.destroy();
        reject(new Error(`WHOIS response from ${server} exceeded the size limit.`));
      }
    });
    socket.on("end", () => resolve(data));
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`WHOIS query to ${server} timed out.`));
    });
    socket.on("error", reject);
  });
}

function firstMatch(text: string, re: RegExp): string | undefined {
  return re.exec(text)?.[1]?.trim() || undefined;
}

function allMatches(text: string, re: RegExp): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(re)) {
    const v = m[1]?.trim();
    if (v) out.add(v);
  }
  return [...out];
}

/** Find the WHOIS server a referral response points to. */
function referralServer(text: string): string | undefined {
  return (
    firstMatch(text, /^\s*(?:refer|whois):\s*(\S+)/im) ??
    firstMatch(text, /^\s*Registrar WHOIS Server:\s*(\S+)/im)
  );
}

/**
 * Whether a WHOIS response actually contains a registration record, rather than
 * a "no match" / "object does not exist" reply (some registrar WHOIS servers
 * answer with boilerplate for domains they don't hold). Used to decide whether
 * a registrar referral is worth preferring over the registry response.
 */
function looksLikeRecord(text: string): boolean {
  return (
    /domain name:/i.test(text) &&
    !/(no match|not found|no entries found|object does not exist|no data found|status:\s*free)/i.test(text)
  );
}

/** Look up WHOIS data for a domain, following registry → registrar referrals. */
export async function lookupWhois(domain: string): Promise<WhoisInfo> {
  const tld = domain.slice(domain.lastIndexOf(".") + 1);

  // 1. Discover the TLD's authoritative WHOIS server via IANA.
  let server = IANA_WHOIS;
  try {
    const ianaText = await whoisQuery(tld, IANA_WHOIS);
    server = firstMatch(ianaText, /^\s*whois:\s*(\S+)/im) ?? IANA_WHOIS;
  } catch {
    // Fall back to querying IANA directly for the domain.
  }

  // 2. Query the registry.
  let raw = await whoisQuery(domain, server);
  let usedServer = server;

  // 3. Follow a single registrar referral if present (thin-registry TLDs).
  const registrar = referralServer(raw);
  if (registrar && registrar !== server && /\./.test(registrar)) {
    try {
      const registrarRaw = await whoisQuery(domain, registrar);
      if (registrarRaw && looksLikeRecord(registrarRaw)) {
        raw = registrarRaw;
        usedServer = registrar;
      }
    } catch {
      // Keep the registry response if the registrar server is unreachable.
    }
  }

  return {
    domain,
    whois_server: usedServer,
    registrar: firstMatch(raw, /Registrar:\s*(.+)/i),
    created: firstMatch(
      raw,
      /(?:Creation Date|Created On|created|Registered on):\s*(.+)/i,
    ),
    updated: firstMatch(raw, /(?:Updated Date|Last Modified|changed):\s*(.+)/i),
    expires: firstMatch(
      raw,
      /(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till|Expires On):\s*(.+)/i,
    ),
    name_servers: allMatches(raw, /(?:Name Server|nserver):\s*(\S+)/gi).map((s) =>
      s.toLowerCase(),
    ),
    status: allMatches(raw, /(?:Domain Status|status):\s*(\S+)/gi),
    registrant_org: firstMatch(raw, /Registrant Organization:\s*(.+)/i),
    raw:
      raw.trim().length > MAX_RAW_CHARS
        ? `${raw.trim().slice(0, MAX_RAW_CHARS)}\n…[raw record truncated at ${MAX_RAW_CHARS} characters]`
        : raw.trim(),
  };
}
