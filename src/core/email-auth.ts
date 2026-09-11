/**
 * Email-authentication and domain-security analysis: SPF, DKIM, DMARC,
 * MTA-STS, TLS-RPT, BIMI and DNSSEC. Everything is read-only and uses public
 * DNS / HTTPS — no API keys.
 */

import {
  COMMON_DKIM_SELECTORS,
  DEFAULT_TIMEOUT_MS,
  SPF_MAX_LOOKUPS,
} from "../constants.js";
import { scoreToGrade } from "../format.js";
import { dohQuery, resolveMx, resolveTxtStrings } from "./dns.js";
import { readTextCapped, safeFetch } from "./netguard.js";

/** RFC 8461 policies are a few lines; anything larger is not a policy. */
const MTA_STS_MAX_BYTES = 64 * 1024;

export interface Finding {
  severity: "error" | "warning" | "info" | "ok";
  message: string;
}

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

export interface SpfResult {
  domain: string;
  found: boolean;
  record?: string;
  multiple_records: boolean;
  all_qualifier?: "+" | "-" | "~" | "?";
  lookup_count: number;
  exceeds_lookup_limit: boolean;
  findings: Finding[];
}

const SPF_LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists", "redirect"];

/** Recursively count SPF DNS-querying terms (RFC 7208 §4.6.4), guarding cycles. */
async function countSpfLookups(
  domain: string,
  visited: Set<string>,
  depth: number,
): Promise<number> {
  if (depth > 10 || visited.has(domain)) return 0;
  visited.add(domain);

  const record = (await resolveTxtStrings(domain)).find((t) =>
    t.toLowerCase().startsWith("v=spf1"),
  );
  if (!record) return 0;

  let count = 0;
  const terms = record.split(/\s+/).slice(1);

  for (const term of terms) {
    const lower = term.toLowerCase();
    const mechanism = lower.replace(/^[+\-~?]/, "").split(/[:=/]/)[0];
    if (!mechanism || !SPF_LOOKUP_MECHANISMS.includes(mechanism)) continue;

    count += 1;
    if (count > SPF_MAX_LOOKUPS + 5) break; // hard stop — already failing

    if (mechanism === "include" || mechanism === "redirect") {
      const target = term.split(/[:=]/)[1];
      if (target) {
        count += await countSpfLookups(target, visited, depth + 1);
      }
    }
  }

  return count;
}

export async function checkSpf(domain: string): Promise<SpfResult> {
  const txt = await resolveTxtStrings(domain);
  const spfRecords = txt.filter((t) => t.toLowerCase().startsWith("v=spf1"));
  const findings: Finding[] = [];

  if (spfRecords.length === 0) {
    findings.push({
      severity: "error",
      message:
        "No SPF record found. Publish a TXT record starting with 'v=spf1' to declare which servers may send mail for this domain.",
    });
    return {
      domain,
      found: false,
      multiple_records: false,
      lookup_count: 0,
      exceeds_lookup_limit: false,
      findings,
    };
  }

  const record = spfRecords[0]!;
  if (spfRecords.length > 1) {
    findings.push({
      severity: "error",
      message:
        "Multiple SPF records published. RFC 7208 permits exactly one; receivers will treat this as a permerror. Merge them into a single record.",
    });
  }

  // Find the `all` mechanism as a standalone term (optionally qualifier-prefixed),
  // not a substring match against the whole record — otherwise an include/a/mx
  // target like `tall.com` or a record with no `all` would be misread.
  const allTerm = record
    .split(/\s+/)
    .slice(1)
    .find((t) => /^[+\-~?]?all$/i.test(t));
  const qualifier = allTerm
    ? /^[+\-~?]/.test(allTerm)
      ? (allTerm.charAt(0) as "+" | "-" | "~" | "?")
      : "+"
    : undefined;

  const hasRedirect = /\bredirect=/i.test(record);
  if (!allTerm && hasRedirect) {
    findings.push({
      severity: "info",
      message:
        "SPF has no 'all' mechanism but uses a 'redirect=' modifier, which supplies the fallback policy from the target domain.",
    });
  } else if (!allTerm) {
    findings.push({
      severity: "warning",
      message:
        "SPF has no 'all' mechanism, so the result for unlisted senders is undefined (neutral). End the record with '-all' (hard fail) or '~all' (soft fail).",
    });
  } else if (qualifier === "+") {
    findings.push({
      severity: "error",
      message:
        "SPF ends in '+all', which authorises every server on the internet to send as your domain. Use '-all' (hard fail) or '~all' (soft fail).",
    });
  } else if (qualifier === "?") {
    findings.push({
      severity: "warning",
      message:
        "SPF ends in '?all' (neutral) — it provides no protection. Move to '~all' or, ideally, '-all'.",
    });
  } else if (qualifier === "~") {
    findings.push({
      severity: "info",
      message:
        "SPF ends in '~all' (soft fail). Acceptable while rolling out; '-all' is the stronger end state.",
    });
  } else {
    findings.push({ severity: "ok", message: "SPF ends in '-all' (hard fail)." });
  }

  const lookupCount = await countSpfLookups(domain, new Set(), 0);
  const exceeds = lookupCount > SPF_MAX_LOOKUPS;
  if (exceeds) {
    findings.push({
      severity: "error",
      message: `SPF triggers ${lookupCount} DNS lookups, over the limit of ${SPF_MAX_LOOKUPS} (RFC 7208). This causes a permerror. Reduce 'include:' chains or flatten the record.`,
    });
  }

  return {
    domain,
    found: true,
    record,
    multiple_records: spfRecords.length > 1,
    all_qualifier: qualifier,
    lookup_count: lookupCount,
    exceeds_lookup_limit: exceeds,
    findings,
  };
}

// ---------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------

export interface DmarcResult {
  domain: string;
  found: boolean;
  record?: string;
  tags: Record<string, string>;
  policy?: string;
  findings: Finding[];
}

export async function checkDmarc(domain: string): Promise<DmarcResult> {
  const txt = await resolveTxtStrings(`_dmarc.${domain}`);
  const record = txt.find((t) => t.toLowerCase().startsWith("v=dmarc1"));
  const findings: Finding[] = [];

  if (!record) {
    findings.push({
      severity: "error",
      message:
        "No DMARC record found at _dmarc." +
        domain +
        ". Publish 'v=DMARC1; p=none; rua=mailto:you@domain' to start monitoring, then tighten to p=quarantine/reject.",
    });
    return { domain, found: false, tags: {}, findings };
  }

  const tags: Record<string, string> = {};
  for (const part of record.split(";")) {
    const [k, v] = part.split("=").map((s) => s.trim());
    if (k && v) tags[k.toLowerCase()] = v;
  }

  const policy = tags["p"];
  if (!policy) {
    findings.push({
      severity: "error",
      message: "DMARC record is missing the required 'p=' policy tag.",
    });
  } else if (policy === "none") {
    findings.push({
      severity: "warning",
      message:
        "DMARC policy is 'p=none' (monitor only). It reports but does not protect. Move to 'quarantine' then 'reject' once your reports look clean.",
    });
  } else {
    findings.push({
      severity: "ok",
      message: `DMARC policy is enforced ('p=${policy}').`,
    });
  }

  if (!tags["rua"]) {
    findings.push({
      severity: "warning",
      message:
        "No aggregate-report address ('rua='). Without it you get no visibility into who is sending as your domain.",
    });
  }

  const pct = tags["pct"];
  if (pct && Number(pct) < 100) {
    findings.push({
      severity: "warning",
      message: `Only ${pct}% of mail is subject to the DMARC policy ('pct=${pct}'). Raise to 100 once you trust the policy.`,
    });
  }

  return { domain, found: true, record, tags, policy, findings };
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

export interface DkimSelectorResult {
  selector: string;
  found: boolean;
  record?: string;
  key_type?: string;
}

export interface DkimResult {
  domain: string;
  any_found: boolean;
  probed_selectors: number;
  selectors: DkimSelectorResult[];
  findings: Finding[];
}

/**
 * Probe DKIM selectors. If `selectors` is empty, a curated list of common
 * provider selectors is tried. Absence is NOT proof DKIM is unconfigured —
 * selectors are arbitrary and undiscoverable.
 */
export async function checkDkim(
  domain: string,
  selectors: string[],
): Promise<DkimResult> {
  const toProbe = selectors.length ? selectors : COMMON_DKIM_SELECTORS;

  const results = await Promise.all(
    toProbe.map(async (selector): Promise<DkimSelectorResult> => {
      const txt = await resolveTxtStrings(`${selector}._domainkey.${domain}`);
      const record = txt.find(
        (t) => /v=dkim1/i.test(t) || /(^|;)\s*k=/i.test(t) || /(^|;)\s*p=/i.test(t),
      );
      if (!record) return { selector, found: false };
      const keyType = /(?:^|;)\s*k=([a-z0-9]+)/i.exec(record)?.[1] ?? "rsa";
      return { selector, found: true, record, key_type: keyType };
    }),
  );

  const found = results.filter((r) => r.found);
  const findings: Finding[] = [];

  if (found.length === 0) {
    findings.push({
      severity: selectors.length ? "error" : "warning",
      message: selectors.length
        ? `None of the supplied selectors published a DKIM key for ${domain}.`
        : `No DKIM key found among ${toProbe.length} common selectors. DKIM may still be configured under a custom selector — pass it explicitly to confirm.`,
    });
  } else {
    findings.push({
      severity: "ok",
      message: `DKIM key(s) found for selector(s): ${found.map((r) => r.selector).join(", ")}.`,
    });
  }

  return {
    domain,
    any_found: found.length > 0,
    probed_selectors: toProbe.length,
    selectors: selectors.length ? results : found, // for the default probe, only report hits
    findings,
  };
}

// ---------------------------------------------------------------------------
// MTA-STS / TLS-RPT / BIMI
// ---------------------------------------------------------------------------

export interface MtaStsResult {
  domain: string;
  dns_record_found: boolean;
  policy_found: boolean;
  mode?: string;
  policy?: Record<string, string | string[]>;
  findings: Finding[];
}

export async function checkMtaSts(domain: string): Promise<MtaStsResult> {
  const findings: Finding[] = [];
  const txt = await resolveTxtStrings(`_mta-sts.${domain}`);
  const dnsRecord = txt.find((t) => /v=STSv1/i.test(t));

  let policyFound = false;
  let mode: string | undefined;
  let policy: Record<string, string | string[]> | undefined;

  try {
    // RFC 8461 §3.3: the policy is fetched over HTTPS without following
    // redirects, and served as text/plain. Anything else means no policy.
    const { res } = await safeFetch(new URL(`https://mta-sts.${domain}/.well-known/mta-sts.txt`), {
      maxRedirects: 0,
      headers: { "user-agent": "domain-security-mcp-server" },
    });
    const type = res.headers.get("content-type") ?? "";
    if (res.status === 200 && /^text\/plain\b/i.test(type)) {
      const body = await readTextCapped(res, MTA_STS_MAX_BYTES);
      const parsed: Record<string, string | string[]> = {};
      const mxs: string[] = [];
      for (const line of body.split(/\r?\n/)) {
        const sep = line.indexOf(":");
        if (sep <= 0) continue;
        const k = line.slice(0, sep).trim().toLowerCase();
        const v = line.slice(sep + 1).trim();
        if (!k || !v) continue;
        if (k === "mx") mxs.push(v);
        else parsed[k] = v;
      }
      if (mxs.length) parsed["mx"] = mxs;
      if (parsed["version"] === "STSv1") {
        policy = parsed;
        mode = typeof parsed["mode"] === "string" ? parsed["mode"] : undefined;
        policyFound = true;
      }
    } else {
      await res.body?.cancel();
    }
  } catch {
    // Policy file unreachable, oversized, or refused by the SSRF guard.
  }

  if (!dnsRecord && !policyFound) {
    findings.push({
      severity: "info",
      message:
        "No MTA-STS found. MTA-STS enforces TLS for inbound mail and prevents downgrade attacks — recommended for domains that receive email.",
    });
  } else if (dnsRecord && !policyFound) {
    findings.push({
      severity: "warning",
      message:
        "An MTA-STS DNS record exists but the policy file at https://mta-sts." +
        domain +
        "/.well-known/mta-sts.txt could not be fetched. The policy is incomplete until both are present.",
    });
  } else if (mode && mode !== "enforce") {
    findings.push({
      severity: "info",
      message: `MTA-STS is in '${mode}' mode. Move to 'enforce' once you have validated it in 'testing'.`,
    });
  } else {
    findings.push({ severity: "ok", message: "MTA-STS is published and enforcing." });
  }

  return {
    domain,
    dns_record_found: Boolean(dnsRecord),
    policy_found: policyFound,
    mode,
    policy,
    findings,
  };
}

export interface TxtPolicyResult {
  domain: string;
  found: boolean;
  record?: string;
  findings: Finding[];
}

export async function checkTlsRpt(domain: string): Promise<TxtPolicyResult> {
  const txt = await resolveTxtStrings(`_smtp._tls.${domain}`);
  const record = txt.find((t) => /v=TLSRPTv1/i.test(t));
  return {
    domain,
    found: Boolean(record),
    record,
    findings: [
      record
        ? { severity: "ok", message: "TLS-RPT is configured (you receive TLS failure reports)." }
        : {
            severity: "info",
            message:
              "No TLS-RPT record. Add '_smtp._tls' TXT with 'v=TLSRPTv1; rua=mailto:…' to receive reports about TLS delivery failures.",
          },
    ],
  };
}

export async function checkBimi(domain: string): Promise<TxtPolicyResult> {
  const txt = await resolveTxtStrings(`default._bimi.${domain}`);
  const record = txt.find((t) => /v=BIMI1/i.test(t));
  return {
    domain,
    found: Boolean(record),
    record,
    findings: [
      record
        ? { severity: "ok", message: "BIMI is published." }
        : {
            severity: "info",
            message:
              "No BIMI record. BIMI displays your logo next to authenticated mail; it requires an enforced DMARC policy first.",
          },
    ],
  };
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

export interface DnssecResult {
  domain: string;
  enabled: boolean;
  validated: boolean;
  ds_records: number;
  dnskey_records: number;
  findings: Finding[];
}

export async function checkDnssec(domain: string): Promise<DnssecResult> {
  const findings: Finding[] = [];
  const [ds, dnskey] = await Promise.all([dohQuery(domain, 43), dohQuery(domain, 48)]);

  const dsCount = (ds.Answer ?? []).filter((a) => a.type === 43).length;
  const dnskeyCount = (dnskey.Answer ?? []).filter((a) => a.type === 48).length;
  const enabled = dsCount > 0 || dnskeyCount > 0;
  const validated = ds.AD === true;

  if (!enabled) {
    findings.push({
      severity: "info",
      message:
        "DNSSEC is not enabled (no DS/DNSKEY records). DNSSEC cryptographically signs DNS answers, preventing spoofing of your records.",
    });
  } else if (!validated) {
    findings.push({
      severity: "warning",
      message:
        "DNSSEC keys are present but the chain of trust did not validate (no AD flag). Check that the DS record at the parent matches your DNSKEY.",
    });
  } else {
    findings.push({ severity: "ok", message: "DNSSEC is enabled and validating." });
  }

  return {
    domain,
    enabled,
    validated,
    ds_records: dsCount,
    dnskey_records: dnskeyCount,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Combined audit
// ---------------------------------------------------------------------------

export interface EmailAuthAudit {
  domain: string;
  grade: string;
  score: number;
  has_mx: boolean;
  mx_hosts: string[];
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: DkimResult;
  top_recommendations: string[];
}

/**
 * Run the headline email-authentication audit: SPF + DMARC + DKIM + MX, scored
 * 0–100 with a letter grade and a prioritised list of fixes.
 */
export async function auditEmailAuth(
  domain: string,
  dkimSelectors: string[],
): Promise<EmailAuthAudit> {
  const [mx, spf, dmarc, dkim] = await Promise.all([
    resolveMx(domain),
    checkSpf(domain),
    checkDmarc(domain),
    checkDkim(domain, dkimSelectors),
  ]);

  let score = 100;
  const recs: string[] = [];

  // SPF (max -40)
  if (!spf.found) {
    score -= 30;
    recs.push("Publish an SPF record ending in '-all'.");
  } else {
    if (spf.all_qualifier === "+") {
      score -= 25;
      recs.push("Replace '+all' in SPF with '-all'.");
    } else if (spf.all_qualifier === "?") {
      score -= 8;
      recs.push("Tighten SPF from '?all' to '~all' or '-all'.");
    }
    if (spf.multiple_records) {
      score -= 15;
      recs.push("Merge the multiple SPF records into one.");
    }
    if (spf.exceeds_lookup_limit) {
      score -= 10;
      recs.push("Reduce SPF DNS lookups below 10 (flatten includes).");
    }
  }

  // DMARC (max -40)
  if (!dmarc.found) {
    score -= 30;
    recs.push("Publish a DMARC record (start with 'p=none; rua=…').");
  } else {
    if (dmarc.policy === "none") {
      score -= 15;
      recs.push("Move DMARC from 'p=none' to 'quarantine' then 'reject'.");
    }
    if (!dmarc.tags["rua"]) {
      score -= 5;
      recs.push("Add a DMARC 'rua=' aggregate-report address.");
    }
  }

  // DKIM (max -20, soft because selectors are undiscoverable)
  if (!dkim.any_found) {
    score -= 15;
    recs.push(
      "Confirm DKIM is configured (no key found on common selectors — verify your provider's selector).",
    );
  }

  // MX context
  if (mx.length === 0) {
    recs.push(
      "No MX records — if this domain never sends mail, also publish SPF '-all' and DMARC 'p=reject' to lock it down against spoofing.",
    );
  }

  score = Math.max(0, Math.min(100, score));

  return {
    domain,
    grade: scoreToGrade(score),
    score,
    has_mx: mx.length > 0,
    mx_hosts: mx.map((m) => m.exchange),
    spf,
    dmarc,
    dkim,
    top_recommendations: recs,
  };
}
