/**
 * HTTP security-header analysis. Fetches a URL and grades the presence and
 * quality of the headers that browsers use to harden a site.
 */

import { DEFAULT_TIMEOUT_MS } from "../constants.js";
import { scoreToGrade } from "../format.js";
import { safeFetch } from "./netguard.js";

interface HeaderCheck {
  header: string;
  present: boolean;
  value?: string;
  weight: number;
  note: string;
}

export interface SecurityHeadersReport {
  url: string;
  final_url: string;
  status: number;
  grade: string;
  score: number;
  checks: HeaderCheck[];
  missing: string[];
}

interface HeaderSpec {
  header: string;
  weight: number;
  note: string;
  evaluate?: (value: string) => string | undefined;
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    header: "strict-transport-security",
    weight: 25,
    note: "Forces HTTPS (HSTS). Use a long max-age and includeSubDomains.",
    evaluate: (v) =>
      /max-age=(\d+)/i.exec(v)?.[1] && Number(/max-age=(\d+)/i.exec(v)?.[1]) < 15552000
        ? "max-age is below the recommended 180 days."
        : undefined,
  },
  {
    header: "content-security-policy",
    weight: 25,
    note: "Mitigates XSS and data injection by allowlisting content sources.",
  },
  {
    header: "x-content-type-options",
    weight: 15,
    note: "Should be 'nosniff' to stop MIME-type sniffing.",
    evaluate: (v) =>
      /nosniff/i.test(v) ? undefined : "Expected the value 'nosniff'.",
  },
  {
    header: "x-frame-options",
    weight: 10,
    note: "Prevents clickjacking (DENY or SAMEORIGIN). CSP frame-ancestors is the modern equivalent.",
  },
  {
    header: "referrer-policy",
    weight: 10,
    note: "Controls how much referrer information is leaked to other origins.",
  },
  {
    header: "permissions-policy",
    weight: 10,
    note: "Restricts access to powerful browser features (camera, geolocation, …).",
  },
  {
    header: "cross-origin-opener-policy",
    weight: 5,
    note: "Isolates the browsing context (helps mitigate cross-origin attacks).",
  },
];

const USER_AGENT = "domain-security-mcp-server (+https://github.com/OrtaMarco/domain-security-mcp-server)";
const MAX_REDIRECTS = 5;

/** Fetch a URL and evaluate its security headers. */
export async function analyzeSecurityHeaders(
  url: URL,
): Promise<SecurityHeadersReport> {
  // Every hop is screened and every connection is guarded (see netguard.ts).
  const { res, finalUrl } = await safeFetch(url, {
    maxRedirects: MAX_REDIRECTS,
    headers: { "user-agent": USER_AGENT },
  });
  await res.body?.cancel(); // only the headers matter

  const checks: HeaderCheck[] = HEADER_SPECS.map((spec) => {
    const value = res.headers.get(spec.header) ?? undefined;
    const present = value !== undefined;
    const qualityNote = present && spec.evaluate ? spec.evaluate(value!) : undefined;
    return {
      header: spec.header,
      present,
      value,
      weight: spec.weight,
      note: qualityNote ?? spec.note,
    };
  });

  const totalWeight = HEADER_SPECS.reduce((sum, s) => sum + s.weight, 0);
  const earned = checks.reduce((sum, c) => sum + (c.present ? c.weight : 0), 0);
  const score = Math.round((earned / totalWeight) * 100);

  return {
    url: url.toString(),
    final_url: finalUrl,
    status: res.status,
    grade: scoreToGrade(score),
    score,
    checks,
    missing: checks.filter((c) => !c.present).map((c) => c.header),
  };
}
