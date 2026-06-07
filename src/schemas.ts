/**
 * Zod output schemas for every tool. Each tool's `outputSchema` is the `.shape`
 * of the matching schema here, and `respond()` attaches the data object as
 * `structuredContent` (validated by the SDK against that schema).
 *
 * Kept in sync with the interfaces in `core/*`.
 */

import { z } from "zod";

const Finding = z.object({ severity: z.string(), message: z.string() });
const NormalizedRecord = z.object({
  type: z.string(),
  host: z.string(),
  value: z.string(),
  priority: z.number().optional(),
  extra: z.record(z.number()).optional(),
});
const DkimSelector = z.object({
  selector: z.string(),
  found: z.boolean(),
  record: z.string().optional(),
  key_type: z.string().optional(),
});
const HeaderCheck = z.object({
  header: z.string(),
  present: z.boolean(),
  value: z.string().optional(),
  weight: z.number(),
  note: z.string(),
});
const MxRecord = z.object({
  exchange: z.string(),
  priority: z.number(),
  ips: z.array(z.string()),
});
const BlacklistHit = z.object({
  list: z.string(),
  zone: z.string(),
  listed: z.boolean(),
  reason: z.string().nullable(),
});
const PropResolver = z.object({
  name: z.string(),
  server: z.string(),
  values: z.array(z.string()),
  error: z.string().nullable(),
});
const Hop = z.object({
  index: z.number(),
  from: z.string(),
  by: z.string(),
  date: z.string().nullable(),
  delaySec: z.number().nullable(),
});

// --- email/auth ------------------------------------------------------------

export const SpfSchema = z.object({
  domain: z.string(),
  found: z.boolean(),
  record: z.string().optional(),
  multiple_records: z.boolean(),
  all_qualifier: z.string().optional(),
  lookup_count: z.number(),
  exceeds_lookup_limit: z.boolean(),
  findings: z.array(Finding),
});

export const DmarcSchema = z.object({
  domain: z.string(),
  found: z.boolean(),
  record: z.string().optional(),
  tags: z.record(z.string()),
  policy: z.string().optional(),
  findings: z.array(Finding),
});

export const DkimSchema = z.object({
  domain: z.string(),
  any_found: z.boolean(),
  probed_selectors: z.number(),
  selectors: z.array(DkimSelector),
  findings: z.array(Finding),
});

export const MtaStsSchema = z.object({
  domain: z.string(),
  dns_record_found: z.boolean(),
  policy_found: z.boolean(),
  mode: z.string().optional(),
  policy: z.record(z.union([z.string(), z.array(z.string())])).optional(),
  findings: z.array(Finding),
});

export const TxtPolicySchema = z.object({
  domain: z.string(),
  found: z.boolean(),
  record: z.string().optional(),
  findings: z.array(Finding),
});

export const DnssecSchema = z.object({
  domain: z.string(),
  enabled: z.boolean(),
  validated: z.boolean(),
  ds_records: z.number(),
  dnskey_records: z.number(),
  findings: z.array(Finding),
});

export const EmailAuditSchema = z.object({
  domain: z.string(),
  grade: z.string(),
  score: z.number(),
  has_mx: z.boolean(),
  mx_hosts: z.array(z.string()),
  spf: SpfSchema,
  dmarc: DmarcSchema,
  dkim: DkimSchema,
  top_recommendations: z.array(z.string()),
});

// --- network ---------------------------------------------------------------

export const DnsLookupSchema = z.object({
  domain: z.string(),
  records: z.record(z.array(NormalizedRecord)),
});

export const ReverseDnsSchema = z.object({
  ip: z.string(),
  hostnames: z.array(z.string()),
});

export const IpInfoSchema = z.object({
  ip: z.string(),
  country_iso: z.string().optional(),
  country_name: z.string().optional(),
  region: z.string().optional(),
  city: z.string().optional(),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
  time_zone: z.string().optional(),
  hostname: z.string().optional(),
});

export const CertificateSchema = z.object({
  host: z.string(),
  port: z.number(),
  subject_common_name: z.string().optional(),
  subject_alt_names: z.array(z.string()),
  issuer_organization: z.string().optional(),
  issuer_common_name: z.string().optional(),
  valid_from: z.string().optional(),
  valid_to: z.string().optional(),
  days_until_expiry: z.number().optional(),
  expired: z.boolean(),
  expires_soon: z.boolean(),
  serial_number: z.string().optional(),
  fingerprint_sha256: z.string().optional(),
});

export const WhoisSchema = z.object({
  domain: z.string(),
  whois_server: z.string().optional(),
  registrar: z.string().optional(),
  created: z.string().optional(),
  updated: z.string().optional(),
  expires: z.string().optional(),
  name_servers: z.array(z.string()),
  status: z.array(z.string()),
  registrant_org: z.string().optional(),
  raw: z.string(),
});

// --- web -------------------------------------------------------------------

export const SecurityHeadersSchema = z.object({
  url: z.string(),
  final_url: z.string(),
  status: z.number(),
  grade: z.string(),
  score: z.number(),
  checks: z.array(HeaderCheck),
  missing: z.array(z.string()),
});

// --- extra -----------------------------------------------------------------

export const CaaSchema = z.object({
  domain: z.string(),
  found: z.boolean(),
  issue: z.array(z.string()),
  issuewild: z.array(z.string()),
  iodef: z.array(z.string()),
});

export const MxSchema = z.object({
  domain: z.string(),
  records: z.array(MxRecord),
});

export const BlacklistSchema = z.object({
  query: z.string(),
  ips: z.array(z.string()),
  listedCount: z.number(),
  checked: z.number(),
  results: z.array(z.object({ ip: z.string(), hits: z.array(BlacklistHit) })),
  note: z.string(),
});

export const PropagationSchema = z.object({
  domain: z.string(),
  type: z.string(),
  consistent: z.boolean(),
  resolvers: z.array(PropResolver),
});

export const HeadersAnalysisSchema = z.object({
  auth: z.object({
    spf: z.string().nullable(),
    dkim: z.string().nullable(),
    dmarc: z.string().nullable(),
  }),
  fields: z.record(z.string()),
  hops: z.array(Hop),
  totalSec: z.number().nullable(),
});
