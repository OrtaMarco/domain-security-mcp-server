/**
 * TLS / SSL certificate inspection.
 *
 * Ported from the ortamarco.me ssl-lookup endpoint, extended with
 * expiry-window analysis.
 */

import { connect, type PeerCertificate } from "node:tls";
import { DEFAULT_TIMEOUT_MS } from "../constants.js";

export interface CertificateInfo {
  host: string;
  port: number;
  subject_common_name?: string;
  subject_alt_names: string[];
  issuer_organization?: string;
  issuer_common_name?: string;
  valid_from?: string;
  valid_to?: string;
  days_until_expiry?: number;
  expired: boolean;
  expires_soon: boolean;
  serial_number?: string;
  fingerprint_sha256?: string;
}

function getPeerCertificate(host: string, port: number): Promise<PeerCertificate> {
  return new Promise((resolve, reject) => {
    const socket = connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          socket.end();
          if (!cert || Object.keys(cert).length === 0) {
            reject(new Error("The server returned an empty certificate."));
            return;
          }
          resolve(cert);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      },
    );
    socket.setTimeout(DEFAULT_TIMEOUT_MS, () => {
      socket.destroy();
      reject(new Error(`TLS connection to ${host}:${port} timed out.`));
    });
    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

function flattenField(value: unknown): string | undefined {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "string") return value;
  return undefined;
}

/** Fetch and summarise the TLS certificate served on `host:port` (default 443). */
export async function inspectCertificate(
  host: string,
  port = 443,
): Promise<CertificateInfo> {
  const cert = await getPeerCertificate(host, port);
  const subject = (cert.subject ?? {}) as Record<string, unknown>;
  const issuer = (cert.issuer ?? {}) as Record<string, unknown>;

  const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined;
  let daysUntilExpiry: number | undefined;
  if (validTo && !Number.isNaN(validTo.getTime())) {
    daysUntilExpiry = Math.round((validTo.getTime() - Date.now()) / 86_400_000);
  }

  const altNames = (cert.subjectaltname ?? "")
    .split(",")
    .map((s) => s.trim().replace(/^DNS:/i, ""))
    .filter(Boolean);

  return {
    host,
    port,
    subject_common_name: flattenField(subject.CN),
    subject_alt_names: altNames,
    issuer_organization: flattenField(issuer.O),
    issuer_common_name: flattenField(issuer.CN),
    valid_from: cert.valid_from,
    valid_to: cert.valid_to,
    days_until_expiry: daysUntilExpiry,
    expired: daysUntilExpiry !== undefined && daysUntilExpiry < 0,
    expires_soon: daysUntilExpiry !== undefined && daysUntilExpiry >= 0 && daysUntilExpiry <= 14,
    serial_number: cert.serialNumber,
    fingerprint_sha256: cert.fingerprint256,
  };
}
