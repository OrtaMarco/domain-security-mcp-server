/**
 * Offline IP geolocation using the geoip-lite bundled database (no API key).
 * Ported from the ortamarco.me ip-lookup endpoint.
 */

import { reverseDns } from "./dns.js";

type GeoipModule = typeof import("geoip-lite");
let geoipModule: Promise<GeoipModule> | undefined;

/**
 * geoip-lite loads its whole database (~150 MB of RSS) synchronously on import,
 * so it is imported on first use rather than at startup — a server that never
 * geolocates an IP never pays for it.
 */
function loadGeoip(): Promise<GeoipModule> {
  geoipModule ??= import("geoip-lite").then((m) => (m as { default?: GeoipModule }).default ?? m);
  return geoipModule;
}

export interface IpInfo {
  ip: string;
  country_iso?: string;
  country_name?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  time_zone?: string;
  hostname?: string;
}

function countryName(iso: string | undefined): string | undefined {
  if (!iso) return undefined;
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(iso) ?? iso;
  } catch {
    return iso;
  }
}

/** Geolocate an IP and attempt a reverse-DNS lookup. */
export async function geolocateIp(ip: string): Promise<IpInfo> {
  const geo = (await loadGeoip()).lookup(ip);

  let hostname: string | undefined;
  try {
    const names = await reverseDns(ip);
    hostname = names[0];
  } catch {
    // No PTR record — leave hostname undefined.
  }

  return {
    ip,
    country_iso: geo?.country || undefined,
    country_name: countryName(geo?.country || undefined),
    region: geo?.region || undefined,
    city: geo?.city || undefined,
    // geoip-lite answers [null, null] for some anycast ranges (Cloudflare 1.1.1.1).
    latitude: geo?.ll?.[0] ?? undefined,
    longitude: geo?.ll?.[1] ?? undefined,
    time_zone: geo?.timezone || undefined,
    hostname,
  };
}
