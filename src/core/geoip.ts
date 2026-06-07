/**
 * Offline IP geolocation using the geoip-lite bundled database (no API key).
 * Ported from the ortamarco.me ip-lookup endpoint.
 */

import geoip from "geoip-lite";
import { reverseDns } from "./dns.js";

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
  const geo = geoip.lookup(ip);

  let hostname: string | undefined;
  try {
    const names = await reverseDns(ip);
    hostname = names[0];
  } catch {
    // No PTR record — leave hostname undefined.
  }

  return {
    ip,
    country_iso: geo?.country,
    country_name: countryName(geo?.country),
    region: geo?.region || undefined,
    city: geo?.city || undefined,
    latitude: geo?.ll?.[0],
    longitude: geo?.ll?.[1],
    time_zone: geo?.timezone || undefined,
    hostname,
  };
}
