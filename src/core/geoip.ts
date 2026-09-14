/**
 * Offline IP geolocation (no API key) on the DB-IP "IP to City Lite" database,
 * licensed CC BY 4.0: IP Geolocation by DB-IP (https://db-ip.com). The MMDB files
 * ship in the @ip-location-db/dbip-city-mmdb package and are read with mmdb-lib.
 * Ported from the ortamarco.me ip-lookup endpoint.
 */

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isIP } from "node:net";
import { Reader, type Response } from "mmdb-lib";
import tzLookup from "@photostructure/tz-lookup";
import { reverseDns } from "./dns.js";

/** CC BY 4.0 requires this credit wherever results from the database are shown. */
export const GEOIP_ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com)";

/** One record of the ip-location-db city layout; an empty string means unknown. */
interface CityRecord {
  country_code?: string;
  state1?: string;
  state2?: string;
  city?: string;
  postcode?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
}

type Family = 4 | 6;

const DB_FILES: Record<Family, string> = {
  4: "@ip-location-db/dbip-city-mmdb/dbip-city-ipv4.mmdb",
  6: "@ip-location-db/dbip-city-mmdb/dbip-city-ipv6.mmdb",
};

const requireFromHere = createRequire(import.meta.url);
const readers: Partial<Record<Family, Promise<Reader<Response>>>> = {};

/**
 * The database is two files, one per address family, and each is held in memory
 * whole once read (~60 MB for IPv4, ~70 MB for IPv6). Each is read on the first
 * lookup of its family — a server that never geolocates never pays, and one that
 * only sees IPv4 never loads the IPv6 file.
 *
 * The IPv4 file must never be asked about an IPv6 address: mmdb-lib walks the
 * first 32 bits of it and answers with an unrelated IPv4 record instead of null.
 */
function reader(family: Family): Promise<Reader<Response>> {
  let pending = readers[family];
  if (!pending) {
    const loading = readFile(requireFromHere.resolve(DB_FILES[family])).then(
      (db) => new Reader<Response>(db),
    );
    // A failed read is not cached: the next lookup tries again.
    loading.catch(() => {
      if (readers[family] === loading) delete readers[family];
    });
    readers[family] = pending = loading;
  }
  return pending;
}

/** `::ffff:8.8.8.8` (or `::ffff:808:808`) is an IPv4 address, and only the IPv4 file has it. */
function unmapIpv4(ip: string): string | undefined {
  let s = ip.toLowerCase().split("%")[0] ?? "";
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    s = `${s.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", tail] = s.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups =
    tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  const n = groups.map((g) => parseInt(g, 16));
  if (n.length !== 8 || n.slice(0, 5).some((g) => g !== 0) || n[5] !== 0xffff) return undefined;
  const [hi = 0, lo = 0] = n.slice(6);
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function countryName(iso: string | undefined): string | undefined {
  if (!iso) return undefined;
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(iso) ?? iso;
  } catch {
    return iso;
  }
}

/** The file stores coordinates as float32; four decimals (~11 m) is already finer than the data. */
function coordinate(value: number | undefined): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? Math.round(value * 1e4) / 1e4 : undefined;
}

/**
 * DB-IP Lite carries no time zone, so it is estimated from the coordinates. Near
 * a zone border the estimate can name a neighbouring zone.
 */
function timeZone(record: CityRecord, latitude?: number, longitude?: number): string | undefined {
  if (record.timezone) return record.timezone;
  if (latitude === undefined || longitude === undefined) return undefined;
  try {
    return tzLookup(latitude, longitude);
  } catch {
    return undefined;
  }
}

export type IpLocation = Omit<IpInfo, "ip" | "hostname">;

/** Offline lookup only, no DNS. Unknown, private and invalid addresses answer `{}`. */
export async function lookupLocation(ip: string): Promise<IpLocation> {
  let address = ip;
  let family = isIP(address);
  if (family === 6) {
    const v4 = unmapIpv4(address);
    if (v4) {
      address = v4;
      family = 4;
    }
  }
  if (family !== 4 && family !== 6) return {};

  const record = (await reader(family)).get(address) as CityRecord | null;
  if (!record) return {};

  const latitude = coordinate(record.latitude);
  const longitude = coordinate(record.longitude);
  return {
    country_iso: record.country_code || undefined,
    country_name: countryName(record.country_code || undefined),
    region: record.state1 || undefined,
    city: record.city || undefined,
    latitude,
    longitude,
    time_zone: timeZone(record, latitude, longitude),
  };
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

/** Geolocate an IP and attempt a reverse-DNS lookup. */
export async function geolocateIp(ip: string): Promise<IpInfo> {
  const location = await lookupLocation(ip);

  let hostname: string | undefined;
  try {
    const names = await reverseDns(ip);
    hostname = names[0];
  } catch {
    // No PTR record — leave hostname undefined.
  }

  return { ip, ...location, hostname };
}
