"""Local hostname and MaxMind enrichment for observed packet endpoints."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


_CANONICAL_NAMES = {
    "asn": "GeoLite2-ASN.mmdb",
    "city": "GeoLite2-City.mmdb",
    "country": "GeoLite2-Country.mmdb",
}


def geoip_data_dir() -> Path:
    configured = os.environ.get("ZCC_GEOIP_DIR", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".zcc-log-explorer" / "geoip"


def _search_dirs() -> list[Path]:
    return [
        geoip_data_dir(),
        Path.home() / "Documents" / "Wireshark" / "MaxMind Databases",
        Path.home() / "Library" / "Application Support" / "Wireshark" / "MaxMind Databases",
    ]


def discover_databases() -> Dict[str, Path]:
    found: Dict[str, Path] = {}
    for directory in _search_dirs():
        for kind, filename in _CANONICAL_NAMES.items():
            candidate = directory / filename
            if kind not in found and candidate.is_file():
                found[kind] = candidate
    return found


def _database_kind(database_type: str) -> str:
    value = (database_type or "").lower()
    if "asn" in value:
        return "asn"
    if "city" in value:
        return "city"
    if "country" in value:
        return "country"
    raise ValueError(f"Unsupported MaxMind database type: {database_type or 'unknown'}")


def save_database(filename: str, data: bytes) -> Path:
    """Validate and atomically save one user-supplied MaxMind MMDB locally."""
    if not filename.lower().endswith(".mmdb"):
        raise ValueError("Choose a MaxMind .mmdb database file.")
    try:
        import maxminddb
    except ImportError as exc:
        raise RuntimeError("Install project dependencies before saving a MaxMind database.") from exc

    directory = geoip_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    draft = directory / ".upload.mmdb"
    draft.write_bytes(data)
    try:
        reader = maxminddb.open_database(str(draft))
        try:
            kind = _database_kind(reader.metadata().database_type)
        finally:
            reader.close()
        target = directory / _CANONICAL_NAMES[kind]
        draft.replace(target)
        return target
    except Exception:
        draft.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class GeoRecord:
    asn: str = ""
    organization: str = ""
    provider_class: str = ""
    country: str = ""
    city: str = ""


def provider_class(organization: str, ip: str = "") -> str:
    try:
        address = ipaddress.ip_address(ip)
        if address.is_private or address.is_loopback or address.is_link_local:
            return "Private / local"
    except ValueError:
        pass
    value = (organization or "").lower()
    classes = (
        ("zscaler", "Zscaler"),
        ("microsoft", "Microsoft / Azure"),
        ("amazon", "Amazon / AWS"),
        ("google", "Google"),
        ("cloudflare", "Cloudflare"),
        ("akamai", "Akamai"),
    )
    for token, label in classes:
        if token in value:
            return label
    return "Other public network" if organization else "Not identified"


def lookup_ips(ips: Iterable[str], databases: Mapping[str, Path] | None = None) -> Dict[str, GeoRecord]:
    unique = list(dict.fromkeys(ip for ip in ips if ip))
    databases = dict(databases or discover_databases())
    try:
        import maxminddb
    except ImportError:
        return {ip: GeoRecord(provider_class=provider_class("", ip)) for ip in unique}

    readers: Dict[str, Any] = {}
    try:
        for kind, path in databases.items():
            try:
                readers[kind] = maxminddb.open_database(str(path))
            except (OSError, ValueError):
                continue
        out: Dict[str, GeoRecord] = {}
        for ip in unique:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                out[ip] = GeoRecord()
                continue
            if address.is_private or address.is_loopback or address.is_link_local:
                out[ip] = GeoRecord(provider_class="Private / local")
                continue
            asn_data = readers.get("asn").get(ip) if readers.get("asn") else None
            geo_reader = readers.get("city") or readers.get("country")
            geo_data = geo_reader.get(ip) if geo_reader else None
            asn_number = (asn_data or {}).get("autonomous_system_number")
            organization = str((asn_data or {}).get("autonomous_system_organization") or "")
            country = str(((geo_data or {}).get("country") or {}).get("iso_code") or "")
            city = str((((geo_data or {}).get("city") or {}).get("names") or {}).get("en") or "")
            out[ip] = GeoRecord(
                asn=f"AS{asn_number}" if asn_number else "",
                organization=organization,
                provider_class=provider_class(organization, ip),
                country=country,
                city=city,
            )
        return out
    finally:
        for reader in readers.values():
            reader.close()


def _merge_stat_rows(
    pcaps: Sequence[Mapping[str, Any]], key: str,
) -> Dict[str, Dict[str, int]]:
    """Sum Wireshark endpoint counters for one key across every capture."""
    totals: Dict[str, Dict[str, int]] = {}
    for pcap in pcaps:
        for name, row in (pcap.get(key) or {}).items():
            target = totals.setdefault(name, {})
            for field_name, value in (row or {}).items():
                target[field_name] = target.get(field_name, 0) + int(value or 0)
    return totals


ENDPOINT_SCOPES = ("IPv4", "IPv6", "TCP", "UDP")


def endpoint_scope_counts(pcaps: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    """Row count per Wireshark scope, counted without any MaxMind lookup.

    Used for the selector labels. Building the full rows just to count them
    would repeat the geo lookups for every scope on every rerun.
    """
    counts = {scope: 0 for scope in ENDPOINT_SCOPES}
    for address in _merge_stat_rows(pcaps, "address_stats"):
        family = address_family(address)
        if family in counts:
            counts[family] += 1
    for key in _merge_stat_rows(pcaps, "transport_stats"):
        proto = split_endpoint(key)[1].upper()
        if proto in counts:
            counts[proto] += 1
    return counts


def build_endpoint_statistics(
    pcaps: Sequence[Mapping[str, Any]],
    *,
    scope: str = "IPv4",
    databases: Mapping[str, Path] | None = None,
) -> List[dict]:
    """Wireshark ``Statistics -> Endpoints`` rows, with local ASN enrichment.

    ``scope`` selects the tab: ``"IPv4"`` / ``"IPv6"`` read the per-address
    table, ``"TCP"`` / ``"UDP"`` read the per-address-and-port table. Columns
    mirror Wireshark's — Address, Packets, Bytes, Tx/Rx Packets and Bytes —
    then add the hostname the capture itself proves and the Country, City, and
    ASN organization that local MaxMind data supplies.

    Ordering matches Wireshark's default: busiest by packets first.
    """
    wanted = (scope or "IPv4").upper()
    transport = wanted in {"TCP", "UDP"}
    totals = _merge_stat_rows(pcaps, "transport_stats" if transport else "address_stats")
    names = combine_hostname_maps(pcaps)

    selected: List[tuple[str, str, int | None, Dict[str, int]]] = []
    for key, row in totals.items():
        if transport:
            ip, proto, port = split_endpoint(key)
            if proto.upper() != wanted:
                continue
        else:
            ip, port = key, None
            if address_family(ip).upper() != wanted:
                continue
        selected.append((key, ip, port, row))

    geo = lookup_ips([ip for _key, ip, _port, _row in selected], databases)

    rows: List[dict] = []
    for _key, ip, port, row in selected:
        record = geo.get(ip)
        # Insertion order is the displayed column order. Port sits directly
        # after Address, as it does in Wireshark's TCP and UDP endpoint tabs.
        entry: dict = {"Address": ip}
        if port is not None:
            entry["Port"] = port
        entry.update({
            "Packets": int(row.get("packets", 0)),
            "Bytes": int(row.get("bytes", 0)),
            "Tx Packets": int(row.get("tx_packets", 0)),
            "Tx Bytes": int(row.get("tx_bytes", 0)),
            "Rx Packets": int(row.get("rx_packets", 0)),
            "Rx Bytes": int(row.get("rx_bytes", 0)),
            "Hostname": ", ".join(names.get(ip, [])[:3]),
            "Country": record.country if record else "",
            "City": record.city if record else "",
            "Organization": record.organization if record else "",
            "ASN": record.asn if record else "",
        })
        rows.append(entry)

    rows.sort(key=lambda item: (-item["Packets"], -item["Bytes"], item["Address"]))
    return rows


def build_resolution_rows(
    pcaps: Sequence[Mapping[str, Any]],
    *,
    databases: Mapping[str, Path] | None = None,
) -> List[dict]:
    """One row per captured hostname → address pair.

    This is the DNS evidence joined to the packet evidence: the addresses a name
    actually resolved to, both families, each with the traffic seen against it
    and the ASN context local MaxMind data can supply. A name that resolved to
    several addresses produces one row per address, because owner and geography
    can differ across them.
    """
    resolutions = resolution_map(pcaps)
    address_totals = _merge_stat_rows(pcaps, "address_stats")
    every_address = [ip for ips in resolutions.values() for ip in ips]
    geo = lookup_ips(every_address, databases)

    rows: List[dict] = []
    for host in sorted(resolutions):
        for ip in resolutions[host]:
            record = geo.get(ip)
            stats = address_totals.get(ip) or {}
            rows.append({
                "Hostname": host,
                "Address": ip,
                "Family": address_family(ip) or "unknown",
                "Packets": int(stats.get("packets", 0)),
                "Bytes": int(stats.get("bytes", 0)),
                "Country": record.country if record else "",
                "City": record.city if record else "",
                "Organization": record.organization if record else "",
                "ASN": record.asn if record else "",
                "Provider class": record.provider_class if record else "",
            })
    rows.sort(key=lambda row: (row["Hostname"], row["Family"], -row["Packets"]))
    return rows


def split_endpoint(endpoint: str) -> tuple[str, str, int | None]:
    """Split ``ip:proto/port`` while preserving IPv6 addresses."""
    match = re.match(r"^(?P<ip>.+):(?P<proto>tcp|udp)/(?P<port>\d+)$", endpoint or "")
    if not match:
        return endpoint, "", None
    return match.group("ip"), match.group("proto"), int(match.group("port"))


def hostname_map(pcap: Mapping[str, Any]) -> Dict[str, list[str]]:
    names: Dict[str, set[str]] = {}
    for ip, values in (pcap.get("dns_answers") or {}).items():
        names.setdefault(ip, set()).update(str(value) for value in values)
    # The forward DNS map carries the same evidence keyed the other way. Reading
    # both means an address is still named when only one direction was recorded.
    for host, ips in (pcap.get("dns_resolutions") or {}).items():
        for ip in ips:
            names.setdefault(str(ip), set()).add(str(host))
    for host, ips in (pcap.get("sni_to_ips") or {}).items():
        for ip in ips:
            names.setdefault(str(ip), set()).add(str(host))
    return {ip: sorted(values) for ip, values in names.items()}


def combine_hostname_maps(pcaps: Sequence[Mapping[str, Any]]) -> Dict[str, list[str]]:
    combined: Dict[str, set[str]] = {}
    for pcap in pcaps:
        for ip, names in hostname_map(pcap).items():
            combined.setdefault(ip, set()).update(names)
    return {ip: sorted(names) for ip, names in combined.items()}


def resolution_map(pcaps: Sequence[Mapping[str, Any]]) -> Dict[str, list[str]]:
    """Query name -> every A/AAAA address observed for it, across captures."""
    combined: Dict[str, set[str]] = {}
    for pcap in pcaps:
        for host, ips in (pcap.get("dns_resolutions") or {}).items():
            combined.setdefault(str(host), set()).update(str(ip) for ip in ips)
        # A capture may hold the response without a matching parsed query.
        for ip, names in (pcap.get("dns_answers") or {}).items():
            for name in names:
                combined.setdefault(str(name), set()).add(str(ip))
    return {host: sort_addresses(ips) for host, ips in combined.items()}


def address_family(ip: str) -> str:
    """``"IPv4"``, ``"IPv6"``, or ``""`` when the value will not parse."""
    try:
        return f"IPv{ipaddress.ip_address(ip).version}"
    except ValueError:
        return ""


def sort_addresses(ips: Iterable[str]) -> list[str]:
    """Numeric order within family, IPv4 before IPv6, unparseable last."""
    def key(value: str):
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return (2, 0, value)
        return (0 if parsed.version == 4 else 1, int(parsed), "")
    return sorted(dict.fromkeys(ips), key=key)
