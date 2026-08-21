"""
ZDX log parsers — ZTraceroute and Webload.

ZCC's ZDX module emits two telemetry log kinds that are gold for
slowness triage **when the customer has Diagnostic Route Collection
enabled in their app profile**:

  * **ZTraceroute** (filename matches ``ztraceroute``, classifier kind
    ``zdx_traceroute``) — per-hop latency / loss probes from the
    endpoint to one or more destinations. Lets us localize WHERE in
    the network path the latency lives (LAN, ISP, transit, edge,
    back-end) instead of just saying "slow".

  * **Webload** (filename matches ``zwebload``, classifier kind
    ``zdx_webload``) — per-page DNS / TCP / TLS / TTFB / total
    timings for the configured probe URLs. Splits "slow page" into
    network vs. server-side.

These files are not present unless the customer enabled route
collection in their ZCC config; the multiplexer stashes the parsed
result on ``summary.bundle_meta`` so the slowness detector can react.

The parsers are tolerant of multiple line shapes:

  * ``key=value`` pairs (most common)
  * ``key: value`` colon-separated
  * Inline JSON ``{"hops": [...]}`` blobs

If a file shape isn't recognised, the parser skips that file rather
than raising — we'd rather silently degrade to "no ZDX data" than
crash the whole pipeline.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


# Caps. ZDX log files are typically small (<1 MB) but we still cap
# to keep enterprise bundles bounded.
_TRACE_MAX_LINES_PER_FILE = 50_000
_TRACE_MAX_TRACES_PER_BUNDLE = 500
_WEBLOAD_MAX_LINES_PER_FILE = 50_000
_WEBLOAD_MAX_ENTRIES_PER_BUNDLE = 500

# Patterns. We're tolerant of several shapes because Zscaler has
# changed the ZDX log format multiple times across ZCC versions.

# Real ZCC ZTraceroute emits ONE line per hop in this shape:
#   ZTC: Hop[3] IP=10.45.10.53,[5,5,5,5,5,5,5,5,5,5], sent=10, received=10,
#     loss=0.00, min=5, max=48, avg=5,sd=12.67
# This pattern captures hop index, IP, per-probe samples, sent/received,
# loss%, and min/max/avg RTT in ms.
_HOP_TEXT_PAT = re.compile(
    r"Hop\[(?P<idx>\d+)\]\s+IP=(?P<ip>[0-9a-fA-F:\.]*),\s*"
    r"\[(?P<samples>[\d,\s\.\-]*)\]"
    r".*?sent=(?P<sent>\d+)"
    r".*?received=(?P<rcvd>\d+)"
    r".*?loss=(?P<loss>[\d\.]+)"
    r".*?min=(?P<rmin>[\d\.\-]+)"
    r".*?max=(?P<rmax>[\d\.\-]+)"
    r".*?avg=(?P<ravg>[\d\.\-]+)",
    re.IGNORECASE,
)

# Records the target a text-format traceroute is about to run:
#   ZTC: traceroute: In - proto=TCP target=DIRECT targetIp=170.114.52.2
# or, for the SME path:
#   ZTC: traceroute: In - proto=ICMP target=ZEN targetIp=87.58.79.69
_DST_TEXT_PAT = re.compile(
    r"traceroute:\s*In\s*-"
    r"(?:.*?proto=(?P<proto>\w+))?"
    r"(?:.*?target=(?P<kind>\w+))?"
    r"\s*targetIp=(?P<dst>[0-9a-fA-F:\.]+)",
    re.IGNORECASE,
)

# Webload page-load record. dns/tcp/tls/ttfb/total in ms.
_WEBLOAD_PAT = re.compile(
    r"(?:url|target)[=:]\s*(?P<url>https?://[^\s]+)"
    r".*?(?:dns(?:_ms)?[=:]\s*(?P<dns>[\d\.]+))?"
    r".*?(?:tcp(?:_ms)?[=:]\s*(?P<tcp>[\d\.]+))?"
    r".*?(?:tls(?:_ms)?[=:]\s*(?P<tls>[\d\.]+))?"
    r".*?(?:ttfb(?:_ms)?[=:]\s*(?P<ttfb>[\d\.]+))?"
    r".*?(?:(?:page|total)(?:_ms)?[=:]\s*(?P<total>[\d\.]+))?",
    re.IGNORECASE | re.DOTALL,
)


def _find_files(bundle, classifier_kind_substr: str) -> List[Path]:
    """Find .log files whose name contains the substring."""
    out = []
    for p in bundle.files:
        if p.suffix != ".log":
            continue
        n = p.name.lower()
        if classifier_kind_substr in n:
            out.append(p)
    return out


def parse_ztraceroute_files(bundle) -> List[Dict[str, Any]]:
    """Walk every ``ztraceroute`` log in the bundle and return a list
    of trace dicts. Each dict has::

        {
          "source_file": "ZSAZdxTraceroute_2026-05-22.log",
          "destination_ip": "140.82.121.4",
          "destination_host": "gateway.zscalertwo.net",  # may be ""
          "hops": [
              {"index": 1, "ip": "192.168.1.1", "rtt_ms": 2.15,
               "loss_pct": 0.0, "hostname": ""},
              ...
          ],
          "max_rtt_ms": 280.0,
          "elbow_hop": 4,   # hop with largest RTT delta from prior hop
          "elbow_delta_ms": 240.0,
          "unreachable_count": 0,  # number of hops with no response
        }

    A "trace" is a run of consecutive hop records sharing the same
    destination. If the log doesn't include explicit destination
    records, hops are grouped by monotonic decrease in hop index
    (i.e. when hop=1 appears, a new trace starts).
    """
    out: List[Dict[str, Any]] = []
    for path in _find_files(bundle, "ztraceroute"):
        if len(out) >= _TRACE_MAX_TRACES_PER_BUNDLE:
            break
        try:
            traces = _parse_one_traceroute_file(path)
        except Exception as e:  # noqa: BLE001
            log.warning("ztraceroute parse failed for %s: %s", path.name, e)
            continue
        for t in traces:
            if len(out) >= _TRACE_MAX_TRACES_PER_BUNDLE:
                break
            t["source_file"] = path.name
            _summarise_trace(t)
            out.append(t)
    return out


def _parse_one_traceroute_file(path: Path) -> List[Dict[str, Any]]:
    """Return list of trace dicts (no summary stats yet).

    Handles BOTH real formats ZCC emits:

      * **Text format**: one ``Hop[N] IP=X,[samples] sent=S, received=R,
        loss=L, min=M, max=N, avg=A`` line per hop, preceded by a
        ``traceroute: In - target=ZEN/DIRECT targetIp=<ip>`` line.
      * **JSON results blob**: multi-line JSON with ``"legs":[...]``
        where each leg has its own ``"hops":[...]``. The "server" leg
        contains the path TO the destination; the "egress" leg covers
        local LAN. Each leg also carries its own ``"latency"`` and
        ``"loss"`` summary stats.

    A "trace" in the returned list always represents one run against
    one destination -- JSON blobs that contain multiple legs are split
    into one trace per leg.
    """
    traces: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    json_buffer: List[str] = []
    in_json = False
    json_depth = 0

    try:
        fp = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as e:
        log.warning("could not read ztraceroute file %s: %s", path, e)
        return []

    with fp:
        for i, line in enumerate(fp):
            if i >= _TRACE_MAX_LINES_PER_FILE:
                break

            # --- JSON results blob handling (multi-line). The blob
            # starts at a "{" on its own (after a "DBG" tail). Track
            # brace depth to know when it ends.
            if in_json:
                json_buffer.append(line)
                json_depth += line.count("{") - line.count("}")
                if json_depth <= 0:
                    blob = "".join(json_buffer)
                    in_json = False
                    json_buffer = []
                    j = _extract_json_blob(blob)
                    if j is not None:
                        for leg_trace in _traces_from_zdx_json(j):
                            traces.append(leg_trace)
                continue

            stripped = line.lstrip()
            if stripped.startswith("{") and (
                '"legs"' in line or '"hops"' in line
                or '"app"' in line or '"hop_info"' in line
            ):
                in_json = True
                json_buffer = [line]
                json_depth = line.count("{") - line.count("}")
                if json_depth <= 0:  # entire JSON on one line
                    blob = "".join(json_buffer)
                    in_json = False
                    json_buffer = []
                    j = _extract_json_blob(blob)
                    if j is not None:
                        for leg_trace in _traces_from_zdx_json(j):
                            traces.append(leg_trace)
                continue

            # --- Text-format trace recognition ---
            # Destination announcement starts a new text trace.
            dst_m = _DST_TEXT_PAT.search(line)
            if dst_m:
                if current and current.get("hops"):
                    traces.append(current)
                current = {
                    "destination_ip": dst_m.group("dst"),
                    "destination_host": "",
                    "destination_kind": (dst_m.group("kind") or "").upper(),
                    "proto": (dst_m.group("proto") or "").upper(),
                    "format": "text",
                    "hops": [],
                }
                continue

            hop_m = _HOP_TEXT_PAT.search(line)
            if hop_m:
                hop = _hop_record_from_text(hop_m)
                if hop is None:
                    continue
                if current is None:
                    # Hop without a preceding destination line -- start
                    # a placeholder trace so we don't drop the data.
                    current = {
                        "destination_ip": "",
                        "destination_host": "",
                        "destination_kind": "",
                        "proto": "",
                        "format": "text",
                        "hops": [],
                    }
                current["hops"].append(hop)

    if current and current.get("hops"):
        traces.append(current)
    return traces


def _hop_record_from_text(m: re.Match) -> Optional[Dict[str, Any]]:
    """Convert one text-format ``Hop[N] IP=X,...avg=N`` match into a hop dict."""
    try:
        idx = int(m.group("idx"))
    except (TypeError, ValueError):
        return None

    def _f(name):
        v = m.group(name)
        try:
            return float(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    rtt_avg = _f("ravg")
    # ZCC encodes "no response" as avg=-1 / min=-1 / max=-1.
    if rtt_avg is not None and rtt_avg < 0:
        rtt_avg = None
    loss = _f("loss")
    if loss is None:
        sent = _f("sent") or 0
        rcvd = _f("rcvd") or 0
        if sent > 0:
            loss = 100.0 * (1 - rcvd / sent)
    return {
        "index": idx,
        "ip": (m.group("ip") or "").strip(),
        "hostname": "",
        "rtt_ms": rtt_avg,            # avg of the probe samples
        "rtt_min_ms": _f("rmin") if (_f("rmin") or 0) >= 0 else None,
        "rtt_max_ms": _f("rmax") if (_f("rmax") or 0) >= 0 else None,
        "loss_pct": loss,
        "probes_sent": _f("sent"),
        "probes_received": _f("rcvd"),
    }


def _extract_json_blob(text: str) -> Optional[Dict[str, Any]]:
    """Extract a {…} JSON blob from anywhere in a text region."""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start: end + 1])
    except (ValueError, json.JSONDecodeError):
        return None


def _traces_from_zdx_json(j: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build trace dicts from a ZDX MTR results JSON. Splits multi-leg
    blobs into one trace per leg so per-DC stats are accurate, BUT
    every leg carries the ``mtr_erefid`` of the parent run so they
    can be reassembled by the UI into a complete client → Zscaler →
    app picture.

    Recognised shapes:
      * Top-level ``legs[]`` with per-leg ``hops[]`` (modern, 2- or 3-leg).
      * Top-level ``metrics.server_ip.hop_info[]`` (older shape).
      * Top-level ``hops[]`` (very old shape).
    """
    out: List[Dict[str, Any]] = []
    legs = j.get("legs")
    if isinstance(legs, list) and legs:
        # Pull the app name from the leg that has one (server > zen).
        # The egress leg's ``name`` is always empty.
        app_name = ""
        for leg in legs:
            if isinstance(leg, dict):
                ln = leg.get("name") or ""
                if ln and (leg.get("dst") == "server" or not app_name):
                    app_name = ln
        for leg in legs:
            if not isinstance(leg, dict):
                continue
            t = _trace_from_leg(leg, j, run_app_name=app_name)
            if t:
                out.append(t)
        return out

    # No legs[]: maybe a single-leg shape with hops at the top level.
    hops_raw = j.get("hops") or j.get("Hops")
    if isinstance(hops_raw, list) and hops_raw:
        leg = {
            "dst": j.get("dst", ""),
            "dst_ip": j.get("dst_ip") or j.get("destination") or "",
            "name": j.get("hostname") or "",
            "hops": hops_raw,
            "latency": j.get("latency"),
            "loss": j.get("loss"),
            "num_hops": j.get("num_hops"),
            "num_unresp_hops": j.get("num_unresp_hops"),
            "proto": j.get("proto"),
        }
        t = _trace_from_leg(leg, j)
        if t:
            out.append(t)
    return out


def _trace_from_leg(leg: Dict[str, Any], blob: Dict[str, Any],
                    run_app_name: str = "") -> Optional[Dict[str, Any]]:
    """One leg of an MTR JSON -> one trace dict.

    ``run_app_name`` is the application hostname captured at the
    parent MTR run level (e.g. "example-tenant-b.my.salesforce.com").
    All legs of one run share it, so the UI can group legs back into
    a single app-reachability story.
    """
    hops_raw = leg.get("hops") or []
    if not isinstance(hops_raw, list) or not hops_raw:
        return None
    hops = []
    for h in hops_raw:
        if not isinstance(h, dict):
            continue
        try:
            idx = int(h.get("hop") or h.get("i") or h.get("index") or 0)
        except (TypeError, ValueError):
            continue
        avg = h.get("avg")
        try:
            avg = float(avg) if avg is not None else None
        except (TypeError, ValueError):
            avg = None
        # ZCC encodes no-response hops as avg/min/max = -1.
        if avg is not None and avg < 0:
            avg = None
        loss = h.get("loss") or h.get("pkt_loss")
        try:
            loss = float(loss) if loss is not None else None
        except (TypeError, ValueError):
            loss = None
        if loss is not None and loss < 0:
            loss = None
        rmin = h.get("min")
        rmax = h.get("max")
        try:
            rmin = float(rmin) if rmin is not None else None
            rmax = float(rmax) if rmax is not None else None
        except (TypeError, ValueError):
            rmin = rmax = None
        if rmin is not None and rmin < 0: rmin = None
        if rmax is not None and rmax < 0: rmax = None
        hops.append({
            "index": idx,
            "ip": str(h.get("ip") or ""),
            "hostname": "",
            "rtt_ms": avg,
            "rtt_min_ms": rmin,
            "rtt_max_ms": rmax,
            "loss_pct": loss,
            "probes_sent": h.get("pkt_sent"),
            "probes_received": h.get("pkt_rcvd"),
        })
    # Pull the SD-block hints from the parent blob — these tell us
    # the SME / SSL-VPN IP / NAT egress IP / sme_ip even if a particular
    # leg doesn't carry them. Used by the app-reachability summariser.
    hints = blob.get("hints") or {}
    sd = hints.get("sd") if isinstance(hints, dict) else None
    sd = sd if isinstance(sd, dict) else {}
    return {
        "destination_ip": str(leg.get("dst_ip") or ""),
        "destination_host": str(
            leg.get("name") or blob.get("hostname") or ""
        ),
        # leg.dst is one of: "egress", "zen", "server".
        # NOTE: "zen" is the leg between the first transit hop and the
        # Zscaler edge SSL-VPN endpoint. Only present in 3-leg traces
        # (ZIA-tunneled apps). 2-leg traces (BYPASS / direct) have only
        # egress + server.
        "destination_kind": str(leg.get("dst") or "").upper(),
        "client_egress_ip": str(leg.get("src_ip") or ""),
        "proto": str(leg.get("proto") or "").upper(),
        "format": "json",
        "hops": hops,
        # ---- Run-level identity (shared across all legs of one MTR) ----
        # The ``erefid`` is ZCC's unique identifier per MTR run. All
        # legs of one run share it, so the UI can stitch them back.
        "mtr_erefid": str(blob.get("erefid") or ""),
        # ``erefid`` is per-session, NOT per-probe -- multiple probes
        # share the same erefid. The unique key for a single MTR run
        # is (erefid, app_id, stime).
        "mtr_run_key": (
            f"{blob.get('erefid','')}_"
            f"{(blob.get('app') or {}).get('id','')}_"
            f"{blob.get('stime','')}"
        ),
        "mtr_stime": blob.get("stime"),
        "app_name": run_app_name,
        "app_id": (blob.get("app") or {}).get("id"),
        # SD response context: tells us the ZIA SME the customer's
        # traffic would go through for this app, even if the trace
        # measures something different.
        "sd_sme_ip": str(sd.get("sme_ip") or ""),
        "sd_sslvpn_ip": str(sd.get("sslvpnIp") or ""),
        "sd_dest_ip": str(sd.get("dest_ip") or ""),
        # Carry the leg's own summary stats forward; they're computed
        # by Zscaler's own MTR engine and are more accurate than
        # anything we'd derive ourselves.
        "leg_latency_ms": _safe_float(leg.get("latency")),
        "leg_loss_pct": _safe_float(leg.get("loss")),
        "leg_num_hops": leg.get("num_hops"),
        "leg_unresp_hops": leg.get("num_unresp_hops"),
    }


def _safe_float(v) -> Optional[float]:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _summarise_trace(t: Dict[str, Any]) -> None:
    """Compute max_rtt_ms, elbow_hop / delta, unreachable_count for a trace."""
    hops = t.get("hops") or []
    rtts = [(h.get("index"), h.get("rtt_ms")) for h in hops
            if h.get("rtt_ms") is not None]
    if not rtts:
        t["max_rtt_ms"] = 0.0
        t["elbow_hop"] = None
        t["elbow_delta_ms"] = 0.0
        t["unreachable_count"] = len(hops)
        return
    max_rtt = max(r[1] for r in rtts)
    t["max_rtt_ms"] = max_rtt
    rtts_sorted = sorted(rtts, key=lambda r: r[0])
    elbow_hop = None
    elbow_delta = 0.0
    prev = None
    for idx, rtt in rtts_sorted:
        if prev is not None:
            delta = rtt - prev
            if delta > elbow_delta:
                elbow_delta = delta
                elbow_hop = idx
        prev = rtt
    t["elbow_hop"] = elbow_hop
    t["elbow_delta_ms"] = elbow_delta
    t["unreachable_count"] = sum(
        1 for h in hops if h.get("rtt_ms") is None
    )


def parse_webload_files(bundle) -> List[Dict[str, Any]]:
    """Walk ``zwebload`` log files and return a list of webload dicts.

    Each dict::

        {
          "source_file": "ZSAZdxWebload_2026-05-22.log",
          "url": "https://outlook.office.com",
          "dns_ms": 12.0,
          "tcp_ms": 8.0,
          "tls_ms": 24.0,
          "ttfb_ms": 420.0,
          "total_ms": 2380.0,
        }
    """
    out: List[Dict[str, Any]] = []
    for path in _find_files(bundle, "zwebload"):
        if len(out) >= _WEBLOAD_MAX_ENTRIES_PER_BUNDLE:
            break
        try:
            entries = _parse_one_webload_file(path)
        except Exception as e:  # noqa: BLE001
            log.warning("zwebload parse failed for %s: %s", path.name, e)
            continue
        for e in entries:
            if len(out) >= _WEBLOAD_MAX_ENTRIES_PER_BUNDLE:
                break
            e["source_file"] = path.name
            out.append(e)
    return out


def _parse_one_webload_file(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            for i, line in enumerate(fp):
                if i >= _WEBLOAD_MAX_LINES_PER_FILE:
                    break
                m = _WEBLOAD_PAT.search(line)
                if not m:
                    continue
                url = m.group("url")
                if not url:
                    continue
                entry = {"url": url}

                def _f(key):
                    v = m.group(key)
                    try:
                        return float(v) if v else None
                    except ValueError:
                        return None
                entry["dns_ms"] = _f("dns")
                entry["tcp_ms"] = _f("tcp")
                entry["tls_ms"] = _f("tls")
                entry["ttfb_ms"] = _f("ttfb")
                entry["total_ms"] = _f("total")
                # Only keep entries with at least one timing.
                if any(entry[k] is not None for k in
                       ("dns_ms", "tcp_ms", "tls_ms", "ttfb_ms", "total_ms")):
                    out.append(entry)
    except OSError as e:
        log.warning("could not read zwebload file %s: %s", path, e)
    return out


def summarize_ztraceroute_health(
    traces: List[Dict[str, Any]],
    sme_dc_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Aggregate ZTraceroute samples into per-destination health metrics.

    For every distinct destination IP across the parsed traces, returns a
    dict with end-to-end latency stats (median / p90 / p99 from each
    trace's terminal-hop avg RTT), packet-loss % (median + max across
    traces), per-trace hop count, and whether the destination is a known
    Zscaler SME / DC.

    The result is what an engineer needs to answer "what's the network
    latency and loss between this client and the Zscaler DC right now":
    one row per destination, sorted by relevance (Zscaler DCs first,
    then by sample count).
    """
    if not traces:
        return []
    by_dst: Dict[str, List[Dict[str, Any]]] = {}
    for t in traces:
        dst = t.get("destination_ip") or "?"
        if not dst or dst == "?":
            continue
        by_dst.setdefault(dst, []).append(t)

    out: List[Dict[str, Any]] = []
    sme_dc_map = sme_dc_map or {}
    for dst, dst_traces in by_dst.items():
        # Per-trace end-to-end latency = max hop's avg RTT (the terminal
        # hop's RTT reflects the round-trip to the destination).
        # leg_latency_ms from JSON is more accurate when present.
        latencies: List[float] = []
        losses: List[float] = []
        hop_counts: List[int] = []
        unresp_counts: List[int] = []
        # Also accumulate per-hop loss across traces, indexed by hop
        # number, so we can identify WHICH hop has the highest loss.
        per_hop_loss: Dict[int, List[float]] = {}
        per_hop_rtt: Dict[int, List[float]] = {}
        per_hop_ip: Dict[int, str] = {}
        for t in dst_traces:
            # Prefer the MTR JSON's own leg latency where available.
            leg_lat = t.get("leg_latency_ms")
            if leg_lat is None:
                # Fall back: max(rtt_ms) across hops in the trace.
                rtts = [h.get("rtt_ms") for h in t.get("hops") or []
                        if h.get("rtt_ms") is not None]
                if rtts:
                    leg_lat = max(rtts)
            if leg_lat is not None and leg_lat > 0:
                latencies.append(float(leg_lat))

            leg_loss = t.get("leg_loss_pct")
            if leg_loss is None:
                hops = t.get("hops") or []
                if hops:
                    # Average per-hop loss as a proxy.
                    h_losses = [h.get("loss_pct") for h in hops
                                if h.get("loss_pct") is not None]
                    if h_losses:
                        leg_loss = sum(h_losses) / len(h_losses)
            if leg_loss is not None:
                losses.append(float(leg_loss))

            n = t.get("leg_num_hops") or len(t.get("hops") or [])
            if n:
                hop_counts.append(int(n))
            u = t.get("leg_unresp_hops")
            if u is None:
                u = t.get("unreachable_count")
            if u is not None:
                unresp_counts.append(int(u))

            for h in t.get("hops") or []:
                idx = h.get("index")
                if idx is None:
                    continue
                per_hop_ip.setdefault(idx, h.get("ip") or "")
                if h.get("loss_pct") is not None:
                    per_hop_loss.setdefault(idx, []).append(
                        float(h["loss_pct"]))
                if h.get("rtt_ms") is not None:
                    per_hop_rtt.setdefault(idx, []).append(
                        float(h["rtt_ms"]))

        def _pct(vals: List[float], p: float) -> Optional[float]:
            if not vals:
                return None
            s = sorted(vals)
            k = int(p * (len(s) - 1))
            return s[k]

        def _median(vals: List[float]) -> Optional[float]:
            if not vals:
                return None
            s = sorted(vals)
            return s[len(s) // 2]

        # Identify the lossiest hop (sorted by median loss).
        worst_hop = None
        worst_hop_loss = 0.0
        for idx, losses_at_hop in per_hop_loss.items():
            med = _median(losses_at_hop)
            if med is not None and med > worst_hop_loss:
                worst_hop = idx
                worst_hop_loss = med

        dc_name = sme_dc_map.get(dst)
        if not dc_name:
            # /24 fallback for the DC label.
            parts = dst.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3]) + "."
                cands = {v for k, v in sme_dc_map.items()
                         if k.startswith(prefix)}
                if len(cands) == 1:
                    dc_name = next(iter(cands))

        hostname = ""
        for t in dst_traces:
            h = t.get("destination_host")
            if h:
                hostname = h
                break

        # If still no DC name but the hostname looks like an SME, harvest
        # the DC code directly from it (this catches tunnel SMEs that
        # appear only as destinations in the bundle, never as the
        # ``sme_ip`` of an MTR result, so they're not in sme_dc_map).
        if not dc_name and hostname:
            mhn = _SME_HOSTNAME_PAT.search(hostname)
            if mhn:
                dc_name = mhn.group("dc").upper()

        out.append({
            "destination_ip": dst,
            "destination_host": hostname,
            "dc_name": dc_name,  # None if not a known Zscaler DC
            "trace_count": len(dst_traces),
            "latency_median_ms": _median(latencies),
            "latency_p90_ms": _pct(latencies, 0.90),
            "latency_p99_ms": _pct(latencies, 0.99),
            "latency_min_ms": min(latencies) if latencies else None,
            "latency_max_ms": max(latencies) if latencies else None,
            "loss_median_pct": _median(losses),
            "loss_max_pct": max(losses) if losses else None,
            "hop_count_median": _median([float(h) for h in hop_counts]),
            "unresp_hops_median": _median(
                [float(u) for u in unresp_counts]),
            "worst_hop_index": worst_hop,
            "worst_hop_ip": per_hop_ip.get(worst_hop, "") if worst_hop else "",
            "worst_hop_loss_pct": worst_hop_loss if worst_hop else None,
        })

    # Sort: Zscaler DCs first (named), then by trace count desc.
    out.sort(key=lambda r: (
        0 if r["dc_name"] else 1,
        -r["trace_count"],
    ))
    return out


def summarize_app_health(
    traces: List[Dict[str, Any]],
    sme_dc_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Reassemble multi-leg MTR runs by ``mtr_erefid`` and produce one
    row per APPLICATION (not per destination IP).

    Each row::

        {
            "app_name":        "example-tenant-b.my.salesforce.com",
            "app_target_ip":   "3.146.43.229",
            "via_zscaler":     True,             # has a ZEN leg
            "sme_ip":          "170.85.97.69",
            "sme_dc":          "DFW2",
            "run_count":       3,
            "latency_median_ms": 17.0,           # MTR-reported end-to-end
            "loss_median_pct":   0.0,
            "underlay_latency_median_ms": 3.0,
            "underlay_loss_median_pct":   0.0,
            "zen_latency_median_ms":      20.0,    # None if not via Zscaler
            "zen_loss_median_pct":        20.0,
            "server_latency_median_ms":   27.0,
            "server_loss_median_pct":     -1,      # -1 = ICMP-rate-limited
            "verdict":         "warn",            # ok / warn / bad
            "verdict_reason":  "ZEN leg loss=20% at transit hop 4.42.110.10",
            "erefids":         ["2517977897819255", "..."],
        }

    Standalone ``target=ZEN`` text-format traces (the ICMP edge probes)
    are NOT included here — they're not app traces. They're surfaced
    separately by ``summarize_edge_probes()``.
    """
    if not traces:
        return []
    sme_dc_map = sme_dc_map or {}

    # 1. Group traces (legs) by ``mtr_run_key`` (= erefid+app+stime,
    # unique per probe attempt). NOT by erefid alone -- erefid is
    # shared across many probes in the same ZCC session.
    by_erefid: Dict[str, List[Dict[str, Any]]] = {}
    for t in traces:
        ref = t.get("mtr_run_key") or t.get("mtr_erefid") or ""
        if not ref:
            continue
        by_erefid.setdefault(ref, []).append(t)

    # 2. Build per-run dicts.
    runs: List[Dict[str, Any]] = []
    for ref, legs in by_erefid.items():
        egress_leg = next(
            (l for l in legs if l.get("destination_kind") == "EGRESS"), None
        )
        zen_leg = next(
            (l for l in legs if l.get("destination_kind") == "ZEN"), None
        )
        server_leg = next(
            (l for l in legs if l.get("destination_kind") == "SERVER"), None
        )
        if server_leg is None and egress_leg is None and zen_leg is None:
            continue
        primary = server_leg or zen_leg or egress_leg
        app_name = primary.get("app_name") or ""
        app_target = (server_leg or zen_leg or egress_leg).get("destination_ip", "")
        sme_ip = (primary.get("sd_sme_ip")
                  or (zen_leg.get("destination_ip") if zen_leg else "")
                  or "")
        runs.append({
            "erefid": ref,
            "app_name": app_name,
            "app_target_ip": app_target,
            "via_zscaler": zen_leg is not None,
            "sme_ip": sme_ip,
            "underlay_leg": egress_leg,
            "zen_leg": zen_leg,
            "server_leg": server_leg,
        })

    # 3. Group runs by app_name.
    by_app: Dict[str, List[Dict[str, Any]]] = {}
    for r in runs:
        key = r["app_name"] or r["app_target_ip"] or "(unknown)"
        by_app.setdefault(key, []).append(r)

    def _med(vs):
        if not vs:
            return None
        s = sorted(vs)
        return s[len(s) // 2]

    def _leg_latency(leg):
        if leg is None:
            return None
        # Prefer ZCC's own leg-latency field; fall back to max hop RTT.
        ll = leg.get("leg_latency_ms")
        if ll is not None and ll > 0:
            return float(ll)
        rtts = [h.get("rtt_ms") for h in (leg.get("hops") or [])
                if h.get("rtt_ms") is not None]
        return max(rtts) if rtts else None

    def _leg_loss(leg):
        if leg is None:
            return None
        ll = leg.get("leg_loss_pct")
        if ll is None:
            return None
        return float(ll)

    out = []
    for app, app_runs in by_app.items():
        underlay_lats, underlay_losses = [], []
        zen_lats, zen_losses = [], []
        server_lats, server_losses = [], []
        end_to_end_lats, end_to_end_losses = [], []
        via_zs_any = False
        sme_ips_seen: set = set()
        target_ips_seen: set = set()
        erefids: List[str] = []

        for r in app_runs:
            erefids.append(r["erefid"])
            if r["via_zscaler"]:
                via_zs_any = True
            if r["sme_ip"]:
                sme_ips_seen.add(r["sme_ip"])
            if r["app_target_ip"]:
                target_ips_seen.add(r["app_target_ip"])

            u_lat = _leg_latency(r["underlay_leg"])
            u_loss = _leg_loss(r["underlay_leg"])
            z_lat = _leg_latency(r["zen_leg"])
            z_loss = _leg_loss(r["zen_leg"])
            s_lat = _leg_latency(r["server_leg"])
            s_loss = _leg_loss(r["server_leg"])

            if u_lat is not None: underlay_lats.append(u_lat)
            if u_loss is not None: underlay_losses.append(u_loss)
            if z_lat is not None: zen_lats.append(z_lat)
            if z_loss is not None: zen_losses.append(z_loss)
            if s_lat is not None: server_lats.append(s_lat)
            if s_loss is not None: server_losses.append(s_loss)

            # End-to-end is the last leg's latency (server preferred).
            e2e_lat = s_lat if s_lat is not None else (
                z_lat if z_lat is not None else u_lat
            )
            if e2e_lat is not None:
                end_to_end_lats.append(e2e_lat)
            e2e_loss = s_loss if s_loss not in (None, -1) else (
                z_loss if z_loss is not None else u_loss
            )
            if e2e_loss is not None:
                end_to_end_losses.append(e2e_loss)

        # Verdict logic. Inspect each leg's stats:
        #   - bad: any leg with median loss >= 5% (excluding -1 / ICMP RL)
        #         OR median latency >= 200ms
        #   - warn: any leg with loss 1-5% or latency 100-200ms
        verdict = "ok"
        reason = []
        for label, lats, losses in [
            ("underlay", underlay_lats, underlay_losses),
            ("client→Zscaler",   zen_lats, zen_losses),
            ("Zscaler→app", server_lats, server_losses),
        ]:
            m_lat = _med(lats)
            m_loss = _med([l for l in losses if l is not None and l >= 0])
            if m_loss is not None and m_loss >= 5:
                verdict = "bad"
                reason.append(
                    f"{label} loss {m_loss:.1f}%"
                )
            elif m_lat is not None and m_lat >= 200:
                verdict = "bad"
                reason.append(
                    f"{label} latency {m_lat:.0f}ms"
                )
            elif (m_loss is not None and m_loss >= 1) or (
                  m_lat is not None and m_lat >= 100):
                if verdict != "bad":
                    verdict = "warn"
                if m_loss is not None and m_loss >= 1:
                    reason.append(f"{label} loss {m_loss:.1f}%")
                if m_lat is not None and m_lat >= 100:
                    reason.append(f"{label} latency {m_lat:.0f}ms")

        sme_dc = None
        for s_ip in sme_ips_seen:
            dc = sme_dc_map.get(s_ip) if sme_dc_map else None
            if not dc:
                # /24 fallback
                parts = s_ip.split(".")
                if len(parts) == 4:
                    prefix = ".".join(parts[:3]) + "."
                    cands = {v for k, v in (sme_dc_map or {}).items()
                             if k.startswith(prefix)}
                    if len(cands) == 1:
                        dc = next(iter(cands))
            if dc:
                sme_dc = dc
                break

        out.append({
            "app_name": app,
            "app_target_ip": sorted(target_ips_seen)[0] if target_ips_seen else "",
            "via_zscaler": via_zs_any,
            "sme_ip": sorted(sme_ips_seen)[0] if sme_ips_seen else "",
            "sme_dc": sme_dc,
            "run_count": len(app_runs),
            "latency_median_ms": _med(end_to_end_lats),
            "loss_median_pct": _med([l for l in end_to_end_losses
                                      if l is not None and l >= 0]),
            "underlay_latency_median_ms": _med(underlay_lats),
            "underlay_loss_median_pct": _med(
                [l for l in underlay_losses if l is not None and l >= 0]
            ),
            "zen_latency_median_ms": _med(zen_lats),
            "zen_loss_median_pct": _med(
                [l for l in zen_losses if l is not None and l >= 0]
            ),
            "server_latency_median_ms": _med(server_lats),
            "server_loss_median_pct": _med(
                [l for l in server_losses if l is not None and l >= 0]
            ),
            "verdict": verdict,
            "verdict_reason": ", ".join(reason) if reason else "all clean",
            "erefids": erefids,
        })

    # Sort: bad first, then warn, then ok; within each, by run_count desc.
    rank = {"bad": 0, "warn": 1, "ok": 2}
    out.sort(key=lambda r: (rank.get(r["verdict"], 9), -r["run_count"]))
    return out


def summarize_edge_probes(
    traces: List[Dict[str, Any]],
    sme_dc_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Aggregate the standalone ICMP-only ``target=ZEN`` text-format
    edge-reachability probes. These DON'T measure any app — they're
    just "is the Zscaler edge alive at IP X?" pings.

    One row per probed edge IP. Returned separately from the app-
    health table so engineers don't conflate "edge health" with
    "app health".
    """
    sme_dc_map = sme_dc_map or {}
    # Only text-format ZEN traces (format=="text" AND destination_kind=="ZEN").
    edge_traces = [
        t for t in (traces or [])
        if t.get("format") == "text"
        and t.get("destination_kind") == "ZEN"
    ]
    if not edge_traces:
        return []
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for t in edge_traces:
        by_ip.setdefault(t.get("destination_ip", "?"), []).append(t)

    def _med(vs):
        if not vs:
            return None
        s = sorted(vs)
        return s[len(s) // 2]

    out = []
    for ip, dts in by_ip.items():
        # Edge probe latency = terminal hop's RTT.
        lats = []
        losses = []
        for t in dts:
            term = max((h for h in (t.get("hops") or [])
                        if h.get("ip") == ip),
                       key=lambda h: h.get("index", 0), default=None)
            if term and term.get("rtt_ms") is not None:
                lats.append(float(term["rtt_ms"]))
            # Per-trace loss: how many hops failed to respond?
            n = len(t.get("hops") or [])
            unresp = t.get("unreachable_count") or 0
            if n:
                losses.append(100.0 * unresp / n)
        dc_name = sme_dc_map.get(ip)
        if not dc_name:
            parts = ip.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3]) + "."
                cands = {v for k, v in sme_dc_map.items()
                         if k.startswith(prefix)}
                if len(cands) == 1:
                    dc_name = next(iter(cands))
        out.append({
            "edge_ip": ip,
            "dc_name": dc_name,
            "probe_count": len(dts),
            "latency_median_ms": _med(lats),
            "icmp_reachability_pct": (
                100.0 - _med(losses) if losses else None
            ),
        })
    out.sort(key=lambda r: (-r["probe_count"],))
    return out


def bundle_has_ztraceroute(bundle) -> bool:
    """Cheap presence check used by detectors that want to fire an
    INFO-level hint when route collection wasn't enabled."""
    for p in bundle.files:
        if p.suffix == ".log" and "ztraceroute" in p.name.lower():
            return True
    return False


# ---- SME → DC name extraction ------------------------------------------
#
# Tunnel logs identify Service Edges only by raw IP (e.g. SMEAddress:
# 87.58.79.69). The human-readable hostname is buried in ZTraceroute's
# JSON output, where each probe records a paired ``sme_ip`` / ``sme_name``.
# Names follow the convention ``zs<N>-<dc>-<node>-sme.gateway.<cloud>.net``
# -- e.g. ``zs2-tlv2-1e2-sme.gateway.zscalertwo.net`` -> DC short name
# "TLV2". We harvest the mapping once per bundle so every other piece of
# the pipeline (Network Identity panel, findings, HTML report, etc.) can
# label any SME IP with its DC.

_SME_HOSTNAME_PAT = re.compile(
    r"zs\d+-(?P<dc>[a-z0-9]+)-[a-z0-9]+-sme\.gateway\.[a-z]+\.net",
    re.IGNORECASE,
)
_SME_PAIR_PAT = re.compile(
    r'"sme_ip"\s*:\s*"(?P<ip>[0-9a-fA-F:.]+)"\s*,?\s*'
    r'"sme_name"\s*:\s*"(?P<name>[^"]+)"',
)


def extract_sme_dc_map(bundle) -> Dict[str, str]:
    """Return ``Dict[sme_ip, dc_short_name]`` harvested from ZTraceroute
    JSON. ``dc_short_name`` is the uppercased middle token of the SME
    hostname (TLV2, CPH3, VIE1, etc.). Names that don't match the expected
    pattern still get recorded as ``sme_ip -> full_hostname`` so the UI
    can fall back on the FQDN when the short-name extraction fails.

    Capped at 200 distinct mappings per bundle (in practice each customer
    sees handfuls of DCs, not hundreds).
    """
    out: Dict[str, str] = {}
    cap = 200
    for path in _find_files(bundle, "ztraceroute"):
        if len(out) >= cap:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                # Read in chunks -- the JSON we want is on adjacent lines
                # but spanning a chunk boundary is fine because the pair
                # pattern is local and we just want hits.
                content = fp.read(_TRACE_MAX_LINES_PER_FILE * 200)
        except OSError:
            continue
        for m in _SME_PAIR_PAT.finditer(content):
            if len(out) >= cap:
                break
            ip = m.group("ip")
            name = m.group("name")
            if ip in out:
                continue
            short = _SME_HOSTNAME_PAT.search(name)
            out[ip] = short.group("dc").upper() if short else name
    return out


def label_sme_ip(ip: str, sme_dc_map: Optional[Dict[str, str]]) -> str:
    """Return ``"<ip> (<DC>)"`` if ip's DC can be inferred, else just ``ip``.

    Resolution order (most authoritative first):
      0. **CENR lookup** -- check the IP against the reviewed inline copy of
         Zscaler's published Cloud Enforcement Node Ranges.
         This is the AUTHORITATIVE tier because the ranges come from
         Zscaler's own routing table; if it matches, we trust it.
         If the inline table cannot load, this tier is silently skipped.
      1. **Exact match** in ``sme_dc_map`` (built from ZTraceroute logs
         in this bundle).
      2. **/24 fallback** -- a Zscaler DC is typically a /24 block;
         when only the probe-target SME shows up in the bundle but the
         tunnel SME is in the same /24, we propagate the DC name.
      3. **/16 fallback** -- last-resort; only when every mapped IP in
         the same /16 agrees on a DC.

    Why we ALSO keep the /24 + /16 fallbacks even with CENR loaded:
    the heuristics extend resolution to anomalous IPs (e.g. a DC that
    Zscaler has added since the last CENR refresh, or an IP that's
    legitimately a Zscaler IP but isn't in the published ranges yet).
    CENR is preferred when both fire; heuristics are the safety net.
    """
    if not ip:
        return ip

    # ---- Tier 0: CENR (most authoritative) ----
    try:
        from . import zscaler_dc_lookup  # local import to avoid cycle
        cenr = zscaler_dc_lookup.lookup_dc_by_ip(ip)
    except Exception:
        cenr = None
    if cenr and cenr.get("code"):
        # Show the airport code + city for context. If we ever want a
        # tighter label, drop the city -- but city helps in mixed-region
        # tables.
        code = cenr["code"]
        city = cenr.get("city") or ""
        # City is already implied by the code, so we only show it when
        # the code is opaque (e.g. an obscure city like "BUE1" most
        # readers won't recognise without the city tag).
        if city and code[:3].upper() not in _WELL_KNOWN_AIRPORTS:
            return f"{ip} ({code} — {city})"
        return f"{ip} ({code})"

    # ---- Tier 1+: existing sme_dc_map heuristics ----
    if not sme_dc_map:
        return ip
    dc = sme_dc_map.get(ip)
    if dc:
        return f"{ip} ({dc})"
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    prefix = ".".join(parts[:3]) + "."
    candidates = {v for k, v in sme_dc_map.items() if k.startswith(prefix)}
    if len(candidates) == 1:
        return f"{ip} ({next(iter(candidates))})"
    prefix16 = ".".join(parts[:2]) + "."
    candidates16 = {v for k, v in sme_dc_map.items() if k.startswith(prefix16)}
    if len(candidates16) == 1:
        return f"{ip} ({next(iter(candidates16))})"
    return ip


# Airport codes a SecureDynamics engineer will instantly recognise --
# we suppress the "— City" tail for these to keep tables tidy. Anything
# outside this set gets the city tag so the engineer doesn't have to
# Google "BUE1".
_WELL_KNOWN_AIRPORTS = frozenset({
    "AMS", "ATL", "BOS", "CHI", "CPH", "DEN", "DFW", "DUB", "FRA",
    "HKG", "IAD", "JFK", "LAX", "LHR", "LON", "MAD", "MIA", "MIL",
    "MUC", "MRS", "NRT", "PAR", "PIT", "SEA", "SFO", "SIN", "SJC",
    "SYD", "TLV", "TPA", "WAS", "ZRH",
})


# ---- Cloud Performance Test (CPT) detection ----------------------------
#
# When a user opens https://zscaler.com/test (the Zscaler Cloud Performance
# Test page), the page issues probes through their browser. The browser's
# tunnel client routes them through whichever SME serves the user's
# current region, and the test page records that SME's IP / hostname and
# displays it as "Data Center". The same probes show up in ZTraceroute
# as ``publicIP = <sme_ip>`` records, because that's the egress IP the
# CPT target sees.
#
# Signature: a cluster of distinct SME IPs appearing as the publicIP /
# sme_ip across a tight time window in ZTraceroute. We surface this as
# an INFO finding so the engineer can correlate a CPT screenshot to a
# specific moment in the bundle.

_PUBLIC_IP_PAT = re.compile(
    r"publicIP\s*=\s*(?P<ip>[0-9a-fA-F:.]+)"
)
_TS_PAT = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+)"
)


def detect_cpt_events(bundle, sme_dc_map: Dict[str, str]) -> List[Dict[str, Any]]:
    """Return a list of Cloud Performance Test events detected in the
    bundle. Each event::

        {
            "sme_ip": "87.58.80.188",
            "dc_name": "TLV2",
            "first_seen": "2026-06-04 19:00:47.730600",
            "last_seen":  "2026-06-04 19:00:47.738912",
            "probe_count": 7,
            "source_file": "ZSAUpm_ZTraceroute_2026-06-04-19-07-41.078764.log",
        }

    Only SMEs that appear in ``sme_dc_map`` count -- that filters
    everything else out (ordinary tunnel SMEs already appear in
    bundle_meta via session_info, so they wouldn't be 'new'
    discoveries).
    """
    if not sme_dc_map:
        return []
    events: List[Dict[str, Any]] = []
    # Per (file, sme_ip) -> (first_ts, last_ts, count)
    aggregated: Dict[tuple, Dict[str, Any]] = {}
    for path in _find_files(bundle, "ztraceroute"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                last_ts = ""
                for line in fp:
                    ts_m = _TS_PAT.match(line)
                    if ts_m:
                        last_ts = ts_m.group("ts")
                    ip_m = _PUBLIC_IP_PAT.search(line)
                    if not ip_m:
                        continue
                    ip = ip_m.group("ip")
                    if ip not in sme_dc_map:
                        continue
                    key = (path.name, ip)
                    rec = aggregated.get(key)
                    if rec is None:
                        aggregated[key] = {
                            "sme_ip": ip,
                            "dc_name": sme_dc_map[ip],
                            "first_seen": last_ts,
                            "last_seen": last_ts,
                            "probe_count": 1,
                            "source_file": path.name,
                        }
                    else:
                        rec["probe_count"] += 1
                        if last_ts:
                            rec["last_seen"] = last_ts
        except OSError:
            continue
    # Only keep clusters with >=3 probes -- single one-offs are noise.
    for rec in aggregated.values():
        if rec["probe_count"] >= 3:
            events.append(rec)
    return events
