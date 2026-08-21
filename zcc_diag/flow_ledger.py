"""Per-connection traffic ledger — Slice 15 (2026-08-19).

Reconstructs what each TCP/UDP connection actually moved, from the
records ZCC writes when the connection *ends*.

Why only close records
----------------------
The corpus sweep (`learned.py`, 46 bundles / 157,068,822 lines) sorted
the byte-carrying lines into three kinds:

* **Final totals**, written once per connection at close —
  `~ZTCPServerConnection ... clt_bytes=N, srv_bytes=M!` (2,637,331
  records, 46/46 bundles), `UDP Proxy: ID: N Connection closed. ...
  Tx Bytes / Rx Bytes`, and `ZSTCPFlowHandler destructor!! tx bytes=,
  rx_byptes=` (Zscaler's typo — `rx_bytes` matches nothing).
* **Running counters**, e.g. `Zpn client socket written bytes: N ...
  Tag id: T`, which grow over the life of a tunnel.
* **Keepalives** — `sendKeepAlive: Sent bytes:` appears 2,227,353 times
  corpus-wide and carries zero user data.

This module reads ONLY the first kind. That is not a filter applied to a
larger set that could be mis-tuned: the running-counter and keepalive
patterns are never compiled into the carrier table at all, so they
cannot reach a total by construction. `running_counter_report()` exists
to *show* the difference — it counts what was deliberately left out, so
"why is your number smaller than grep's?" has an answer with numbers in
it. Measured on bundle 21: the ledger totals 1,463,293 bytes, while
adding the running counters and keepalives would report 105,148,396 —
72x, because a running counter re-states the same bytes on every line.

What is NOT inferred
--------------------
* A flow with no destination on any of its lines gets `dest = None`.
  The UI renders that as an em dash. It is never guessed from a
  neighbouring line, because `learned.FALSE_JOINS` measured fqdn<->ipv4
  co-occurrence at 20.9% — i.e. mostly wrong.
* `first_ts` comes from real lines carrying the same connection ID, via
  the slice-14 edge table. If the store was built with
  `index_ids=False`, `first_ts` is simply the close timestamp and
  `lifetime_available` is False.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .protocol_grammar import (
    RE_FLOW_DESTRUCTOR,
    RE_TCP_CONN_CLOSE,
    RE_UDP_CONN_CLOSE,
    RE_ZPA_TAG_BYTES,
)
# `_row_to_line` is the store's own row->IndexedLine conversion. Reused
# rather than re-implemented so the two can never drift on column order.
from .log_store import _COLS, _row_to_line

# --------------------------------------------------------------------
# Carrier prefilters
# --------------------------------------------------------------------
# Cheap SQL LIKE anchors that select candidate records before any regex
# runs. Each is a literal the corresponding carrier regex REQUIRES, so
# a record that fails all three cannot be a close record.
_CARRIER_LIKES = (
    "%clt_bytes%",        # RE_TCP_CONN_CLOSE
    "%Connection closed.%",  # RE_UDP_CONN_CLOSE
    "%destructor!!%",     # RE_FLOW_DESTRUCTOR
)

#: The UDP close line continues past what `RE_UDP_CONN_CLOSE` captures:
#: `... Rx Bytes: 1180 Rx packets: 4`. learned.py stops at Rx Bytes, so
#: the receive packet count is picked up here rather than by widening a
#: verified pattern.
_RE_UDP_RX_PACKETS = re.compile(r"Rx packets:\s*(\d+)", re.I)

#: Destination evidence for a TCP flow. The close record itself carries
#: only `ID=` and the byte totals — no destination — so the destination
#: has to come from another line of the SAME connection. These are the
#: labelled forms ZCC writes on the request path, e.g.
#:   ID=321378895, HTTP Request Version: HTTP/1.1 Host=127.0.0.1:9000 ...
#:   ID=321378895, readFromClient: Host Address: 127.0.0.1:9000
#: Anchored on the label, never on a bare dotted token.
_RE_DEST_HOST = re.compile(
    r"(?:Host Address:\s*|Host=)(?P<host>[A-Za-z0-9_.\-]+)"
    r"(?::(?P<port>\d{1,5}))?",
)

#: Running counters + keepalives. Compiled ONLY for
#: `running_counter_report`, never for the ledger itself.
_RE_KEEPALIVE_BYTES = re.compile(
    r"sendKeepAlive:\s*Sent bytes:\s*(\d+)", re.I)


@dataclass(frozen=True)
class Flow:
    """One connection's final accounting, as written by ZCC at close.

    `client_bytes` / `server_bytes` map onto the log fields like this:

        tcp close   clt_bytes   -> client_bytes   srv_bytes -> server_bytes
        udp close   Tx Bytes    -> client_bytes   Rx Bytes  -> server_bytes
        destructor  tx bytes    -> client_bytes   rx_byptes -> server_bytes

    The UDP and destructor lines are written from the proxy's point of
    view (Tx = sent towards the destination), which is the same
    direction ZCC calls "client" on the TCP line. The mapping is stated
    here rather than left implicit because getting it backwards silently
    reverses every upload/download conclusion drawn from this table.
    """
    conn_id: str
    proto: str                      # "tcp" | "udp"
    first_ts: datetime              # earliest line carrying conn_id
    last_ts: datetime               # the close record itself
    client_bytes: int
    server_bytes: int
    packets_tx: Optional[int]
    packets_rx: Optional[int]
    # An IP for UDP (`Dst Addr: 10.147.59.122:53`) and usually a
    # hostname for TCP (`Host=aks-prod-eastus...`), because those are
    # the two forms the log actually writes. Not normalised to one or
    # the other — resolving a name to an address would be inference.
    dest: Optional[str]
    dest_port: Optional[int]
    dest_source_file: Optional[str]  # provenance for the destination
    dest_line_no: Optional[int]
    source_file: str                # provenance for the byte totals
    line_no: int
    carrier: str                    # which verified pattern produced it
    lifetime_lines: int             # lines attributed to this flow

    @property
    def total_bytes(self) -> int:
        return self.client_bytes + self.server_bytes

    @property
    def destination(self) -> Optional[str]:
        if not self.dest:
            return None
        return (f"{self.dest}:{self.dest_port}" if self.dest_port
                else self.dest)


@dataclass
class AggRow:
    """One aggregate row, with the evidence it was built from.

    `flow_ids` are indexes into `FlowLedger.flows` — the drill-down from
    a row to the individual connections. `provenance` is a small sample
    of (source_file, line_no) for the UI to show without opening the
    drill-down; `provenance_complete` says whether the sample is the
    whole set.
    """
    key: str
    flows: int
    client_bytes: int
    server_bytes: int
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    flow_ids: List[int] = field(default_factory=list)
    provenance: List[Tuple[str, int]] = field(default_factory=list)
    provenance_complete: bool = True

    @property
    def total_bytes(self) -> int:
        return self.client_bytes + self.server_bytes


@dataclass
class FlowLedger:
    """Every reconstructed flow in one bundle, plus the accounting."""
    flows: List[Flow] = field(default_factory=list)
    #: close records seen per carrier, before de-duplication
    carrier_counts: Dict[str, int] = field(default_factory=dict)
    #: connection IDs that produced BOTH a TCP-close and a destructor
    #: record. Counted, and only the TCP close is kept — see
    #: `_dedupe_carriers`.
    duplicate_carrier_conn_ids: int = 0
    #: candidate records the prefilter selected but no carrier matched
    unmatched_candidates: int = 0
    #: lines carrying a conn_id after that ID's last close record —
    #: connections still open when the bundle was captured
    lines_after_last_close: int = 0
    lifetime_available: bool = True
    conn_ids_reused: int = 0
    #: `LogStore.duplicate_source_files` — bundles that ship a log twice
    #: (an extracted copy beside its rotation, or a nested bundle) really
    #: do contain each of those connections twice, and the ledger totals
    #: will say so. Carried here so the number is visible next to the
    #: totals instead of having to be remembered.
    source_files_duplicated: int = 0

    # ---- aggregation (the primary interface) ----
    def totals(self) -> Dict[str, object]:
        """Bundle-level totals. 2.6 M flows never reach a UI as rows."""
        tcp = sum(1 for f in self.flows if f.proto == "tcp")
        udp = sum(1 for f in self.flows if f.proto == "udp")
        clt = sum(f.client_bytes for f in self.flows)
        srv = sum(f.server_bytes for f in self.flows)
        ptx = sum(f.packets_tx or 0 for f in self.flows)
        prx = sum(f.packets_rx or 0 for f in self.flows)
        no_dest = sum(1 for f in self.flows if f.dest is None)
        return {
            "flows": len(self.flows),
            "tcp_flows": tcp,
            "udp_flows": udp,
            "client_bytes": clt,
            "server_bytes": srv,
            "total_bytes": clt + srv,
            "packets_tx": ptx or None,
            "packets_rx": prx or None,
            "first_ts": min((f.first_ts for f in self.flows), default=None),
            "last_ts": max((f.last_ts for f in self.flows), default=None),
            "flows_without_destination": no_dest,
            "zero_byte_flows": sum(1 for f in self.flows
                                   if f.total_bytes == 0),
            "carrier_counts": dict(self.carrier_counts),
            "source_files_duplicated": self.source_files_duplicated,
        }

    def by_destination(self, top: Optional[int] = None,
                       provenance_limit: int = 5) -> List[AggRow]:
        """Traffic per destination, busiest first by total bytes.

        Flows whose records carry no destination are grouped under the
        key `"(no destination on record)"` rather than dropped or
        attributed to a guess — on a TCP-heavy bundle that group can be
        large, and hiding it would silently shrink the totals.
        """
        buckets: Dict[str, List[int]] = defaultdict(list)
        for i, f in enumerate(self.flows):
            buckets[f.destination or "(no destination on record)"].append(i)
        rows = [self._row(k, ids, provenance_limit)
                for k, ids in buckets.items()]
        rows.sort(key=lambda r: (-r.total_bytes, r.key))
        return rows[:top] if top else rows

    def by_hour(self, provenance_limit: int = 5) -> List[AggRow]:
        """Traffic per UTC hour, oldest first.

        Bucketed on the CLOSE timestamp, because that is the moment the
        totals were written; a long-lived connection contributes all of
        its bytes to the hour it ended in. Stated because the obvious
        alternative (spreading bytes over the connection's lifetime)
        would be interpolation, and nothing here interpolates.
        """
        buckets: Dict[str, List[int]] = defaultdict(list)
        for i, f in enumerate(self.flows):
            buckets[f.last_ts.strftime("%Y-%m-%d %H:00 UTC")].append(i)
        rows = [self._row(k, ids, provenance_limit)
                for k, ids in buckets.items()]
        rows.sort(key=lambda r: r.key)
        return rows

    def by_proto(self, provenance_limit: int = 5) -> List[AggRow]:
        buckets: Dict[str, List[int]] = defaultdict(list)
        for i, f in enumerate(self.flows):
            buckets[f.proto].append(i)
        return sorted((self._row(k, ids, provenance_limit)
                       for k, ids in buckets.items()),
                      key=lambda r: (-r.total_bytes, r.key))

    def flows_for(self, row: AggRow) -> List[Flow]:
        """The individual connections behind an aggregate row."""
        return [self.flows[i] for i in row.flow_ids]

    def _row(self, key: str, ids: Sequence[int],
             provenance_limit: int) -> AggRow:
        fl = [self.flows[i] for i in ids]
        prov = [(f.source_file, f.line_no) for f in fl[:provenance_limit]]
        return AggRow(
            key=key,
            flows=len(fl),
            client_bytes=sum(f.client_bytes for f in fl),
            server_bytes=sum(f.server_bytes for f in fl),
            first_ts=min(f.first_ts for f in fl),
            last_ts=max(f.last_ts for f in fl),
            flow_ids=list(ids),
            provenance=prov,
            provenance_complete=len(prov) == len(fl),
        )


# --------------------------------------------------------------------
# Build
# --------------------------------------------------------------------

def _parse_close(text: str) -> Optional[dict]:
    """Match one record against the three FINAL carriers, in order."""
    m = RE_TCP_CONN_CLOSE.search(text)
    if m:
        return {
            "carrier": "tcp_conn_close", "proto": "tcp",
            "conn_id": m.group("conn"),
            "client_bytes": int(m.group("clt")),
            "server_bytes": int(m.group("srv")),
            "packets_tx": None, "packets_rx": None,
            "dest": None, "dest_port": None,
        }
    m = RE_UDP_CONN_CLOSE.search(text)
    if m:
        dst = m.group("dst") or ""
        ip, _, port = dst.rpartition(":")
        return {
            "carrier": "udp_conn_close", "proto": "udp",
            "conn_id": m.group("conn"),
            "client_bytes": int(m.group("tx")),
            "server_bytes": int(m.group("rx")),
            "packets_tx": int(m.group("txp")),
            "packets_rx": (int(_RE_UDP_RX_PACKETS.search(text).group(1))
                           if _RE_UDP_RX_PACKETS.search(text) else None),
            # `Dst Addr: 10.147.59.122:53` — the destination IS on this
            # record, so a UDP flow never needs the lifetime lookup.
            "dest": ip or dst or None,
            "dest_port": int(port) if port.isdigit() else None,
        }
    m = RE_FLOW_DESTRUCTOR.search(text)
    if m:
        return {
            "carrier": "flow_destructor",
            "proto": m.group("kind").lower(),
            "conn_id": m.group("conn"),
            "client_bytes": int(m.group("tx")),
            "server_bytes": int(m.group("rx")),
            "packets_tx": None, "packets_rx": None,
            "dest": None, "dest_port": None,
        }
    return None


def _candidate_lines(store):
    """Records that could be a close record, body OR continuation.

    One query per source, not one per pattern: an earlier version ran
    three queries and de-duplicated the results on (source_file,
    line_no), which quietly dropped 25 TCP and 188 UDP close records on
    bundle 21 — that address was not unique until the store started
    labelling duplicate basenames. Never de-duplicate on an address you
    have not proved to be a key.

    The second query exists because slice 13 attaches untimestamped
    lines to the record above them, so a wrapped close line is not in
    `body` at all; the NOT LIKE clause keeps a record that matched on
    both sides from being yielded twice.
    """
    where_body = " OR ".join("body LIKE ?" for _ in _CARRIER_LIKES)
    cur = store._conn.execute(
        f"SELECT {_COLS} FROM lines WHERE {where_body}", _CARRIER_LIKES)
    for r in cur.fetchall():
        yield _row_to_line(r)
    cols_q = ", ".join("l." + c for c in _COLS.split(","))
    where_cont = " OR ".join("c.cont LIKE ?" for _ in _CARRIER_LIKES)
    where_not = " AND ".join("l.body NOT LIKE ?" for _ in _CARRIER_LIKES)
    cur = store._conn.execute(
        f"SELECT {cols_q} FROM lines l JOIN line_cont c "
        f"ON c.source_file = l.source_file AND c.line_no = l.line_no "
        f"WHERE ({where_cont}) AND ({where_not})",
        _CARRIER_LIKES + _CARRIER_LIKES)
    for r in cur.fetchall():
        yield _row_to_line(r)


def _lifetime_index(store, conn_ids: Sequence[str], batch: int = 400):
    """`conn_id -> [(ts, source_file, line_no, body), ...]`, oldest first.

    Straight off the slice-14 edge table: this is the JOIN that used to
    be a `LIKE '%ID=716357394%'` scan of the whole bundle.
    """
    out: Dict[str, List[tuple]] = defaultdict(list)
    ids = list(conn_ids)
    cols = "e.id_value, lines.ts, lines.source_file, lines.line_no, lines.body"
    for i in range(0, len(ids), batch):
        chunk = ids[i:i + batch]
        q = (f"SELECT {cols} FROM line_ids e JOIN lines "
             f"ON lines.source_file = e.source_file "
             f"AND lines.line_no = e.line_no "
             f"WHERE e.id_type = 'conn_id' AND e.id_value IN "
             f"({','.join('?' * len(chunk))})")
        for v, ts, sf, ln, body in store._conn.execute(q, chunk):
            out[v].append((ts, sf, ln, body))
    for v in out:
        out[v].sort()
    return out


def _dedupe_carriers(records: List[dict]) -> Tuple[List[dict], int]:
    """Drop a destructor record when the same connection also produced a
    TCP close record.

    Both are final, so summing both would double count the connection.
    The `~ZTCPServerConnection` line is preferred because it is the one
    verified across 46/46 bundles (2,637,331 records) and it carries the
    client/server split; the destructor carries only tx/rx. Measured on
    bundles 01/05/18/21: zero destructor records, so this path is
    defensive — but it is cheap and the alternative is a silent
    doubling on whatever bundle does emit both.
    """
    tcp_close_ids = {r["conn_id"] for r in records
                     if r["carrier"] == "tcp_conn_close"}
    kept, dropped = [], 0
    for r in records:
        if (r["carrier"] == "flow_destructor"
                and r["conn_id"] in tcp_close_ids):
            dropped += 1
            continue
        kept.append(r)
    return kept, dropped


def build_ledger(store, lifetime: bool = True) -> FlowLedger:
    """Reconstruct every closed connection in `store`.

    `lifetime=False` skips the per-connection line lookup: flows still
    carry their byte totals and their own timestamp, but `first_ts`
    equals the close time and TCP flows have no destination (the close
    record does not carry one).

    Cost, measured on bundle 21 (1,126,322 lines, 5,131 flows): 1.1 s
    with lifetime enrichment, because the connection lookup is a JOIN on
    the slice-14 edge table rather than a text scan.
    """
    ledger = FlowLedger()
    ledger.source_files_duplicated = getattr(
        store, "duplicate_source_files", 0)
    raw: List[dict] = []
    carrier_counts: Dict[str, int] = defaultdict(int)

    for line in _candidate_lines(store):
        text = store.record_text(line)
        parsed = _parse_close(text)
        if parsed is None:
            ledger.unmatched_candidates += 1
            continue
        parsed["ts"] = line.ts
        parsed["source_file"] = line.source_file
        parsed["line_no"] = line.line_no
        carrier_counts[parsed["carrier"]] += 1
        raw.append(parsed)

    ledger.carrier_counts = dict(carrier_counts)
    raw, dropped = _dedupe_carriers(raw)
    ledger.duplicate_carrier_conn_ids = dropped
    raw.sort(key=lambda r: (r["ts"], r["source_file"], r["line_no"]))

    lifetimes: Dict[str, List[tuple]] = {}
    if lifetime and getattr(store, "ids_indexed", False):
        lifetimes = _lifetime_index(store, {r["conn_id"] for r in raw})
    else:
        ledger.lifetime_available = False

    # Segment each connection ID's lines by its successive close
    # records. ZCC reuses connection IDs after a service restart (the
    # same gotcha that bit the tag_id correlator) — 1,512 of bundle 21's
    # 4,248 connection IDs close more than once — so a flow is keyed on
    # its close RECORD, never on the ID alone: line -> first close at or
    # after it.
    closes_by_id: Dict[str, List[dict]] = defaultdict(list)
    for r in raw:
        closes_by_id[r["conn_id"]].append(r)
    ledger.conn_ids_reused = sum(1 for v in closes_by_id.values()
                                 if len(v) > 1)

    assigned: Dict[Tuple[str, int], List[tuple]] = defaultdict(list)
    for cid, closes in closes_by_id.items():
        rows = lifetimes.get(cid, ())
        if not rows:
            continue
        bounds = [c["ts"].timestamp() for c in closes]
        j = 0
        for ts, sf, ln, body in rows:
            while j < len(bounds) and ts > bounds[j]:
                j += 1
            if j >= len(bounds):
                ledger.lines_after_last_close += 1
                continue
            c = closes[j]
            assigned[(c["source_file"], c["line_no"])].append(
                (ts, sf, ln, body))

    for r in raw:
        key = (r["source_file"], r["line_no"])
        own = assigned.get(key, [])
        first_ts = (datetime.fromtimestamp(own[0][0], tz=timezone.utc)
                    if own else r["ts"])
        dest_val, dest_port = r["dest"], r["dest_port"]
        dest_sf, dest_ln = (r["source_file"], r["line_no"]) if dest_val \
            else (None, None)
        if dest_val is None:
            for _ts, sf, ln, body in own:
                m = _RE_DEST_HOST.search(body or "")
                if m:
                    dest_val = m.group("host")
                    dest_port = (int(m.group("port")) if m.group("port")
                                 else None)
                    dest_sf, dest_ln = sf, ln
                    break
        ledger.flows.append(Flow(
            conn_id=r["conn_id"], proto=r["proto"],
            first_ts=first_ts, last_ts=r["ts"],
            client_bytes=r["client_bytes"], server_bytes=r["server_bytes"],
            packets_tx=r["packets_tx"], packets_rx=r["packets_rx"],
            dest=dest_val, dest_port=dest_port,
            dest_source_file=dest_sf, dest_line_no=dest_ln,
            source_file=r["source_file"], line_no=r["line_no"],
            carrier=r["carrier"], lifetime_lines=len(own),
        ))
    return ledger


# --------------------------------------------------------------------
# What was deliberately left out
# --------------------------------------------------------------------

def running_counter_report(store) -> Dict[str, object]:
    """Count the byte-carrying lines the ledger refuses to total.

    Returns the records and the summed byte values for the two excluded
    families, so the difference between "what the ledger reports" and
    "what a naive sum of every `bytes` field would report" is a number
    the operator can see rather than a claim they have to trust.

    `zpa_tag_bytes_sum` in particular is NOT traffic: it is the sum of
    running counters, so the same byte is counted once per log line it
    appeared on. Bundle 21: 49,194 records summing to 103,650,530
    against a real ledger total of 1,463,293.
    """
    tag_records = tag_sum = 0
    ka_records = ka_sum = 0
    for like, kind in (("%written bytes%", "tag"),
                       ("%rxBytes%", "tag"),
                       ("%sendKeepAlive%", "keepalive")):
        cur = store._conn.execute(
            "SELECT body, source_file, line_no FROM lines WHERE body LIKE ?",
            (like,))
        for body, _sf, _ln in cur.fetchall():
            if kind == "tag":
                for m in RE_ZPA_TAG_BYTES.finditer(body or ""):
                    tag_records += 1
                    tag_sum += int(m.group("bytes"))
            else:
                for m in _RE_KEEPALIVE_BYTES.finditer(body or ""):
                    ka_records += 1
                    ka_sum += int(m.group(1))
    return {
        "zpa_tag_byte_records": tag_records,
        "zpa_tag_bytes_sum": tag_sum,
        "keepalive_records": ka_records,
        "keepalive_bytes_sum": ka_sum,
        "note": ("running counters and keepalives; excluded from the "
                 "ledger by construction, shown here for comparison"),
    }
