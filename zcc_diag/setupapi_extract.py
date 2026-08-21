"""Windows ``setupapi.dev.log`` reader — Slice 18 (2026-08-19).

The Windows *device install log*. Every Windows ZCC bundle carries one and
until now the toolkit threw it away: it is not a ZCC-format line
(``YYYY-MM-DD HH:MM:SS (-0400) [pid:tid] LVL body``), so ``log_parser``
skipped the file and ``log_store`` never indexed a byte of it.

Measured on the extracted corpus at ``outputs/corpus`` (26 bundles):

* 17 of 26 bundles carry a ``setupapi.dev.log`` — 26.7 MB, 369,128 lines.
  The 9 without it are the macOS bundles and the ZPA-only exports.
* 16,721 sections open (``>>>  [...]``), 16,717 close with an exit status.
  The 4 that never close are real: 2 in bundle 06 are abandoned
  mid-file (a Lenovo ``DrvSetupInstallDriver`` that the writing process
  never finished), 2 more sit at end-of-file where the log was cut.
* 14,318 of the 16,721 sections (85.6%) are
  ``Device Installation Restrictions Policy Check`` — a no-body probe
  Windows emits on every PnP arrival. Any "sections parsed" number that
  does not say this out loud is mostly counting noise. The remaining
  2,403 substantive sections span 25 distinct kinds.

What this module is for
-----------------------
ZCC's own logs show the *symptom* of a network-filter conflict
(``ZEVENT_FW_SUBLAYER_WEIGHT_MISMATCH``, ``Highest weight sublayer:``).
setupapi shows *when the drivers were staged, installed, removed or
reinstalled*, with signature and version, which is what turns a symptom
into a timeline.

What the corpus actually contains — read this before trusting a search
---------------------------------------------------------------------
* **Zscaler LWF is here.** ``ZS_ZAPPRD`` / ``zapprd.sys`` appears in 10 of
  the 17 files (41 sections), as the pair
  ``SetupCopyOEMInf - ...\\ZAPPRD.inf`` followed
  by ``Install network driver - ZS_ZAPPRD``, and on removal as
  ``Deinstall network driver`` (``netcfg.exe -u zs_zapprd``) plus
  ``DelService=zapprd``. 14 ``Install network driver - ZS_ZAPPRD``
  sections corpus-wide.
* **Defender ATP's ``SenseNdr`` is NOT here.** Zero hits for
  ``SenseNdr``/``WdNisDrv``/``MsSecFlt``/"Windows Defender" across all
  369,128 lines of all 17 files. This is not a parser gap — it is how
  Windows works: the WFP sublayer that ``ZEVENT_FW_SUBLAYER_WEIGHT_MISMATCH``
  complains about is registered at *runtime* by the ``SENSE`` service
  through the WFP API (``FwpmSubLayerAdd``); it is not a PnP driver
  install and never passes through SetupAPI. setupapi can date the
  Zscaler side of that conflict. It cannot date the Defender side.
  Callers must not present an absence of SenseNdr here as evidence that
  Defender ATP is absent.
* Competing network stacks that DO show up: Npcap (``INSECURE_NPCAP``,
  18 sections), WireGuard + Wintun (bundle 24 — 83 ``Delete Device -
  SWD\\WIREGUARD`` sections), OpenVPN DCO (``ovpn-dco``), Palo Alto
  GlobalProtect (``PanGpd``), SonicWall VPN (``SnwlVA``), NordLayer TAP
  (``tapnordlayer``), Citrix.

Clocks — the one thing that is easy to get wrong here
-----------------------------------------------------
setupapi writes **local wall-clock**, ``YYYY/MM/DD HH:MM:SS.mmm``, with no
zone and no offset. ZCC log lines are the opposite: the numeric time on a
ZCC line **is UTC** and the ``(-0400)`` is device-local-offset metadata.
Mixing the two silently produces an error equal to the device's offset —
4 to 7 hours on the US bundles, which is longer than most incidents.

So every timestamp this module produces is a *naive* ``datetime`` and is
named ``*_local``. There is no ``tzinfo`` on it, deliberately, so a
comparison against a tz-aware ZCC timestamp raises ``TypeError`` instead
of quietly returning a wrong answer. To correlate, the caller must call
:func:`to_utc` and hand it the offset it read off a ZCC log line. There
is no default offset and nothing is inferred from ``AppInfo.xml`` —
Windows reports the STANDARD offset there year-round.

No findings, no severity, no ranking, no inference. Every field on a
:class:`SetupApiSection` came from a line that this module can point at
by file and line number.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

log = logging.getLogger(__name__)

__all__ = [
    "SETUPAPI_CLOCK",
    "SETUPAPI_CLOCK_NOTE",
    "POLICY_CHECK_KIND",
    "NETWORK_CLASS_GUIDS",
    "SetupApiSection",
    "SetupApiLog",
    "DriverEvent",
    "find_setupapi_logs",
    "parse_file",
    "parse_lines",
    "iter_sections",
    "select",
    "in_time_order",
    "device_timeline",
    "network_driver_events",
    "kind_counts",
    "exit_status_counts",
    "to_utc",
]


# --------------------------------------------------------------------
# Clock contract
# --------------------------------------------------------------------

#: Machine-readable marker for the clock every ``*_local`` field uses.
#: Consumers that render timestamps should branch on this rather than
#: assume; ZCC's own line timestamps carry ``"utc"``.
SETUPAPI_CLOCK = "naive-local"

SETUPAPI_CLOCK_NOTE = (
    "setupapi.dev.log timestamps are device LOCAL wall-clock with no zone "
    "recorded. ZCC log-line timestamps are UTC (the parenthesised offset "
    "on a ZCC line is device-local metadata, not part of the clock). "
    "These two are not comparable without an explicit UTC offset — see "
    "setupapi_extract.to_utc()."
)


def to_utc(local_naive: datetime, utc_offset: timedelta) -> datetime:
    """Convert a naive-local setupapi timestamp to an aware UTC one.

    ``utc_offset`` is the device's *actual* offset at that instant and is
    mandatory. Get it from the ``(-0400)`` field of a ZCC log line near
    the same wall-clock time — that field is the only place in a bundle
    that records the true offset in force. Do not take it from
    ``AppInfo.xml``: Windows reports the STANDARD offset there all year
    (``(UTC-05:00) Eastern Time`` even in June), which is an hour wrong
    for half the calendar.

    Raises ``ValueError`` if handed an already-aware datetime, because
    that means the caller has mixed clocks somewhere upstream.
    """
    if local_naive.tzinfo is not None:
        raise ValueError(
            "to_utc() expects a naive-local setupapi timestamp; got an "
            "aware datetime, which suggests a clock mix-up upstream"
        )
    return (local_naive - utc_offset).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------
# Line grammar
# --------------------------------------------------------------------
# Every anchor below was counted against the corpus (/tmp/all.txt =
# concatenation of all 17 files, 369,128 lines) so the denominators in
# the module docstring are reproducible.

#: ``>>>  [Install network driver - ZS_ZAPPRD]`` — 16,721 matches.
_RE_HEADER = re.compile(r"^>>>\s+\[(?P<head>.*)\]\s*$")

#: ``>>>  Section start 2026/07/01 05:04:15.644`` — 16,721 matches, i.e.
#: exactly one per header. The two counts being equal is why a header is
#: a safe section anchor.
_RE_START = re.compile(
    r"^>>>\s+Section start\s+(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s*$"
)

#: ``<<<  Section end 2026/07/01 05:04:17.045`` — 16,717 matches.
_RE_END = re.compile(
    r"^<<<\s+Section end\s+(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s*$"
)

#: ``<<<  [Exit status: SUCCESS]`` — 16,717 matches. Observed values:
#: SUCCESS (16,489), FAILURE(0x00000002) (87), FAILURE(0x00000003) (85),
#: FAILURE(0x00000103) (51), SUCCESS (REBOOT_REQUIRED) (4),
#: FAILURE(0x00000057) (1).
_RE_EXIT = re.compile(r"^<<<\s+\[Exit status:\s*(?P<status>.*?)\]\s*$")

#: ``[Boot Session: 2026/03/17 05:10:46.184]`` — 129 corpus-wide.
_RE_BOOT = re.compile(
    r"^\[Boot Session:\s*(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\s*$"
)

#: File preamble. A single file can contain more than one of these: the
#: log wraps, and 3 of the 17 files have a binary-garbage region followed
#: by a fresh ``[Device Install Log]`` block mid-file.
_RE_LOGHDR = re.compile(r"\[Device Install Log\]\s*$")
_RE_PREAMBLE_KV = re.compile(
    r"^\s+(?P<key>OS Version|Service Pack|Suite|ProductType|Architecture)"
    r"\s*=\s*(?P<val>.+?)\s*$"
)

#: Body line: optional bang column, 3-letter subsystem tag, payload.
#: Corpus tag census: sto 80,263 / inf 75,059 / idb 24,674 / pol 19,400 /
#: utl 17,849 / flq 15,793 / cpy 10,429 / dvi 9,176 / dvs 5,271 /
#: sig 4,238 / set 2,569 / cmd 2,342 / ump 919 / ndv 426.
#: The bang column is exactly two widths — ``!`` (42,271) for warnings
#: and ``!!!`` (262) for errors. There is no ``!!``.
_RE_BODY = re.compile(r"^(?P<bang>!{0,3})\s+(?P<tag>[a-z]{3}):(?P<rest>.*)$")

_TS_FMT = "%Y/%m/%d %H:%M:%S.%f"


def _parse_ts(raw: str) -> Optional[datetime]:
    """``2026/07/01 05:04:15.644`` -> naive datetime. None if malformed.

    Returns naive on purpose. See the module docstring: attaching a
    tzinfo here would be a guess, and a wrong one on any device that
    moved between zones or crossed a DST boundary mid-log.
    """
    try:
        return datetime.strptime(" ".join(raw.split()), _TS_FMT)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------
# Body-field grammar
# --------------------------------------------------------------------
# The same logical field is written three ways depending on which
# subsystem emitted it and how deeply nested it is. Corpus counts for
# ``Class GUID`` alone: ``inf: Class GUID = {...}`` 3,470,
# ``utl: Class GUID - {...}`` 1,696, ``dvs: ... - ...`` 258,
# ``set: ... : ...`` 211, ``dvi: ... - ...`` 29, ``inf: ... : ...`` 70.
# A parser that reads only the ``=`` form loses 2,264 of 5,734 — and one
# that reads only ``inf`` loses every Driver Node block, which is where
# the ZS_ZAPPRD install records its version.
#
# So the separator class is ``[:=-]``, and each field carries the SET OF
# TAGS it was actually observed under. The tag set is the guard, not a
# blanket "match anywhere": a bare `Provider\s*[:=]` over all lines also
# hits ETW-provider braces (``dvi: {Add ETW provider: Intel-NPU-Kmd}``)
# and would report an ETW provider as the INF publisher. Two things stop
# that — the ``^\s*`` anchor (scope markers always open with ``{``) and
# the tag set (``provider`` is only ever read off ``inf``).

_KV = r"\s*(?:[:=]|-)\s*"


def _field(tags: str, name: str, attr: str) -> Tuple[frozenset, re.Pattern, str]:
    return (
        frozenset(tags.split()),
        re.compile(rf"^\s*{re.escape(name)}{_KV}(?P<v>\S.*?)\s*$"),
        attr,
    )


#: (allowed tags, regex, attribute). First value wins per attribute — the
#: outermost occurrence, since the nested repeats are the driver-store
#: copy restating the same INF. Tag sets are exactly what was measured;
#: nothing speculative is listed.
_SCALARS: List[Tuple[frozenset, re.Pattern, str]] = [
    # `Catalog File` also appears under `sig` (235x) but there it is the
    # full DriverStore\Temp path of the catalog being verified, not the
    # INF's declared catalog name. Different fact, so `sig` is excluded.
    _field("inf", "Provider", "provider"),
    _field("inf utl dvs sto ndv", "Driver Version", "driver_version_raw"),
    _field("inf", "Catalog File", "catalog_file"),
    _field("inf", "Driver Store Path", "driver_store_path"),
    _field("inf", "Published Inf Path", "published_inf_path"),
    _field("sig", "Signer Name", "signer_name"),
    _field("sig utl dvi", "Signer Score", "signer_score"),
    _field("sig", "Signer Status", "signer_status"),
    # Driver Node block (`dvi:` inside `{Build Driver List}`) splits the
    # version across two lines instead of the combined
    # `MM/DD/YYYY,a.b.c.d`. This is the ONLY place the ZS_ZAPPRD
    # `Install network driver` section states its version — 58 `Version`
    # and 58 `DrvDate` lines corpus-wide.
    _field("dvi", "Version", "node_version"),
    _field("dvi", "DrvDate", "node_drvdate"),
]

#: ``dvi:           DevDesc      - Zscaler LightWeight Filter``
#: and ``dvi:           Description - Zscaler LightWeight Filter``.
#: Measured device descriptions include "Zscaler LightWeight Filter" (14),
#: "Npcap Packet Driver (NPCAP)" (18), "PANGP Virtual Ethernet Adapter
#: Secure", "SonicWall VPN Adapter", "TAP-NordLayer Windows Adapter V9",
#: "OpenVPN Data Channel Offload".
#:
#: Restricted to the device-oriented tags. ``inf: Description = ...``
#: (53 lines) is the *Windows service* description from an AddService
#: block — "RPC endpoint service which allows..." — a different fact that
#: would silently pollute the device name if this ran on ``inf`` too.
_RE_DEVDESC = re.compile(r"^\s*(?:DevDesc|Description)\s+-\s+(?P<v>.+?)\s*$")
_DEVDESC_TAGS = frozenset({"dvi", "utl", "ndv", "dvs"})
_RE_HWID = re.compile(r"^\s*HardwareID\s+-\s+(?P<v>.+?)\s*$")
#: ``dvi: InfName - c:\...\zapprd.inf`` and, in the `utl:`/`dvs:` Driver
#: Node block, ``Driver INF - oem301.inf (C:\WINDOWS\...\wireguard.inf)``.
_RE_INFNAME = re.compile(r"^\s*(?:InfName|Driver INF)\s+-\s+(?P<v>.+?)\s*$")

#: Windows' own literal for "this field has no value". Kept out of the
#: name lists so a device does not end up called "<none>". Reading a
#: documented null marker as null is not inference.
_NULL_MARKERS = frozenset({"<none>", "(none)", "n/a"})

#: Class GUID gets its own collector rather than a first-wins scalar,
#: because 190 of the 2,403 substantive sections (7.9%) name MORE THAN
#: ONE distinct setup class — a `Driver Install (DrvSetupInstallDriver)`
#: over a vendor bundle touches several INFs, and a
#: `Device Install (DiInstallDriver)` logs both the candidate class and
#: the "Class GUID of device changed to:" result. Collapsing that to one
#: value would silently pick an arbitrary winner, so all of them are
#: kept and :attr:`SetupApiSection.class_guid_ambiguous` says when it
#: happened.
_RE_CLASSGUID = re.compile(
    r"^\s*Class GUID\s*(?:[:=]|-)\s*(?P<v>\{[0-9a-fA-F-]+\})\s*$"
)
_CLASSGUID_TAGS = frozenset({"inf", "utl", "dvs", "set", "dvi"})
_RE_CREATED_DEV = re.compile(r"Created device '(?P<v>[^']+)'")
_RE_DEVINST = re.compile(r"^\s*Device Instance ID\s*[:=]?\s*(?P<v>\S.*?)\s*$")

#: ``inf: AddService=zapprd,,zapprd_Service_Inst  (oem37.inf line 72)``
#: and ``inf: DelService=zapprd,0x200  (oem144.inf line 85)``. These are
#: the two lines that name the Windows *service* a driver package owns,
#: which is the name that shows up later in ZCC's own driver messages.
_RE_ADDSVC = re.compile(r"AddService\s*=\s*(?P<v>[^,\s]+)")
_RE_DELSVC = re.compile(r"DelService\s*=\s*(?P<v>[^,\s]+)")
#: ``inf: {Add Service: WireGuard}`` — the Win10+ "configure driver"
#: path writes the service name this way instead of AddService=.
_RE_ADDSVC_BRACE = re.compile(r"\{Add Service:\s*(?P<v>[^}]+?)\s*\}")
#: ``dvi: Deleted service 'zapprd'. 15:27:26.124``
_RE_DELETED_SVC = re.compile(r"Deleted service '(?P<v>[^']+)'")
#: ``dvi: Add Service: Created service 'zapprd'.``
_RE_CREATED_SVC = re.compile(r"Created (?:new )?service '(?P<v>[^']+)'")

#: The command line that triggered the section, e.g.
#: ``cmd: "C:\WINDOWS\System32\netcfg.exe" -l "...ZAPPRD.inf" -c s -i ZS_ZAPPRD``
#: 2,342 cmd lines corpus-wide. Present on most non-policy-check sections.
_RE_CMD_PAYLOAD = re.compile(r"^\s*(?P<v>\S.*?)\s*$")

#: ``Driver Version = 05/20/2026,3.8.8.535`` -> date + version.
_RE_DRVVER = re.compile(
    r"^(?P<d>\d{1,2}/\d{1,2}/\d{4})\s*,\s*(?P<v>[0-9][0-9.]*)\s*$"
)


def _parse_mdy(raw: str) -> Optional[date]:
    """``05/20/2026`` -> date. None if it does not parse.

    US ordering is not an assumption: setupapi is a Windows-internal log
    written in the invariant locale, and the corpus confirms it — 06/21,
    08/23, 10/12, 01/14 all appear with a day part above 12 in the second
    position, which only parses as MM/DD.
    """
    try:
        return datetime.strptime(raw, "%m/%d/%Y").date()
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------
# Network-stack classification
# --------------------------------------------------------------------

#: Windows setup-class GUIDs for the network stack. Anything installed
#: under one of these is part of the packet path, which is the class of
#: driver that can collide with the Zscaler LWF.
NETWORK_CLASS_GUIDS: Dict[str, str] = {
    "{4d36e972-e325-11ce-bfc1-08002be10318}": "Net",         # adapters
    "{4d36e973-e325-11ce-bfc1-08002be10318}": "NetTrans",    # protocols
    "{4d36e974-e325-11ce-bfc1-08002be10318}": "NetService",  # LWF / services
    "{4d36e975-e325-11ce-bfc1-08002be10318}": "NetClient",
}

#: Section kinds that are network by construction — netcfg.exe drives
#: these and nothing else does. 29 "Install network driver" and 9
#: "Deinstall network driver" sections corpus-wide.
_NETWORK_KINDS = frozenset({"Install network driver", "Deinstall network driver"})

#: The kind Windows emits on every PnP arrival with an empty body.
#: Exposed because any honest "sections parsed" figure has to subtract it.
POLICY_CHECK_KIND = "Device Installation Restrictions Policy Check"

#: Vendor labels for names actually observed in this corpus, plus the
#: obvious near neighbours in the same product families. This table is
#: ADDITIVE — a section is never excluded from
#: :func:`network_driver_events` for failing to match it, and an
#: unrecognised network driver comes back with ``vendor=None`` rather
#: than being dropped. The point is to save the engineer a lookup, not
#: to define the universe.
_VENDOR_MARKERS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    # Confirmed present in the corpus.
    ("Zscaler", ("zapprd", "zs_zapprd", "zscaler", "zsatdi", "zsafilterdriver")),
    ("Npcap/WinPcap", ("npcap", "winpcap", "insecure_npcap")),
    ("WireGuard", ("wireguard", "wintun")),
    ("OpenVPN", ("ovpn-dco", "openvpn", "tap0901", "tap-windows")),
    ("Palo Alto GlobalProtect", ("pangp", "pangpd", "globalprotect")),
    ("SonicWall", ("snwlva", "sonicwall")),
    ("NordLayer/NordVPN", ("tapnordlayer", "nordlayer", "nordvpn")),
    ("Citrix", ("citrix",)),
    # Not observed in this corpus. Listed because they are the same
    # class of endpoint-security / VPN filter and the next bundle may
    # carry one; each is a name Windows would write here if installed.
    ("Microsoft Defender", ("sensendr", "wdnisdrv", "mssecflt", "windows defender")),
    ("Cisco AnyConnect/Umbrella", ("acsock", "vpnva", "anyconnect", "umbrella", "csc_")),
    ("Fortinet", ("forticlient", "fortissl", "fortinet")),
    ("Check Point", ("checkpoint", "cpepctrl", "trac")),
    ("Netskope", ("netskope", "stagentsvc")),
    ("CrowdStrike", ("csagent", "crowdstrike", "csfirmware")),
    ("SentinelOne", ("sentinel", "sentinelone")),
    ("Sophos", ("sophos",)),
    ("Symantec/Broadcom", ("symantec", "teefer", "srtsp")),
    ("VMware", ("vmnet", "vmware")),
    ("VirtualBox", ("vboxnet",)),
    ("Juniper/Pulse", ("pulse", "juniper", "jnprva")),
)


def _vendor_for(*texts: Optional[str]) -> Optional[str]:
    """Label from the first marker that appears in any supplied text.

    Case-folded substring, not prefix: the same product shows up as
    ``ZS_ZAPPRD`` in a header, ``zs_zapprd`` in a HardwareID and
    ``C:\\Program Files\\Zscaler\\...\\ZAPPRD.inf`` in a path.
    """
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return None
    for label, markers in _VENDOR_MARKERS:
        if any(m in blob for m in markers):
            return label
    return None


# --------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------


@dataclass(frozen=True)
class SetupApiSection:
    """One ``>>>  [...]`` .. ``<<<  [Exit status: ...]`` block.

    Every populated field is a verbatim value from a body line inside
    this section's line range. Fields with no supporting line stay
    ``None`` / empty — nothing here is carried over from a neighbouring
    section or defaulted.
    """

    # --- identity ---------------------------------------------------
    kind: str
    """Text before the first ``" - "`` in the header, e.g.
    ``Install network driver``. 25 distinct kinds corpus-wide."""

    target: Optional[str] = None
    """Text after the first ``" - "``, e.g. ``ZS_ZAPPRD`` or an INF path
    or a device instance ID. ``None`` for the bare kinds
    (``Deinstall network driver``, ``Device Installation Restrictions
    Policy Check``). No header in the corpus contains a second ``" - "``,
    so a single split is unambiguous."""

    raw_header: str = ""

    # --- clock (NAIVE LOCAL — see module docstring) ------------------
    start_local: Optional[datetime] = None
    end_local: Optional[datetime] = None
    boot_session_local: Optional[datetime] = None
    """Most recent ``[Boot Session: ...]`` line above this section."""

    # --- outcome ----------------------------------------------------
    exit_status: Optional[str] = None
    """Verbatim, e.g. ``SUCCESS``, ``SUCCESS (REBOOT_REQUIRED)``,
    ``FAILURE(0x00000103)``. ``None`` means the section never closed."""

    exit_code: Optional[int] = None
    """Integer from ``FAILURE(0x...)``; ``0`` for SUCCESS; ``None`` if the
    section never closed or the status did not parse."""

    succeeded: Optional[bool] = None
    """``True``/``False`` from the status text; ``None`` if unterminated.
    This is a restatement of the log's own word, not a judgement."""

    reboot_required: bool = False

    # --- driver / device identity -----------------------------------
    command: Optional[str] = None
    provider: Optional[str] = None
    class_guid: Optional[str] = None
    """First setup class named in the section. See ``class_guids``."""
    class_guids: Tuple[str, ...] = ()
    """Every distinct setup class the section named, in first-seen order.
    Usually length 0 or 1; 190 of 2,403 substantive sections name more
    than one."""
    network_class: Optional[str] = None
    """``Net`` / ``NetTrans`` / ``NetService`` / ``NetClient`` if ANY entry
    in ``class_guids`` is one of :data:`NETWORK_CLASS_GUIDS`. Read it as
    "this section touched the network stack", not "this section is only
    about the network stack" — check ``class_guid_ambiguous``."""

    driver_version_raw: Optional[str] = None
    driver_version: Optional[str] = None
    driver_date: Optional[date] = None
    """Parsed from the ``MM/DD/YYYY,a.b.c.d`` half of Driver Version.
    This is the INF's declared build date, not an install time."""

    catalog_file: Optional[str] = None
    inf_names: Tuple[str, ...] = ()
    driver_store_path: Optional[str] = None
    published_inf_path: Optional[str] = None
    device_descriptions: Tuple[str, ...] = ()
    hardware_ids: Tuple[str, ...] = ()
    device_instance_ids: Tuple[str, ...] = ()
    services_added: Tuple[str, ...] = ()
    services_removed: Tuple[str, ...] = ()
    signer_name: Optional[str] = None
    signer_score: Optional[str] = None
    signer_status: Optional[str] = None

    # --- annotations the log itself marked --------------------------
    warnings: Tuple[str, ...] = ()
    """Lines the log flagged with a single ``!``. 42,271 corpus-wide."""
    errors: Tuple[str, ...] = ()
    """Lines the log flagged with ``!!!``. 262 corpus-wide."""

    # --- provenance -------------------------------------------------
    source: str = ""
    header_line: int = 0
    """1-based line number of the ``>>>  [...]`` line."""
    last_line: int = 0
    """1-based line number of the ``<<<  [Exit status]`` line, or of the
    last line consumed if the section never closed."""
    body_line_count: int = 0
    body: Tuple[str, ...] = ()
    """Verbatim body lines — empty unless ``parse_file(keep_body=True)``.
    Capped at ``max_body_lines``; ``body_line_count`` is uncapped."""

    log_block: int = 0
    """Which ``[Device Install Log]`` preamble this section falls under.
    Usually 0; 3 of the 17 corpus files wrap and restart the header
    mid-file after a region of binary garbage."""

    # --- derived, but only from this section's own fields ------------
    vendor: Optional[str] = None
    """Best-effort label from :data:`_VENDOR_MARKERS`, or ``None``.
    Advisory only — matching or not matching changes no other field."""

    @property
    def duration(self) -> Optional[timedelta]:
        """End minus start. ``None`` when the section never closed.
        Both endpoints are on the same local clock, so the delta is
        valid even though the absolute times are zone-less."""
        if self.start_local is None or self.end_local is None:
            return None
        return self.end_local - self.start_local

    @property
    def unterminated(self) -> bool:
        return self.exit_status is None

    @property
    def class_guid_ambiguous(self) -> bool:
        """The section named more than one setup class, so ``class_guid``
        and ``network_class`` describe only part of what it did."""
        return len(self.class_guids) > 1

    @property
    def is_policy_check(self) -> bool:
        return self.kind == POLICY_CHECK_KIND

    @property
    def is_network(self) -> bool:
        """Network stack by any of three independent signals: the section
        kind, the INF setup class, or a ``netcfg.exe`` command line."""
        if self.kind in _NETWORK_KINDS:
            return True
        if self.network_class:
            return True
        return bool(self.command and "netcfg.exe" in self.command.lower())

    @property
    def names(self) -> Tuple[str, ...]:
        """Every human-facing name this section carries, deduped and in a
        stable order. This is what substring search runs against."""
        seen: List[str] = []
        for v in (
            (self.target,)
            + self.device_descriptions
            + self.hardware_ids
            + self.inf_names
            + self.services_added
            + self.services_removed
            + self.device_instance_ids
        ):
            if v and v not in seen:
                seen.append(v)
        return tuple(seen)

    def haystack(self) -> str:
        """Case-folded blob used by :func:`select`'s ``contains`` filter.
        Includes the header, the names, the INF paths and the provider —
        i.e. everything an engineer would plausibly type."""
        parts = [self.raw_header, self.provider or "", self.command or "",
                 self.driver_store_path or "", self.published_inf_path or "",
                 self.catalog_file or ""]
        parts.extend(self.names)
        return " ".join(parts).lower()


@dataclass(frozen=True)
class SetupApiLog:
    """One parsed ``setupapi.dev.log``.

    Constructed even when the file is missing or unreadable — check
    :attr:`present` — so callers never need a try/except around parsing.
    """

    source: str
    present: bool = False
    error: Optional[str] = None
    """Why ``present`` is False, or why parsing stopped early. Verbatim
    OS error text; never a diagnosis."""

    # Preamble, first block only (the wrapped blocks restate the same
    # machine, and taking the first keeps the value tied to one line).
    os_version: Optional[str] = None
    service_pack: Optional[str] = None
    suite: Optional[str] = None
    product_type: Optional[str] = None
    architecture: Optional[str] = None

    boot_sessions_local: Tuple[datetime, ...] = ()
    sections: Tuple[SetupApiSection, ...] = ()

    # Accounting — every line of the file lands in exactly one bucket.
    total_lines: int = 0
    section_lines: int = 0
    structural_lines: int = 0
    """Preamble, ``[BeginLog]``, ``[Boot Session: ...]`` and blank lines."""
    unrecognised_lines: int = 0
    """Lines outside any section that matched nothing — binary-garbage
    regions, mostly. 3 of the 17 corpus files contain such a region."""

    bytes_read: int = 0
    truncated_by_limit: bool = False
    """The ``max_bytes``/``max_lines`` budget was hit before EOF."""

    clock: str = SETUPAPI_CLOCK

    # ---- accounting helpers ----------------------------------------

    @property
    def section_count(self) -> int:
        return len(self.sections)

    @property
    def unterminated_count(self) -> int:
        """Sections with no ``[Exit status]``. Corpus: 4 of 16,721."""
        return sum(1 for s in self.sections if s.unterminated)

    @property
    def substantive_sections(self) -> Tuple[SetupApiSection, ...]:
        """Everything that is not the empty-bodied policy-check probe.
        Corpus: 2,403 of 16,721 (14.4%)."""
        return tuple(s for s in self.sections if not s.is_policy_check)

    @property
    def span_local(self) -> Optional[Tuple[datetime, datetime]]:
        stamps = [s.start_local for s in self.sections if s.start_local]
        if not stamps:
            return None
        ends = [s.end_local for s in self.sections if s.end_local]
        return (min(stamps), max(ends + stamps))


@dataclass(frozen=True)
class DriverEvent:
    """One row of the network-filter install/removal summary.

    A flattened view of a :class:`SetupApiSection` — same provenance, no
    new facts. ``action`` is a restatement of the section kind, mapped
    through :data:`_ACTION_BY_KIND`; kinds with no entry keep the kind
    text verbatim.
    """

    when_local: Optional[datetime]
    action: str
    name: str
    """Best available name: device description, else hardware ID, else
    the header target. Never synthesised."""
    vendor: Optional[str]
    driver_version: Optional[str]
    driver_date: Optional[date]
    provider: Optional[str]
    service: Optional[str]
    network_class: Optional[str]
    exit_status: Optional[str]
    succeeded: Optional[bool]
    signer_status: Optional[str]
    source: str
    header_line: int
    last_line: int
    section_kind: str


#: Section kind -> plain verb. Only kinds observed in the corpus are
#: mapped; anything else falls through to the raw kind string so an
#: unmapped kind is visible rather than silently relabelled.
_ACTION_BY_KIND: Dict[str, str] = {
    "Install network driver": "install",
    "Deinstall network driver": "uninstall",
    "SetupCopyOEMInf": "stage",
    "Setup Import Driver Package": "stage",
    "Stage Driver Updates": "stage",
    "Driver Install (DrvSetupInstallDriver)": "install",
    "Device Install (DiInstallDriver)": "install",
    "Device Install (DiInstallDevice)": "install",
    "Device Install (Hardware initiated)": "install",
    "Device Install (UpdateDriverForPlugAndPlayDevices)": "update",
    "Device Install (Install Windows Update driver)": "update",
    "Install Driver Updates": "update",
    "Restart Device": "restart",
    "Delete Device": "delete",
    "Uninstall device subtree": "uninstall",
    "Uninstall device subtree (DiUninstallDevice)": "uninstall",
    "Driver Uninstall (DrvSetupUninstallDriver)": "uninstall",
    "SetupUninstallOEMInf": "unstage",
    "Unstage Driver Updates": "unstage",
    "Uninstall Driver Updates": "unstage",
    "Enable Device Install": "enable",
    "Disable Device Install": "disable",
    "Device and Driver Disk Cleanup Handler": "cleanup",
    "Verify Driver Store Integrity": "verify",
    "Device Installation Restrictions Policy Check": "policy-check",
}


# --------------------------------------------------------------------
# Mutable accumulator (the frozen dataclass is built once, at close)
# --------------------------------------------------------------------


class _Acc:
    """Scratch state for the section currently being read.

    Separate from :class:`SetupApiSection` so the public shape can stay
    frozen and hashable while parsing still does in-place appends.
    """

    __slots__ = (
        "kind", "target", "raw_header", "header_line", "last_line",
        "start_local", "end_local", "exit_status", "boot", "log_block",
        "scalars", "inf_names", "descs", "hwids", "devinsts", "guids",
        "svc_add", "svc_del", "warnings", "errors", "body",
        "body_count", "command", "keep_body", "max_body_lines",
    )

    def __init__(self, header: str, line_no: int, boot, log_block: int,
                 keep_body: bool, max_body_lines: int):
        # Single split: no corpus header has a second " - ".
        kind, _, target = header.partition(" - ")
        self.kind = kind.strip()
        self.target = target.strip() or None
        self.raw_header = header
        self.header_line = line_no
        self.last_line = line_no
        self.start_local: Optional[datetime] = None
        self.end_local: Optional[datetime] = None
        self.exit_status: Optional[str] = None
        self.boot = boot
        self.log_block = log_block
        self.scalars: Dict[str, str] = {}
        self.inf_names: List[str] = []
        self.descs: List[str] = []
        self.hwids: List[str] = []
        self.devinsts: List[str] = []
        self.guids: List[str] = []
        self.svc_add: List[str] = []
        self.svc_del: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
        self.body: List[str] = []
        self.body_count = 0
        self.command: Optional[str] = None
        self.keep_body = keep_body
        self.max_body_lines = max_body_lines

    # -- body ingestion ----------------------------------------------

    @staticmethod
    def _push(bucket: List[str], value: Optional[str], cap: int = 32) -> None:
        """Ordered set-append with a cap.

        Cap exists because one 83-section WireGuard teardown in bundle 24
        repeats the same device ID hundreds of times; an unbounded list
        would be a memory leak dressed as provenance. Dedup keeps the cap
        from ever biting in practice (measured max distinct per section:
        6 hardware IDs).
        """
        if not value:
            return
        v = value.strip()
        if not v or v in bucket:
            return
        if len(bucket) < cap:
            bucket.append(v)

    def feed(self, raw_line: str, line_no: int) -> None:
        self.last_line = line_no
        m = _RE_BODY.match(raw_line)
        if not m:
            # Wrapped/garbled continuation. Counted, not dropped
            # silently: body_line_count is the honest denominator.
            self.body_count += 1
            if self.keep_body and len(self.body) < self.max_body_lines:
                self.body.append(raw_line)
            return

        bang, tag, rest = m.group("bang"), m.group("tag"), m.group("rest")
        self.body_count += 1
        if self.keep_body and len(self.body) < self.max_body_lines:
            self.body.append(raw_line)

        if bang == "!!!":
            if len(self.errors) < 64:
                self.errors.append(raw_line.strip())
        elif bang == "!":
            if len(self.warnings) < 64:
                self.warnings.append(raw_line.strip())

        if tag == "cmd" and self.command is None:
            cm = _RE_CMD_PAYLOAD.match(rest)
            if cm:
                self.command = cm.group("v")
            return

        if tag in _CLASSGUID_TAGS:
            gm = _RE_CLASSGUID.match(rest)
            if gm:
                self._push(self.guids, gm.group("v").lower())

        # Tag-scoped scalars — see the note above _SCALARS for why the
        # tag set is part of the match and not just the field name.
        for tags, pat, name in _SCALARS:
            if tag not in tags or name in self.scalars:
                continue
            sm = pat.match(rest)
            if sm:
                val = sm.group("v").strip()
                if val and val.lower() not in _NULL_MARKERS:
                    self.scalars[name] = val
                break

        if tag in _DEVDESC_TAGS:
            dm = _RE_DEVDESC.match(rest)
            if dm and dm.group("v").strip().lower() not in _NULL_MARKERS:
                self._push(self.descs, dm.group("v"))

        if tag in ("dvi", "utl", "ndv", "dvs", "sto"):
            hm = _RE_HWID.match(rest)
            if hm:
                self._push(self.hwids, hm.group("v"))
            im = _RE_INFNAME.match(rest)
            if im:
                self._push(self.inf_names, im.group("v"))
            cd = _RE_CREATED_DEV.search(rest)
            if cd:
                self._push(self.devinsts, cd.group("v"))
            di = _RE_DEVINST.match(rest)
            if di:
                self._push(self.devinsts, di.group("v"))

        if tag in ("inf", "dvi"):
            for pat, bucket in (
                (_RE_ADDSVC, self.svc_add),
                (_RE_ADDSVC_BRACE, self.svc_add),
                (_RE_CREATED_SVC, self.svc_add),
                (_RE_DELSVC, self.svc_del),
                (_RE_DELETED_SVC, self.svc_del),
            ):
                sm2 = pat.search(rest)
                if sm2:
                    self._push(bucket, sm2.group("v"))

    # -- close --------------------------------------------------------

    def build(self, source: str) -> SetupApiSection:
        status = self.exit_status
        exit_code: Optional[int] = None
        succeeded: Optional[bool] = None
        reboot = False
        if status is not None:
            up = status.upper()
            reboot = "REBOOT_REQUIRED" in up
            if up.startswith("SUCCESS"):
                succeeded, exit_code = True, 0
            else:
                succeeded = False
                fm = re.search(r"\(0x([0-9a-fA-F]+)\)", status)
                if fm:
                    exit_code = int(fm.group(1), 16)

        # Two independent statements of the same fact. `Driver Version`
        # is the combined `MM/DD/YYYY,a.b.c.d` the INF declares; the
        # Driver Node block instead writes `Version -` and `DrvDate -` on
        # separate lines. The combined form is preferred when present;
        # the split form is the fallback, and it is the ONLY form the
        # `Install network driver - ZS_ZAPPRD` sections carry.
        version = self.scalars.get("driver_version_raw")
        drv_ver: Optional[str] = None
        drv_date: Optional[date] = None
        if version:
            vm = _RE_DRVVER.match(version)
            if vm:
                drv_ver = vm.group("v")
                drv_date = _parse_mdy(vm.group("d"))
            else:
                # e.g. `ndv: Driver Version - 2.7.3.0` — version only.
                drv_ver = version
        if drv_ver is None:
            drv_ver = self.scalars.get("node_version")
        if drv_date is None and self.scalars.get("node_drvdate"):
            drv_date = _parse_mdy(self.scalars["node_drvdate"])
        if version is None and drv_ver is not None:
            # Keep `driver_version_raw` honest: it is what a line said.
            version = ", ".join(
                v for v in (self.scalars.get("node_drvdate"), drv_ver) if v
            )

        # `network_class` is "any of them", not "the first of them" — a
        # section that installs a NIC alongside three chipset drivers is
        # still a section that touched the network stack.
        guid = self.guids[0] if self.guids else None
        net_class = next(
            (NETWORK_CLASS_GUIDS[g] for g in self.guids if g in NETWORK_CLASS_GUIDS),
            None,
        )

        # INF name also comes from the header target when the target is a
        # path (SetupCopyOEMInf, Setup Import Driver Package). Recorded as
        # a name, not as evidence of an install.
        inf_names = list(self.inf_names)
        if self.target and self.target.lower().endswith(".inf"):
            base = self.target.replace("/", "\\").rsplit("\\", 1)[-1]
            if base not in inf_names:
                inf_names.insert(0, base)

        vendor = _vendor_for(
            self.raw_header, self.command, self.scalars.get("provider"),
            self.scalars.get("driver_store_path"),
            *self.descs, *self.hwids, *inf_names,
            *self.svc_add, *self.svc_del, *self.devinsts,
        )

        return SetupApiSection(
            kind=self.kind,
            target=self.target,
            raw_header=self.raw_header,
            start_local=self.start_local,
            end_local=self.end_local,
            boot_session_local=self.boot,
            exit_status=status,
            exit_code=exit_code,
            succeeded=succeeded,
            reboot_required=reboot,
            command=self.command,
            provider=self.scalars.get("provider"),
            class_guid=guid,
            class_guids=tuple(self.guids),
            network_class=net_class,
            driver_version_raw=version,
            driver_version=drv_ver,
            driver_date=drv_date,
            catalog_file=self.scalars.get("catalog_file"),
            inf_names=tuple(inf_names),
            driver_store_path=self.scalars.get("driver_store_path"),
            published_inf_path=self.scalars.get("published_inf_path"),
            device_descriptions=tuple(self.descs),
            hardware_ids=tuple(self.hwids),
            device_instance_ids=tuple(self.devinsts),
            services_added=tuple(self.svc_add),
            services_removed=tuple(self.svc_del),
            signer_name=self.scalars.get("signer_name"),
            signer_score=self.scalars.get("signer_score"),
            signer_status=self.scalars.get("signer_status"),
            warnings=tuple(self.warnings),
            errors=tuple(self.errors),
            source=source,
            header_line=self.header_line,
            last_line=self.last_line,
            body_line_count=self.body_count,
            body=tuple(self.body),
            log_block=self.log_block,
            vendor=vendor,
        )


# --------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------

#: Default read budget. The largest corpus file is 3.8 MB and the whole
#: 17-file set is 26.7 MB, so 128 MiB is ~5x the entire corpus in one
#: file — generous enough never to bite in practice, small enough that a
#: pathological or corrupt file cannot exhaust memory. Parsing is
#: line-streaming regardless; the budget bounds *time*, and only the
#: accumulated sections bound memory.
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_LINES = 5_000_000
DEFAULT_MAX_BODY_LINES = 500


def find_setupapi_logs(root: str) -> List[str]:
    """Every ``setupapi.dev*.log`` under ``root``, sorted.

    Windows keeps ``setupapi.dev.log`` plus rotated ``setupapi.dev.N.log``
    siblings. In this corpus only the unrotated name is ever present
    (17 files, 17 bundles), but the glob covers the rotation because
    losing history to a filename is the exact failure this module exists
    to prevent. Returns ``[]`` for a missing or unreadable ``root``.
    """
    out: List[str] = []
    if not root or not os.path.isdir(root):
        return out
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            low = fn.lower()
            if low.startswith("setupapi.dev") and low.endswith(".log"):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def parse_file(
    path: str,
    *,
    keep_body: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_body_lines: int = DEFAULT_MAX_BODY_LINES,
) -> SetupApiLog:
    """Parse a ``setupapi.dev.log`` from disk. Never raises.

    A missing, unreadable, empty or truncated file comes back as a
    ``SetupApiLog`` with ``present`` set accordingly and ``error`` holding
    the OS message. Truncation mid-section is not an error condition —
    the section is emitted with ``exit_status=None`` and
    :attr:`SetupApiSection.unterminated` True.

    Decoding is ``utf-8`` with ``errors="replace"``. 3 of the 17 corpus
    files contain a region of binary garbage where the log wrapped;
    strict decoding would abort the whole file over it.
    """
    if not path:
        return SetupApiLog(source="", present=False, error="no path given")
    if not os.path.isfile(path):
        return SetupApiLog(source=path, present=False, error="file not found")
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return SetupApiLog(source=path, present=False, error=f"stat failed: {exc}")
    if size == 0:
        return SetupApiLog(source=path, present=True, error="file is empty",
                           bytes_read=0)

    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            return parse_lines(
                fh,
                source=path,
                keep_body=keep_body,
                max_bytes=max_bytes,
                max_lines=max_lines,
                max_body_lines=max_body_lines,
            )
    except OSError as exc:
        # Locked / permission-denied / disappeared between stat and open.
        log.warning("setupapi: cannot read %s: %s", path, exc)
        return SetupApiLog(source=path, present=False, error=f"read failed: {exc}")


def parse_lines(
    lines: Iterable[str],
    *,
    source: str = "<memory>",
    keep_body: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_body_lines: int = DEFAULT_MAX_BODY_LINES,
) -> SetupApiLog:
    """Parse from any iterable of text lines.

    This is the entry point for archive-backed reads — pair it with
    ``walker._iter_text_lines(member_bytes)`` to parse a setupapi log
    straight out of a bundle zip without extracting it.
    """
    preamble: Dict[str, str] = {}
    boots: List[datetime] = []
    sections: List[SetupApiSection] = []
    acc: Optional[_Acc] = None
    boot_now: Optional[datetime] = None
    log_block = 0
    total = section_lines = structural = unrecognised = 0
    nbytes = 0
    truncated = False
    err: Optional[str] = None

    def _close(a: _Acc) -> None:
        sections.append(a.build(source))

    for raw in lines:
        total += 1
        nbytes += len(raw)
        if total > max_lines or nbytes > max_bytes:
            truncated = True
            err = (f"stopped at line {total} / {nbytes} bytes "
                   f"(max_lines={max_lines}, max_bytes={max_bytes})")
            break

        line = raw.rstrip("\r\n")

        m = _RE_HEADER.match(line)
        if m:
            # A new header closes whatever was open. 2 corpus sections
            # (bundle 06, a Lenovo DrvSetupInstallDriver) end this way:
            # the writing process died mid-section and the next install
            # simply started writing. They are kept, marked unterminated.
            if acc is not None:
                _close(acc)
            acc = _Acc(m.group("head"), total, boot_now, log_block,
                       keep_body, max_body_lines)
            structural += 1
            continue

        if acc is not None:
            ms = _RE_START.match(line)
            if ms:
                acc.start_local = _parse_ts(ms.group("ts"))
                acc.last_line = total
                structural += 1
                continue
            me = _RE_END.match(line)
            if me:
                acc.end_local = _parse_ts(me.group("ts"))
                acc.last_line = total
                structural += 1
                continue
            mx = _RE_EXIT.match(line)
            if mx:
                acc.exit_status = mx.group("status").strip()
                acc.last_line = total
                structural += 1
                _close(acc)
                acc = None
                continue

        mb = _RE_BOOT.match(line)
        if mb:
            ts = _parse_ts(mb.group("ts"))
            if ts is not None:
                boots.append(ts)
                boot_now = ts
            structural += 1
            # A Boot Session marker outside a section is structural; one
            # inside a section would be a wrap, and the section stays open
            # so its provenance range is not silently shortened.
            continue

        if _RE_LOGHDR.search(line):
            log_block += 1
            structural += 1
            continue

        mk = _RE_PREAMBLE_KV.match(line)
        if mk and acc is None:
            preamble.setdefault(mk.group("key"), mk.group("val"))
            structural += 1
            continue

        if acc is not None:
            acc.feed(line, total)
            section_lines += 1
            continue

        if not line.strip() or line.strip() == "[BeginLog]":
            structural += 1
        else:
            unrecognised += 1

    if acc is not None:
        # EOF (or budget) inside a section: keep it, unterminated.
        _close(acc)

    return SetupApiLog(
        source=source,
        present=True,
        error=err,
        os_version=preamble.get("OS Version"),
        service_pack=preamble.get("Service Pack"),
        suite=preamble.get("Suite"),
        product_type=preamble.get("ProductType"),
        architecture=preamble.get("Architecture"),
        boot_sessions_local=tuple(boots),
        sections=tuple(sections),
        total_lines=total,
        section_lines=section_lines,
        structural_lines=structural,
        unrecognised_lines=unrecognised,
        bytes_read=nbytes,
        truncated_by_limit=truncated,
    )


def iter_sections(
    lines: Iterable[str],
    *,
    source: str = "<memory>",
    keep_body: bool = False,
    max_body_lines: int = DEFAULT_MAX_BODY_LINES,
) -> Iterator[SetupApiSection]:
    """Yield sections one at a time without holding them all.

    For the ~85% case where the caller only wants the handful of
    substantive sections out of a file that is 85.6% policy-check probes,
    this keeps peak memory at one section. No preamble or accounting is
    produced — use :func:`parse_lines` when those are wanted.
    """
    acc: Optional[_Acc] = None
    boot_now: Optional[datetime] = None
    log_block = 0
    n = 0
    for raw in lines:
        n += 1
        line = raw.rstrip("\r\n")

        m = _RE_HEADER.match(line)
        if m:
            if acc is not None:
                yield acc.build(source)
            acc = _Acc(m.group("head"), n, boot_now, log_block,
                       keep_body, max_body_lines)
            continue

        if acc is not None:
            ms = _RE_START.match(line)
            if ms:
                acc.start_local = _parse_ts(ms.group("ts"))
                acc.last_line = n
                continue
            me = _RE_END.match(line)
            if me:
                acc.end_local = _parse_ts(me.group("ts"))
                acc.last_line = n
                continue
            mx = _RE_EXIT.match(line)
            if mx:
                acc.exit_status = mx.group("status").strip()
                acc.last_line = n
                yield acc.build(source)
                acc = None
                continue

        mb = _RE_BOOT.match(line)
        if mb:
            ts = _parse_ts(mb.group("ts"))
            if ts is not None:
                boot_now = ts
            continue

        if _RE_LOGHDR.search(line):
            log_block += 1
            continue

        if acc is not None:
            acc.feed(line, n)

    if acc is not None:
        yield acc.build(source)


# --------------------------------------------------------------------
# Query helpers
# --------------------------------------------------------------------


def _as_sections(
    source: "SetupApiLog | Sequence[SetupApiSection] | Sequence[SetupApiLog]",
) -> List[SetupApiSection]:
    """Accept a log, a list of logs, or a list of sections.

    Cross-bundle questions ("when did each machine get zapprd?") need the
    multi-log form; single-bundle triage needs the single-log form.
    """
    if isinstance(source, SetupApiLog):
        return list(source.sections)
    out: List[SetupApiSection] = []
    for item in source:
        if isinstance(item, SetupApiLog):
            out.extend(item.sections)
        elif isinstance(item, SetupApiSection):
            out.append(item)
    return out


def select(
    source,
    *,
    contains: Optional[str] = None,
    kind: Optional[str] = None,
    kinds: Optional[Sequence[str]] = None,
    vendor: Optional[str] = None,
    network_only: bool = False,
    include_policy_checks: bool = False,
    failures_only: bool = False,
    since_local: Optional[datetime] = None,
    until_local: Optional[datetime] = None,
) -> List[SetupApiSection]:
    """Filter sections. All criteria AND together; ``None`` means "any".

    ``include_policy_checks`` defaults False because
    ``Device Installation Restrictions Policy Check`` is 85.6% of all
    sections and carries no device identity — leaving it in makes every
    result set look full of hits that say nothing. Set True to get the
    raw population back.

    ``contains`` is a case-folded substring over
    :meth:`SetupApiSection.haystack` — header, names, INF paths,
    provider, command line.

    Ordering is by ``start_local`` ascending; sections with no start
    timestamp sort last, in file order, rather than being dropped.
    """
    rows = _as_sections(source)
    if not include_policy_checks:
        rows = [s for s in rows if not s.is_policy_check]
    if kind is not None:
        rows = [s for s in rows if s.kind == kind]
    if kinds:
        wanted = set(kinds)
        rows = [s for s in rows if s.kind in wanted]
    if vendor is not None:
        rows = [s for s in rows if s.vendor == vendor]
    if network_only:
        rows = [s for s in rows if s.is_network]
    if failures_only:
        rows = [s for s in rows if s.succeeded is False]
    if contains:
        needle = contains.lower()
        rows = [s for s in rows if needle in s.haystack()]
    if since_local is not None:
        rows = [s for s in rows
                if s.start_local is None or s.start_local >= since_local]
    if until_local is not None:
        rows = [s for s in rows
                if s.start_local is None or s.start_local <= until_local]
    return in_time_order(rows)


def in_time_order(sections: Sequence[SetupApiSection]) -> List[SetupApiSection]:
    """Stable sort by ``start_local``, undated sections last.

    The sort key uses a boolean-first tuple rather than a sentinel
    datetime so a real timestamp can never collide with "missing".
    """
    return sorted(
        sections,
        key=lambda s: (s.start_local is None,
                       s.start_local or datetime.min,
                       s.source,
                       s.header_line),
    )


def device_timeline(source, needle: str, **kw) -> List[SetupApiSection]:
    """Every section mentioning ``needle``, oldest first.

    Thin alias for ``select(..., contains=needle)`` — named because
    "show me the install history of this driver" is the question this
    module exists to answer, and the name should say so.
    """
    return select(source, contains=needle, **kw)


def kind_counts(source, *, include_policy_checks: bool = True) -> Dict[str, int]:
    """Section kind -> count, descending. Explicit denominator: the caller
    chooses whether the policy-check probe is in the population."""
    rows = _as_sections(source)
    if not include_policy_checks:
        rows = [s for s in rows if not s.is_policy_check]
    counts: Dict[str, int] = {}
    for s in rows:
        counts[s.kind] = counts.get(s.kind, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def exit_status_counts(source, *, include_policy_checks: bool = True) -> Dict[str, int]:
    """Exit-status text -> count. Unterminated sections are counted under
    the literal key ``"<unterminated>"`` rather than being omitted, so the
    counts always sum to the section total."""
    rows = _as_sections(source)
    if not include_policy_checks:
        rows = [s for s in rows if not s.is_policy_check]
    counts: Dict[str, int] = {}
    for s in rows:
        key = s.exit_status if s.exit_status is not None else "<unterminated>"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def network_driver_events(source) -> List[DriverEvent]:
    """Flat, time-ordered summary of network-stack driver activity.

    Selection is by :attr:`SetupApiSection.is_network` — section kind,
    INF setup class, or a ``netcfg.exe`` command line. It is NOT gated on
    the vendor table: an unrecognised network filter appears with
    ``vendor=None``, because a driver nobody has heard of is exactly the
    one worth showing.

    Note what this cannot cover: WFP sublayers registered at runtime
    through the WFP API — Microsoft Defender ATP's ``SenseNdr`` among
    them — never pass through SetupAPI and so cannot appear here. Zero
    ``SenseNdr`` lines exist in the 369,128-line corpus. That is a
    property of Windows, not a gap in this function.
    """
    out: List[DriverEvent] = []
    for s in in_time_order([x for x in _as_sections(source) if x.is_network]):
        name = ""
        if s.device_descriptions:
            name = s.device_descriptions[0]
        elif s.hardware_ids:
            name = s.hardware_ids[0]
        elif s.target:
            name = s.target
        service = None
        if s.services_added:
            service = s.services_added[0]
        elif s.services_removed:
            service = s.services_removed[0]
        out.append(
            DriverEvent(
                when_local=s.start_local,
                action=_ACTION_BY_KIND.get(s.kind, s.kind),
                name=name,
                vendor=s.vendor,
                driver_version=s.driver_version,
                driver_date=s.driver_date,
                provider=s.provider,
                service=service,
                network_class=s.network_class,
                exit_status=s.exit_status,
                succeeded=s.succeeded,
                signer_status=s.signer_status,
                source=s.source,
                header_line=s.header_line,
                last_line=s.last_line,
                section_kind=s.kind,
            )
        )
    return out
