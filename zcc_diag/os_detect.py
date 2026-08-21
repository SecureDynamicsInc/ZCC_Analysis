"""
Detect the operating system that produced a ZCC log bundle.

Strategy (in order of confidence, first match wins):
  1. ``AppInfo.xml`` ``OS Name:`` line                  -- 0.98
  2. ``SystemInfo.xml`` family markers                  -- 0.9 / 0.85 / 0.8
  3. Filename heuristics (Windows-only files etc.)      -- 0.7 / 0.6
  4. Outer bundle filename pattern                      -- 0.6
  5. Unknown                                            -- 0.0

Detection is read-only and never executes anything from the bundle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .bundle import ExtractedBundle


@dataclass(frozen=True)
class OSDetection:
    os_family: str            # "windows" | "macos" | "linux" | "unknown"
    os_name: Optional[str]
    os_version: Optional[str]
    confidence: float
    evidence: str


# Compiled once.
_RE_APPINFO_OS_NAME = re.compile(r"OS Name:\s*([^\r\n]+)", re.IGNORECASE)
_RE_APPINFO_OS_VERSION = re.compile(r"OS Version:\s*([^\r\n]+)", re.IGNORECASE)
_RE_DARWIN = re.compile(r"\bDarwin\b|\bmacOS\b|\bMac OS X\b", re.IGNORECASE)
_RE_LINUX_KERNEL = re.compile(r"Linux\s+\S+\s+\d+\.\d+\.\d+", re.IGNORECASE)
_RE_WINDOWS_GENERIC = re.compile(r"Microsoft\s+Windows", re.IGNORECASE)

# Outer-bundle filename patterns. ZCC's "Export Logs" tray menu produces
# two distinct names depending on OS:
#   Windows: ``Zscaler-YYYY-MM-DD-HH-MM-SS.zip``
#   macOS:   ``Zscaler-<unix_epoch_seconds>.<microseconds>.zip``
# HubSpot tacks a ``-<6hex>.zip`` suffix on every form upload; users
# sometimes prepend their own prefix (``Kipp_SSL_Issues_Zscaler-...``).
# We strip the suffix and accept the first ``Zscaler-`` substring.
_RE_BUNDLE_NAME_EPOCH = re.compile(
    r"Zscaler-\d{10}\.\d+", re.IGNORECASE
)
_RE_BUNDLE_NAME_DATETIME = re.compile(
    r"Zscaler-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}", re.IGNORECASE
)
_RE_HUBSPOT_HEX_SUFFIX = re.compile(r"-[0-9a-f]{6}\.zip$", re.IGNORECASE)


def _read_head(path: Path, max_bytes: int) -> str:
    """Read the first ``max_bytes`` of a file as latin-1 (never fails on
    bytes; ASCII content -- which is all we match against -- decodes
    identically to UTF-8)."""
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes).decode("latin-1", errors="replace")
    except OSError:
        return ""


def _classify_family_from_os_name(os_name: str) -> str:
    """Map a free-text OS name (e.g. parsed from ``OS Name:``) to a family.
    Caller must ensure the input really is an OS-name line, not arbitrary
    log text -- the keyword set is intentionally broad."""
    s = os_name.lower()
    if "windows" in s or "microsoft" in s:
        return "windows"
    if "darwin" in s or "mac os" in s or "macos" in s:
        return "macos"
    if "linux" in s or "ubuntu" in s or "redhat" in s or "centos" in s:
        return "linux"
    return "unknown"


def _detect_from_appinfo(bundle: ExtractedBundle) -> Optional[OSDetection]:
    """Tier 1: ``log-*/AppInfo.xml`` -- the strongest signal.
    The ``OS Name:`` / ``OS Version:`` lines sit near the top of the file."""
    for p in bundle.root.rglob("AppInfo.xml"):
        text = _read_head(p, 32 * 1024)
        m_name = _RE_APPINFO_OS_NAME.search(text)
        if not m_name:
            continue
        os_name = m_name.group(1).strip()
        family = _classify_family_from_os_name(os_name)
        if family == "unknown":
            continue
        m_ver = _RE_APPINFO_OS_VERSION.search(text)
        return OSDetection(
            os_family=family,
            os_name=os_name,
            os_version=m_ver.group(1).strip() if m_ver else None,
            confidence=0.98,
            evidence=f"AppInfo.xml: OS Name: {os_name}",
        )
    return None


def _detect_from_appinfo_mac_plist(
    bundle: ExtractedBundle,
) -> Optional[OSDetection]:
    """Tier 1b (macOS): ``AppInfo.log`` is a binary/plist-format file on
    Mac bundles (Windows uses ``AppInfo.xml``). The ``Machine Info``
    key carries a string like ``Version 26.4.1 (Build 25E253) ;arm;
    Apple M4`` -- parse it for OS version and architecture.
    """
    import plistlib
    for p in bundle.root.rglob("AppInfo.log"):
        try:
            with open(p, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        machine_info = data.get("Machine Info")
        if not isinstance(machine_info, str):
            continue
        # ``Version X.Y.Z (Build NNNNN) ;arch; Model`` -- the leading
        # ``Version`` is the macOS version, not a separate name. The
        # presence of this format is itself the macOS signature.
        import re
        m = re.match(
            r"Version\s+([\d.]+)\s*\(Build\s+([\w]+)\)\s*;\s*([\w]+)\s*;\s*(.+)",
            machine_info.strip(),
        )
        if not m:
            # Fall back: if Machine Info exists, we still know it's
            # macOS even if the format shifts.
            return OSDetection(
                os_family="macos",
                os_name="macOS",
                os_version=None,
                confidence=0.85,
                evidence=f"AppInfo.log plist Machine Info: {machine_info[:80]}",
            )
        os_ver, build, arch, model = m.groups()
        return OSDetection(
            os_family="macos",
            os_name=f"macOS {os_ver} ({arch}, {model})",
            os_version=f"{os_ver} (Build {build})",
            confidence=0.97,
            evidence=f"AppInfo.log plist: {machine_info[:100]}",
        )
    return None


def _detect_from_systeminfo(
    bundle: ExtractedBundle,
) -> Optional[OSDetection]:
    """Tier 2: bundle-level ``SystemInfo.xml``. We deliberately do NOT
    extract a version here -- the file has multiple ``Version:`` lines
    (driver versions, OS, image) and disambiguating them isn't worth the
    risk of returning a wrong number."""
    for p in bundle.root.rglob("SystemInfo.xml"):
        text = _read_head(p, 64 * 1024)
        if "<WindowsPatch>" in text or _RE_WINDOWS_GENERIC.search(text):
            return OSDetection(
                os_family="windows",
                os_name="Microsoft Windows",
                os_version=None,
                confidence=0.9,
                evidence=f"SystemInfo.xml: <WindowsPatch> / Microsoft markers",
            )
        if _RE_DARWIN.search(text):
            return OSDetection(
                os_family="macos",
                os_name="macOS",
                os_version=None,
                confidence=0.85,
                evidence="SystemInfo.xml: Darwin/macOS marker",
            )
        if _RE_LINUX_KERNEL.search(text):
            return OSDetection(
                os_family="linux",
                os_name="Linux",
                os_version=None,
                confidence=0.8,
                evidence="SystemInfo.xml: Linux kernel marker",
            )
    return None


# Filename markers checked against ``bundle.files`` (already walked once
# during extraction).
_WINDOWS_MARKERS = frozenset({
    "setupapi.dev.log", "appevents.xml", "sysevents.xml", "setupevents.xml",
})
_MACOS_MARKERS = frozenset({
    "system_profile.txt",
    "kextstat.txt",
    # Mac launchd / Zscaler-on-Mac process artefacts:
    "com.zscaler.zscalerservice.log",
    "com.zscaler.zscalerserviceout.log",
    "com.zscaler.upmservicecontroller_stderr.log",
    "com.zscaler.upmservicecontroller_stdout.log",
    # Mac packet filter + config-profile dumps:
    "pf.log",
    "profiles.log",
})
_LINUX_MARKERS = frozenset({"dmesg.log", "lsmod.txt", "iptables.txt"})


def _detect_from_filenames(
    bundle: ExtractedBundle,
) -> Optional[OSDetection]:
    """Tier 3: filename heuristics, single pass over ``bundle.files``."""
    names = {p.name.lower() for p in bundle.files}

    if names & _WINDOWS_MARKERS:
        return OSDetection(
            os_family="windows",
            os_name="Microsoft Windows",
            os_version=None,
            confidence=0.7,
            evidence=f"Windows-only files: {sorted(names & _WINDOWS_MARKERS)}",
        )
    if names & _MACOS_MARKERS:
        return OSDetection(
            os_family="macos",
            os_name="macOS",
            os_version=None,
            confidence=0.7,
            evidence=f"macOS-only files: {sorted(names & _MACOS_MARKERS)}",
        )
    if names & _LINUX_MARKERS:
        return OSDetection(
            os_family="linux",
            os_name="Linux",
            os_version=None,
            confidence=0.7,
            evidence=f"Linux-only files: {sorted(names & _LINUX_MARKERS)}",
        )
    if any(n.endswith(".exe.log") for n in names):
        return OSDetection(
            os_family="windows",
            os_name="Microsoft Windows",
            os_version=None,
            confidence=0.6,
            evidence="*.exe.log files present (Windows-only naming)",
        )
    return None


def _detect_from_bundle_name(
    bundle: ExtractedBundle,
) -> Optional[OSDetection]:
    """Tier 4 fallback: inspect the outer ZIP filename. Free signal
    (no I/O) and useful when the bundle has been trimmed (e.g.
    ``Zscaler-1773844931.647336-small-...zip``) and the AppInfo /
    SystemInfo / filename-marker tiers all returned None.

    Mac bundles export as ``Zscaler-<epoch>.<usec>.zip`` (>= 10 digits
    of seconds); Windows bundles as ``Zscaler-YYYY-MM-DD-HH-MM-SS.zip``.
    """
    name = bundle.source_zip.name
    # Drop HubSpot form-upload suffix so the canonical pattern can match.
    name_stripped = _RE_HUBSPOT_HEX_SUFFIX.sub(".zip", name)
    if _RE_BUNDLE_NAME_EPOCH.search(name_stripped):
        return OSDetection(
            os_family="macos",
            os_name="macOS",
            os_version=None,
            confidence=0.6,
            evidence=f"bundle filename uses epoch pattern: {name}",
        )
    if _RE_BUNDLE_NAME_DATETIME.search(name_stripped):
        return OSDetection(
            os_family="windows",
            os_name="Microsoft Windows",
            os_version=None,
            confidence=0.6,
            evidence=f"bundle filename uses datetime pattern: {name}",
        )
    return None


def detect_os(bundle: ExtractedBundle) -> OSDetection:
    """Run the detection chain. Always returns an :class:`OSDetection`."""
    for fn in (
        _detect_from_appinfo,           # Windows AppInfo.xml
        _detect_from_appinfo_mac_plist, # macOS AppInfo.log (plist)
        _detect_from_systeminfo,
        _detect_from_filenames,
        _detect_from_bundle_name,       # outer-zip filename fallback
    ):
        result = fn(bundle)
        if result is not None:
            return result
    return OSDetection(
        os_family="unknown",
        os_name=None,
        os_version=None,
        confidence=0.0,
        evidence="No OS markers found in bundle.",
    )
