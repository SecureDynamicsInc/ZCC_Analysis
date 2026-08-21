"""
PII redaction for ZCC log content.

Two-phase design:
  1. Pre-pass: read ``AppInfo.xml`` / ``SystemInfo.xml`` once and seed the
     mapping with known facts (hostname, domain, username, MAC).
  2. Stream: ``scrub(text)`` walks regex patterns to catch PII the pre-pass
     missed (emails/UPNs, public IPs, MACs in log lines, auth tokens).

Tokens are counter-based (``<HOST_001>``, ``<EMAIL_002>`` ...). Real values
live ONLY in the sidecar JSON. Anyone holding the redacted output without
the sidecar cannot reverse the redaction.

Allowlist: Zscaler infrastructure hostnames and private/CGNAT/link-local
IPs are deliberately left visible -- they are network topology, not PII,
and engineers need them readable for troubleshooting.

The redactor is a regular object, not a singleton. Construct one per
bundle so its sidecar is bundle-scoped.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .bundle import ExtractedBundle

log = logging.getLogger(__name__)


# --- Regexes -----------------------------------------------------------

_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_RE_IPV4 = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
# IPv6 candidates -- intentionally loose; the substitution callback
# validates with ``ipaddress.ip_address`` to reject HH:MM:SS timestamps
# and other false positives.
#
# Phase 58e-C8 (2026-07-08): previous pattern required 2–7 `hex:`
# groups AND a trailing hextet, matching only the fully-expanded form
# ("2001:db8:0:0:0:0:0:1"). Every `::`-compressed IPv6 fell through
# — ("::1", "fe80::1", "2001:db8::1", "::ffff:1.2.3.4"). ZCC logs use
# the compressed form almost exclusively. Result: the redactor
# claimed to scrub IPv6 but literally couldn't see the common form.
#
# The new pattern is intentionally over-broad. The callback in
# `_redact_ipv6` validates each candidate with `ipaddress.ip_address`
# and rejects anything that isn't a real address, so false matches
# (log-line timestamps, hex dumps) are filtered downstream.
#
# Covers:
#   - fully-expanded: 2001:db8:0:0:0:0:0:1
#   - :: compression: ::1, fe80::1, 2001:db8::1
#   - IPv4-mapped:    ::ffff:192.168.1.1
#   - bracketed form: [fe80::1] (URL-style)
_RE_IPV6 = re.compile(
    r"\[?"                                         # optional leading '['
    r"(?:"
    r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}"    # 8 hextets, no compression
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){0,7}"                  # zero-or-more hextets
    r":(?::?[0-9a-fA-F]{1,4}){0,7}"                # then :: + optional tail
    r"|"
    r"::(?:ffff(?::0{1,4})?:)?"                    # ::ffff: (IPv4-mapped prefix)
    r"(?:\d{1,3}\.){3}\d{1,3}"                     # + IPv4 dotted-quad
    r")"
    r"\]?"                                         # optional trailing ']'
)
# MAC: colon- or hyphen-separated. Negative lookbehind/ahead reject when
# the surrounding context is also hex/dash so we don't false-match the
# inside of timestamps like 25-03-25-16-52-31.
_RE_MAC = re.compile(
    r"(?<![\w-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w-])"
)
# Auth tokens: long base64-ish runs. Min 40 chars to avoid UUIDs (32) and
# short opaque IDs. Allow trailing '='.
_RE_BASE64_BLOB = re.compile(
    r"\b[A-Za-z0-9+/]{40,}={0,2}\b"
)
# Windows SID: 'S-1-' then revision-and-authority dashes. Always PII.
_RE_WIN_SID = re.compile(
    r"\bS-\d-\d+(?:-\d+){2,}\b"
)

# Pre-pass extractors for the structured XML files. Word boundary before
# the keyword prevents matching substrings like 'USERDNSDOMAIN:'.
# Horizontal-whitespace-only after the colon prevents the value glob from
# crossing into the next line.
_RE_APPINFO_HOSTNAME = re.compile(
    r"\bHost Name:[ \t]*([^\r\n]+)", re.IGNORECASE
)
_RE_APPINFO_DOMAIN = re.compile(
    r"(?<!USERDNS)\bDomain:[ \t]*([^\r\n]+)", re.IGNORECASE
)
_RE_APPINFO_OWNER = re.compile(
    r"\bRegistered Owner:[ \t]*([^\r\n]+)", re.IGNORECASE
)
_RE_APPINFO_LOGON_SERVER = re.compile(
    r"\bLogon Server:[ \t]*\\\\([^\r\n\s]+)", re.IGNORECASE
)


# --- Allowlist ---------------------------------------------------------

_HOSTNAME_ALLOWLIST_SUBSTRINGS = (
    ".zscaler.net",
    ".zscalerone.net",
    ".zscalertwo.net",
    ".zscalerthree.net",
    ".zscloud.net",
    ".zscalergov.net",
    ".cloudfront.net",
    ".akamai.net",
    ".akamaiedge.net",
)

_HOSTNAME_ALLOWLIST_EXACT = frozenset({
    "localhost",
    "localhost.localdomain",
})


def _hostname_is_allowlisted(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h in _HOSTNAME_ALLOWLIST_EXACT:
        return True
    for s in _HOSTNAME_ALLOWLIST_SUBSTRINGS:
        # Match both 'foo.zscaler.net' (suffix with dot) and bare
        # 'zscaler.net'. Without this, the @-domain of an email like
        # ip@zscalerthree.net would not be recognised.
        if h.endswith(s) or h == s.lstrip("."):
            return True
    return False


def _ip_is_visible(ip: str) -> bool:
    """Return True if the IP should stay visible in redacted output.

    Private, loopback, link-local, multicast, CGNAT (100.64/10), and
    'this network' (0.0.0.0/8) all stay visible per the user's choice.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv4Address)
            and addr in ipaddress.IPv4Network("100.64.0.0/10"))
    )


# --- Public API --------------------------------------------------------

@dataclass
class RedactionStats:
    by_kind: Dict[str, int] = field(default_factory=dict)

    def hit(self, kind: str) -> None:
        self.by_kind[kind] = self.by_kind.get(kind, 0) + 1

    def total(self) -> int:
        return sum(self.by_kind.values())


class Redactor:
    """Per-bundle PII redactor.

    Typical use::

        r = Redactor()
        r.prepass(bundle)
        scrubbed = r.scrub(some_text)

    Mappings never leave memory and are destroyed with the active run.
    """

    KIND_HOST = "HOST"
    KIND_USER = "USER"
    KIND_DOMAIN = "DOMAIN"
    KIND_EMAIL = "EMAIL"
    KIND_IP = "IP"
    KIND_MAC = "MAC"
    KIND_TOKEN = "TOKEN"
    KIND_SID = "SID"

    # Kinds that are case-insensitive on lookup (DNS / email casing).
    _CASEFOLD_KINDS = frozenset({KIND_HOST, KIND_EMAIL, KIND_DOMAIN})

    def __init__(self) -> None:
        # lookup-key -> token
        self._mapping: Dict[str, str] = {}
        # token -> original raw value (preserves case for the sidecar)
        self._reverse: Dict[str, str] = {}
        # per-kind counters
        self._counters: Dict[str, int] = {}
        # Known literals from pre-pass; (kind, raw, compiled_regex).
        self._literals: List[Tuple[str, str, re.Pattern]] = []
        self.stats = RedactionStats()

    # --- internal helpers ---------------------------------------------

    def _new_token(self, kind: str) -> str:
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        return f"<{kind}_{n:03d}>"

    def _intern(self, kind: str, raw: str) -> str:
        key = raw.lower() if kind in self._CASEFOLD_KINDS else raw
        tok = self._mapping.get(key)
        if tok is None:
            tok = self._new_token(kind)
            self._mapping[key] = tok
            self._reverse[tok] = raw
        return tok

    # --- pre-pass ------------------------------------------------------

    def prepass(self, bundle: ExtractedBundle) -> None:
        """Scan known structured files for high-confidence PII and seed
        the mapping. Idempotent."""
        for p in bundle.root.rglob("AppInfo.xml"):
            self._prepass_file(p)
        for p in bundle.root.rglob("SystemInfo.xml"):
            self._prepass_file(p)
        # Sort literals longest-first so substring replacement doesn't
        # leave fragments (e.g. "DESKTOP-BKB" inside "DESKTOP-BKBPLIM").
        self._literals.sort(key=lambda t: -len(t[1]))

    def _prepass_file(self, path: Path) -> None:
        try:
            with open(path, "rb") as f:
                text = f.read(64 * 1024).decode("latin-1", errors="replace")
        except OSError:
            return

        for kind, regex in (
            (self.KIND_HOST, _RE_APPINFO_HOSTNAME),
            (self.KIND_DOMAIN, _RE_APPINFO_DOMAIN),
            (self.KIND_USER, _RE_APPINFO_OWNER),
            (self.KIND_HOST, _RE_APPINFO_LOGON_SERVER),
        ):
            for m in regex.finditer(text):
                raw = m.group(1).strip()
                if not raw or raw.upper() == "N/A":
                    continue
                if kind == self.KIND_HOST and _hostname_is_allowlisted(raw):
                    continue
                self._intern(kind, raw)
                self._literals.append(
                    (kind, raw, re.compile(re.escape(raw), re.IGNORECASE))
                )

    # --- streaming scrub ----------------------------------------------

    def scrub(self, text: str) -> str:
        """Return ``text`` with PII replaced by tokens."""
        if not text:
            return text

        # 1. Known literals from pre-pass (longest-first, pre-compiled).
        for kind, raw, pattern in self._literals:
            key = raw.lower() if kind in self._CASEFOLD_KINDS else raw
            tok = self._mapping[key]
            new_text, n = pattern.subn(tok, text)
            if n:
                text = new_text
                for _ in range(n):
                    self.stats.hit(kind)

        # 2. Emails / UPNs.
        def _email_sub(m: re.Match) -> str:
            raw = m.group(0)
            domain = raw.rsplit("@", 1)[-1]
            if _hostname_is_allowlisted(domain):
                return raw
            self.stats.hit(self.KIND_EMAIL)
            return self._intern(self.KIND_EMAIL, raw)
        text = _RE_EMAIL.sub(_email_sub, text)

        # 3. IPs.
        def _ipv4_sub(m: re.Match) -> str:
            raw = m.group(0)
            # Sanity-check: the regex allows '999.999.999.999'; reject
            # anything ipaddress can't parse.
            try:
                ipaddress.IPv4Address(raw)
            except ValueError:
                return raw
            if _ip_is_visible(raw):
                return raw
            self.stats.hit(self.KIND_IP)
            return self._intern(self.KIND_IP, raw)
        text = _RE_IPV4.sub(_ipv4_sub, text)

        def _ipv6_sub(m: re.Match) -> str:
            raw = m.group(0)
            # The IPv6 regex over-matches on HH:MM:SS-style strings.
            # Validate with stdlib; bail on anything not a real IPv6.
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                return raw
            if _ip_is_visible(raw):
                return raw
            self.stats.hit(self.KIND_IP)
            return self._intern(self.KIND_IP, raw)
        text = _RE_IPV6.sub(_ipv6_sub, text)

        # 4. MACs.
        def _mac_sub(m: re.Match) -> str:
            self.stats.hit(self.KIND_MAC)
            return self._intern(self.KIND_MAC, m.group(0))
        text = _RE_MAC.sub(_mac_sub, text)

        # 5. Windows SIDs (Windows-specific, always PII).
        def _sid_sub(m: re.Match) -> str:
            self.stats.hit(self.KIND_SID)
            return self._intern(self.KIND_SID, m.group(0))
        text = _RE_WIN_SID.sub(_sid_sub, text)

        # 6. Long base64 / auth tokens.
        def _tok_sub(m: re.Match) -> str:
            self.stats.hit(self.KIND_TOKEN)
            return self._intern(self.KIND_TOKEN, m.group(0))
        text = _RE_BASE64_BLOB.sub(_tok_sub, text)

        return text

    def scrub_iter(self, lines: Iterable[str]) -> Iterable[str]:
        for line in lines:
            yield self.scrub(line)

    # Deliberately no sidecar or export method. Even a redaction map contains
    # customer-derived values and must remain an in-memory implementation
    # detail of the current run.
