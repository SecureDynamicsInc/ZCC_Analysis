#!/usr/bin/env python3
"""Fail closed when source, staged changes, or commits resemble case evidence."""

from __future__ import annotations

from pathlib import Path
import argparse
import ipaddress
import os
import re
import subprocess


FORBIDDEN_SUFFIXES = {
    ".7z", ".bz2", ".cab", ".dmp", ".etl", ".evtx", ".gz", ".har",
    ".jsonl", ".key", ".log", ".mmdb", ".ndjson", ".p12", ".p7b",
    ".pcap", ".pcapng", ".pem", ".pfx", ".rar", ".tar", ".tgz",
    ".xz", ".zip",
}
FORBIDDEN_DIRECTORY_NAMES = {
    "captures", "case-files", "customer-data", "customer-evidence",
    "customer-logs", "deployment-snapshots", "evidence", "exports", "logs",
    "packet-captures", "raw-evidence", "support-bundles", "uploads",
    "known_cases", "knowledge", "corpus", "snapshots",
}
FORBIDDEN_FILENAMES = {
    ".env", "registry.json", "bundle_cache.py", "agent_handoff.py",
    "learned.py", "baseline.py",
}
MAX_TRACKED_FILE_BYTES = 2_000_000
WORKTREE_SCAN_EXCLUDES = {
    ".git", ".mypy_cache", ".pytest_cache", ".run", ".ruff_cache",
    ".tox", ".venv", "__pycache__", "node_modules",
}
ALLOWED_EMAIL_DOMAINS = {
    "example.com", "example.invalid", "example.net", "example.org",
    "zscaler.com", "zscaler.net", "zscalerthree.net",
}
ALLOWED_SYNTHETIC_EMAIL_LOCAL_PARTS = {
    "ip", "user", "user-a", "user-b", "user-c",
}
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})(?![\w.-])", re.I)
ENCODED_EMAIL_RE = re.compile(
    r"(?<![\w.+-])([A-Z0-9._%+-]+)%40([A-Z0-9.-]+\.[A-Z]{2,})(?![\w.-])",
    re.I,
)
HOME_PATH_RE = re.compile(
    r"(?:/" + "Users/|/" + r"home/|[A-Za-z]:\\" + r"Users\\)"
    r"(?!user(?:name)?(?:[/\\]|\b))[^\s'\"<>/\\]+",
    re.I,
)
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "bearer token": re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}\b", re.I),
    "cloud drive reference": re.compile(
        r"\bGoogle" + r"\s+Drive\b|"
        r"https?://(?:drive|docs)\." + r"google\.com/|"
        r"(?:[A-Za-z]:\\|/)(?:My" + r"\s+Drive|Google\s+Drive)(?:\\|/)",
        re.I,
    ),
}

# These are known customer/user indicators found during the incident audit.
# Keep the fragments split so this guardrail does not flag its own source.
CUSTOMER_DATA_PATTERNS = {
    "known customer identifier": re.compile(
        r"\bmr" + r"ioa\b|\bpro" + r"core\b|\bintelli" + r"check\b|"
        r"\bsafe" + r"march\b|\bsecure" + r"efs\b",
        re.I,
    ),
    "known individual identifier": re.compile(
        r"\bcha" + r"zell\b|\bla" + r"key\b|\belsab" + r"bagh\b|"
        r"\bfera" + r"gen\b|\bplan" + r"glois\b|\bvmf" + r"sh\b|"
        r"\bsecure" + r"fs\b|\bp?was" + r"mund\b|\bgrf" + r"cpa(?:\b|_)",
        re.I,
    ),
    "known customer network identifier": re.compile(
        r"\b100\.33\.141\." + r"98\b",
        re.I,
    ),
    "ticket export identifier": re.compile(r"\bfile-export-\d{6,}\b", re.I),
}

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
DOMAIN_TOKEN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}"
    r"(?![\w.-])",
    re.I,
)
UUID_RE = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])",
    re.I,
)
ALLOWED_DOMAIN_SUFFIXES = {
    "example.com", "example.invalid", "example.net", "example.org",
    "localhost", "apache.org", "github.com", "maxmind.com", "python.org",
    "securedynamics.net", "streamlit.io", "wireshark.org", "zscaler.com",
    "zscaler.net", "zscalerthree.net", "zscalertwo.net", "zscloud.net",
    "zscalerbeta.net", "zscalergov.net", "zscalerten.net", "zpath.net",
}
ALLOWED_EXACT_DOMAINS = {
    "agent.jumpcloud.com", "anthropic.com", "api.anthropic.com",
    "app.atera.com", "app.kaseya.com", "app.ninjarmm.com",
    "captive.apple.com", "claude.ai", "connect.jumpcloud.com",
    "connectivitycheck.gstatic.com", "copilot.microsoft.com",
    "detectportal.firefox.com", "dns.umbrella.com", "edns.wandera.com",
    "gemini.google.com", "graph.microsoft.com", "login.live.com",
    "login.microsoftonline.com", "openai.com", "outlook.office.com",
    "remotedesktop.google.com", "setupapi.dev", "time.apple.com",
    "www.apple.com",
    "www.msftconnecttest.com", "ipv6.msftconnecttest.com",
    "msftconnecttest.com", "www.msftncsi.com", "dns.msftncsi.com",
    "msftncsi.com",
}
LIKELY_HOST_TLDS = {
    "aero", "app", "biz", "cloud", "co", "com", "dev", "edu", "email",
    "gov", "info", "int", "invalid", "io", "jobs", "lan", "local",
    "mil", "mobi", "museum", "name", "net", "online", "org", "pro",
    "site", "solutions", "support", "systems", "tech", "test", "travel",
    "xyz",
}
NON_HOST_FILE_SUFFIXES = {
    "c", "cc", "cfg", "conf", "cpp", "cs", "css", "csv", "go", "h",
    "hpp", "htm", "html", "ini", "java", "js", "json", "jsx", "lock",
    "md", "ps1", "py", "rb", "rs", "rst", "sh", "sql", "svg", "toml",
    "ts", "tsx", "txt", "xml", "yaml", "yml",
}
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
UNC_RE = re.compile(r"\\\\[A-Za-z0-9][A-Za-z0-9-]{0,62}\\[^\s\\]+", re.I)
WINDOWS_DEVICE_RE = re.compile(r"\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{4,}\b", re.I)
OBFUSCATED_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+\s*(?:\(at\)|\[at\])\s*"
    r"[A-Z0-9-]+(?:\s*(?:\(dot\)|\[dot\]|\sdot\s)\s*[A-Z0-9-]+|"
    r"\.[A-Z0-9-]+)+",
    re.I,
)
PLAIN_AT_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+\s+at\s+"
    r"[A-Z0-9-]+(?:\.[A-Z0-9-]+)+",
    re.I,
)
HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])")
BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])"
)


def _domain_candidates(text: str):
    """Yield plausible hostnames without treating ordinary code attributes as hosts."""
    for match in DOMAIN_TOKEN_RE.finditer(text):
        value = match.group(0)
        tld = value.rsplit(".", 1)[-1].lower()
        # Two-letter country-code TLDs close the previous .de/.us/.uk blind
        # spot. The reviewed generic set covers common and private DNS suffixes
        # without flagging Python attributes such as ``path.read_text``.
        if tld in NON_HOST_FILE_SUFFIXES:
            continue
        if len(tld) == 2 or tld in LIKELY_HOST_TLDS:
            yield match


def _is_allowed_domain(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return (
        domain in ALLOWED_EXACT_DOMAINS
        or any(domain == allowed or domain.endswith("." + allowed)
               for allowed in ALLOWED_DOMAIN_SUFFIXES)
    )


def _looks_like_version(text: str, start: int) -> bool:
    prefix = text[max(0, start - 32):start]
    return bool(re.search(r"\b(?:version|ver|v)\s*[:=]?\s*$", prefix, re.I))


def _run_git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True,
    ).stdout


def tracked_files() -> list[Path]:
    output = _run_git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return [Path(value.decode()) for value in output.split(b"\0") if value]


def worktree_files() -> list[Path]:
    """Include ignored files so dropping a support ZIP in the clone still fails."""
    paths: list[Path] = []
    for root, directories, files in os.walk("."):
        directories[:] = [
            name for name in directories if name not in WORKTREE_SCAN_EXCLUDES
        ]
        base = Path(root)
        for name in files:
            path = (base / name)
            try:
                paths.append(path.relative_to("."))
            except ValueError:
                continue
    return paths


def prohibited(path: Path) -> bool:
    lowered = path.as_posix().lower()
    return (
        path.suffix.lower() in FORBIDDEN_SUFFIXES
        or path.name.lower() in FORBIDDEN_FILENAMES
        or any(part.lower() in FORBIDDEN_DIRECTORY_NAMES for part in path.parts)
        or "deployment-snapshot" in lowered
        or "deployment-snapshots/" in lowered
        or (
            lowered.startswith("tests/corpus/snapshots/")
            and path.suffix.lower() == ".json"
        )
    )


def content_findings_bytes(data: bytes) -> list[str]:
    if len(data) > MAX_TRACKED_FILE_BYTES:
        return [f"tracked file exceeds {MAX_TRACKED_FILE_BYTES:,} bytes"]
    if b"\0" in data:
        return ["opaque/binary tracked file"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["tracked file is not UTF-8 text"]

    findings = []
    for match in EMAIL_RE.finditer(text):
        local_part = match.group(1).lower()
        domain = match.group(2).lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            findings.append(f"non-example email address ({domain})")
        elif local_part not in ALLOWED_SYNTHETIC_EMAIL_LOCAL_PARTS:
            findings.append("non-generic example email local part")
    for match in ENCODED_EMAIL_RE.finditer(text):
        local_part = match.group(1).lower()
        domain = match.group(2).lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            findings.append(f"URL-encoded non-example email address ({domain})")
        elif local_part not in ALLOWED_SYNTHETIC_EMAIL_LOCAL_PARTS:
            findings.append("URL-encoded non-generic email local part")
    if HOME_PATH_RE.search(text):
        findings.append("user-specific home-directory path")
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(label)
    for label, pattern in CUSTOMER_DATA_PATTERNS.items():
        if pattern.search(text):
            findings.append(label)
    return sorted(set(findings))


def content_findings(path: Path) -> list[str]:
    if path.is_symlink():
        return ["tracked symbolic link"]
    return content_findings_bytes(path.read_bytes())


def aggressive_added_line_findings(text: str) -> list[str]:
    """Catch customer-shaped indicators in newly introduced text.

    Existing reviewed protocol references remain possible, but new source and
    documentation must use reserved examples. A maintainer can add a genuinely
    public vendor domain to the narrow central allowlist through review.
    """
    findings: list[str] = []
    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address in SHARED_ADDRESS_SPACE or _looks_like_version(text, match.start()):
            continue
        if not (address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved):
            findings.append("public IPv4 address in added content")
    for match in IPV6_RE.finditer(text):
        if not any(character.isdigit() for character in match.group(0)):
            continue
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if (address.is_global and not address.is_multicast):
            findings.append("public IPv6 address in added content")
    for match in _domain_candidates(text):
        if not _is_allowed_domain(match.group(0)):
            findings.append("unapproved domain name in added content")
    if UUID_RE.search(text):
        findings.append("UUID-like identifier in added content")
    if UNC_RE.search(text):
        findings.append("UNC path in added content")
    if WINDOWS_DEVICE_RE.search(text):
        findings.append("Windows device name in added content")
    if OBFUSCATED_EMAIL_RE.search(text) or PLAIN_AT_EMAIL_RE.search(text):
        findings.append("obfuscated email address in added content")
    if HEX_BLOB_RE.search(text) or BASE64_BLOB_RE.search(text):
        findings.append("long encoded blob in added content")
    return sorted(set(findings))


def _scan_patch(patch: str) -> list[str]:
    findings: list[str] = []
    current = "(unknown)"
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            reasons = aggressive_added_line_findings(line[1:])
            if reasons:
                findings.append(f"{current}: {', '.join(reasons)}")
    return sorted(set(findings))


def staged_findings() -> list[str]:
    patch = _run_git("diff", "--cached", "--no-ext-diff", "--unified=0").decode(
        "utf-8", errors="replace",
    )
    return _scan_patch(patch)


def commit_range_findings(revision_range: str) -> list[str]:
    """Inspect every added/modified blob in every commit, not only final HEAD."""
    findings: list[str] = []
    commits = _run_git("rev-list", "--reverse", revision_range).decode().splitlines()
    for commit in commits:
        paths = _run_git(
            "diff-tree", "--root", "--no-commit-id", "--diff-filter=AM",
            "--name-only", "-r", "-z", commit,
        ).split(b"\0")
        for raw_path in paths:
            if not raw_path:
                continue
            path_text = raw_path.decode("utf-8", errors="replace")
            path = Path(path_text)
            if prohibited(path):
                findings.append(f"{commit[:12]}:{path_text}: prohibited path")
                continue
            try:
                data = _run_git("show", f"{commit}:{path_text}")
            except subprocess.CalledProcessError:
                continue
            for reason in content_findings_bytes(data):
                findings.append(f"{commit[:12]}:{path_text}: {reason}")
        patch = _run_git("show", "--format=", "--no-ext-diff", "--unified=0", commit)
        for reason in _scan_patch(patch.decode("utf-8", errors="replace")):
            findings.append(f"{commit[:12]}:{reason}")
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--commits-range")
    args = parser.parse_args()
    # Deleted-but-not-yet-committed files may remain in the index during a local
    # cleanup; CI evaluates the committed tree, where every tracked path exists.
    # Scan the actual worktree, including ignored files. `.gitignore` prevents
    # accidental staging but must never become a hiding place for case data.
    paths = [path for path in worktree_files() if path.exists()]
    unsafe = [path for path in paths if prohibited(path)]
    content_unsafe = {path: content_findings(path) for path in paths if not prohibited(path)}
    content_unsafe = {path: reasons for path, reasons in content_unsafe.items() if reasons}
    change_unsafe = staged_findings() if args.staged else []
    history_unsafe = (
        commit_range_findings(args.commits_range) if args.commits_range else []
    )
    if not unsafe and not content_unsafe and not change_unsafe and not history_unsafe:
        print("Worktree contains no prohibited evidence files or common sensitive-data indicators.")
        return 0
    if unsafe:
        print("Remove these prohibited tracked files before publishing:")
        for path in unsafe:
            print(f"  {path}")
    if content_unsafe:
        print("Review and remove these sensitive-data indicators:")
        for path, reasons in content_unsafe.items():
            print(f"  {path}: {', '.join(reasons)}")
    if change_unsafe:
        print("Remove these customer-shaped indicators from staged additions:")
        for finding in change_unsafe:
            print(f"  {finding}")
    if history_unsafe:
        print("Sensitive data cannot exist even temporarily in the commit range:")
        for finding in history_unsafe:
            print(f"  {finding}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
