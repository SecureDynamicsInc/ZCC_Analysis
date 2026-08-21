from pathlib import Path

from scripts.check_public_tree import (
    aggressive_added_line_findings,
    content_findings,
    prohibited,
    worktree_files,
)


def test_prohibits_common_customer_evidence_paths_and_formats():
    assert prohibited(Path("customer-data/notes.txt"))
    assert prohibited(Path("tests/captures/session.pcapng"))
    assert prohibited(Path("sample-support.zip"))
    assert prohibited(Path("GeoLite2-ASN.mmdb"))
    assert prohibited(Path("local/registry.json"))


def test_allows_normal_source_and_synthetic_text_paths():
    assert not prohibited(Path("zcc_diag/parser.py"))
    assert not prohibited(Path("tests/test_parser.py"))
    assert not prohibited(Path("docs/DATA_HANDLING.md"))


def test_prohibits_retained_case_and_learning_paths():
    assert prohibited(Path("zcc_diag/known_cases/cases.py"))
    assert prohibited(Path("knowledge/observations.md"))
    assert prohibited(Path("tests/corpus/registry.json"))
    assert prohibited(Path("zcc_diag/ui/bundle_cache.py"))


def test_worktree_scan_does_not_treat_gitignore_as_a_privacy_boundary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitignore").write_text("*.zip\n")
    (tmp_path / "forgotten-support.zip").write_bytes(b"not really a zip")
    assert Path("forgotten-support.zip") in worktree_files()


def test_content_scan_accepts_reserved_synthetic_values(tmp_path):
    sample = tmp_path / "synthetic.txt"
    sample.write_text("user@example.invalid 192.0.2.10 2001:db8::10")
    assert content_findings(sample) == []


def test_content_scan_rejects_identity_and_secret_indicators(tmp_path):
    sample = tmp_path / "unsafe.txt"
    sample.write_text(
        "person@" + "customer.example.biz\n"
        + "/" + "Users/realperson/Desktop/support.zip\n"
        + "-----BEGIN " + "PRIVATE KEY-----\n"
    )
    findings = content_findings(sample)
    assert "non-example email address (customer.example.biz)" in findings
    assert "user-specific home-directory path" in findings
    assert "private key" in findings


def test_content_scan_rejects_opaque_binary(tmp_path):
    sample = tmp_path / "binary.bin"
    sample.write_bytes(b"header\x00payload")
    assert content_findings(sample) == ["opaque/binary tracked file"]


def test_content_scan_rejects_cloud_drive_locations(tmp_path):
    samples = (
        "https://" + "drive." + "google.com/drive/folders/example",
        "https://" + "docs." + "google.com/document/d/example",
        "D:\\" + "My " + "Drive\\private-build",
        "originals retained in " + "Google " + "Drive",
    )
    for index, value in enumerate(samples):
        sample = tmp_path / f"cloud-drive-{index}.txt"
        sample.write_text(value)
        assert "cloud drive reference" in content_findings(sample)


def test_content_scan_rejects_person_named_example_addresses(tmp_path):
    samples = (
        "first.last@" + "example.invalid",
        "first.last%40" + "example.invalid",
    )
    for index, value in enumerate(samples):
        sample = tmp_path / f"named-email-{index}.txt"
        sample.write_text(value)
        findings = content_findings(sample)
        assert any("non-generic" in finding for finding in findings)


def test_content_scan_rejects_known_customer_indicators(tmp_path):
    samples = (
        "mr" + "ioa.local",
        "pro" + "core.okta.com",
        "cha" + "zell",
        "p" + "was" + "mund",
        "grf" + "cpa_license",
        "100.33.141." + "98",
    )
    for index, value in enumerate(samples):
        sample = tmp_path / f"customer-marker-{index}.txt"
        sample.write_text(value)
        findings = content_findings(sample)
        assert any("known" in finding for finding in findings)


def test_added_line_scan_rejects_customer_shaped_network_identifiers():
    assert "public IPv4 address in added content" in aggressive_added_line_findings(
        "destination = '8.8." + "8.8'"
    )
    assert "unapproved domain name in added content" in aggressive_added_line_findings(
        "host = 'private.customer." + "biz'"
    )
    assert "UUID-like identifier in added content" in aggressive_added_line_findings(
        "tenant = '123e4567-e89b-12d3-" + "a456-426614174000'"
    )


def test_added_line_scan_accepts_reserved_examples_and_loopback():
    assert aggressive_added_line_findings(
        "user@example.invalid 192.0.2.10 http://127.0.0.1:8501"
    ) == []


def test_added_line_scan_rejects_extended_customer_shaped_identifiers():
    lines = [
        "host=mail.acme-demo.co." + "uk timeout",
        "host=fileserver01.acme-demo." + "lan unreachable",
        "unc=" + "\\\\ACME-FS01\\evidence\\bundle",
        "device=" + "DESKTOP-" + "J4K2M9 user logged on",
        "contact ops " + "(at) acme-demo (dot) co (dot) uk",
        "destination=" + "2606:4700:4700:" + ":1111",
        "payload=" + ("ab" * 32),
    ]
    findings = {
        finding
        for line in lines
        for finding in aggressive_added_line_findings(line)
    }
    assert "unapproved domain name in added content" in findings
    assert "UNC path in added content" in findings
    assert "Windows device name in added content" in findings
    assert "obfuscated email address in added content" in findings
    assert "public IPv6 address in added content" in findings
    assert "long encoded blob in added content" in findings


def test_added_line_scan_accepts_documentation_ipv6_cgnat_and_versions():
    assert aggressive_added_line_findings(
        "2001:db8::10 100.64.0.8 version 4.8.0.156"
    ) == []


def test_added_line_scan_accepts_reviewed_public_vendor_endpoints():
    assert aggressive_added_line_findings(
        "gateway.zscalertwo.net captive.apple.com www.msftconnecttest.com"
    ) == []


def test_domain_scan_does_not_treat_python_attributes_as_hostnames():
    assert aggressive_added_line_findings(
        "path.read_text() and session.state.value and result.example.invalid"
    ) == []
