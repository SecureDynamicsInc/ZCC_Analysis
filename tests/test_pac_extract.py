"""PAC recovery: every shape a bundle can carry a PAC in, plus the caps."""

from __future__ import annotations

import json

import pytest

from zcc_diag.pac_extract import describe, scan_bundle


PAC = """function FindProxyForURL(url, host) {

    var privateIP = /^(0|10|127|192\\.168|172\\.1[6789])\\.[0-9.]+$/;
    var resolved_ip = dnsResolve(host);

    /* Don't send non-FQDN or private IP auths to us */
    if (isPlainHostName(host) || privateIP.test(resolved_ip))
        return "DIRECT";

    /* test with ZPA */
    if (isInNet(resolved_ip, "100.64.0.0", "255.255.0.0"))
        return "DIRECT";

    /* Bypass for Federated IdP */
    if (shExpMatch(host, "customer.onelogin.com") ||
            shExpMatch(host, "*.mcas.ms"))
        return "DIRECT";

    if (localHostOrDomainIs(host, "trust.zscaler.net"))
        return "DIRECT";

    return "PROXY gateway.zscalertwo.net:80; DIRECT";
}"""

TS = "2026-08-18 14:02:11.123456(+0000)[1234:5678] INF "


def _log_line(message: str) -> str:
    return f"{TS}{message}\n"


@pytest.fixture()
def bundle(tmp_path):
    return tmp_path


def test_standalone_pac_file_is_returned_byte_for_byte(bundle):
    (bundle / "MSSP_AppPAC.js").write_text(PAC, encoding="utf-8")

    scan = scan_bundle(bundle)

    assert scan.found == 1
    document = scan.documents[0]
    assert document.text == PAC
    assert document.standalone_file is True
    assert document.truncated is False


def test_inline_pac_blob_in_a_tunnel_log_is_carved_at_the_next_record(bundle):
    (bundle / "ZSATunnel.log").write_text(
        _log_line("ZUpmPacDownloader::downloadPac: pac content follows:")
        + PAC + "\n"
        + _log_line("ZUpmPacDownloader::downloadPac: pac applied"),
        encoding="utf-8",
    )

    scan = scan_bundle(bundle)

    document = scan.documents[0]
    assert document.text == PAC
    assert document.log_embedded is True
    assert document.truncated is False
    # The following log record must not bleed into the PAC source.
    assert "pac applied" not in document.text
    assert "downloadPac" in document.context
    assert document.line_no == 2


def test_pac_logged_one_prefixed_line_at_a_time_keeps_its_indentation(bundle):
    prefixed = "".join(_log_line(line) for line in PAC.split("\n"))
    (bundle / "ZSAService.log").write_text(
        _log_line("ZSAService: applying proxy config") + prefixed,
        encoding="utf-8",
    )

    scan = scan_bundle(bundle)

    document = scan.documents[0]
    assert document.preamble_stripped is True
    assert document.text == PAC
    assert "    var privateIP" in document.text
    assert TS not in document.text


def test_pac_stored_as_an_escaped_config_value_is_restored_without_the_payload(bundle):
    (bundle / "policy.json").write_text(
        json.dumps({"pacContent": PAC, "tenant": "example"}), encoding="utf-8"
    )

    scan = scan_bundle(bundle)

    document = scan.documents[0]
    assert document.json_unescaped is True
    assert document.text == PAC
    # The surrounding JSON must be cut at the string literal's closing quote.
    assert "tenant" not in document.text


def test_identical_pac_copies_collapse_to_one_document(bundle):
    (bundle / "ZSATunnel.log").write_text(
        _log_line("first download") + PAC + "\n" + _log_line("applied"),
        encoding="utf-8",
    )
    rotation = bundle / "ZSATunnel.log_extracted"
    rotation.mkdir()
    (rotation / "ZSATunnel.log.1").write_text(
        _log_line("older download") + PAC + "\n" + _log_line("applied"),
        encoding="utf-8",
    )

    scan = scan_bundle(bundle)

    assert scan.found == 1
    assert scan.total_occurrences == 2
    assert len(scan.documents[0].sources) == 2


def test_two_different_pacs_stay_separate(bundle):
    other = PAC.replace("customer.onelogin.com", "other.okta.com")
    (bundle / "ZSATunnel.log").write_text(
        _log_line("a") + PAC + "\n" + _log_line("x"), encoding="utf-8"
    )
    (bundle / "ZSAService.log").write_text(
        _log_line("b") + other + "\n" + _log_line("x"), encoding="utf-8"
    )

    scan = scan_bundle(bundle)

    assert scan.found == 2
    assert {doc.fingerprint for doc in scan.documents} == {
        doc.fingerprint for doc in scan.documents
    }
    assert len({doc.fingerprint for doc in scan.documents}) == 2


def test_prose_mentioning_the_function_is_not_reported_as_a_pac(bundle):
    (bundle / "ZSATray.log").write_text(
        _log_line("checking FindProxyForURL availability")
        + _log_line("PAC fetch successful")
        + _log_line("ZUpmPacDownloader::makeRestApiCall: Pac Server returned 304"),
        encoding="utf-8",
    )

    scan = scan_bundle(bundle)

    assert scan.found == 0
    assert scan.files_scanned == 1


def test_binary_and_archive_members_are_never_opened(bundle):
    (bundle / "capture.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + PAC.encode())
    (bundle / "ZSATunnel.log.zip").write_bytes(b"PK\x03\x04" + PAC.encode())
    (bundle / "GeoLite2-ASN.mmdb").write_bytes(PAC.encode())

    scan = scan_bundle(bundle)

    assert scan.files_eligible == 0
    assert scan.found == 0


def test_rotation_named_with_a_numeric_suffix_is_eligible(bundle):
    (bundle / "ZSATunnel.log.3").write_text(
        _log_line("older") + PAC + "\n" + _log_line("done"), encoding="utf-8"
    )

    scan = scan_bundle(bundle)

    assert scan.found == 1


def test_document_cap_is_reported_rather_than_silently_truncating(bundle):
    for index in range(4):
        variant = PAC.replace("customer.onelogin.com", f"tenant{index}.onelogin.com")
        (bundle / f"ZSATunnel{index}.log").write_text(
            _log_line("d") + variant + "\n" + _log_line("x"), encoding="utf-8"
        )

    scan = scan_bundle(bundle, max_documents=2)

    assert scan.found == 2
    assert scan.hit_document_cap is True
    assert scan.complete is False


def test_plain_logs_are_read_before_rotation_contents(bundle):
    rotation = bundle / "ZSATunnel.log_extracted"
    rotation.mkdir()
    (rotation / "ZSATunnel.log.9").write_text(
        _log_line("old") + PAC.replace("gateway", "oldgateway") + "\n", encoding="utf-8"
    )
    (bundle / "ZSATunnel.log").write_text(
        _log_line("current") + PAC + "\n" + _log_line("x"), encoding="utf-8"
    )

    scan = scan_bundle(bundle, max_documents=1)

    assert scan.documents[0].source_file == "ZSATunnel.log"


def test_describe_reports_what_the_pac_says(bundle):
    (bundle / "proxy.pac").write_text(PAC, encoding="utf-8")

    info = describe(scan_bundle(bundle).documents[0])

    assert info["direct_returns"] == 4
    assert info["proxy_returns"] == 1
    assert info["proxy_targets"] == ("PROXY gateway.zscalertwo.net:80; DIRECT",)
    assert "customer.onelogin.com" in info["host_patterns"]
    assert "*.mcas.ms" in info["host_patterns"]
    assert "trust.zscaler.net" in info["host_patterns"]
    assert info["subnets"] == ("100.64.0.0/255.255.0.0",)
    assert info["functions"] == ("FindProxyForURL",)


def test_empty_bundle_reports_complete_coverage(bundle):
    (bundle / "ZSATunnel.log").write_text(_log_line("nothing to see"), encoding="utf-8")

    scan = scan_bundle(bundle)

    assert scan.found == 0
    assert scan.complete is True
    assert scan.unreadable == []


# --------------------------------------------------------------------------
# Live rules vs commented-out history.
#
# A PAC is a working document: withdrawn bypasses stay in it behind `//`.
# Counting those as active answers "is this host bypassed?" with a yes for a
# rule that is switched off, so the split is a correctness concern.
# --------------------------------------------------------------------------

PAC_WITH_HISTORY = """function FindProxyForURL(url, host) {

    var privateIP = /^(0|10|127|192\\.168)\\.[0-9.]+$/;

    if (privateIP.test(dnsResolve(host)))
        return "DIRECT";

    /* Bypass for Federated IdP */
    if (shExpMatch(host, "customer.onelogin.com"))
        return "DIRECT";

//  if (shExpMatch(host, "login.live.com"))
//      return "DIRECT";

    /* Retired: routed via a country gateway
//  if (shExpMatch(host, "accounts.live.com"))
//      return "PROXY 10.1.1.1:80; DIRECT";
    */

    return "PROXY 165.225.60.15:80; PROXY 104.129.198.10:80; DIRECT";
}"""


def test_commented_out_rules_are_excluded_from_live_counts(bundle):
    (bundle / "history.pac").write_text(PAC_WITH_HISTORY, encoding="utf-8")

    info = describe(scan_bundle(bundle).documents[0])

    assert info["host_patterns"] == ("customer.onelogin.com",)
    assert set(info["commented_host_patterns"]) == {"login.live.com", "accounts.live.com"}
    assert info["direct_returns"] == 2
    # One commented `return "DIRECT"`. The other commented return is a PROXY
    # statement, counted below rather than here.
    assert info["commented_direct_returns"] == 1
    assert info["proxy_returns"] == 1
    assert info["commented_proxy_targets"] == ("PROXY 10.1.1.1:80; DIRECT",)


def test_a_regex_literal_is_not_mistaken_for_a_comment(bundle):
    (bundle / "regex.pac").write_text(
        'function FindProxyForURL(url, host) {\n'
        '    var scheme = /^https?:\\/\\//;\n'
        '    if (scheme.test(url) && shExpMatch(host, "live.example.test"))\n'
        '        return "DIRECT";\n'
        '    return "PROXY 10.0.0.1:80";\n'
        '}\n',
        encoding="utf-8",
    )

    info = describe(scan_bundle(bundle).documents[0])

    # The `\/\/` inside the regex must not swallow the rest of the line.
    assert info["host_patterns"] == ("live.example.test",)
    assert info["proxy_returns"] == 1


def test_forwarding_targets_split_a_failover_list_with_ports(bundle):
    (bundle / "delivered.pac").write_text(PAC_WITH_HISTORY, encoding="utf-8")

    info = describe(scan_bundle(bundle).documents[0])

    assert info["is_template"] is False
    assert info["unresolved_variables"] == ()
    assert [
        (item["order"], item["kind"], item["host"], item["port"], item["variable"])
        for item in info["forwarding_targets"]
    ] == [
        (1, "PROXY", "165.225.60.15", 80, False),
        (2, "PROXY", "104.129.198.10", 80, False),
        (3, "DIRECT", "", None, False),
    ]


def test_unsubstituted_gateway_variables_mark_the_pac_as_a_template(bundle):
    # Zscaler's PAC server replaces these when it serves the file, so a PAC
    # recovered from a client's logs carries addresses instead.
    (bundle / "template.pac").write_text(
        'function FindProxyForURL(url, host) {\n'
        '    if (isPlainHostName(host)) return "DIRECT";\n'
        '    return "PROXY ${COUNTRY_GATEWAY_FX}:80; '
        'PROXY ${COUNTRY_SECONDARY_GATEWAY_FX}:80; DIRECT";\n'
        '}\n',
        encoding="utf-8",
    )

    info = describe(scan_bundle(bundle).documents[0])

    assert info["is_template"] is True
    assert info["unresolved_variables"] == (
        "COUNTRY_GATEWAY_FX", "COUNTRY_SECONDARY_GATEWAY_FX",
    )
    variables = [item for item in info["forwarding_targets"] if item["variable"]]
    assert [(item["host"], item["port"]) for item in variables] == [
        ("${COUNTRY_GATEWAY_FX}", 80),
        ("${COUNTRY_SECONDARY_GATEWAY_FX}", 80),
    ]


def test_strip_comments_preserves_line_count_and_indentation(bundle):
    from zcc_diag.pac_extract import strip_comments

    stripped = strip_comments(PAC_WITH_HISTORY)

    # Offsets stay aligned so a quoted line number still matches the source.
    assert len(stripped.splitlines()) == len(PAC_WITH_HISTORY.splitlines())
    assert "    if (privateIP.test" in stripped
    assert "login.live.com" not in stripped


# --------------------------------------------------------------------------
# Line endings and interleaved records.
#
# Both of these showed up as a PAC that looked wrong on screen rather than as
# an exception: a blank row between every real line, and a source that stopped
# before the closing brace.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r", "\n\r"])
def test_every_line_ending_convention_yields_one_line_break(bundle, ending):
    body = PAC.replace("\n", ending)
    (bundle / "endings.pac").write_bytes(body.encode())

    document = scan_bundle(bundle).documents[0]

    # splitlines() treats a lone \r as its own break, so normalising after a
    # split would put a blank row between every real line of the PAC.
    assert document.text == PAC
    assert "\r" not in document.text
    assert document.line_count == len(PAC.split("\n"))


@pytest.mark.parametrize("ending", ["\r\n", "\n\r"])
def test_line_endings_do_not_double_lines_inside_a_log(bundle, ending):
    payload = (_log_line("pac content follows:") + PAC + "\n"
               + _log_line("pac applied")).replace("\n", ending)
    (bundle / "ZSATunnel.log").write_bytes(payload.encode())

    document = scan_bundle(bundle).documents[0]

    assert document.text == PAC
    assert document.line_count == len(PAC.split("\n"))


def test_records_interleaved_into_the_pac_do_not_cut_the_source_short(bundle):
    # ZCC can write its own records into the middle of a PAC it is dumping.
    # The closing brace ends the body, not the next timestamp.
    lines = PAC.split("\n")
    middle = len(lines) // 2
    payload = (
        _log_line("pac content follows:")
        + "\n".join(lines[:middle]) + "\n"
        + _log_line("ZUpmPacDownloader: still writing pac")
        + "\n".join(lines[middle:]) + "\n"
        + _log_line("pac applied")
    )
    (bundle / "ZSATunnel.log").write_text(payload, encoding="utf-8")

    document = scan_bundle(bundle).documents[0]

    assert document.truncated is False
    assert document.text == PAC
    assert document.text.rstrip().endswith("}")
    assert "still writing pac" not in document.text


def test_a_record_after_the_closing_brace_still_ends_the_pac(bundle):
    (bundle / "ZSATunnel.log").write_text(
        _log_line("pac content follows:") + PAC + "\n"
        + _log_line("ZSATunnel: tunnel forwarding")
        + _log_line("ZSATunnel: more unrelated output"),
        encoding="utf-8",
    )

    document = scan_bundle(bundle).documents[0]

    assert document.text == PAC
    assert "tunnel forwarding" not in document.text


# --------------------------------------------------------------------------
# Writer-inserted blank lines.
#
# When a component writes a multi-line blob out line by line, each write can
# carry the blob's own newline and the writer's, leaving a blank line after
# every line of the original.
# --------------------------------------------------------------------------

def _double_blank_lines(text: str) -> str:
    """Simulate a writer that leaves a blank line after every written line.

    A run of one blank in the source becomes two; adjacent lines gain one. That
    is the pattern reported from a real bundle, and removing one blank per run
    inverts it exactly.
    """
    out = []
    for line in text.split("\n"):
        out.append(line)
        if line.strip():
            out.append("")
    return "\n".join(out)


def test_writer_doubled_blank_lines_are_collapsed_one_per_run():
    from zcc_diag.pac_extract import collapse_doubled_blank_lines

    doubled = "\n".join([
        "function FindProxyForURL(url, host) {", "", "",
        "//  header comment", "", "",
        "//  another header", "",
        "//  adjacent line one", "",
        "//  adjacent line two", "",
        '    return "PROXY 10.0.0.1:80";', "}",
    ])

    restored, removed = collapse_doubled_blank_lines(doubled)

    # One blank leaves a run entirely; a pair of blanks becomes one.
    assert restored.split("\n") == [
        "function FindProxyForURL(url, host) {", "",
        "//  header comment", "",
        "//  another header",
        "//  adjacent line one",
        "//  adjacent line two",
        '    return "PROXY 10.0.0.1:80";', "}",
    ]
    assert removed == 5


def test_genuine_paragraph_spacing_is_left_alone():
    from zcc_diag.pac_extract import collapse_doubled_blank_lines

    restored, removed = collapse_doubled_blank_lines(PAC)

    assert removed == 0
    assert restored == PAC


def test_a_doubled_pac_in_a_log_is_restored_and_reports_what_it_removed(bundle):
    (bundle / "ZSATunnel.log").write_text(
        _log_line("pac content follows:") + _double_blank_lines(PAC) + "\n"
        + _log_line("pac applied"),
        encoding="utf-8",
    )

    document = scan_bundle(bundle).documents[0]

    assert document.spacing_restored is True
    assert document.blank_lines_collapsed > 0
    # The restored copy matches the original file, not the doubled log copy.
    assert document.text == PAC
    # The copy as the bundle held it stays available and is not the same text.
    assert document.as_found != document.text
    assert document.as_found.count("\n") > document.text.count("\n")


def test_a_doubled_standalone_pac_is_restored_too(bundle):
    (bundle / "doubled.pac").write_text(_double_blank_lines(PAC), encoding="utf-8")

    document = scan_bundle(bundle).documents[0]

    assert document.spacing_restored is True
    assert document.text == PAC
