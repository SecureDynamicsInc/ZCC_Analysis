from zcc_diag.wireshark_filters import (
    FILTER_LIBRARY,
    detected_pcap_filters,
    dns_failure_filter,
    endpoint_display_filter,
    tcp_reset_filter,
)


def test_library_has_copyable_zscaler_troubleshooting_coverage():
    assert len(FILTER_LIBRARY) >= 15
    keys = {recipe.key for recipe in FILTER_LIBRARY}
    assert {"dns_failures", "tcp_resets", "tcp_retransmissions", "tls_fatal",
            "http_connect", "udp_443", "tls_sni"} <= keys
    assert all("<" not in recipe.display_filter for recipe in FILTER_LIBRARY)


def test_dns_failure_filter_is_tailored_to_observed_names():
    value = dns_failure_filter(["missing.example.test  [A]", "api.example.test"])
    assert "dns.flags.rcode != 0" in value
    assert 'dns.qry.name == "missing.example.test"' in value
    assert 'dns.qry.name == "api.example.test"' in value


def test_endpoint_filters_support_ipv4_and_ipv6():
    assert endpoint_display_filter("198.51.100.25") == "ip.addr == 198.51.100.25"
    assert endpoint_display_filter("2001:db8::25") == "ipv6.addr == 2001:db8::25"
    value = tcp_reset_filter(["198.51.100.25:tcp/443", "2001:db8::25:tcp/443"])
    assert "tcp.flags.reset == 1" in value
    assert "ip.addr == 198.51.100.25" in value
    assert "ipv6.addr == 2001:db8::25" in value


def test_detected_capture_filters_only_include_observed_signal_types():
    recipes = detected_pcap_filters({
        "dns_nxdomain": {"missing.example.test  [A]": 2},
        "tcp_reset_endpoints": {"198.51.100.25:tcp/443": 1},
        "tcp_retransmits": {},
        "tls_alert_endpoints": {},
        "tcp_syns": {"198.51.100.25:tcp/443": 3},
        "tcp_syn_acks": {"198.51.100.25:tcp/443": 1},
    })
    assert [recipe.key for recipe in recipes] == [
        "detected_dns", "detected_rst", "detected_syn",
    ]
    assert all(recipe.display_filter for recipe in recipes)
