from zcc_diag.endpoint_intel import (
    GeoRecord,
    hostname_map,
    provider_class,
    split_endpoint,
)
from zcc_diag.ui import endpoint_intelligence


def test_provider_class_identifies_common_networks_and_private_ips():
    assert provider_class("ZSCALER, INC.", "1.2.3.4") == "Zscaler"
    assert provider_class("MICROSOFT-CORP-MSN-AS-BLOCK", "1.2.3.4") == "Microsoft / Azure"
    assert provider_class("", "10.0.0.8") == "Private / local"


def test_hostname_map_combines_captured_dns_and_sni_without_live_lookup():
    result = hostname_map({
        "dns_answers": {"203.0.113.10": {"api.example.test"}},
        "sni_to_ips": {"login.example.test": {"203.0.113.10"}},
    })
    assert result["203.0.113.10"] == ["api.example.test", "login.example.test"]


def test_split_endpoint_preserves_ipv6():
    assert split_endpoint("2001:db8::5:tcp/443") == ("2001:db8::5", "tcp", 443)


def test_problem_endpoint_rows_surface_signals_and_enrichment(monkeypatch):
    monkeypatch.setattr(
        endpoint_intelligence,
        "lookup_ips",
        lambda ips: {
            "203.0.113.10": GeoRecord(
                asn="AS64500",
                organization="ZSCALER, INC.",
                provider_class="Zscaler",
                country="US",
            )
        },
    )
    pcaps = [{
        "bytes_per_endpoint": {"203.0.113.10:tcp/443": 4096},
        "endpoints": {"203.0.113.10:tcp/443": 8},
        "tcp_syns": {"203.0.113.10:tcp/443": 5},
        "tcp_syn_acks": {"203.0.113.10:tcp/443": 2},
        "tcp_reset_endpoints": {"203.0.113.10:tcp/443": 1},
        "tcp_retransmits": {"203.0.113.10:tcp/443": 2},
        "tls_alert_endpoints": {},
        "dns_answers": {"203.0.113.10": {"gateway.example.test"}},
        "sni_to_ips": {},
    }]

    rows = endpoint_intelligence.build_endpoint_rows(pcaps)

    assert len(rows) == 1
    row = rows[0]
    assert "3 SYN without captured SYN-ACK" in row["Issue signals"]
    assert row["Hostname"] == "gateway.example.test"
    assert row["Provider class"] == "Zscaler"
    assert row["ASN"] == "AS64500"
