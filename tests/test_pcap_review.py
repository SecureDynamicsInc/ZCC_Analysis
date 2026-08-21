from zcc_diag.pcap_review import _parse_dns_address_answers


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def test_parse_dns_a_answer_for_hostname_correlation():
    name = "gateway.example.test"
    header = (
        b"\x12\x34"  # ID
        b"\x81\x80"  # standard successful response
        b"\x00\x01"  # one question
        b"\x00\x01"  # one answer
        b"\x00\x00\x00\x00"
    )
    question = _qname(name) + b"\x00\x01\x00\x01"
    answer = (
        b"\xc0\x0c"  # compressed owner name
        b"\x00\x01\x00\x01"  # A / IN
        b"\x00\x00\x00\x3c"  # TTL
        b"\x00\x04"
        b"\xcb\x00\x71\x0a"  # 203.0.113.10
    )

    assert _parse_dns_address_answers(header + question + answer) == [
        (name, "203.0.113.10")
    ]
