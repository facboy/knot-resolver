import ipaddress
import random
import string
from typing import Any

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DomainName,
    EscQuotesString,
    InterfaceName,
    InterfaceOptionalPort,
    InterfacePort,
    IPAddressOptionalPort,
    IPAddressPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    IPv6Network96,
    PinSha256,
    PortNumber,
    RawString,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.utils.modeling import BaseSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError


def _rand_domain(label_chars: int, levels: int = 1) -> str:
    return "".join(
        ["".join(random.choices(string.ascii_letters + string.digits, k=label_chars)) + "." for i in range(levels)]
    )


@pytest.mark.parametrize("val", [1, 65_535, 5353, 5000])
def test_port_number_valid(val: int):
    assert int(PortNumber(val)) == val


@pytest.mark.parametrize("val", [0, 65_636, -1, "53"])
def test_port_number_invalid(val: Any):
    with raises(ValueError):
        PortNumber(val)


@pytest.mark.parametrize("val", ["5368709120B", "5242880K", "5120M", "5G"])
def test_size_unit_valid(val: str):
    o = SizeUnit(val)
    assert int(o) == 5368709120
    assert str(o) == val
    assert o.bytes() == 5368709120


@pytest.mark.parametrize("val", ["-5B", 5, -5242880, "45745mB"])
def test_size_unit_invalid(val: Any):
    with raises(ValueError):
        SizeUnit(val)


@pytest.mark.parametrize("val", ["1d", "24h", "1440m", "86400s", "86400000ms"])
def test_time_unit_valid(val: str):
    o = TimeUnit(val)
    assert int(o) == 86400000
    assert str(o) == val
    assert o.seconds() == 86400
    assert o.millis() == 86400000


@pytest.mark.parametrize("val", ["-1", "-24h", "1440mm", 6575, -1440])
def test_time_unit_invalid(val: Any):
    with raises(ValueError):
        TimeUnit("-1")


def test_parsing_units():
    class TestSchema(BaseSchema):
        size: SizeUnit
        time: TimeUnit

    o = TestSchema({"size": "3K", "time": "10m"})
    assert o.size == SizeUnit("3072B")
    assert o.time == TimeUnit("600s")
    assert o.size.bytes() == 3072
    assert o.time.seconds() == 10 * 60


def test_checked_path():
    class TestSchema(BaseSchema):
        p: CheckedPath

    assert str(TestSchema({"p": "/tmp"}).p) == "/tmp"


@pytest.mark.parametrize(
    "val",
    [
        "YmE3ODE2YmY4ZjAx+2ZlYTQxNDE0MGRlNWRhZTIyMjNiMDAzNjFhMzk/MTc3YTljYjQxMGZmNjFmMjAwMTVhZA==",
        "OTJmODU3ZDMyOWMwOWNlNTU4Y2M0YWNjMjI5NWE2NWJlMzY4MzRmMzY3NGU3NDAwNTI1YjMxZTMxYTgzMzQwMQ==",
    ],
)
def test_pin_sha256_valid(val: str):
    o = PinSha256(val)
    assert str(o) == val


@pytest.mark.parametrize(
    "val",
    [
        "!YmE3ODE2YmY4ZjAxY2ZlYTQxNDE0MGRlNWRhZTIyMjNiMDAzNjFhMzk2MTc3YTljjQxMGZmNjFmMjAwMTVhZA==",
        "OTJmODU3ZDMyOWMwOWNlNTU4Y2M0YWNjMjI5NWE2NWJlMzY4MzRmMzY3NGU3NDAwNTI1YjMxZTMxYTgzMzQwMQ",
        "YmFzZTY0IQ",
    ],
)
def test_pin_sha256_invalid(val: str):
    with raises(KresManagerException):
        PinSha256(val)


@pytest.mark.parametrize(
    "val,exp",
    [
        ("string", "string"),
        (2000, "2000"),
        ('"double quotes"', r"\"double quotes\""),
        ("'single quotes'", r"\'single quotes\'"),
        # fmt: off
        ('\"double quotes\"', r"\"double quotes\""),
        ("\'single quotes\'", r"\'single quotes\'"),
        ('\\"double quotes\\"', r'\\"double quotes\\"'),
        ("\\'single quotes\\'", r"\\'single quotes\\'"),
        # fmt: on
    ],
)
def test_esc_quotes_string_valid(val: Any, exp: str):
    assert str(EscQuotesString(val)) == exp


@pytest.mark.parametrize("val", [1.1, False])
def test_escaped_quotes_string_invalid(val: Any):
    with raises(DataValidationError):
        EscQuotesString(val)


@pytest.mark.parametrize(
    "val,exp",
    [
        (2000, "2000"),
        ("string", r"string"),
        ("[^i*&2@]\t", r"[^i*&2@]\t"),
        # fmt: off
        ("\"\n\"", r'\"\n\"'),
        ("\'\n\'", r'\'\n\''),
        ('\'\n\'', r'\'\n\''),
        ('\"\n\"', r'\"\n\"'),
        ("'\n'", r'\'\n\''),
        ('"\n"', r'\"\n\"'),
        # fmt: on
    ],
)
def test_raw_string_valid(val: Any, exp: str):
    assert str(RawString(val)) == exp


@pytest.mark.parametrize("val", [1.1, False])
def test_raw_string_invalid(val: Any):
    with raises(DataValidationError):
        RawString(val)


@pytest.mark.parametrize(
    "val",
    [
        ".",
        "example.com",
        "this.is.example.com.",
        "test.example.com",
        "test-example.com",
        "bücher.com.",
        "příklad.cz",
        _rand_domain(63),
        _rand_domain(1, 127),
    ],
)
def test_domain_name_valid(val: str):
    o = DomainName(val)
    assert str(o) == val
    assert o == DomainName(val)
    assert o.punycode() == val.encode("idna").decode("utf-8") if val != "." else "."


@pytest.mark.parametrize(
    "val",
    [
        "test.example..com.",
        "-example.com",
        "test-.example.net",
        ".example.net",
        _rand_domain(64),
        _rand_domain(1, 128),
    ],
)
def test_domain_name_invalid(val: str):
    with raises(ValueError):
        DomainName(val)


@pytest.mark.parametrize("val", ["lo", "eth0", "wlo1", "web_ifgrp", "e8-2"])
def test_interface_name_valid(val: str):
    assert str(InterfaceName(val)) == val


@pytest.mark.parametrize("val", ["_lo", "-wlo1", "lo_", "wlo1-", "e8--2", "web__ifgrp"])
def test_interface_name_invalid(val: Any):
    with raises(ValueError):
        InterfaceName(val)


@pytest.mark.parametrize("val", ["lo@5353", "2001:db8::1000@5001"])
def test_interface_port_valid(val: str):
    o = InterfacePort(val)
    assert str(o) == val
    assert o == InterfacePort(val)
    assert str(o.if_name if o.if_name else o.addr) == val.split("@", 1)[0]
    assert o.port == PortNumber(int(val.split("@", 1)[1]))


@pytest.mark.parametrize("val", ["lo", "2001:db8::1000", "53"])
def test_interface_port_invalid(val: Any):
    with raises(ValueError):
        InterfacePort(val)


@pytest.mark.parametrize("val", ["lo", "123.4.5.6", "lo@5353", "2001:db8::1000@5001"])
def test_interface_optional_port_valid(val: str):
    o = InterfaceOptionalPort(val)
    assert str(o) == val
    assert o == InterfaceOptionalPort(val)
    assert str(o.if_name if o.if_name else o.addr) == (val.split("@", 1)[0] if "@" in val else val)
    assert o.port == (PortNumber(int(val.split("@", 1)[1])) if "@" in val else None)


@pytest.mark.parametrize("val", ["lo@", "@53"])
def test_interface_optional_port_invalid(val: Any):
    with raises(ValueError):
        InterfaceOptionalPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6@5353", "2001:db8::1000@53"])
def test_ip_address_port_valid(val: str):
    o = IPAddressPort(val)
    assert str(o) == val
    assert o == IPAddressPort(val)
    assert str(o.addr) == val.split("@", 1)[0]
    assert o.port == PortNumber(int(val.split("@", 1)[1]))


@pytest.mark.parametrize(
    "val", ["123.4.5.6", "2001:db8::1000", "123.4.5.6.7@5000", "2001:db8::10000@5001", "123.4.5.6@"]
)
def test_ip_address_port_invalid(val: Any):
    with raises(ValueError):
        IPAddressPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "123.4.5.6@5353", "2001:db8::1000", "2001:db8::1000@53"])
def test_ip_address_optional_port_valid(val: str):
    o = IPAddressOptionalPort(val)
    assert str(o) == val
    assert o == IPAddressOptionalPort(val)
    assert str(o.addr) == (val.split("@", 1)[0] if "@" in val else val)
    assert o.port == (PortNumber(int(val.split("@", 1)[1])) if "@" in val else None)


@pytest.mark.parametrize("val", ["123.4.5.6.7", "2001:db8::10000", "123.4.5.6@", "@55"])
def test_ip_address_optional_port_invalid(val: Any):
    with raises(ValueError):
        IPAddressOptionalPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "192.168.0.1"])
def test_ipv4_address_valid(val: str):
    o = IPv4Address(val)
    assert str(o) == val
    assert o == IPv4Address(val)


@pytest.mark.parametrize("val", ["123456", "2001:db8::1000"])
def test_ipv4_address_invalid(val: Any):
    with raises(ValueError):
        IPv4Address(val)


@pytest.mark.parametrize("val", ["2001:db8::1000", "2001:db8:85a3::8a2e:370:7334"])
def test_ipv6_address_valid(val: str):
    o = IPv6Address(val)
    assert str(o) == val
    assert o == IPv6Address(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "2001::db8::1000"])
def test_ipv6_address_invalid(val: Any):
    with raises(ValueError):
        IPv6Address(val)


@pytest.mark.parametrize("val", ["10.11.12.0/24", "64:ff9b::/96"])
def test_ip_network_valid(val: str):
    o = IPNetwork(val)
    assert str(o) == val
    assert o.to_std().prefixlen == int(val.split("/", 1)[1])
    assert o.to_std() == ipaddress.ip_network(val)


@pytest.mark.parametrize("val", ["10.11.12.13/8", "10.11.12.5/128"])
def test_ip_network_invalid(val: str):
    with raises(ValueError):
        IPNetwork(val)


@pytest.mark.parametrize("val", ["fe80::/96", "64:ff9b::/96"])
def test_ipv6_96_network_valid(val: str):
    assert str(IPv6Network96(val)) == val


@pytest.mark.parametrize("val", ["fe80::/95", "10.11.12.3/96", "64:ff9b::1/96"])
def test_ipv6_96_network_invalid(val: Any):
    with raises(ValueError):
        IPv6Network96(val)
