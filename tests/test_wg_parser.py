"""Tests for WireGuard .conf parser and serializer."""

from __future__ import annotations

from pathlib import Path

import pytest

from ppv.wg_parser import (
    WireGuardParseError,
    parse_endpoint,
    parse_wireguard_conf,
    profile_to_conf,
)

VALID_PRIV = "ERERERERERERERERERERERERERERERERERERERERERE="
VALID_PUB = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="


def test_parse_existing_warpplus_conf() -> None:
    warp_path = Path(__file__).resolve().parent.parent / "warpplus.conf"
    if warp_path.exists():
        text = warp_path.read_text(encoding="utf-8")
        prof = parse_wireguard_conf(text, name="WARP+")
        assert prof.addresses == [
            "172.16.0.2/24",
            "fd01:5ca1:ab1e:8714:7297:f261:6863:2fab/120",
        ]
    else:
        sample = f"""
[Interface]
PrivateKey = {VALID_PRIV}
Address = 172.16.0.2/24
Address = fd01:5ca1:ab1e::2/120
DNS = 1.1.1.1

[Peer]
PublicKey = {VALID_PUB}
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
"""
        prof = parse_wireguard_conf(sample, name="WARP+")
        assert prof.private_key == VALID_PRIV
        assert prof.public_key == VALID_PUB
        assert prof.addresses == ["172.16.0.2/24", "fd01:5ca1:ab1e::2/120"]

    assert prof.dns == ["1.1.1.1"]
    assert prof.endpoint_host == "engage.cloudflareclient.com"
    assert prof.endpoint_port == 2408
    assert prof.allowed_ips == ["0.0.0.0/0", "::/0"]


def test_parse_ipv6_endpoint_preshared_and_reserved() -> None:
    conf = f"""
[Interface]
PrivateKey = {VALID_PRIV}
Address = 10.7.0.2
DNS = 1.1.1.1, 8.8.8.8 # inline comment
MTU = 1380
# Reserved = 249, 86, 237

[Peer]
PublicKey = {VALID_PUB}
PresharedKey = {VALID_PRIV}
Endpoint = [2606:4700:d0::a29f:c007]:2408
AllowedIPs = 10.7.0.0/24, 0.0.0.0/0
PersistentKeepalive = 15
"""
    prof = parse_wireguard_conf(conf, name="Custom")
    assert prof.addresses == ["10.7.0.2/32"]
    assert prof.dns == ["1.1.1.1", "8.8.8.8"]
    assert prof.mtu == 1380
    assert prof.reserved == [249, 86, 237]
    assert prof.preshared_key == VALID_PRIV
    assert prof.endpoint_host == "2606:4700:d0::a29f:c007"
    assert prof.endpoint_port == 2408
    assert prof.endpoint == "[2606:4700:d0::a29f:c007]:2408"
    assert prof.persistent_keepalive == 15

    serialized = profile_to_conf(prof)
    reparsed = parse_wireguard_conf(serialized, name="Custom")
    assert reparsed.private_key == prof.private_key
    assert reparsed.reserved == [249, 86, 237]
    assert reparsed.endpoint == prof.endpoint


def test_parse_endpoint_validation() -> None:
    assert parse_endpoint("162.159.192.7:2408") == ("162.159.192.7", 2408)
    assert parse_endpoint("[::1]:51820") == ("::1", 51820)
    with pytest.raises(WireGuardParseError):
        parse_endpoint("no-port-here")
    with pytest.raises(WireGuardParseError):
        parse_endpoint("example.com:70000")


def test_invalid_key_raises() -> None:
    bad = f"[Interface]\nPrivateKey = not-a-key\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUB}\nEndpoint = 1.2.3.4:51820\n"
    with pytest.raises(WireGuardParseError):
        parse_wireguard_conf(bad)
