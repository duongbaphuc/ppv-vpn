"""Tests for Cloudflare WARP registration and WireGuard keypair generation."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from ppv import warp_api
from ppv.warp_api import (
    WarpRegistrationError,
    decode_client_id_reserved,
    generate_wireguard_keypair,
    register_warp_profile,
)


def test_generate_wireguard_keypair_valid_32_bytes() -> None:
    priv, pub = generate_wireguard_keypair()
    assert len(base64.b64decode(priv)) == 32
    assert len(base64.b64decode(pub)) == 32
    assert priv != pub


def test_decode_client_id_reserved() -> None:
    # base64("+Vbt") -> b'\xf9V\xed' -> [249, 86, 237]
    assert decode_client_id_reserved("+Vbt") == [249, 86, 237]
    assert decode_client_id_reserved(None) is None
    assert decode_client_id_reserved("not-b64!") is None


def test_register_warp_profile_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_resp = MagicMock()
    fake_resp.ok = True
    fake_resp.json.return_value = {
        "config": {
            "client_id": "+Vbt",
            "interface": {
                "addresses": {
                    "v4": "172.16.0.2",
                    "v6": "2606:4700:110::2",
                }
            },
            "peers": [
                {
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": {"host": "engage.cloudflareclient.com:2408"},
                }
            ],
        }
    }
    monkeypatch.setattr(warp_api.requests, "post", lambda *a, **kw: fake_resp)

    prof = register_warp_profile(name="My WARP")
    assert prof.name == "My WARP"
    assert prof.addresses == ["172.16.0.2/32", "2606:4700:110::2/128"]
    assert prof.reserved == [249, 86, 237]
    assert prof.endpoint == "engage.cloudflareclient.com:2408"
    assert prof.source == "warp"


def test_register_warp_profile_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_resp = MagicMock()
    fake_resp.ok = False
    fake_resp.status_code = 429
    fake_resp.text = "Too Many Requests"
    monkeypatch.setattr(warp_api.requests, "post", lambda *a, **kw: fake_resp)

    with pytest.raises(WarpRegistrationError):
        register_warp_profile()
