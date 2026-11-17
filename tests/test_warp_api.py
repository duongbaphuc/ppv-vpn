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


def test_register_warp_profile_falls_back_to_windows_cert_store_on_ssl_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_resp = MagicMock()
    fake_resp.ok = True
    fake_resp.json.return_value = {
        "config": {
            "client_id": "+Vbt",
            "interface": {"addresses": {"v4": "172.16.0.2"}},
            "peers": [
                {
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": {"host": "engage.cloudflareclient.com:2408"},
                }
            ],
        }
    }

    def raise_ssl(*args, **kwargs):
        raise warp_api.requests.exceptions.SSLError("certificate verify failed")

    fake_session = MagicMock()
    fake_session.post.return_value = fake_resp

    monkeypatch.setattr(warp_api.requests, "post", raise_ssl)
    monkeypatch.setattr(warp_api, "_build_windows_trust_session", lambda: fake_session)

    prof = register_warp_profile(name="Corporate WARP")
    assert prof.name == "Corporate WARP"
    assert prof.reserved == [249, 86, 237]
    fake_session.post.assert_called_once()


def test_register_warp_profile_falls_back_to_doh_and_direct_ip_sni_on_dns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_dns(*args, **kwargs):
        raise warp_api.requests.exceptions.ConnectionError(
            "NameResolutionError: Failed to resolve 'api.cloudflareclient.com' ([Errno 11001] getaddrinfo failed)"
        )

    doh_resp = MagicMock()
    doh_resp.ok = True
    doh_resp.json.return_value = {
        "Answer": [{"type": 1, "data": "104.16.24.84"}]
    }

    reg_resp = MagicMock()
    reg_resp.ok = True
    reg_resp.json.return_value = {
        "config": {
            "client_id": "+Vbt",
            "interface": {"addresses": {"v4": "172.16.0.2"}},
            "peers": [
                {
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": {"host": "engage.cloudflareclient.com:2408"},
                }
            ],
        }
    }

    called_urls: list[str] = []
    called_headers: list[dict[str, str]] = []

    class _FakeSniSession:
        def post(self, url: str, headers=None, json=None, timeout=None):  # noqa: A002
            _ = (json, timeout)
            called_urls.append(url)
            called_headers.append(dict(headers or {}))
            return reg_resp

    monkeypatch.setattr(warp_api.requests, "post", raise_dns)
    monkeypatch.setattr(warp_api.requests, "get", lambda *a, **kw: doh_resp)
    monkeypatch.setattr(
        warp_api,
        "_build_sni_session",
        lambda sni, use_windows_store=False: _FakeSniSession(),
    )

    prof = register_warp_profile(name="DoH Fallback WARP")
    assert prof.name == "DoH Fallback WARP"
    assert called_urls == ["https://104.16.24.84/v0a2158/reg"]
    assert called_headers[0]["Host"] == "api.cloudflareclient.com"


def test_register_warp_profile_direct_ip_sni_uses_wincert_and_reports_simplewall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_dns(*args, **kwargs):
        raise warp_api.requests.exceptions.ConnectionError("[Errno 11001] getaddrinfo failed")

    class _SslThenTimeoutSession:
        def __init__(self, use_windows_store: bool) -> None:
            self._use_win = use_windows_store

        def post(self, *args, **kwargs):
            if not self._use_win:
                raise warp_api.requests.exceptions.SSLError("self-signed cert")
            raise warp_api.requests.exceptions.ConnectTimeout("blocked by firewall")

    win_store_calls: list[bool] = []

    def fake_sni_session(sni: str, use_windows_store: bool = False):
        _ = sni
        win_store_calls.append(use_windows_store)
        return _SslThenTimeoutSession(use_windows_store)

    monkeypatch.setattr(warp_api.requests, "post", raise_dns)
    monkeypatch.setattr(warp_api, "_resolve_warp_api_ips_via_doh", lambda timeout=5.0: ["104.16.24.84"])
    monkeypatch.setattr(warp_api, "_build_sni_session", fake_sni_session)
    monkeypatch.setattr(warp_api, "_iter_process_entries", lambda: [(999, "simplewall.exe")])

    with pytest.raises(WarpRegistrationError) as exc_info:
        register_warp_profile()

    assert win_store_calls == [False, True]
    assert "simplewall.exe" in str(exc_info.value)
