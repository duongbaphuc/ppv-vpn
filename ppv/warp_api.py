"""Cloudflare WARP free WireGuard profile generator."""

from __future__ import annotations

import base64
import contextlib
import datetime
import ipaddress
import random
import socket
import ssl
import string
from typing import Any

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from requests.adapters import HTTPAdapter

from ppv.models import WireGuardProfile
from ppv.process_helper import _iter_process_entries


class _WinCertHTTPAdapter(HTTPAdapter):
    """HTTPAdapter with optional Windows Certificate Store trust and explicit TLS SNI hostname."""

    def __init__(
        self,
        ssl_context: ssl.SSLContext | None = None,
        sni_hostname: str | None = None,
    ) -> None:
        self._ssl_context = ssl_context
        self._sni_hostname = sni_hostname
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self._ssl_context is not None:
            kwargs["ssl_context"] = self._ssl_context
        if self._sni_hostname:
            kwargs["server_hostname"] = self._sni_hostname
            kwargs["assert_hostname"] = self._sni_hostname
        return super().init_poolmanager(*args, **kwargs)


def _build_windows_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Many enterprise Windows Root CAs omit the critical flag on Basic Constraints,
    # which Python 3.13 / OpenSSL 3.x VERIFY_X509_STRICT rejects by default.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    enum_certs = getattr(ssl, "enum_certificates", None)
    if callable(enum_certs):
        for store_name in ("ROOT", "CA"):
            try:
                certs = enum_certs(store_name)
            except Exception:
                continue
            for cert_bytes, enc, _trust in certs:
                if enc == "x509_asn":
                    with contextlib.suppress(Exception):
                        ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert_bytes))
    return ctx


def _build_windows_trust_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _WinCertHTTPAdapter(_build_windows_ssl_context()))
    return session


def _build_sni_session(sni_hostname: str, use_windows_store: bool = False) -> requests.Session:
    ctx = _build_windows_ssl_context() if use_windows_store else None
    session = requests.Session()
    session.mount("https://", _WinCertHTTPAdapter(ssl_context=ctx, sni_hostname=sni_hostname))
    return session


WARP_API_HOST = "api.cloudflareclient.com"
WARP_API_PATH = "/v0a2158/reg"
WARP_REG_URL = f"https://{WARP_API_HOST}{WARP_API_PATH}"
WARP_DOH_ENDPOINTS: tuple[str, ...] = (
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://8.8.8.8/resolve",
)
WARP_FALLBACK_IPS: tuple[str, ...] = (
    "104.16.24.84",
    "104.16.192.82",
    "162.159.192.4",
)
WARP_HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.10-2158",
    "Content-Type": "application/json; charset=UTF-8",
}


class WarpRegistrationError(RuntimeError):
    """Raised when registering a free Cloudflare WARP key fails."""


def generate_wireguard_keypair() -> tuple[str, str]:
    """Generate a base64-encoded WireGuard X25519 (private_key, public_key) pair."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = base64.b64encode(
        priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode("ascii")
    pub_b64 = base64.b64encode(
        pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return priv_b64, pub_b64


def decode_client_id_reserved(client_id: str | None) -> list[int] | None:
    """Decode Cloudflare WARP client_id base64 into the 3-byte WireGuard reserved field."""
    if not client_id:
        return None
    try:
        raw = base64.b64decode(client_id.strip())
    except Exception:
        return None
    if len(raw) >= 3:
        return [int(raw[0]), int(raw[1]), int(raw[2])]
    return None


def _random_id(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=length))


def _is_dns_resolution_error(exc: BaseException) -> bool:
    """Return True when exc (or its causal chain) indicates DNS hostname resolution failure."""
    visited: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        cur = stack.pop()
        if id(cur) in visited:
            continue
        visited.add(id(cur))
        if isinstance(cur, socket.gaierror):
            return True
        msg = str(cur).lower()
        if any(
            marker in msg
            for marker in (
                "getaddrinfo failed",
                "failed to resolve",
                "nameresolutionerror",
                "temporary failure in name resolution",
                "[errno 11001]",
                "[errno 11002]",
            )
        ):
            return True
        if cur.__cause__ is not None:
            stack.append(cur.__cause__)
        if cur.__context__ is not None:
            stack.append(cur.__context__)
        for arg in getattr(cur, "args", ()):
            if isinstance(arg, BaseException):
                stack.append(arg)
    return False


def _resolve_warp_api_ips_via_doh(timeout: float = 5.0) -> list[str]:
    """Resolve api.cloudflareclient.com via IP-based DoH, appending static edge IPs."""
    ips: list[str] = []
    seen: set[str] = set()

    def _add_ip(raw_ip: str) -> None:
        cleaned = raw_ip.strip()
        if not cleaned or cleaned in seen:
            return
        with contextlib.suppress(ValueError):
            ipaddress.IPv4Address(cleaned)
            seen.add(cleaned)
            ips.append(cleaned)

    for doh_url in WARP_DOH_ENDPOINTS:
        try:
            try:
                resp = requests.get(
                    doh_url,
                    params={"name": WARP_API_HOST, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                    timeout=timeout,
                )
            except requests.exceptions.SSLError:
                resp = _build_windows_trust_session().get(
                    doh_url,
                    params={"name": WARP_API_HOST, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                    timeout=timeout,
                )
            if resp.ok:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if isinstance(ans, dict) and ans.get("type") == 1:
                        _add_ip(str(ans.get("data", "")))
            if ips:
                break
        except Exception:
            continue

    for fallback_ip in WARP_FALLBACK_IPS:
        _add_ip(fallback_ip)
    return ips


def _post_warp_direct_ip(
    ip: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float,
) -> requests.Response:
    direct_url = f"https://{ip}{WARP_API_PATH}"
    direct_headers = {**headers, "Host": WARP_API_HOST}
    try:
        return _build_sni_session(WARP_API_HOST, use_windows_store=False).post(
            direct_url, headers=direct_headers, json=payload, timeout=timeout
        )
    except requests.exceptions.SSLError:
        return _build_sni_session(WARP_API_HOST, use_windows_store=True).post(
            direct_url, headers=direct_headers, json=payload, timeout=timeout
        )


def _format_warp_connection_error(
    exc: requests.RequestException,
    had_dns_failure: bool = False,
) -> str:
    simplewall_on = any(
        name.lower() == "simplewall.exe" for _pid, name in _iter_process_entries()
    )
    if had_dns_failure or _is_dns_resolution_error(exc) or simplewall_on:
        hints: list[str] = []
        if simplewall_on:
            hints.append(
                "Phát hiện simplewall.exe đang chạy — hãy kiểm tra và cho phép PPV-VPN.exe kết nối mạng trong simplewall"
            )
        hints.append(
            "hoặc kiểm tra kết nối DNS/mạng (cũng có thể dùng '+ Nhập file .conf' nếu đã có file WireGuard)"
        )
        return (
            f"Không thể kết nối tới máy chủ Cloudflare WARP: {exc}\n\n"
            f"Gợi ý: {'; '.join(hints)}."
        )
    return f"Không thể kết nối tới máy chủ Cloudflare WARP: {exc}"


def register_warp_profile(
    name: str = "Cloudflare WARP",
    timeout: float = 15.0,
) -> WireGuardProfile:
    """Register a fresh free Cloudflare WARP WireGuard profile via the public client API."""
    priv_key, pub_key = generate_wireguard_keypair()
    install_id = _random_id(22)
    fcm_token = f"{install_id}:APA91b{_random_id(134)}"
    tos = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    payload = {
        "key": pub_key,
        "install_id": install_id,
        "fcm_token": fcm_token,
        "tos": tos,
        "model": "PC",
        "serial_number": install_id,
        "locale": "en_US",
    }

    resp: requests.Response | None = None
    try:
        try:
            resp = requests.post(WARP_REG_URL, headers=WARP_HEADERS, json=payload, timeout=timeout)
        except requests.exceptions.SSLError:
            win_session = _build_windows_trust_session()
            resp = win_session.post(
                WARP_REG_URL, headers=WARP_HEADERS, json=payload, timeout=timeout
            )
    except requests.RequestException as exc:
        if not _is_dns_resolution_error(exc):
            raise WarpRegistrationError(_format_warp_connection_error(exc)) from exc

        last_exc: requests.RequestException = exc
        for candidate_ip in _resolve_warp_api_ips_via_doh(timeout=min(timeout, 5.0)):
            try:
                resp = _post_warp_direct_ip(
                    candidate_ip,
                    WARP_HEADERS,
                    payload,
                    timeout=min(timeout, 8.0),
                )
                break
            except requests.RequestException as ip_exc:
                last_exc = ip_exc
                continue
        if resp is None:
            raise WarpRegistrationError(
                _format_warp_connection_error(last_exc, had_dns_failure=True)
            ) from last_exc

    if not resp.ok:
        raise WarpRegistrationError(
            f"Cloudflare WARP trả về lỗi HTTP {resp.status_code}: {resp.text[:200]}"
        )

    try:
        data = resp.json()
        cfg = data["config"]
        iface_addrs = cfg["interface"]["addresses"]
        peer = cfg["peers"][0]
        peer_pub = peer["public_key"]
        endpoint_host_port = peer["endpoint"].get("host") or "engage.cloudflareclient.com:2408"
        if ":" in endpoint_host_port:
            ep_host, ep_port_str = endpoint_host_port.rsplit(":", 1)
            ep_port = int(ep_port_str)
        else:
            ep_host, ep_port = endpoint_host_port, 2408
    except Exception as exc:
        raise WarpRegistrationError(f"Dữ liệu trả về từ Cloudflare không hợp lệ: {exc}") from exc

    addresses: list[str] = []
    if iface_addrs.get("v4"):
        v4 = iface_addrs["v4"]
        addresses.append(v4 if "/" in v4 else f"{v4}/32")
    if iface_addrs.get("v6"):
        v6 = iface_addrs["v6"]
        addresses.append(v6 if "/" in v6 else f"{v6}/128")

    if not addresses:
        raise WarpRegistrationError("Cloudflare WARP không cấp địa chỉ IP cho thiết bị.")

    reserved = decode_client_id_reserved(cfg.get("client_id"))

    return WireGuardProfile(
        name=name.strip() or "Cloudflare WARP",
        private_key=priv_key,
        addresses=addresses,
        dns=["1.1.1.1"],
        mtu=1280,
        public_key=peer_pub,
        endpoint_host=ep_host,
        endpoint_port=ep_port,
        allowed_ips=["0.0.0.0/0", "::/0"],
        persistent_keepalive=25,
        reserved=reserved,
        source="warp",
    )
