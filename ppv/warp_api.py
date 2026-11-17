"""Cloudflare WARP free WireGuard profile generator."""

from __future__ import annotations

import base64
import contextlib
import datetime
import random
import ssl
import string

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from requests.adapters import HTTPAdapter

from ppv.models import WireGuardProfile


class _WinCertHTTPAdapter(HTTPAdapter):
    """HTTPAdapter verifying HTTPS against Windows Certificate Store (enterprise Root CAs)."""

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self._ssl_context = ssl_context
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(*args, **kwargs)


def _build_windows_trust_session() -> requests.Session:
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
    session = requests.Session()
    session.mount("https://", _WinCertHTTPAdapter(ctx))
    return session

WARP_REG_URL = "https://api.cloudflareclient.com/v0a2158/reg"
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

    try:
        try:
            resp = requests.post(WARP_REG_URL, headers=WARP_HEADERS, json=payload, timeout=timeout)
        except requests.exceptions.SSLError:
            win_session = _build_windows_trust_session()
            resp = win_session.post(
                WARP_REG_URL, headers=WARP_HEADERS, json=payload, timeout=timeout
            )
    except requests.RequestException as exc:
        raise WarpRegistrationError(f"Không thể kết nối tới máy chủ Cloudflare WARP: {exc}") from exc

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
