"""Parser and serializer for WireGuard (.conf) configuration files."""

from __future__ import annotations

import base64
import ipaddress
import re

from ppv.models import WireGuardProfile


class WireGuardParseError(ValueError):
    """Raised when a WireGuard configuration file is invalid."""


_RESERVED_COMMENT_RE = re.compile(r"^#\s*reserved\s*=\s*(.+)$", re.IGNORECASE)


def _strip_inline_comment(value: str) -> str:
    for sep in ("#", ";"):
        if sep in value:
            value = value.split(sep, 1)[0]
    return value.strip()


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _validate_wg_key(key: str, field_name: str) -> str:
    cleaned = key.strip()
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        raise WireGuardParseError(f"{field_name} không đúng định dạng base64 hợp lệ.") from exc
    if len(raw) != 32:
        raise WireGuardParseError(f"{field_name} phải có độ dài 32 byte (44 ký tự base64).")
    return cleaned


def _normalize_cidr(value: str, default_v4_prefix: int = 32, default_v6_prefix: int = 128) -> str:
    cleaned = value.strip()
    if "/" not in cleaned:
        addr = ipaddress.ip_address(cleaned)
        prefix = default_v4_prefix if addr.version == 4 else default_v6_prefix
        return f"{addr}/{prefix}"
    iface = ipaddress.ip_interface(cleaned)
    return str(iface)


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse an endpoint string (`host:port`, `ipv4:port`, or `[ipv6]:port`)."""
    raw = endpoint.strip()
    if not raw:
        raise WireGuardParseError("Thiếu Endpoint trong mục [Peer].")

    if raw.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", raw)
        if not match:
            raise WireGuardParseError(f"Endpoint IPv6 không hợp lệ: {endpoint}")
        host, port_str = match.group(1), match.group(2)
    else:
        if raw.count(":") != 1:
            raise WireGuardParseError(f"Endpoint không hợp lệ: {endpoint}")
        host, port_str = raw.rsplit(":", 1)

    host = host.strip()
    if not host:
        raise WireGuardParseError(f"Tên miền/IP Endpoint trống: {endpoint}")
    try:
        port = int(port_str)
    except ValueError as exc:
        raise WireGuardParseError(f"Cổng Endpoint không hợp lệ: {port_str}") from exc
    if not (1 <= port <= 65535):
        raise WireGuardParseError(f"Cổng Endpoint ngoài phạm vi (1-65535): {port}")
    return host, port


def _parse_reserved(raw_value: str) -> list[int] | None:
    cleaned = raw_value.strip().strip("[]")
    parts = [p.strip() for p in cleaned.split(",") if p.strip()]
    if len(parts) != 3:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if all(0 <= n <= 255 for n in nums):
        return nums
    return None


def parse_wireguard_conf(
    text: str,
    name: str = "WireGuard Profile",
    source: str = "imported",
) -> WireGuardProfile:
    """Parse WireGuard .conf text into a WireGuardProfile."""
    section: str | None = None
    iface_data: dict[str, list[str]] = {}
    peers: list[dict[str, list[str]]] = []
    current_peer: dict[str, list[str]] | None = None
    reserved: list[int] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        reserved_match = _RESERVED_COMMENT_RE.match(line)
        if reserved_match:
            parsed_res = _parse_reserved(reserved_match.group(1))
            if parsed_res is not None:
                reserved = parsed_res
            continue

        if line.startswith(("#", ";")):
            continue

        if line.startswith("[") and line.endswith("]"):
            sec_name = line[1:-1].strip().lower()
            if sec_name == "interface":
                section = "interface"
            elif sec_name == "peer":
                section = "peer"
                current_peer = {}
                peers.append(current_peer)
            else:
                section = None
            continue

        if "=" not in line or section is None:
            continue

        key, val = line.split("=", 1)
        key = key.strip().lower()
        val = _strip_inline_comment(val)
        if not val:
            continue

        if section == "interface":
            iface_data.setdefault(key, []).append(val)
        elif section == "peer" and current_peer is not None:
            current_peer.setdefault(key, []).append(val)

    if "privatekey" not in iface_data:
        raise WireGuardParseError("Thiếu PrivateKey trong mục [Interface].")
    private_key = _validate_wg_key(iface_data["privatekey"][0], "PrivateKey")

    raw_addresses: list[str] = []
    for entry in iface_data.get("address", []):
        raw_addresses.extend(_split_csv(entry))
    if not raw_addresses:
        raise WireGuardParseError("Thiếu Address trong mục [Interface].")
    try:
        addresses = [_normalize_cidr(a, 32, 128) for a in raw_addresses]
    except ValueError as exc:
        raise WireGuardParseError(f"Address không hợp lệ: {exc}") from exc

    dns_servers: list[str] = []
    for entry in iface_data.get("dns", []):
        for item in _split_csv(entry):
            try:
                ipaddress.ip_address(item)
                dns_servers.append(item)
            except ValueError:
                # Ignore domain DNS names if any or keep only valid IPs
                pass
    if not dns_servers:
        dns_servers = ["1.1.1.1"]

    mtu: int | None = None
    if "mtu" in iface_data:
        try:
            mtu_val = int(iface_data["mtu"][0])
            if 576 <= mtu_val <= 65535:
                mtu = mtu_val
        except ValueError:
            pass

    if "reserved" in iface_data and reserved is None:
        reserved = _parse_reserved(iface_data["reserved"][0])

    if not peers:
        raise WireGuardParseError("Thiếu mục [Peer] trong file cấu hình.")
    peer = peers[0]

    if "publickey" not in peer:
        raise WireGuardParseError("Thiếu PublicKey trong mục [Peer].")
    public_key = _validate_wg_key(peer["publickey"][0], "Peer PublicKey")

    preshared_key: str | None = None
    if "presharedkey" in peer:
        preshared_key = _validate_wg_key(peer["presharedkey"][0], "PresharedKey")

    if "endpoint" not in peer:
        raise WireGuardParseError("Thiếu Endpoint trong mục [Peer].")
    endpoint_host, endpoint_port = parse_endpoint(peer["endpoint"][0])

    raw_allowed: list[str] = []
    for entry in peer.get("allowedips", []):
        raw_allowed.extend(_split_csv(entry))
    if raw_allowed:
        try:
            allowed_ips = [str(ipaddress.ip_network(a, strict=False)) for a in raw_allowed]
        except ValueError as exc:
            raise WireGuardParseError(f"AllowedIPs không hợp lệ: {exc}") from exc
    else:
        allowed_ips = ["0.0.0.0/0", "::/0"]

    keepalive: int | None = 25
    if "persistentkeepalive" in peer:
        try:
            ka = int(peer["persistentkeepalive"][0])
            keepalive = ka if ka > 0 else None
        except ValueError:
            pass

    if "reserved" in peer and reserved is None:
        reserved = _parse_reserved(peer["reserved"][0])

    return WireGuardProfile(
        name=name.strip() or "WireGuard Profile",
        private_key=private_key,
        addresses=addresses,
        dns=dns_servers,
        mtu=mtu,
        public_key=public_key,
        preshared_key=preshared_key,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        allowed_ips=allowed_ips,
        persistent_keepalive=keepalive,
        reserved=reserved,
        source=source,
    )


def profile_to_conf(profile: WireGuardProfile) -> str:
    """Serialize a WireGuardProfile back to standard WireGuard .conf text."""
    lines: list[str] = ["[Interface]", f"PrivateKey = {profile.private_key}"]
    for addr in profile.addresses:
        lines.append(f"Address = {addr}")
    if profile.dns:
        lines.append(f"DNS = {', '.join(profile.dns)}")
    if profile.mtu:
        lines.append(f"MTU = {profile.mtu}")
    if profile.reserved and len(profile.reserved) == 3:
        lines.append(f"# Reserved = {', '.join(str(x) for x in profile.reserved)}")

    lines.extend(["", "[Peer]", f"PublicKey = {profile.public_key}"])
    if profile.preshared_key:
        lines.append(f"PresharedKey = {profile.preshared_key}")
    lines.append(f"Endpoint = {profile.endpoint}")
    for cidr in profile.allowed_ips:
        lines.append(f"AllowedIPs = {cidr}")
    if profile.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {profile.persistent_keepalive}")

    return "\n".join(lines) + "\n"
