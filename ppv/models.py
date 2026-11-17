"""Data models for WireGuard profiles, per-app split-tunneling rules, and settings."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

SplitMode = Literal["include", "exclude"]
DnsMode = Literal["split", "vpn_all", "local"]
MatchType = Literal["name", "path"]


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass
class WireGuardProfile:
    """Represents a parsed WireGuard / WARP+ tunnel profile."""

    name: str
    private_key: str
    addresses: list[str]
    public_key: str
    endpoint_host: str
    endpoint_port: int
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    dns: list[str] = field(default_factory=lambda: ["1.1.1.1"])
    mtu: int | None = None
    preshared_key: str | None = None
    allowed_ips: list[str] = field(default_factory=lambda: ["0.0.0.0/0", "::/0"])
    persistent_keepalive: int | None = 25
    reserved: list[int] | None = None
    source: str = "imported"
    created_at: str = field(default_factory=utc_now_iso)

    @property
    def endpoint(self) -> str:
        if ":" in self.endpoint_host and not self.endpoint_host.startswith("["):
            return f"[{self.endpoint_host}]:{self.endpoint_port}"
        return f"{self.endpoint_host}:{self.endpoint_port}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WireGuardProfile:
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            name=str(data["name"]),
            private_key=str(data["private_key"]),
            addresses=[str(x) for x in data.get("addresses", [])],
            public_key=str(data["public_key"]),
            endpoint_host=str(data["endpoint_host"]),
            endpoint_port=int(data["endpoint_port"]),
            dns=[str(x) for x in data.get("dns", ["1.1.1.1"])],
            mtu=int(data["mtu"]) if data.get("mtu") is not None else None,
            preshared_key=str(data["preshared_key"]) if data.get("preshared_key") else None,
            allowed_ips=[str(x) for x in data.get("allowed_ips", ["0.0.0.0/0", "::/0"])],
            persistent_keepalive=(
                int(data["persistent_keepalive"])
                if data.get("persistent_keepalive") is not None
                else None
            ),
            reserved=[int(x) for x in data["reserved"]] if data.get("reserved") else None,
            source=str(data.get("source", "imported")),
            created_at=str(data.get("created_at") or utc_now_iso()),
        )


@dataclass
class AppRule:
    """Represents an application rule for per-app VPN split tunneling."""

    display_name: str
    exe_name: str
    exe_path: str
    enabled: bool = True
    match_type: MatchType = "name"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppRule:
        match_type = data.get("match_type", "name")
        if match_type not in ("name", "path"):
            match_type = "name"
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            display_name=str(data.get("display_name") or data["exe_name"]),
            exe_name=str(data["exe_name"]),
            exe_path=str(data.get("exe_path") or data["exe_name"]),
            enabled=bool(data.get("enabled", True)),
            match_type=match_type,
        )


@dataclass
class AppSettings:
    """Persistent application configuration."""

    active_profile_id: str | None = None
    split_mode: SplitMode = "include"
    dns_mode: DnsMode = "split"
    bypass_lan: bool = True
    strict_route: bool = False
    ipv6_enabled: bool = False
    default_mtu: int = 1280
    minimize_to_tray: bool = True
    start_minimized: bool = False
    auto_connect_on_start: bool = False
    auto_stop_other_vpns: bool = True
    app_rules: list[AppRule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_profile_id": self.active_profile_id,
            "split_mode": self.split_mode,
            "dns_mode": self.dns_mode,
            "bypass_lan": self.bypass_lan,
            "strict_route": self.strict_route,
            "ipv6_enabled": self.ipv6_enabled,
            "default_mtu": self.default_mtu,
            "minimize_to_tray": self.minimize_to_tray,
            "start_minimized": self.start_minimized,
            "auto_connect_on_start": self.auto_connect_on_start,
            "auto_stop_other_vpns": self.auto_stop_other_vpns,
            "app_rules": [r.to_dict() for r in self.app_rules],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppSettings:
        split_mode = data.get("split_mode", "include")
        if split_mode not in ("include", "exclude"):
            split_mode = "include"
        dns_mode = data.get("dns_mode", "split")
        if dns_mode not in ("split", "vpn_all", "local"):
            dns_mode = "split"
        return cls(
            active_profile_id=data.get("active_profile_id"),
            split_mode=split_mode,
            dns_mode=dns_mode,
            bypass_lan=bool(data.get("bypass_lan", True)),
            strict_route=bool(data.get("strict_route", False)),
            ipv6_enabled=bool(data.get("ipv6_enabled", False)),
            default_mtu=int(data.get("default_mtu", 1280)),
            minimize_to_tray=bool(data.get("minimize_to_tray", True)),
            start_minimized=bool(data.get("start_minimized", False)),
            auto_connect_on_start=bool(data.get("auto_connect_on_start", False)),
            auto_stop_other_vpns=bool(data.get("auto_stop_other_vpns", True)),
            app_rules=[AppRule.from_dict(r) for r in data.get("app_rules", [])],
        )
