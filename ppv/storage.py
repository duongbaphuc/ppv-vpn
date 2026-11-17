"""Persistent storage for WireGuard profiles, per-app rules, and app settings."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from ppv.models import AppSettings, WireGuardProfile
from ppv.wg_parser import WireGuardParseError, parse_wireguard_conf, profile_to_conf


def get_app_root() -> Path:
    """Return the base directory containing application binaries/resources."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_data_dir() -> Path:
    """Return writable data directory (portable `data/` if writable, else `%LOCALAPPDATA%\\PPV-VPN`)."""
    app_root = get_app_root()
    portable_dir = app_root / "data"
    try:
        portable_dir.mkdir(parents=True, exist_ok=True)
        probe = portable_dir / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return portable_dir
    except OSError:
        local_app = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        fallback = local_app / "PPV-VPN"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


class AppStorage:
    """Loads and saves profiles and settings on disk."""

    def __init__(self, data_dir: Path | None = None, auto_seed_root: Path | None = None) -> None:
        self.data_dir = data_dir or get_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir = self.data_dir / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir = self.data_dir / "runtime"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.settings_path = self.data_dir / "settings.json"
        self.profiles_index_path = self.data_dir / "profiles.json"
        self._auto_seed_root = auto_seed_root if auto_seed_root is not None else get_app_root()

    def load_settings(self) -> AppSettings:
        if not self.settings_path.exists():
            return AppSettings()
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return AppSettings.from_dict(raw)
        except Exception:
            return AppSettings()

    def save_settings(self, settings: AppSettings) -> None:
        self.settings_path.write_text(
            json.dumps(settings.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def load_profiles(self) -> list[WireGuardProfile]:
        profiles: list[WireGuardProfile] = []
        if self.profiles_index_path.exists():
            try:
                raw_list = json.loads(self.profiles_index_path.read_text(encoding="utf-8"))
                for item in raw_list:
                    profiles.append(WireGuardProfile.from_dict(item))
            except Exception:
                profiles = []

        if not profiles:
            self._seed_default_warp_conf(profiles)
            if profiles:
                self.save_profiles(profiles)
        return profiles

    def _seed_default_warp_conf(self, profiles: list[WireGuardProfile]) -> None:
        candidate = self._auto_seed_root / "warpplus.conf"
        if not candidate.exists():
            return
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
            prof = parse_wireguard_conf(text, name="WARP+ (warpplus.conf)", source="imported")
            profiles.append(prof)
        except WireGuardParseError:
            pass

    def save_profiles(self, profiles: Iterable[WireGuardProfile]) -> None:
        prof_list = list(profiles)
        self.profiles_index_path.write_text(
            json.dumps([p.to_dict() for p in prof_list], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        # Also mirror readable .conf copies in profiles/ for user convenience
        expected_files = set()
        for prof in prof_list:
            fname = f"{prof.id}.conf"
            expected_files.add(fname)
            (self.profiles_dir / fname).write_text(profile_to_conf(prof), encoding="utf-8")
        for existing in self.profiles_dir.glob("*.conf"):
            if existing.name not in expected_files:
                existing.unlink(missing_ok=True)

    def ensure_active_profile(
        self, settings: AppSettings, profiles: list[WireGuardProfile]
    ) -> WireGuardProfile | None:
        if not profiles:
            settings.active_profile_id = None
            return None
        for prof in profiles:
            if prof.id == settings.active_profile_id:
                return prof
        settings.active_profile_id = profiles[0].id
        self.save_settings(settings)
        return profiles[0]
