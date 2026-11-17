"""Tests for persistent storage and warpplus.conf auto-seeding."""

from __future__ import annotations

from pathlib import Path

from ppv.models import AppRule, AppSettings
from ppv.storage import AppStorage


def test_storage_round_trip_and_autoseed(tmp_path: Path) -> None:
    seed_root = tmp_path / "app_root"
    seed_root.mkdir()
    sample_conf = """[Interface]
PrivateKey = ERERERERERERERERERERERERERERERERERERERERERE=
Address = 172.16.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0
"""
    (seed_root / "warpplus.conf").write_text(sample_conf, encoding="utf-8")

    storage = AppStorage(data_dir=tmp_path / "data", auto_seed_root=seed_root)
    profiles = storage.load_profiles()
    assert len(profiles) == 1
    assert profiles[0].endpoint_host == "engage.cloudflareclient.com"
    assert (storage.profiles_dir / f"{profiles[0].id}.conf").exists()

    settings = storage.load_settings()
    active = storage.ensure_active_profile(settings, profiles)
    assert active is not None
    assert settings.active_profile_id == profiles[0].id

    settings.app_rules.append(
        AppRule(
            display_name="Chrome",
            exe_name="chrome.exe",
            exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
    )
    storage.save_settings(settings)

    reloaded: AppSettings = storage.load_settings()
    assert len(reloaded.app_rules) == 1
    assert reloaded.app_rules[0].exe_name == "chrome.exe"
