# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Settings roundtrip + defaults."""
from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.settings import Settings, load_settings, save_settings


def test_defaults_when_file_missing():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "missing.json"
        s = load_settings(p)
        assert s.source is None
        assert s.is_configured() is False
        assert "No device" in s.describe()
        print(f"OK defaults: {s.describe()!r}")


def test_roundtrip_file_source():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        save_settings(
            Settings(
                source="file",
                file_path="/tmp/cert.p12",
                tsa_url="https://freetsa.org/tsr",
                tsa_username="aruba_user",
                tsa_password="aruba_secret",
            ),
            p,
        )
        loaded = load_settings(p)
        assert loaded.source == "file"
        assert loaded.file_path == "/tmp/cert.p12"
        assert loaded.tsa_url == "https://freetsa.org/tsr"
        assert loaded.tsa_username == "aruba_user"
        assert loaded.tsa_password == "aruba_secret"
        assert loaded.is_configured() is True
        print(f"OK file roundtrip: {loaded.describe()!r} (tsa={loaded.tsa_url!r})")


def test_saved_file_has_user_only_perms():
    """The settings file can carry a TSA password — must be mode 0600."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        save_settings(Settings(source="file", file_path="/x", tsa_password="s3cret"), p)
        if os.name == "posix":
            mode = stat.S_IMODE(p.stat().st_mode)
            assert mode == 0o600, f"file perms: {oct(mode)}, atteso 0o600"
            print(f"OK perms file: {oct(mode)}")
        else:  # pragma: no cover
            print("SKIP perms test (non-POSIX)")


def test_roundtrip_pkcs11_source():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        save_settings(
            Settings(
                source="pkcs11",
                pkcs11_library="/usr/lib64/libykcs11.so.2",
                pkcs11_cert_id="02:abc123",
                pkcs11_cert_subject="CN=YubiKey Test,O=Test",
            ),
            p,
        )
        loaded = load_settings(p)
        assert loaded.source == "pkcs11"
        assert loaded.pkcs11_cert_id == "02:abc123"
        assert loaded.is_configured() is True
        assert "YubiKey" in loaded.describe()
        print(f"OK pkcs11 roundtrip: {loaded.describe()!r}")


def test_corrupted_file_falls_back_to_defaults():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        p.write_text("not json")
        s = load_settings(p)
        assert s.source is None
        print("OK corrupted file → defaults")


def test_unknown_source_value_treated_as_none():
    """Malicious or stale config shouldn't crash the loader."""
    import json
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        p.write_text(json.dumps({"source": "evil", "file_path": "/x"}))
        s = load_settings(p)
        assert s.source is None
        assert s.is_configured() is False
        print("OK unknown source rejected")


# ---------------------------------------------------------------------------
# Multi-country settings (phase 3+)
# ---------------------------------------------------------------------------

from sigillum.core.settings import (  # noqa: E402
    LOTL_COUNTRIES,
    default_country_from_locale,
)


def test_default_country_from_locale(monkeypatch):
    """Locale → LOTL country mapping handles the common cases + EU quirks."""
    monkeypatch.setenv("LANG", "it_IT.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    assert default_country_from_locale() == "IT"

    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    assert default_country_from_locale() == "DE"

    # ISO uses GB but the LOTL uses UK.
    monkeypatch.setenv("LANG", "en_GB.UTF-8")
    assert default_country_from_locale() == "UK"

    # ISO uses GR but the LOTL uses EL (Hellas).
    monkeypatch.setenv("LANG", "el_GR.UTF-8")
    assert default_country_from_locale() == "EL"

    # Non-EU locale → IT fallback.
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    assert default_country_from_locale() == "IT"

    # Empty / C locale → IT fallback.
    monkeypatch.setenv("LANG", "")
    assert default_country_from_locale() == "IT"
    print("OK default_country_from_locale")


def test_effective_country_respects_override(monkeypatch):
    monkeypatch.setenv("LANG", "it_IT.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)

    s = Settings()
    assert s.effective_country() == "IT"  # locale fallback

    s.country = "DE"
    assert s.effective_country() == "DE"  # explicit override wins

    s.country = "XX"  # not in LOTL → ignored, fall back to locale
    assert s.effective_country() == "IT"
    print("OK effective_country override + invalid → fallback")


def test_active_countries_defaults_to_primary(monkeypatch):
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)

    s = Settings()
    assert s.active_countries() == ["FR"]  # one-element list, never empty

    s.tsl_active_countries = ["IT", "DE"]
    assert s.active_countries() == ["IT", "DE"]
    print("OK active_countries fallback + explicit")


def test_record_import_mirrors_legacy_field_for_primary(monkeypatch):
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)

    s = Settings()  # primary derived from LANG → DE
    s.record_import("DE", "2026-05-25T10:00:00+00:00")
    s.record_import("IT", "2026-05-25T11:00:00+00:00")

    assert s.tsl_imports == {
        "DE": "2026-05-25T10:00:00+00:00",
        "IT": "2026-05-25T11:00:00+00:00",
    }
    # Only the primary country mirrors into the legacy tsl_last_import.
    assert s.tsl_last_import == "2026-05-25T10:00:00+00:00"
    print("OK record_import legacy mirror")


def test_legacy_v0_1_migration(monkeypatch):
    """A v0.1 settings file (only tsl_last_import) is migrated on load."""
    monkeypatch.setenv("LANG", "it_IT.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "settings.json"
        p.write_text(
            '{"source": "file", "file_path": "/x.p12",'
            ' "tsl_last_import": "2026-05-24T10:00:00+00:00"}'
        )
        loaded = load_settings(p)
        # New fields populated from the legacy timestamp + locale default.
        assert loaded.tsl_imports == {"IT": "2026-05-24T10:00:00+00:00"}
        assert loaded.tsl_active_countries == ["IT"]
        # Legacy field preserved verbatim.
        assert loaded.tsl_last_import == "2026-05-24T10:00:00+00:00"
        print("OK v0.1 → v0.2 migration")


def test_lotl_countries_is_a_reasonable_set():
    # Sanity: spot-check a few member states + EEA, and the LOTL-quirky codes.
    for cc in ("IT", "DE", "FR", "ES", "EL", "UK", "NO", "IS"):
        assert cc in LOTL_COUNTRIES, f"{cc} missing from LOTL_COUNTRIES"
    # GR is the ISO code for Greece, not the LOTL one — must NOT be present.
    assert "GR" not in LOTL_COUNTRIES
    assert "GB" not in LOTL_COUNTRIES
    print(f"OK LOTL_COUNTRIES: {len(LOTL_COUNTRIES)} entries")


if __name__ == "__main__":
    test_defaults_when_file_missing()
    test_roundtrip_file_source()
    test_saved_file_has_user_only_perms()
    test_roundtrip_pkcs11_source()
    test_corrupted_file_falls_back_to_defaults()
    test_unknown_source_value_treated_as_none()
    test_lotl_countries_is_a_reasonable_set()
    # The monkeypatch-based tests need pytest fixtures; invoke via:
    #   pytest tests/test_settings.py
    print("\nTutti i test settings passati (esegui `pytest tests/test_settings.py` per i test parametrici).")
