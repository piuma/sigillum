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


if __name__ == "__main__":
    test_defaults_when_file_missing()
    test_roundtrip_file_source()
    test_saved_file_has_user_only_perms()
    test_roundtrip_pkcs11_source()
    test_corrupted_file_falls_back_to_defaults()
    test_unknown_source_value_treated_as_none()
    print("\nTutti i test settings passati.")
