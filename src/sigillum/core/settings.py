# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Persisted user settings: configured signing device + TSA preferences.

Stored as JSON at $XDG_CONFIG_HOME/sigillum/settings.json (typically
~/.config/sigillum/settings.json). The file is overwritten atomically via
a temp-file-and-rename and chmod'd to 0600 because it can carry the TSA
HTTP Basic-Auth password.

We never persist the signing PIN or the certificate-file password.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from ..i18n import _


SourceKind = Literal["file", "pkcs11"]


@dataclass
class Settings:
    source: SourceKind | None = None
    # File-based credential
    file_path: str = ""
    # PKCS#11 credential (token)
    pkcs11_library: str = ""
    pkcs11_cert_id: str = ""
    pkcs11_cert_subject: str = ""  # cached for UI display; not authoritative
    # Timestamp Authority for level-T signatures
    tsa_url: str = ""
    tsa_username: str = ""
    tsa_password: str = ""
    # ISO 8601 timestamp of the last successful AgID TSL import (UTC)
    tsl_last_import: str = ""
    # Visible signature preferences (PAdES only)
    signature_position: str = "bottom-right"
    signature_image: str = ""

    def is_configured(self) -> bool:
        if self.source == "file":
            return bool(self.file_path)
        if self.source == "pkcs11":
            return bool(self.pkcs11_library and self.pkcs11_cert_id)
        return False

    def describe(self) -> str:
        """Short, human-friendly description of the configured device."""
        if self.source == "file":
            if self.file_path:
                return _("File: {path}").format(path=self.file_path)
            return _("File (not set)")
        if self.source == "pkcs11":
            label = self.pkcs11_cert_subject or self.pkcs11_cert_id or _("(no cert chosen)")
            return _("PKCS#11 token: {label}").format(label=label)
        return _("No device configured")


def settings_path() -> Path:
    """Path of the settings file (honors $XDG_CONFIG_HOME)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sigillum" / "settings.json"


def load_settings(path: Path | None = None) -> Settings:
    """Load settings from disk; return defaults if missing or malformed."""
    p = path or settings_path()
    if not p.exists():
        return Settings()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Settings()
    if not isinstance(data, dict):
        return Settings()
    return Settings(
        source=data.get("source") if data.get("source") in ("file", "pkcs11") else None,
        file_path=str(data.get("file_path", "")),
        pkcs11_library=str(data.get("pkcs11_library", "")),
        pkcs11_cert_id=str(data.get("pkcs11_cert_id", "")),
        pkcs11_cert_subject=str(data.get("pkcs11_cert_subject", "")),
        tsa_url=str(data.get("tsa_url", "")),
        tsa_username=str(data.get("tsa_username", "")),
        tsa_password=str(data.get("tsa_password", "")),
        tsl_last_import=str(data.get("tsl_last_import", "")),
        signature_position=str(data.get("signature_position", "bottom-right")),
        signature_image=str(data.get("signature_image", "")),
    )


def save_settings(s: Settings, path: Path | None = None) -> None:
    """Atomically persist settings to disk with user-only permissions.

    The file can contain the TSA password, so we set mode 0600 on the temp
    file *before* renaming into place. On platforms without POSIX perms
    (Windows) `os.chmod` is a no-op and we don't error.
    """
    p = path or settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(asdict(s), indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, p)
