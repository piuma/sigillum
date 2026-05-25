# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from ..i18n import _


SourceKind = Literal["file", "pkcs11"]


# Mapping for the two cases where the locale ISO-3166 code differs from the
# code used in the EU LOTL/eIDAS framework. Everything else is identity.
_LOCALE_TO_LOTL_COUNTRY = {
    "GB": "UK",  # ISO uses GB; the LOTL uses UK historically
    "GR": "EL",  # ISO uses GR; the LOTL uses EL (Hellas)
}

# Country codes that actually have an XML TSL pointer in the EU LOTL.
# Used to validate the locale-derived default so a stray locale (e.g. en_US)
# doesn't propagate a meaningless code into the trust-store configuration.
LOTL_COUNTRIES: frozenset[str] = frozenset({
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
    "FI", "FR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU",
    "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "UK",
})


def default_country_from_locale() -> str:
    """Return the LOTL country code derived from $LANG (or $LC_ALL).

    Falls back to ``"IT"`` for any locale that isn't an EU/EEA member state
    listed in the LOTL (e.g. ``en_US``, ``C``, unset). Picks Italy as the
    safety default because the project's primary user base is Italian.
    """
    lang = os.environ.get("LANG") or os.environ.get("LC_ALL") or ""
    if "_" in lang:
        cc = lang.split("_", 1)[1].split(".", 1)[0].upper()
        if cc.isalpha() and len(cc) == 2:
            cc = _LOCALE_TO_LOTL_COUNTRY.get(cc, cc)
            if cc in LOTL_COUNTRIES:
                return cc
    return "IT"


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
    # User's primary eIDAS country (LOTL code). Decoupled from the UI
    # language: a user may want German trust services while running the
    # interface in Italian. Empty means "derive from $LANG".
    country: str = ""
    # Legacy: ISO 8601 timestamp of the last successful TSL import (UTC).
    # Kept in the schema for backward compatibility with v0.1 installs; the
    # authoritative source for multi-country setups is `tsl_imports`.
    tsl_last_import: str = ""
    # NEW (v0.2+): ISO 8601 timestamps per imported country (uppercase ISO code).
    # Example: {"IT": "2026-05-25T10:00:00+00:00", "DE": "2026-05-24T..."}.
    tsl_imports: dict[str, str] = field(default_factory=dict)
    # NEW: countries whose trust store is included when verifying signatures.
    # Empty means "use the primary country only" (see `active_countries`).
    tsl_active_countries: list[str] = field(default_factory=list)
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

    def effective_country(self) -> str:
        """Resolve the primary eIDAS country: explicit setting → $LANG → IT.

        This is the single source of truth for "which country am I working
        in?" — used to decide which TSL to auto-import, which TSA presets
        to show, and what to default to in new operations.
        """
        cc = (self.country or "").upper()
        if cc in LOTL_COUNTRIES:
            return cc
        return default_country_from_locale()

    def active_countries(self) -> list[str]:
        """Return the country codes whose trust store the verifier should load.

        If the user hasn't customised the list, falls back to the primary
        country only. The returned list always contains at least one entry.
        """
        if self.tsl_active_countries:
            return list(self.tsl_active_countries)
        return [self.effective_country()]

    def last_import_for(self, country: str) -> str:
        """ISO timestamp of the last import for *country*, or empty string."""
        return self.tsl_imports.get(country.upper(), "")

    def record_import(self, country: str, iso_timestamp: str) -> None:
        """Update the in-memory record after a successful import.

        Also mirrors into the legacy ``tsl_last_import`` when *country* is the
        user's primary one so the v0.1 read path keeps working.
        """
        cc = country.upper()
        self.tsl_imports[cc] = iso_timestamp
        if cc == self.effective_country():
            self.tsl_last_import = iso_timestamp


def settings_path() -> Path:
    """Path of the settings file (honors $XDG_CONFIG_HOME)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sigillum" / "settings.json"


def _parse_tsl_imports(raw) -> dict[str, str]:
    """Best-effort parse of the tsl_imports dict from JSON (uppercase keys)."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, str) and k.isalpha():
            out[k.upper()] = v
    return out


def _parse_active_countries(raw) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [c.upper() for c in raw if isinstance(c, str) and c.isalpha()]


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

    legacy_last = str(data.get("tsl_last_import", ""))
    tsl_imports = _parse_tsl_imports(data.get("tsl_imports"))
    tsl_active = _parse_active_countries(data.get("tsl_active_countries"))

    # Country override: only accept it if it's actually in the LOTL.
    raw_country = str(data.get("country", "")).upper()
    country = raw_country if raw_country in LOTL_COUNTRIES else ""
    primary = country or default_country_from_locale()

    # Migration: v0.1 wrote only `tsl_last_import` (one timestamp, implicitly
    # Italy). If we see that case, populate the modern fields so future writes
    # use the new schema while leaving the legacy field intact.
    if legacy_last and not tsl_imports:
        tsl_imports = {primary: legacy_last}
        if not tsl_active:
            tsl_active = [primary]

    return Settings(
        source=data.get("source") if data.get("source") in ("file", "pkcs11") else None,
        file_path=str(data.get("file_path", "")),
        pkcs11_library=str(data.get("pkcs11_library", "")),
        pkcs11_cert_id=str(data.get("pkcs11_cert_id", "")),
        pkcs11_cert_subject=str(data.get("pkcs11_cert_subject", "")),
        tsa_url=str(data.get("tsa_url", "")),
        tsa_username=str(data.get("tsa_username", "")),
        tsa_password=str(data.get("tsa_password", "")),
        country=country,
        tsl_last_import=legacy_last,
        tsl_imports=tsl_imports,
        tsl_active_countries=tsl_active,
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
