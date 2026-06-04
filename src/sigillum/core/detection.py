# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Auto-detection of PKCS#11 drivers and tokens.

Iterates a curated list of well-known driver paths, tries to load each one,
enumerates the certificates available, and reports back the combinations
that yield real (non-empty) results. The UI uses this to remove the need
for the user to know the exact `.so` path of the vendor driver.

Detection is intentionally read-only — we never log in. Tokens whose certs
are private (require PIN to be enumerated) will report 0 certs here; the
user must then provide the PIN at sign-time. This is rare in practice
because most vendor drivers expose certs as public objects.
"""
from __future__ import annotations

import glob
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..i18n import _
from .credentials import CertificateInfo, PKCS11Provider


# Drivers we look for under fixed system paths. Order matters: vendor-specific
# drivers (Bit4id, ykcs11) tend to expose certs as public objects while OpenSC
# may hide them on some chip families (cf. CNS Athena bug). We try OpenSC last
# so that more reliable vendor drivers win when both are installed.
SYSTEM_DRIVER_PATHS: tuple[str, ...] = (
    # YubiKey — host packages
    "/usr/lib64/libykcs11.so.2",
    "/usr/lib64/libykcs11.so",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so.2",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    # YubiKey — Flatpak bundled (only visible inside the sandbox)
    "/app/lib/libykcs11.so.2",
    "/app/lib/libykcs11.so",
    # Bit4id (closed-source vendor — host only, not redistributable)
    "/usr/lib64/libbit4xpki.so",
    "/usr/lib/x86_64-linux-gnu/libbit4xpki.so",
    "/usr/local/lib/libbit4xpki.so",
    "/opt/bit4id/lib/libbit4xpki.so",
    # Aruba Sign desktop bundle ships the Bit4id PKCS#11 driver under
    # /opt/arubasign/...; the sibling `libsmmulti.so` is not a PKCS#11
    # module (no `C_GetFunctionList`) so we deliberately don't probe it.
    "/opt/arubasign/asp/lin-x64/driver/libbit4xpki.so",
    # Actalis (Cyberlogic CyberMW middleware shipped with the Actalis CNS
    # / qualified-signature smartcards, closed-source).
    "/usr/lib64/libcybermw.so",
    "/usr/lib/x86_64-linux-gnu/libcybermw.so",
    "/usr/local/lib/libcybermw.so",
    # OpenSC — host packages
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    # OpenSC — Flatpak bundled
    "/app/lib/pkcs11/opensc-pkcs11.so",
    "/app/lib/opensc-pkcs11.so",
)


def _is_flatpak() -> bool:
    """True when running inside a Flatpak sandbox.

    Flatpak guarantees `/.flatpak-info` exists in the sandbox and is absent
    on the host — that's the official detection knob.
    """
    return Path("/.flatpak-info").is_file()


def _flatpak_host_view(path: str) -> str:
    """Translate a host path into its sandbox-visible view.

    Inside a Flatpak sandbox the host's `/usr` and `/opt` (when exposed via
    `--filesystem=/usr/...:ro` or `--filesystem=/opt:ro`) are mounted under
    `/run/host/...`, not at their original locations — the sandbox already
    has its own `/usr` from the runtime. Outside Flatpak this is a no-op.
    """
    if not _is_flatpak():
        return path
    if path.startswith(("/usr/", "/opt/")):
        return f"/run/host{path}"
    return path

# Vendor distributions often install their PKCS#11 module under the user's
# home directory. We glob for the typical layouts of Aruba Sign, InfoCamere
# `infocamere_sign_desktop`, Dike, etc.
USER_DRIVER_GLOBS: tuple[str, ...] = (
    "~/infocamere/*/etc/sign_engine/libbit4xpki.so",
    "~/.config/infocamere/*/etc/sign_engine/libbit4xpki.so",
    "~/.local/share/infocamere/*/etc/sign_engine/libbit4xpki.so",
    "~/aruba/*/lib/libbit4xpki.so",
    "~/.aruba/*/lib/libbit4xpki.so",
    "~/.config/aruba/*/lib/libbit4xpki.so",
    "~/dike*/lib/libbit4xpki.so",
    "~/.config/dike*/lib/libbit4xpki.so",
    "~/downloads/*/sign_engine/libbit4xpki.so",
    "~/Downloads/*/sign_engine/libbit4xpki.so",
    "~/downloads/etc/sign_engine/libbit4xpki.so",
)


@dataclass(frozen=True)
class DetectedToken:
    """A PKCS#11 driver + token combination that exposes at least one cert."""
    library_path: str
    library_label: str  # short human-friendly name (e.g. "Bit4id (InfoCamere)")
    certificates: Sequence[CertificateInfo]


# Known USB vendor IDs for security tokens / smartcard readers. The third
# element marks the driver category:
#   "open_source" — installable from distro repos (we ship install commands)
#   "proprietary" — vendor-only, not redistributable (we ship a vendor link)
_USB_VENDOR_MAP: dict[str, tuple[str, str, str]] = {
    # vid       (display_name, driver hint, kind)
    "1050": ("YubiKey (Yubico)",              "yubico-piv-tool",  "open_source"),
    "25dd": ("Bit4id Digital-DNA / Aruba Key", "libbit4xpki.so",  "proprietary"),
    "0dc3": ("Athena Smartcard",              "opensc",           "open_source"),
    "076b": ("OmniKey / HID smartcard reader","opensc",           "open_source"),
    "0529": ("SafeNet eToken (Thales)",       "SafeNet PKCS#11",  "proprietary"),
    "058f": ("Alcor Micro smartcard reader",  "opensc",           "open_source"),
    "08e6": ("Gemalto / Thales smartcard",    "opensc",           "open_source"),
    "0a89": ("ACS / Advanced Card Systems",   "opensc",           "open_source"),
}


@dataclass(frozen=True)
class UsbToken:
    vendor_id: str       # hex like "25dd"
    product_id: str      # hex like "2354"
    vendor_name: str     # human-readable label from _USB_VENDOR_MAP
    driver_hint: str     # short driver identifier ("yubico-piv-tool", "opensc", ...)
    driver_kind: str     # "open_source" | "proprietary"


def detect_usb_tokens() -> list[UsbToken]:
    """Scan /sys/bus/usb/devices for connected vendors we recognise.

    This is a sysfs walk with stdlib only — no libusb dependency. Used to
    show the user *which* driver they're missing when `detect_tokens()`
    fails to find a working PKCS#11 module.
    """
    devices_dir = Path("/sys/bus/usb/devices")
    if not devices_dir.is_dir():
        return []
    out: list[UsbToken] = []
    seen: set[tuple[str, str]] = set()
    for entry in devices_dir.iterdir():
        try:
            vid = (entry / "idVendor").read_text().strip().lower()
            pid = (entry / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        if (vid, pid) in seen or vid not in _USB_VENDOR_MAP:
            continue
        seen.add((vid, pid))
        name, hint, kind = _USB_VENDOR_MAP[vid]
        out.append(UsbToken(vid, pid, name, hint, kind))
    return out


# Distro-specific install commands for the open-source driver names we know.
# `None` means "not packaged under that name on this distro — fall back to
# generic instructions".
_INSTALL_COMMANDS: dict[str, dict[str, str]] = {
    "fedora": {
        "yubico-piv-tool": "sudo dnf install -y yubico-piv-tool",
        "opensc":          "sudo dnf install -y opensc",
    },
    "debian": {
        "yubico-piv-tool": "sudo apt install -y yubico-piv-tool",
        "opensc":          "sudo apt install -y opensc opensc-pkcs11",
    },
    "arch": {
        "yubico-piv-tool": "sudo pacman -S --needed yubico-piv-tool",
        "opensc":          "sudo pacman -S --needed opensc",
    },
    "suse": {
        "yubico-piv-tool": "sudo zypper install -y yubico-piv-tool",
        "opensc":          "sudo zypper install -y opensc",
    },
}

# Vendor download pages for the proprietary drivers we identify. These are
# stable landing pages — the user navigates to the specific download from
# there (each vendor gates their binaries behind a EULA/login form, so
# direct curl doesn't work).
_VENDOR_DOWNLOAD_PAGES: dict[str, list[tuple[str, str]]] = {
    "libbit4xpki.so": [
        ("Aruba (Aruba Key / firma)", "https://www.pec.it/download-software-driver-firma"),
        ("InfoCamere (Sign Desktop / DiKe)", "https://www.firma.infocert.it/installazione/"),
        ("Namirial (Firma Certa)", "https://www.firmacerta.it/installazione-firmacerta-windows-linux.php"),
    ],
    "SafeNet PKCS#11": [
        ("Thales SafeNet Authentication Client",
         "https://supportportal.thalesgroup.com/csm?id=safenet_authentication_client_downloads"),
    ],
}


def detect_distro_family() -> str:
    """Best-effort distro identification from /etc/os-release.

    Returns one of: "fedora", "debian", "arch", "suse", "unknown".
    """
    try:
        content = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    fields: dict[str, str] = {}
    for line in content.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip().strip('"')
    candidates = (fields.get("ID", "") + " " + fields.get("ID_LIKE", "")).lower()
    if any(x in candidates for x in ("fedora", "rhel", "centos", "rocky", "alma")):
        return "fedora"
    if any(x in candidates for x in ("debian", "ubuntu", "mint")):
        return "debian"
    if any(x in candidates for x in ("arch", "manjaro", "endeavour")):
        return "arch"
    if any(x in candidates for x in ("suse", "opensuse")):
        return "suse"
    return "unknown"


@dataclass(frozen=True)
class DriverSuggestion:
    """Actionable guidance for installing a missing PKCS#11 driver."""
    driver_hint: str
    kind: str                 # "open_source" | "proprietary"
    install_command: str | None  # shell command for the current distro, or None
    vendor_links: list[tuple[str, str]]  # [(label, url), ...] for proprietary


def suggest_driver(token: UsbToken) -> DriverSuggestion:
    """Combine token + distro detection into install guidance."""
    distro = detect_distro_family()
    cmd = _INSTALL_COMMANDS.get(distro, {}).get(token.driver_hint)
    links = _VENDOR_DOWNLOAD_PAGES.get(token.driver_hint, [])
    return DriverSuggestion(
        driver_hint=token.driver_hint,
        kind=token.driver_kind,
        install_command=cmd,
        vendor_links=links,
    )


def _label_for(path: str) -> str:
    """Heuristic short label from a driver path. Used in the UI dropdown."""
    p = path.lower()
    if "ykcs11" in p:
        return "YubiKey (ykcs11)"
    if "bit4xpki" in p:
        if "infocamere" in p:
            return "Bit4id — InfoCamere"
        if "aruba" in p:
            return "Bit4id — Aruba"
        if "dike" in p:
            return "Bit4id — Dike"
        return "Bit4id"
    if "cybermw" in p:
        return "Actalis (CyberMW)"
    if "opensc" in p:
        return _("OpenSC (generic smartcard)")
    return Path(path).name


def find_available_drivers(extra: Sequence[str] | None = None) -> list[str]:
    """Return every known PKCS#11 driver `.so` that exists on this machine.

    Order: *extra* (user-configured, highest priority), then
    ``SYSTEM_DRIVER_PATHS``, then expanded ``USER_DRIVER_GLOBS``. Entries
    are deduplicated by resolved absolute path so two entries pointing to
    the same file aren't tried twice.

    Each *extra* entry may be:
      * a **directory** — scanned recursively for ``*.so`` / ``*.so.*``;
      * a **glob** (``*``, ``?``, ``[``) — expanded with :mod:`glob`;
      * an **exact file path**.
    ``~`` is always expanded.
    """
    seen: set[str] = set()
    out: list[str] = []

    def _accept(path: str) -> None:
        if not Path(path).is_file():
            return
        real = str(Path(path).resolve())
        if real in seen:
            return
        seen.add(real)
        out.append(path)

    def _add_pattern(pattern: str) -> None:
        for match in glob.glob(str(Path(pattern).expanduser())):
            _accept(match)

    def _add_extra(entry: str) -> None:
        p = Path(entry).expanduser()
        if p.is_dir():
            # Recursive scan for shared objects. Sorted for deterministic order.
            for match in sorted(p.rglob("*.so*")):
                _accept(str(match))
        else:
            _add_pattern(entry)

    for entry in (extra or ()):
        _add_extra(entry)
    for path in SYSTEM_DRIVER_PATHS:
        # Inside a Flatpak sandbox the host's /usr and /opt are mounted at
        # /run/host/...; SYSTEM_DRIVER_PATHS is written with host paths so
        # this rewrite lets the same list work in both contexts.
        candidate = _flatpak_host_view(path)
        if Path(candidate).is_file():
            _accept(candidate)
    for pattern in USER_DRIVER_GLOBS:
        _add_pattern(pattern)
    return out


def detect_tokens(extra: Sequence[str] | None = None) -> list[DetectedToken]:
    """Try every available driver; report tokens that expose ≥1 certificate.

    A driver that loads cleanly but reports zero certs is silently skipped:
    that's the OpenSC + CNS Athena situation where the chip is fine but
    the wrong driver hides the certs. The caller can fall back to the
    full list from `find_available_drivers()` and let the user pick
    manually if `detect_tokens()` returns empty.

    *extra* is forwarded to ``find_available_drivers`` and is intended to
    receive ``Settings.extra_pkcs11_drivers`` so user-configured paths win
    over the built-in lists.
    """
    out: list[DetectedToken] = []
    seen_fingerprints: set[tuple[str, ...]] = set()
    for lib in find_available_drivers(extra):
        try:
            provider = PKCS11Provider(lib)
            certs = list(provider.list_certificates())
        except Exception:  # noqa: BLE001 — try the next driver
            continue
        if not certs:
            continue
        # If the SAME set of cert IDs was already found via another driver,
        # don't list it twice — keep the first (which is the highest-priority
        # working driver per our ordering).
        fp = tuple(sorted(c.id for c in certs))
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)
        out.append(DetectedToken(
            library_path=lib,
            library_label=_label_for(lib),
            certificates=certs,
        ))
    return out
