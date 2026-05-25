# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Italian eIDAS Trust List (TSL) importer.

Downloads the AgID-maintained TSL (https://eidas.agid.gov.it/TL/TSL-IT.xml),
extracts the X.509 certificates of currently-active qualified trust services,
and writes them as two PEM bundles under $XDG_DATA_HOME/sigillum/trusted/:
  - it-eidas-signing.pem  → CAs for qualified signatures (signers' trust store)
  - it-eidas-tsa.pem      → CAs for qualified timestamp authorities

We do NOT verify the XAdES signature on the TSL itself in this iteration —
we rely on HTTPS to AgID's endpoint (TOFU). Adding ETSI TS 119 612 signature
verification is the natural next step for a hardened deployment.
"""
from __future__ import annotations

import base64
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


AGID_TSL_URL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"

_NS = "http://uri.etsi.org/02231/v2#"

# AgID statuses that mean the service is currently usable.
_ACTIVE_STATUSES = {
    "granted",                   # eIDAS-qualified, in service
    "recognisedatnationallevel", # recognised by AgID at national level
}

# ServiceTypeIdentifier suffixes that classify a service into the TSA bucket.
# Everything else goes into the signing bucket. Source: ETSI TS 119 612.
_TSA_TYPE_SUFFIXES = {"TSA", "QTST", "TSS-QTST"}


@dataclass
class TSLImportResult:
    signing_count: int
    tsa_count: int
    when: datetime
    signing_path: Path
    tsa_path: Path


def fetch_tsl(url: str = AGID_TSL_URL, timeout: float = 30.0) -> bytes:
    """Download the TSL XML. Caller handles network errors."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def parse_tsl(xml_bytes: bytes) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Return (signing_cas, tsa_cas) extracted from active service entries.

    Certificates are deduplicated by SHA-256 fingerprint across the whole file
    so that operators serving multiple service types don't get duplicated.
    Historical service instances (`ServiceHistoryInstance`) are skipped.
    """
    root = ET.fromstring(xml_bytes)
    signing: dict[bytes, x509.Certificate] = {}
    tsa: dict[bytes, x509.Certificate] = {}

    for svc in root.iter(f"{{{_NS}}}TSPService"):
        si = svc.find(f"{{{_NS}}}ServiceInformation")
        if si is None:
            continue
        status = (si.findtext(f"{{{_NS}}}ServiceStatus", "") or "").rsplit("/", 1)[-1]
        if status not in _ACTIVE_STATUSES:
            continue
        type_uri = si.findtext(f"{{{_NS}}}ServiceTypeIdentifier", "") or ""
        type_suffix = type_uri.rsplit("/", 1)[-1]
        bucket = tsa if type_suffix in _TSA_TYPE_SUFFIXES else signing

        for x509_el in si.iter(f"{{{_NS}}}X509Certificate"):
            if not x509_el.text:
                continue
            try:
                der = base64.b64decode("".join(x509_el.text.split()))
                cert = x509.load_der_x509_certificate(der)
            except Exception:  # noqa: BLE001 — skip individual bad entries
                continue
            fp = cert.fingerprint(hashes.SHA256())
            bucket.setdefault(fp, cert)

    return list(signing.values()), list(tsa.values())


def trusted_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "sigillum" / "trusted"


def signing_pem_path() -> Path:
    return trusted_dir() / "it-eidas-signing.pem"


def tsa_pem_path() -> Path:
    return trusted_dir() / "it-eidas-tsa.pem"


def save_certs_as_pem(certs: list[x509.Certificate], path: Path) -> None:
    """Write the certs as a concatenated PEM bundle, atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)


def import_agid_tsl(url: str = AGID_TSL_URL) -> TSLImportResult:
    """Full flow: fetch, parse, save. Caller handles network/parse errors."""
    xml_bytes = fetch_tsl(url)
    signing, tsa = parse_tsl(xml_bytes)
    sp, tp = signing_pem_path(), tsa_pem_path()
    save_certs_as_pem(signing, sp)
    save_certs_as_pem(tsa, tp)
    return TSLImportResult(
        signing_count=len(signing),
        tsa_count=len(tsa),
        when=datetime.now(timezone.utc),
        signing_path=sp,
        tsa_path=tp,
    )


def import_age_days(iso_timestamp: str) -> int | None:
    """Days since the given ISO 8601 timestamp; None if input is empty/invalid."""
    if not iso_timestamp:
        return None
    try:
        dt = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def load_pem_bundle(path: Path) -> list[x509.Certificate]:
    """Best-effort load of a PEM bundle; returns [] if the file is missing."""
    if not path.exists():
        return []
    try:
        return list(x509.load_pem_x509_certificates(path.read_bytes()))
    except Exception:  # noqa: BLE001
        return []
