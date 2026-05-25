# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""TSL parser unit tests using the live AgID file (cached locally if present)."""
from __future__ import annotations

import os
import sys
import tempfile
import urllib.request

import pytest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.tsl import (
    AGID_TSL_URL,
    import_age_days,
    parse_tsl,
    save_certs_as_pem,
)


# Reuse a local copy if a previous test pulled it; otherwise download.
CACHE = Path("/tmp/agid-tsl.xml")


def _load_xml() -> bytes:
    if CACHE.exists() and CACHE.stat().st_size > 100_000:
        return CACHE.read_bytes()
    with urllib.request.urlopen(AGID_TSL_URL, timeout=30) as r:
        data = r.read()
    CACHE.write_bytes(data)
    return data


@pytest.mark.network
def test_parse_yields_signing_and_tsa_certs():
    xml = _load_xml()
    signing, tsa = parse_tsl(xml)
    assert len(signing) > 100, f"troppo pochi cert firmatari: {len(signing)}"
    assert len(tsa) > 5, f"troppo pochi cert TSA: {len(tsa)}"
    # Overlap is allowed: some QTSPs (es. Namirial) usano la stessa CA per più
    # tipi di servizio. Verifichiamo solo che l'overlap sia piccolo.
    from cryptography.hazmat.primitives import hashes
    sig_fps = {c.fingerprint(hashes.SHA256()) for c in signing}
    tsa_fps = {c.fingerprint(hashes.SHA256()) for c in tsa}
    overlap = sig_fps & tsa_fps
    assert len(overlap) < 10, f"overlap inatteso: {len(overlap)} cert"
    print(f"OK parse: signing={len(signing)}, tsa={len(tsa)}, overlap={len(overlap)}")
    # Expected Italian QTSPs (sample check).
    subjects = "\n".join(c.subject.rfc4514_string() for c in signing + tsa)
    for name in ("InfoCert", "Aruba", "Namirial"):
        assert name in subjects, f"manca {name} nella TSL"
    print("OK presence: InfoCert, Aruba, Namirial nella TSL")


@pytest.mark.network
def test_save_as_pem_roundtrip():
    from cryptography import x509
    xml = _load_xml()
    signing, _ = parse_tsl(xml)
    sample = signing[:3]
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bundle.pem"
        save_certs_as_pem(sample, p)
        assert p.stat().st_size > 0
        loaded = list(x509.load_pem_x509_certificates(p.read_bytes()))
        assert len(loaded) == len(sample)
        print(f"OK PEM roundtrip: {len(loaded)} cert")


def test_import_age_days():
    assert import_age_days("") is None
    assert import_age_days("not-a-date") is None
    now = datetime.now(timezone.utc)
    assert import_age_days(now.isoformat()) == 0
    older = (now - __import__("datetime").timedelta(days=45)).isoformat()
    assert import_age_days(older) == 45
    print("OK age days")


if __name__ == "__main__":
    test_parse_yields_signing_and_tsa_certs()
    test_save_as_pem_roundtrip()
    test_import_age_days()
    print("\nTutti i test TSL passati.")
