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
    EU_LOTL_URL,
    TSLPointer,
    fetch_country_tsl_signers_from_lotl,
    find_country_pointer,
    import_age_days,
    list_imported_countries,
    load_active_trust_stores,
    parse_lotl,
    parse_tsl,
    save_certs_as_pem,
    signing_pem_path,
    tsa_pem_path,
    usable_national_tsls,
)


# Reuse a local copy if a previous test pulled it; otherwise download.
CACHE = Path("/tmp/agid-tsl.xml")
LOTL_CACHE = Path("/tmp/eu-lotl.xml")


def _load_xml() -> bytes:
    if CACHE.exists() and CACHE.stat().st_size > 100_000:
        return CACHE.read_bytes()
    with urllib.request.urlopen(AGID_TSL_URL, timeout=30) as r:
        data = r.read()
    CACHE.write_bytes(data)
    return data


def _load_lotl() -> bytes:
    if LOTL_CACHE.exists() and LOTL_CACHE.stat().st_size > 100_000:
        return LOTL_CACHE.read_bytes()
    with urllib.request.urlopen(EU_LOTL_URL, timeout=30) as r:
        data = r.read()
    LOTL_CACHE.write_bytes(data)
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


# ---------------------------------------------------------------------------
# Multi-country LOTL parsing (phase 1/4)
# ---------------------------------------------------------------------------

@pytest.mark.network
def test_parse_lotl_returns_raw_pointers():
    """parse_lotl is the raw view: includes PDFs and the EU self-reference."""
    lotl = _load_lotl()
    pointers = parse_lotl(lotl)
    assert isinstance(pointers, list)
    assert len(pointers) > 30, f"too few pointers in LOTL: {len(pointers)}"
    # Every pointer carries country + url.
    for p in pointers:
        assert isinstance(p, TSLPointer)
        assert p.country and p.tsl_url
    # The EU self-reference should be present in the raw view.
    eu = [p for p in pointers if p.country == "EU"]
    assert eu, "EU self-pointer missing from raw parse_lotl"
    print(f"OK raw LOTL: {len(pointers)} pointers (incl. EU self-ref)")


@pytest.mark.network
def test_usable_national_tsls_filters_pdf_and_eu():
    """usable_national_tsls returns the curated map: XML only, no EU self-ref."""
    lotl = _load_lotl()
    nat = usable_national_tsls(lotl)
    assert isinstance(nat, dict)
    assert "EU" not in nat, "EU self-pointer leaked into curated view"
    # We expect roughly 30 EU/EEA countries with XML TSLs.
    assert 25 <= len(nat) <= 35, f"unexpected national TSL count: {len(nat)}"
    # All values must be XML pointers.
    for cc, p in nat.items():
        assert p.is_xml, f"non-XML pointer slipped through for {cc}: {p.mime_type}"
    # Italy must be there and carry signing certificates.
    assert "IT" in nat
    assert len(nat["IT"].signing_certs) > 0
    print(f"OK curated LOTL: {len(nat)} countries, all XML")


@pytest.mark.network
def test_find_country_pointer():
    lotl = _load_lotl()
    it = find_country_pointer(lotl, "IT")
    assert it is not None
    assert it.country == "IT"
    assert it.tsl_url.endswith(".xml")
    # Case-insensitive country lookup.
    assert find_country_pointer(lotl, "it") is not None
    # Unknown country → None (graceful).
    assert find_country_pointer(lotl, "ZZ") is None
    # Signers count matches the helper.
    signers = fetch_country_tsl_signers_from_lotl(lotl, "IT")
    assert len(signers) == len(it.signing_certs)
    print(f"OK find_country_pointer: IT/it/ZZ behave correctly")


# ---------------------------------------------------------------------------
# Per-country trust store layout (phase 2)
# ---------------------------------------------------------------------------

def test_pem_paths_per_country():
    """signing_pem_path / tsa_pem_path use lowercase ISO codes; IT path is stable."""
    assert signing_pem_path("IT").name == "it-eidas-signing.pem"
    assert signing_pem_path("DE").name == "de-eidas-signing.pem"
    # Case-insensitive input, lowercase output.
    assert signing_pem_path("de").name == "de-eidas-signing.pem"
    assert tsa_pem_path("FR").name == "fr-eidas-tsa.pem"
    # Default keeps backward-compat with v0.1 (Italy).
    assert signing_pem_path().name == "it-eidas-signing.pem"
    print("OK per-country PEM paths")


def test_load_active_trust_stores_dedups(tmp_path, monkeypatch):
    """Two countries sharing a cross-recognised CA must yield one entry."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    from cryptography.x509.oid import NameOID

    # Build a self-signed CA we can stuff into both per-country bundles.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Shared Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    # Redirect trusted_dir to a temp folder so we don't touch the user's setup.
    monkeypatch.setattr("sigillum.core.tsl.trusted_dir", lambda: tmp_path)

    pem = cert.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "xa-eidas-signing.pem").write_bytes(pem)
    (tmp_path / "xb-eidas-signing.pem").write_bytes(pem)
    (tmp_path / "xa-eidas-tsa.pem").write_bytes(pem)
    (tmp_path / "xb-eidas-tsa.pem").write_bytes(pem)

    signing, tsa = load_active_trust_stores(["XA", "XB"])
    assert len(signing) == 1, "duplicate signing CA leaked into the union"
    assert len(tsa) == 1, "duplicate TSA CA leaked into the union"
    # And empty input is safe.
    assert load_active_trust_stores([]) == ([], [])
    print("OK load_active_trust_stores dedup")


def test_list_imported_countries(tmp_path, monkeypatch):
    """list_imported_countries scans the trust dir for *-eidas-signing.pem files."""
    monkeypatch.setattr("sigillum.core.tsl.trusted_dir", lambda: tmp_path)
    assert list_imported_countries() == []
    (tmp_path / "it-eidas-signing.pem").write_bytes(b"")
    (tmp_path / "de-eidas-signing.pem").write_bytes(b"")
    (tmp_path / "noise-file.txt").write_bytes(b"")  # ignored
    assert list_imported_countries() == ["DE", "IT"]
    print("OK list_imported_countries")


if __name__ == "__main__":
    test_parse_yields_signing_and_tsa_certs()
    test_save_as_pem_roundtrip()
    test_import_age_days()
    test_parse_lotl_returns_raw_pointers()
    test_usable_national_tsls_filters_pdf_and_eu()
    test_find_country_pointer()
    test_pem_paths_per_country()
    # The two parametrised tests need pytest's tmp_path/monkeypatch fixtures
    # to run; invoke via `pytest tests/test_tsl.py` for those.
    print("\nTutti i test TSL passati (esegui `pytest tests/test_tsl.py` per i test parametrici).")
