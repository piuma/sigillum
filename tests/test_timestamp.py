# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Live tests for standalone timestamping (TSR + TSD) against FreeTSA.

Requires network. Skipped silently when FreeTSA is unreachable so the rest
of the test suite stays green offline.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.network

import socket
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography import x509

from sigillum.core.timestamp import (
    TSAConfig,
    extract_tsd_content,
    make_tsd,
    make_tsr,
    verify_tsd,
    verify_tsr,
)


TSA_URL = "https://freetsa.org/tsr"
FREETSA_CA_URL = "https://freetsa.org/files/cacert.pem"


def _reachable(url: str, timeout: float = 5.0) -> bool:
    host = urlparse(url).hostname
    port = 443 if url.startswith("https") else 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _fetch_ca() -> list[x509.Certificate]:
    with urllib.request.urlopen(FREETSA_CA_URL, timeout=10) as r:
        return list(x509.load_pem_x509_certificates(r.read()))


def test_tsr_roundtrip():
    if not _reachable(TSA_URL):
        print("SKIP: FreeTSA non raggiungibile")
        return

    ca = _fetch_ca()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.txt"
        src.write_bytes(b"Documento per TSR.\n")
        tsa = TSAConfig(url=TSA_URL)

        tsr_path = make_tsr(src, tmp / "doc.txt.tsr", tsa)
        # A standalone TST is typically ~4-5KB; sanity-check it's not empty.
        assert tsr_path.stat().st_size > 1000, "TSR sospettosamente piccolo"

        result = verify_tsr(tsr_path, src, tsa_trusted_certs=ca)
        s = result.signers[0]
        assert s.hash_valid is True, s.errors
        assert s.signature_valid is True, s.errors
        assert s.cert_trusted is True, s.errors
        assert s.timestamp is not None
        assert "freetsa" in s.tsa_subject.lower()
        print(f"OK TSR: ts={s.timestamp.isoformat()} tsa_trusted={s.cert_trusted}")


def test_tsd_roundtrip_self_contained():
    if not _reachable(TSA_URL):
        print("SKIP: FreeTSA non raggiungibile")
        return

    ca = _fetch_ca()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.txt"
        original = b"Documento per TSD, contenuto embedded.\n"
        src.write_bytes(original)
        tsa = TSAConfig(url=TSA_URL)

        tsd_path = make_tsd(src, tmp / "doc.txt.tsd", tsa)
        # TSD must be larger than the TSR alone because it also carries the
        # original content + metadata.
        assert tsd_path.stat().st_size > len(original) + 1000

        # Self-contained verification — no original file passed.
        result = verify_tsd(tsd_path, tsa_trusted_certs=ca)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is True
        assert s.timestamp is not None

        # extract_tsd_content recovers the bytes byte-for-byte.
        fname, content = extract_tsd_content(tsd_path)
        assert content == original
        assert fname == "doc.txt"
        print(f"OK TSD: ts={s.timestamp.isoformat()} fname={fname!r} content_ok={content == original}")


def test_tsr_detects_tampered_original():
    if not _reachable(TSA_URL):
        print("SKIP: FreeTSA non raggiungibile")
        return

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.txt"
        src.write_bytes(b"Originale")
        tsa = TSAConfig(url=TSA_URL)
        tsr_path = make_tsr(src, tmp / "doc.txt.tsr", tsa)

        tampered = tmp / "tampered.txt"
        tampered.write_bytes(b"contenuto manomesso")
        result = verify_tsr(tsr_path, tampered)
        s = result.signers[0]
        assert s.hash_valid is False, "manomissione non rilevata"
        print(f"OK TSR tampering: hash_valid=False, errors={s.errors}")


if __name__ == "__main__":
    test_tsr_roundtrip()
    test_tsd_roundtrip_self_contained()
    test_tsr_detects_tampered_original()
    print("\nTutti i test timestamp passati.")
