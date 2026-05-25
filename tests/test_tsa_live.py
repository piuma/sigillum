# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Test live: firma livello T contro FreeTSA per PAdES e CAdES.

Richiede rete (https://freetsa.org/tsr). Salta in modo silenzioso se la TSA
non è raggiungibile in pochi secondi — non è una regressione del codice nostro.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.network

import socket
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import (
    CAdESSigner,
    PAdESSigner,
    SignatureLevel,
    SignOptions,
)
from sigillum.core.verifier import CAdESVerifier, PAdESVerifier

from fixtures import (
    make_minimal_pdf,
    make_p12_from_chain,
    make_test_chain,
)


TSA_URL = "https://freetsa.org/tsr"
FREETSA_CA_URL = "https://freetsa.org/files/cacert.pem"


def _fetch_freetsa_ca() -> list[x509.Certificate]:
    """Download FreeTSA root CA to seed the TSA trust store for this test."""
    with urllib.request.urlopen(FREETSA_CA_URL, timeout=10) as r:
        return list(x509.load_pem_x509_certificates(r.read()))


def _tsa_reachable(url: str, timeout: float = 5.0) -> bool:
    """Quick TCP probe to skip the test cleanly when the network is down."""
    host = urlparse(url).hostname
    port = 443 if url.startswith("https") else 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _make_credential(tmp: Path):
    chain = make_test_chain()
    p12_path = tmp / "test.p12"
    p12_path.write_bytes(make_p12_from_chain(chain, password="test"))
    cred = FileProvider(p12_path).unlock(str(p12_path), "test")
    return cred, chain


def test_pades_level_t_with_freetsa():
    if not _tsa_reachable(TSA_URL):
        print("SKIP: FreeTSA non raggiungibile")
        return

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cred, chain = _make_credential(tmp)
        pdf_path = tmp / "sample.pdf"
        pdf_path.write_bytes(make_minimal_pdf())
        signed_path = tmp / "sample-signed.pdf"

        before = datetime.now(timezone.utc)
        PAdESSigner().sign(
            input_path=pdf_path,
            output_path=signed_path,
            credential=cred,
            options=SignOptions(level=SignatureLevel.T, tsa_url=TSA_URL),
        )
        after = datetime.now(timezone.utc)

        tsa_roots = _fetch_freetsa_ca()
        result = PAdESVerifier(
            trusted_certs=[chain.ca_cert], tsa_trusted_certs=tsa_roots,
        ).verify(signed_path)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.timestamp is not None, "SignerInfo.timestamp non popolato"
        # Tolleranza ampia: gen_time può precedere/seguire la finestra locale
        # per via di drift NTP e ritardo di rete.
        assert s.timestamp.tzinfo is not None
        delta_before = (s.timestamp - before).total_seconds()
        delta_after = (after - s.timestamp).total_seconds()
        assert -300 <= delta_before and -300 <= delta_after, (
            f"timestamp fuori finestra: {s.timestamp} (sign window [{before}, {after}])"
        )
        assert s.timestamp_trusted is True, (
            f"TSA non fidata: {s.errors} (tsa_subject={s.tsa_subject!r})"
        )
        assert "freetsa" in s.tsa_subject.lower(), s.tsa_subject
        print(
            f"OK PAdES-T: gen_time={s.timestamp.isoformat()} "
            f"tsa={s.tsa_subject!r} trusted={s.timestamp_trusted}"
        )


def test_cades_level_t_with_freetsa():
    if not _tsa_reachable(TSA_URL):
        print("SKIP: FreeTSA non raggiungibile")
        return

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cred, chain = _make_credential(tmp)
        src = tmp / "doc.txt"
        src.write_bytes(b"Documento CAdES-T\n")
        p7m = tmp / "doc.txt.p7m"

        before = datetime.now(timezone.utc)
        CAdESSigner().sign(
            input_path=src,
            output_path=p7m,
            credential=cred,
            options=SignOptions(level=SignatureLevel.T, tsa_url=TSA_URL),
        )
        after = datetime.now(timezone.utc)

        tsa_roots = _fetch_freetsa_ca()
        result = CAdESVerifier(
            trusted_certs=[chain.ca_cert], tsa_trusted_certs=tsa_roots,
        ).verify(p7m)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.timestamp is not None, "SignerInfo.timestamp non popolato"
        assert s.timestamp_trusted is True, (
            f"TSA non fidata: {s.errors} (tsa_subject={s.tsa_subject!r})"
        )
        assert "freetsa" in s.tsa_subject.lower(), s.tsa_subject
        print(
            f"OK CAdES-T: gen_time={s.timestamp.isoformat()} "
            f"tsa={s.tsa_subject!r} trusted={s.timestamp_trusted}"
        )


if __name__ == "__main__":
    test_pades_level_t_with_freetsa()
    test_cades_level_t_with_freetsa()
    print("\nTest TSA live completati.")
