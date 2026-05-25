# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Roundtrip CAdES: firma di un file in .p7m enveloping e verifica."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import CAdESSigner, SignatureLevel, SignOptions
from sigillum.core.verifier import CAdESVerifier

from fixtures import make_test_chain, make_p12_from_chain


SAMPLE_CONTENT = b"Contenuto di prova per la firma CAdES.\nRiga 2.\n"


def _setup(tmp: Path):
    chain = make_test_chain()
    src_path = tmp / "documento.txt"
    p12_path = tmp / "test.p12"
    src_path.write_bytes(SAMPLE_CONTENT)
    p12_path.write_bytes(make_p12_from_chain(chain, password="test"))

    provider = FileProvider(p12_path)
    cred = provider.unlock(str(p12_path), "test")

    p7m_path = tmp / "documento.txt.p7m"
    CAdESSigner().sign(
        input_path=src_path,
        output_path=p7m_path,
        credential=cred,
        options=SignOptions(level=SignatureLevel.B, reason="CAdES test"),
    )
    return src_path, p7m_path, chain


def test_cades_signed_file_is_a_valid_cms():
    """La struttura del .p7m deve essere un CMS SignedData con contenuto embedded."""
    from asn1crypto import cms as asn1cms

    with tempfile.TemporaryDirectory() as td:
        _, p7m_path, _ = _setup(Path(td))
        ci = asn1cms.ContentInfo.load(p7m_path.read_bytes())
        assert ci["content_type"].native == "signed_data"
        signed_data = ci["content"]
        embedded = signed_data["encap_content_info"]["content"]
        assert embedded is not None and embedded.contents, (
            "il .p7m deve contenere il contenuto embedded (enveloping)"
        )
        # Il contenuto embedded deve essere esattamente il file originale.
        assert embedded.native == SAMPLE_CONTENT
        print(f"OK: .p7m strutturalmente valido, {p7m_path.stat().st_size} byte")


def test_cades_verify_untrusted():
    with tempfile.TemporaryDirectory() as td:
        _, p7m_path, _ = _setup(Path(td))
        result = CAdESVerifier().verify(p7m_path)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is False
        assert "Sigillum Test Signer" in s.subject
        print(f"OK (untrusted): subject={s.subject!r}")


def test_cades_verify_with_ca_in_trust_store():
    with tempfile.TemporaryDirectory() as td:
        _, p7m_path, chain = _setup(Path(td))
        result = CAdESVerifier(trusted_certs=[chain.ca_cert]).verify(p7m_path)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is True, f"errori: {s.errors}"
        assert result.all_valid is True
        print(f"OK (trusted): subject={s.subject!r}, valid={s.valid}")


def test_cades_verify_detects_tampering():
    """Modificare il contenuto embedded deve invalidare la firma."""
    from asn1crypto import cms as asn1cms, core

    with tempfile.TemporaryDirectory() as td:
        _, p7m_path, _ = _setup(Path(td))
        ci = asn1cms.ContentInfo.load(p7m_path.read_bytes())
        signed_data = ci["content"]
        # Sostituiamo il contenuto embedded con qualcosa di diverso.
        signed_data["encap_content_info"] = asn1cms.ContentInfo({
            "content_type": "data",
            "content": core.OctetString(b"contenuto manomesso"),
        })
        p7m_path.write_bytes(ci.dump())

        result = CAdESVerifier().verify(p7m_path)
        s = result.signers[0]
        assert s.hash_valid is False, "manomissione del contenuto non rilevata"
        print(f"OK (tampering rilevato): hash_valid={s.hash_valid}")


if __name__ == "__main__":
    test_cades_signed_file_is_a_valid_cms()
    test_cades_verify_untrusted()
    test_cades_verify_with_ca_in_trust_store()
    test_cades_verify_detects_tampering()
    print("\nTutti i test di roundtrip CAdES passati.")
