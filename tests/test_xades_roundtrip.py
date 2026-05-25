# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Roundtrip XAdES: firma XML enveloped e verifica."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import SignOptions, SignatureLevel, XAdESSigner
from sigillum.core.verifier import XAdESVerifier

from fixtures import make_p12_from_chain, make_test_chain


SAMPLE_XML = b"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Fattura>
  <Numero>42</Numero>
  <Importo valuta=\"EUR\">199.90</Importo>
</Fattura>
"""


def _setup(tmp: Path):
    chain = make_test_chain()
    src_path = tmp / "fattura.xml"
    p12_path = tmp / "test.p12"
    src_path.write_bytes(SAMPLE_XML)
    p12_path.write_bytes(make_p12_from_chain(chain, password="test"))

    provider = FileProvider(p12_path)
    cred = provider.unlock(str(p12_path), "test")

    signed_path = tmp / "fattura-signed.xml"
    XAdESSigner().sign(
        input_path=src_path,
        output_path=signed_path,
        credential=cred,
        options=SignOptions(level=SignatureLevel.B, reason="XAdES test"),
    )
    return src_path, signed_path, chain


def test_xades_signed_xml_contains_signature():
    with tempfile.TemporaryDirectory() as td:
        _, signed_path, _ = _setup(Path(td))
        signed = signed_path.read_bytes()
        assert b"<ds:Signature" in signed or b"<Signature" in signed
        assert b"SignedProperties" in signed


def test_xades_verify_untrusted():
    with tempfile.TemporaryDirectory() as td:
        _, signed_path, _ = _setup(Path(td))
        result = XAdESVerifier().verify(signed_path)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is False
        assert "Sigillum Test Signer" in s.subject


def test_xades_verify_with_ca_in_trust_store():
    with tempfile.TemporaryDirectory() as td:
        _, signed_path, chain = _setup(Path(td))
        result = XAdESVerifier(trusted_certs=[chain.ca_cert]).verify(signed_path)
        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is True, f"errori: {s.errors}"
        assert result.all_valid is True


def test_xades_verify_detects_tampering():
    with tempfile.TemporaryDirectory() as td:
        _, signed_path, _ = _setup(Path(td))
        data = signed_path.read_bytes()
        data = data.replace(b"199.90", b"299.90", 1)
        signed_path.write_bytes(data)

        result = XAdESVerifier().verify(signed_path)
        s = result.signers[0]
        assert not (s.hash_valid and s.signature_valid), (
            "manomissione del contenuto non rilevata"
        )


if __name__ == "__main__":
    test_xades_signed_xml_contains_signature()
    test_xades_verify_untrusted()
    test_xades_verify_with_ca_in_trust_store()
    test_xades_verify_detects_tampering()
    print("\nTutti i test di roundtrip XAdES passati.")
