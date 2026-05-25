# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Unit tests for the LT post-processor (no network).

We forge a small PKI in-process (rootCA → ocspSigner + leafCert), build
an OCSP response with the rootCA's key, then verify that:

  1. `add_lt_attributes()` embeds id-aa-ets-certValues and
     id-aa-ets-revocationValues in the signer_info.unsigned_attrs of a
     T-level CMS without touching the signature bytes.
  2. The structures round-trip identically through asn1crypto.

The end-to-end "real OCSP from a real CA" path requires network and a
publicly-issued cert; it's exercised manually rather than in CI.
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from asn1crypto import cms as asn1cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import NameOID

from fixtures import write_fixture_files
from sigillum.core.credentials import FileProvider
from sigillum.core.lt import (
    CertificateValues,
    RevocationValues,
    add_lt_attributes,
)
from sigillum.core.signer import CAdESSigner, SignatureLevel, SignOptions


def _build_ocsp_response(target: x509.Certificate, issuer: x509.Certificate,
                        issuer_key) -> bytes:
    """Forge a Good OCSP response for `target` signed by `issuer_key`."""
    builder = crypto_ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=target,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=crypto_ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.now(timezone.utc) - timedelta(minutes=1),
        next_update=datetime.now(timezone.utc) + timedelta(days=1),
        revocation_time=None,
        revocation_reason=None,
    )
    builder = builder.responder_id(crypto_ocsp.OCSPResponderEncoding.HASH, issuer)
    resp = builder.sign(issuer_key, hashes.SHA256())
    return resp.public_bytes(serialization.Encoding.DER)


def test_add_lt_attributes_embeds_certs_and_ocsp():
    """Build a real CAdES T-signed file with our test PKI, then attach LT."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf, p12, chain_obj = write_fixture_files(tmp, password="test")

        # Sign a small CAdES (B-level is enough for the LT post-processing).
        src = tmp / "doc.txt"
        src.write_bytes(b"contenuto di prova LT")
        p7m = tmp / "doc.txt.p7m"

        cred = FileProvider(p12).unlock(str(p12), "test")
        CAdESSigner().sign(
            input_path=src,
            output_path=p7m,
            credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )

        original_bytes = p7m.read_bytes()
        original_signature = _extract_signature_bytes(original_bytes)

        # Forge an OCSP response for the leaf signed by the test CA.
        ocsp_der = _build_ocsp_response(
            chain_obj.signer_cert, chain_obj.ca_cert, chain_obj.ca_key,
        )

        lt_bytes = add_lt_attributes(
            original_bytes,
            certificates=[chain_obj.signer_cert, chain_obj.ca_cert],
            ocsp_responses=[ocsp_der],
        )

        # The signature value is part of signed_attrs / signature; LT attrs
        # land in unsigned_attrs and must NOT change the signature bytes.
        assert _extract_signature_bytes(lt_bytes) == original_signature, (
            "LT post-processing alterò la firma — proibito"
        )

        # Parse back and inspect the new unsigned_attrs.
        ci = asn1cms.ContentInfo.load(lt_bytes)
        signer_info = ci["content"]["signer_infos"][0]
        attrs = signer_info["unsigned_attrs"]
        attr_types = {a["type"].native for a in attrs}
        assert "certificate_values" in attr_types, attr_types
        assert "revocation_values" in attr_types, attr_types

        # Decode the contained structures end-to-end (no leftover bytes).
        for a in attrs:
            t = a["type"].native
            if t == "certificate_values":
                cv = a["values"][0]
                assert isinstance(cv, CertificateValues)
                assert len(cv) == 2
            elif t == "revocation_values":
                rv = a["values"][0]
                assert isinstance(rv, RevocationValues)
                ocsps = rv["ocsp_vals"]
                assert ocsps is not None and len(ocsps) == 1
        print(f"OK LT roundtrip: {len(lt_bytes) - len(original_bytes)} byte aggiunti "
              f"(certs + OCSP)")


def _extract_signature_bytes(p7m_bytes: bytes) -> bytes:
    ci = asn1cms.ContentInfo.load(p7m_bytes)
    return ci["content"]["signer_infos"][0]["signature"].native


def test_add_lt_attributes_is_idempotent_without_inputs():
    """No certs + no OCSP → input is returned unchanged."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf, p12, _chain = write_fixture_files(tmp, password="test")
        src = tmp / "doc.txt"
        src.write_bytes(b"hello")
        out = tmp / "doc.txt.p7m"
        cred = FileProvider(p12).unlock(str(p12), "test")
        CAdESSigner().sign(
            input_path=src, output_path=out, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )
        before = out.read_bytes()
        after = add_lt_attributes(before)
        assert after == before
        print("OK no-op pass-through senza materiale LT")


if __name__ == "__main__":
    test_add_lt_attributes_embeds_certs_and_ocsp()
    test_add_lt_attributes_is_idempotent_without_inputs()
    print("\nTutti i test LT passati.")
