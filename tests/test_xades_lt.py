# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""XAdES LT enrichment: adding CertificateValues + RevocationValues to a
T-level XAdES signature must not invalidate the XMLDSig signature.

We sign a tiny XML, attach LT material, re-parse and verify with our
XAdESVerifier.
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp
from lxml import etree

from fixtures import write_fixture_files
from sigillum.core.credentials import FileProvider
from sigillum.core.signer import SignatureLevel, SignOptions, XAdESSigner
from sigillum.core.verifier import XAdESVerifier
from sigillum.core.xades_lt import add_lt_properties


_DS = "http://www.w3.org/2000/09/xmldsig#"
_XADES = "http://uri.etsi.org/01903/v1.3.2#"


def _build_ocsp_response(target, issuer, issuer_key) -> bytes:
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
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )


def test_lt_props_preserve_signature():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _pdf, p12, chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")

        src = tmp / "doc.xml"
        src.write_bytes(b"<?xml version='1.0'?><doc><item>hello</item></doc>")
        signed = tmp / "doc.signed.xml"
        XAdESSigner().sign(
            input_path=src, output_path=signed, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )
        original = signed.read_bytes()

        ocsp_der = _build_ocsp_response(
            chain.signer_cert, chain.ca_cert, chain.ca_key,
        )

        lt_xml = add_lt_properties(
            original,
            certificates=[chain.signer_cert, chain.ca_cert],
            ocsp_responses=[ocsp_der],
        )

        # Structural assertions.
        tree = etree.fromstring(lt_xml)
        ns = {"ds": _DS, "xades": _XADES}
        cv = tree.find(".//xades:CertificateValues", ns)
        rv = tree.find(".//xades:RevocationValues", ns)
        assert cv is not None and len(cv) == 2, "EncapsulatedX509Certificate mancanti"
        assert rv is not None
        ov = rv.find("xades:OCSPValues", ns)
        assert ov is not None and len(ov) == 1, "EncapsulatedOCSPValue mancante"

        lt_path = tmp / "doc.lt.xml"
        lt_path.write_bytes(lt_xml)
        result = XAdESVerifier(trusted_certs=[chain.ca_cert]).verify(lt_path)
        s = result.signers[0]
        assert s.hash_valid is True, f"hash invalidato: {s.errors}"
        assert s.signature_valid is True, f"firma invalidata: {s.errors}"
        assert s.cert_trusted is True
        print(
            f"OK XAdES LT: {len(original)} → {len(lt_xml)} byte "
            f"(+{len(lt_xml) - len(original)}), firma intatta"
        )


def test_idempotent_rerun():
    """Running add_lt_properties twice replaces the old block, doesn't dup."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _pdf, p12, chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")
        src = tmp / "doc.xml"
        src.write_bytes(b"<?xml version='1.0'?><doc/>")
        signed = tmp / "doc.signed.xml"
        XAdESSigner().sign(
            input_path=src, output_path=signed, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )
        original = signed.read_bytes()
        once = add_lt_properties(original, certificates=[chain.signer_cert])
        twice = add_lt_properties(once, certificates=[chain.signer_cert])
        # Both calls produce a single CertificateValues node.
        for blob in (once, twice):
            tree = etree.fromstring(blob)
            cvs = tree.findall(".//{http://uri.etsi.org/01903/v1.3.2#}CertificateValues")
            assert len(cvs) == 1, f"atteso 1 nodo, trovati {len(cvs)}"
        print("OK XAdES LT idempotente sui re-run")


def test_no_op_without_inputs():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _pdf, p12, _chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")
        src = tmp / "doc.xml"
        src.write_bytes(b"<?xml version='1.0'?><doc/>")
        signed = tmp / "doc.signed.xml"
        XAdESSigner().sign(
            input_path=src, output_path=signed, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )
        before = signed.read_bytes()
        after = add_lt_properties(before)
        assert after == before
        print("OK no-op senza materiale LT")


if __name__ == "__main__":
    test_lt_props_preserve_signature()
    test_idempotent_rerun()
    test_no_op_without_inputs()
    print("\nTutti i test XAdES LT passati.")
