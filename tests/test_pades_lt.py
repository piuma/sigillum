# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""PAdES LT post-processing test: appending a DSS dictionary to a signed PDF
must NOT invalidate the signature.

We sign a PDF at level B with the in-process test PKI, then call
`add_dss()` to append cert/OCSP material, then re-verify with our normal
PAdES verifier. Hash + signature flags must remain True after the DSS is
attached (the bytes covered by /ByteRange are untouched — the DSS lives
after %%EOF in the incremental update region).
"""
from __future__ import annotations

import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp

from fixtures import write_fixture_files
from sigillum.core.credentials import FileProvider
from sigillum.core.pades_lt import add_dss
from sigillum.core.signer import PAdESSigner, SignatureLevel, SignOptions
from sigillum.core.verifier import PAdESVerifier


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
    resp = builder.sign(issuer_key, hashes.SHA256())
    return resp.public_bytes(serialization.Encoding.DER)


def test_dss_preserves_signature():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf, p12, chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")

        signed = tmp / "signed.pdf"
        PAdESSigner().sign(
            input_path=pdf, output_path=signed, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )

        original = signed.read_bytes()

        # Forge OCSP for the leaf using the test CA's private key.
        ocsp_der = _build_ocsp_response(
            chain.signer_cert, chain.ca_cert, chain.ca_key,
        )

        lt_pdf = add_dss(
            original,
            certificates=[chain.signer_cert, chain.ca_cert],
            ocsp_responses=[ocsp_der],
        )
        # The LT PDF strictly extends the original via incremental update.
        assert lt_pdf.startswith(original), (
            "incremental update must append; old bytes must be unchanged"
        )
        # New DSS material is present.
        assert b"/DSS" in lt_pdf
        assert b"/Type /DSS" in lt_pdf
        assert b"/Certs" in lt_pdf and b"/OCSPs" in lt_pdf
        # Our incremental update adds exactly one new %%EOF + startxref on
        # top of whatever the signed PDF already had (endesive itself uses
        # an incremental update to attach the signature, so the count
        # before us is typically 2).
        assert lt_pdf.count(b"%%EOF") == original.count(b"%%EOF") + 1
        before_startxrefs = list(re.finditer(rb"startxref\s+(\d+)", original))
        after_startxrefs = list(re.finditer(rb"startxref\s+(\d+)", lt_pdf))
        assert len(after_startxrefs) == len(before_startxrefs) + 1

        lt_path = tmp / "signed.lt.pdf"
        lt_path.write_bytes(lt_pdf)

        result = PAdESVerifier(trusted_certs=[chain.ca_cert]).verify(lt_path)
        s = result.signers[0]
        assert s.hash_valid is True, f"hash invalidato da add_dss: {s.errors}"
        assert s.signature_valid is True, f"firma invalidata: {s.errors}"
        assert s.cert_trusted is True
        print(
            f"OK PAdES LT: {len(original)} → {len(lt_pdf)} byte"
            f" (+{len(lt_pdf) - len(original)} DSS), firma ancora valida"
        )


def test_no_op_without_inputs():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf, p12, _chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")
        signed = tmp / "signed.pdf"
        PAdESSigner().sign(
            input_path=pdf, output_path=signed, credential=cred,
            options=SignOptions(level=SignatureLevel.B),
        )
        before = signed.read_bytes()
        after = add_dss(before)
        assert after == before
        print("OK no-op senza materiale LT")


if __name__ == "__main__":
    test_dss_preserves_signature()
    test_no_op_without_inputs()
    print("\nTutti i test PAdES LT passati.")
