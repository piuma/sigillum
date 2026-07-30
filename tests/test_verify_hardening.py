# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Negative-path verification tests: coverage and revocation.

Roundtrip tests prove the signer works; these prove the *verifier* says no.
Two failures used to slip through silently:

  - a PDF modified after signing (an incremental update appended after the
    /ByteRange) verified as fully valid, because the signature over the bytes
    it does cover is impeccable;
  - a certificate revoked for key compromise verified as trusted, because the
    OCSP material embedded at signing time was never read back.

Both cases are exercised here, along with the two cases that must NOT be
flagged: a DSS-only tail (that is what PAdES-LT looks like) and a revocation
that happened after a timestamped signature.
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp

from fixtures import make_test_chain, write_fixture_files
from sigillum.core.credentials import FileProvider
from sigillum.core.lt import add_lt_attributes
from sigillum.core.pades_lt import add_dss, read_dss
from sigillum.core.pdf_coverage import TRAILING_UNKNOWN, TRAILING_VALIDATION_DATA
from sigillum.core.revocation import RevocationInfo, RevocationStatus
from sigillum.core.signer import CAdESSigner, PAdESSigner, SignatureLevel, SignOptions
from sigillum.core.verifier import CAdESVerifier, PAdESVerifier, SignerInfo

# An incremental update that adds a page object: a plain document edit, the
# thing a signature is supposed to make detectable.
_APPENDED_EDIT = (
    b"\n7 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    b"xref\n0 0\ntrailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
)


def _ocsp(
    target, issuer, issuer_key, *,
    status=crypto_ocsp.OCSPCertStatus.GOOD,
    revoked_at=None,
    reason=None,
    responder=None,
    responder_key=None,
) -> bytes:
    """A DER OCSPResponse for `target`, signed by `issuer_key` by default.

    `responder` / `responder_key` let a test sign a response with a key that
    has no business answering for this CA.
    """
    builder = crypto_ocsp.OCSPResponseBuilder().add_response(
        cert=target,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=datetime.now(timezone.utc) - timedelta(minutes=1),
        next_update=datetime.now(timezone.utc) + timedelta(days=1),
        revocation_time=revoked_at,
        revocation_reason=reason,
    )
    builder = builder.responder_id(
        crypto_ocsp.OCSPResponderEncoding.HASH, responder or issuer)
    response = builder.sign(responder_key or issuer_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


def _sign_pdf(tmp: Path) -> tuple[bytes, object]:
    """A level-B signed PDF plus the test PKI that signed it."""
    pdf_path, p12_path, chain = write_fixture_files(tmp, password="test")
    provider = FileProvider(p12_path)
    credential = provider.unlock(provider.list_certificates()[0].id, "test")
    signed_path = tmp / "signed.pdf"
    PAdESSigner().sign(
        input_path=pdf_path, output_path=signed_path, credential=credential,
        options=SignOptions(level=SignatureLevel.B, reason="Test"),
    )
    return signed_path.read_bytes(), chain


def _verify_pdf(tmp: Path, name: str, data: bytes, chain):
    path = tmp / name
    path.write_bytes(data)
    return PAdESVerifier([chain.ca_cert]).verify(path)


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def test_plain_signature_covers_the_whole_file():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        result = _verify_pdf(tmp, "b.pdf", signed, chain)

        assert result.coverage is not None
        assert result.coverage.whole_file is True
        assert result.coverage.signed_bytes == len(signed)
        assert result.all_valid is True


def test_content_appended_after_signing_is_reported():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        result = _verify_pdf(tmp, "edited.pdf", signed + _APPENDED_EDIT, chain)

        # The signature itself is untouched — that is exactly the trap.
        assert result.signers[0].hash_valid is True
        assert result.signers[0].signature_valid is True
        # ... and the document as a whole must not pass.
        assert result.coverage.whole_file is False
        assert result.coverage.trailing == TRAILING_UNKNOWN
        assert result.coverage.modified is True
        assert result.all_valid is False
        assert result.errors, "an unaccounted-for tail must be reported"


def test_dss_only_tail_is_not_a_modification():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        lt_pdf = add_dss(
            signed,
            certificates=[chain.signer_cert, chain.ca_cert],
            ocsp_responses=[_ocsp(chain.signer_cert, chain.ca_cert, chain.ca_key)],
        )
        result = _verify_pdf(tmp, "lt.pdf", lt_pdf, chain)

        assert result.coverage.whole_file is False  # the DSS lives past the range
        assert result.coverage.trailing == TRAILING_VALIDATION_DATA
        assert result.coverage.modified is False
        assert result.all_valid is True
        assert not result.errors


def test_edit_after_a_dss_is_still_caught():
    """The DSS exemption must not become a hiding place for an edit."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        lt_pdf = add_dss(signed, certificates=[chain.ca_cert])
        result = _verify_pdf(tmp, "lt-edited.pdf", lt_pdf + _APPENDED_EDIT, chain)

        assert result.coverage.modified is True
        assert result.all_valid is False


def test_dss_keeps_the_acroform_the_signature_registered():
    """A DSS update clones the *current* catalog, not the original one.

    Cloning the pre-signature catalog would drop the /AcroForm endesive adds
    when it registers the signature field, leaving an LT file whose signature
    no validator that goes through the form would find.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        assert b"/AcroForm" in signed
        lt_pdf = add_dss(signed, certificates=[chain.ca_cert])
        appended = lt_pdf[len(signed):]
        assert b"/Catalog" in appended
        assert b"/AcroForm" in appended


# ---------------------------------------------------------------------------
# Revocation — PAdES (/DSS material)
# ---------------------------------------------------------------------------

def test_dss_material_is_read_back():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        lt_pdf = add_dss(
            signed,
            certificates=[chain.signer_cert, chain.ca_cert],
            ocsp_responses=[_ocsp(chain.signer_cert, chain.ca_cert, chain.ca_key)],
        )
        material = read_dss(lt_pdf)

        assert len(material.certificates) == 2
        assert len(material.ocsp_responses) == 1
        assert {c.subject for c in material.certificates} == {
            chain.signer_cert.subject, chain.ca_cert.subject}


def test_embedded_ocsp_reports_a_good_certificate():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        lt_pdf = add_dss(
            signed,
            certificates=[chain.ca_cert],
            ocsp_responses=[_ocsp(chain.signer_cert, chain.ca_cert, chain.ca_key)],
        )
        info = _verify_pdf(tmp, "good.pdf", lt_pdf, chain).signers[0]

        assert info.revocation.status is RevocationStatus.GOOD
        assert info.revocation.source == "embedded-ocsp"
        assert info.revoked is False
        assert info.valid is True


def test_revoked_certificate_is_not_valid():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        lt_pdf = add_dss(
            signed,
            certificates=[chain.ca_cert],
            ocsp_responses=[_ocsp(
                chain.signer_cert, chain.ca_cert, chain.ca_key,
                status=crypto_ocsp.OCSPCertStatus.REVOKED,
                revoked_at=datetime.now(timezone.utc) - timedelta(days=2),
                reason=x509.ReasonFlags.key_compromise,
            )],
        )
        result = _verify_pdf(tmp, "revoked.pdf", lt_pdf, chain)
        info = result.signers[0]

        assert info.revocation.status is RevocationStatus.REVOKED
        assert info.revocation.reason == "key_compromise"
        assert info.cert_trusted is True   # the chain is fine; the cert is not
        assert info.revoked is True
        assert info.valid is False
        assert result.all_valid is False
        assert any("REVOKED" in err for err in info.errors)


def test_ocsp_from_a_foreign_ca_is_not_believed():
    """Embedded material is attacker-reachable: it has to be verified."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        intruder = make_test_chain()
        forged = _ocsp(
            chain.signer_cert, chain.ca_cert, chain.ca_key,
            responder=intruder.ca_cert, responder_key=intruder.ca_key,
        )
        lt_pdf = add_dss(signed, certificates=[chain.ca_cert],
                         ocsp_responses=[forged])
        info = _verify_pdf(tmp, "forged.pdf", lt_pdf, chain).signers[0]

        assert info.revocation.status is not RevocationStatus.GOOD
        assert info.revocation.status is RevocationStatus.UNAVAILABLE


def test_ocsp_for_another_certificate_is_ignored():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        other = make_test_chain()
        lt_pdf = add_dss(
            signed,
            certificates=[chain.ca_cert],
            ocsp_responses=[_ocsp(other.signer_cert, other.ca_cert, other.ca_key)],
        )
        info = _verify_pdf(tmp, "mismatched.pdf", lt_pdf, chain).signers[0]

        assert info.revocation.status is RevocationStatus.UNAVAILABLE
        assert info.valid is True  # unknown revocation is not a rejection


def test_no_material_means_not_checked():
    """A B-level signature must not be decorated with a verdict we never made."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed, chain = _sign_pdf(tmp)
        info = _verify_pdf(tmp, "plain.pdf", signed, chain).signers[0]

        assert info.revocation.status is RevocationStatus.NOT_CHECKED
        assert info.valid is True


# ---------------------------------------------------------------------------
# Revocation — CAdES (RevocationValues unsigned attr)
# ---------------------------------------------------------------------------

def test_cades_revocation_values_are_read():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf_path, p12_path, chain = write_fixture_files(tmp, password="test")
        provider = FileProvider(p12_path)
        credential = provider.unlock(provider.list_certificates()[0].id, "test")
        p7m_path = tmp / "sample.pdf.p7m"
        CAdESSigner().sign(
            input_path=pdf_path, output_path=p7m_path, credential=credential,
            options=SignOptions(level=SignatureLevel.B),
        )
        revoked = add_lt_attributes(
            p7m_path.read_bytes(),
            certificates=[chain.ca_cert],
            ocsp_responses=[_ocsp(
                chain.signer_cert, chain.ca_cert, chain.ca_key,
                status=crypto_ocsp.OCSPCertStatus.REVOKED,
                revoked_at=datetime.now(timezone.utc) - timedelta(days=1),
                reason=x509.ReasonFlags.key_compromise,
            )],
        )
        lt_path = tmp / "revoked.p7m"
        lt_path.write_bytes(revoked)

        result = CAdESVerifier([chain.ca_cert]).verify(lt_path)
        info = result.signers[0]

        assert info.revocation.status is RevocationStatus.REVOKED
        assert info.valid is False
        assert result.all_valid is False


# ---------------------------------------------------------------------------
# When a revocation does *not* invalidate a signature
# ---------------------------------------------------------------------------

def _revoked_info(*, reason: str, timestamp_trusted: bool, signed_before: bool):
    revoked_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    stamp = revoked_at - timedelta(days=10 if signed_before else -10)
    return SignerInfo(
        hash_valid=True, signature_valid=True, cert_trusted=True,
        timestamp=stamp, timestamp_trusted=timestamp_trusted,
        revocation=RevocationInfo(
            status=RevocationStatus.REVOKED, revoked_at=revoked_at, reason=reason),
    )


def test_revocation_after_a_timestamped_signature_keeps_it_valid():
    info = _revoked_info(
        reason="cessation_of_operation", timestamp_trusted=True, signed_before=True)
    assert info.revoked is False
    assert info.valid is True


def test_revocation_before_the_signature_invalidates_it():
    info = _revoked_info(
        reason="cessation_of_operation", timestamp_trusted=True, signed_before=False)
    assert info.revoked is True


def test_key_compromise_invalidates_even_an_earlier_signature():
    info = _revoked_info(
        reason="key_compromise", timestamp_trusted=True, signed_before=True)
    assert info.revoked is True


def test_without_a_trusted_timestamp_the_revocation_stands():
    info = _revoked_info(
        reason="cessation_of_operation", timestamp_trusted=False, signed_before=True)
    assert info.revoked is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"OK: {name}")
