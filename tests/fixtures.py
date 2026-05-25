# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Helpers per i test: PDF minimale e una chain CA -> Signer in PKCS#12."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def make_minimal_pdf() -> bytes:
    """Return a syntactically valid 1-page empty PDF with correct xref offsets."""
    header = b"%PDF-1.4\n"
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    ]
    body = bytearray(header)
    offsets = []
    for obj in objs:
        offsets.append(len(body))
        body.extend(obj)

    xref_offset = len(body)
    xref = bytearray(b"xref\n0 4\n0000000000 65535 f \n")
    for off in offsets:
        xref.extend(f"{off:010d} 00000 n \n".encode())

    trailer = (
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return bytes(body) + bytes(xref) + trailer


@dataclass
class TestChain:
    """Test PKI: a CA and a leaf signing cert issued by it."""
    ca_key: rsa.RSAPrivateKey
    ca_cert: x509.Certificate
    signer_key: rsa.RSAPrivateKey
    signer_cert: x509.Certificate


def make_test_chain() -> TestChain:
    """Build a 2-level chain: self-signed CA -> leaf signing cert.

    The leaf carries the extensions required by `cryptography`'s X.509 path
    validator (SKI, AKI, KeyUsage, ExtendedKeyUsage), so it can be successfully
    verified when the CA is added to the trust store.
    """
    now = datetime.now(timezone.utc)

    # --- CA ---
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sigillum Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Sigillum Test CA"),
    ])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # --- Leaf signer ---
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sigillum Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Sigillum Test Signer"),
    ])
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(ca_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        # SAN is required by cryptography.x509.verification.build_client_verifier()
        # (which endesive uses) — without it, validation fails even with a
        # trusted CA. A dummy rfc822Name is enough.
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("signer@sigillum.test")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return TestChain(ca_key=ca_key, ca_cert=ca_cert,
                     signer_key=signer_key, signer_cert=signer_cert)


def make_p12_from_chain(chain: TestChain, password: str = "test") -> bytes:
    """Serialize the leaf + CA chain into a PKCS#12 blob."""
    return pkcs12.serialize_key_and_certificates(
        name=b"sigillum-test",
        key=chain.signer_key,
        cert=chain.signer_cert,
        cas=[chain.ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


def write_fixture_files(
    tmpdir: Path, password: str = "test"
) -> tuple[Path, Path, TestChain]:
    """Write a minimal PDF and a PKCS#12 (chain CA->signer) into tmpdir."""
    pdf_path = tmpdir / "sample.pdf"
    p12_path = tmpdir / "test.p12"
    chain = make_test_chain()
    pdf_path.write_bytes(make_minimal_pdf())
    p12_path.write_bytes(make_p12_from_chain(chain, password))
    return pdf_path, p12_path, chain
