# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""File encryption: symmetric (password) and asymmetric (certificate).

Four modes are supported:

  1. **Symmetric AES-256-CBC + PKCS#7 padding + PBKDF2-SHA256** — the
     default password-based mode. Output container starts with magic
     `SIGILLUM` followed by version, algorithm name, salt, IV, ciphertext.
  2. **Symmetric with selectable algorithm** (AES-128, AES-256, 3DES,
     Blowfish) — same container, different cipher.
  3. **Asymmetric with a recipient certificate** — produces a CMS
     `EnvelopedData` (RFC 5652) saved as `.p7e`. The content is encrypted
     with a one-shot AES-256-CBC session key; the session key is wrapped
     under the recipient's RSA public key with RSAES-PKCS1-v1.5.
  4. **Asymmetric with a PKCS#12 file** — same envelope structure; the
     recipient cert is loaded from the `.p12`.

Decryption auto-detects the format from the input bytes:

  - leading `SIGILLUM` magic  → symmetric
  - CMS ContentInfo wrapping `enveloped_data` → asymmetric

Asymmetric decryption can use either a software private key (PKCS#12 file)
or a hardware token via PKCS#11 (the `SigningCredential.hsm` path provides
`rsa_decrypt()`).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from asn1crypto import algos, cms, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# TripleDES is being moved to a "decrepit" namespace in cryptography 48+;
# we still expose it because the spec asks for it, but import it tolerantly.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    _TripleDES = algorithms.TripleDES  # type: ignore[attr-defined]
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..i18n import _
from .credentials import SigningCredential


# ---------------------------------------------------------------------------
# Symmetric cipher catalog
# ---------------------------------------------------------------------------

# Symmetric algorithm names are deliberately stable strings: they're written
# verbatim into the SIGILLUM container header. Adding a new entry preserves
# backwards-compat as long as existing names keep their semantics.
SymmetricName = Literal["AES-256", "AES-128", "3DES", "Blowfish"]


@dataclass(frozen=True)
class _SymSpec:
    key_size: int   # bytes
    block_size: int  # bytes (== IV size in CBC mode)
    factory: type   # cryptography.hazmat.primitives.ciphers.algorithms.*


_SYMMETRIC: dict[str, _SymSpec] = {
    "AES-256": _SymSpec(32, 16, algorithms.AES),
    "AES-128": _SymSpec(16, 16, algorithms.AES),
    "3DES":    _SymSpec(24, 8, _TripleDES),
    # Blowfish accepts 4–56 byte keys; 16 (128-bit) is a safe middle ground.
    "Blowfish": _SymSpec(16, 8, algorithms.Blowfish),
}

SYMMETRIC_NAMES: tuple[str, ...] = tuple(_SYMMETRIC.keys())


# PBKDF2-SHA256 iterations. NIST SP 800-132 (2024) recommends ≥ 600k for
# password hashing with HMAC-SHA-256 on modern hardware.
_PBKDF2_ITERATIONS = 600_000
_SALT_SIZE = 16

_MAGIC = b"SIGILLUM"
_FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# Symmetric (password-based)
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes, key_size: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_symmetric(
    plaintext: bytes,
    password: str,
    algorithm: SymmetricName = "AES-256",
) -> bytes:
    """Encrypt `plaintext` with `password`. Return the SIGILLUM container."""
    if algorithm not in _SYMMETRIC:
        raise ValueError(
            _("unsupported algorithm: {algo!r}. Valid: {valid}").format(
                algo=algorithm, valid=", ".join(SYMMETRIC_NAMES)
            )
        )
    spec = _SYMMETRIC[algorithm]

    salt = os.urandom(_SALT_SIZE)
    iv = os.urandom(spec.block_size)
    key = _derive_key(password, salt, spec.key_size)

    padder = padding.PKCS7(spec.block_size * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(spec.factory(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()

    algo_bytes = algorithm.encode("ascii")
    if len(algo_bytes) > 255:
        raise ValueError(_("algorithm name too long"))
    return (
        _MAGIC
        + bytes([_FORMAT_VERSION])
        + bytes([len(algo_bytes)])
        + algo_bytes
        + salt
        + iv
        + ct
    )


def decrypt_symmetric(blob: bytes, password: str) -> bytes:
    """Inverse of `encrypt_symmetric`. Raises ValueError on bad input."""
    if not blob.startswith(_MAGIC):
        raise ValueError(_("SIGILLUM header missing or file is not symmetric"))
    pos = len(_MAGIC)
    version = blob[pos]; pos += 1
    if version != _FORMAT_VERSION:
        raise ValueError(_("unsupported format version: {version}").format(version=version))
    algo_len = blob[pos]; pos += 1
    algorithm = blob[pos:pos + algo_len].decode("ascii")
    pos += algo_len
    if algorithm not in _SYMMETRIC:
        raise ValueError(_("unknown algorithm: {algo!r}").format(algo=algorithm))
    spec = _SYMMETRIC[algorithm]
    salt = blob[pos:pos + _SALT_SIZE]; pos += _SALT_SIZE
    iv = blob[pos:pos + spec.block_size]; pos += spec.block_size
    ct = blob[pos:]

    key = _derive_key(password, salt, spec.key_size)
    dec = Cipher(spec.factory(key), modes.CBC(iv)).decryptor()
    try:
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(spec.block_size * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as ex:
        # PKCS7 unpadder raises on bad padding — typical sign of wrong password
        # or tampered ciphertext. Re-raise with a friendlier message.
        raise ValueError(_("wrong password or tampered content")) from ex


# ---------------------------------------------------------------------------
# Asymmetric (CMS EnvelopedData)
# ---------------------------------------------------------------------------

def encrypt_asymmetric(
    plaintext: bytes,
    recipient_cert: x509.Certificate,
) -> bytes:
    """Build a CMS `EnvelopedData` (RFC 5652) blob — what a `.p7e` contains.

    The content is encrypted with a one-shot AES-256-CBC session key; the
    session key is wrapped under the recipient's RSA public key with
    RSAES-PKCS1-v1.5 (the most widely interoperable mode for Italian
    qualified certs, even older ones that don't advertise OAEP support).
    """
    pub = recipient_cert.public_key()

    # Content encryption (AES-256-CBC + PKCS#7)
    session_key = os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(session_key), modes.CBC(iv)).encryptor()
    encrypted_content = enc.update(padded) + enc.finalize()

    # Session-key wrap
    encrypted_session_key = pub.encrypt(session_key, asym_padding.PKCS1v15())

    # Build the CMS RecipientIdentifier from the cert's issuer + serial.
    cert_der = recipient_cert.public_bytes(serialization.Encoding.DER)
    asn1_cert = asn1_x509.Certificate.load(cert_der)

    enveloped = cms.EnvelopedData({
        "version": "v0",  # no originatorInfo, no unprotectedAttrs
        "recipient_infos": cms.RecipientInfos([
            cms.RecipientInfo(
                name="ktri",
                value=cms.KeyTransRecipientInfo({
                    "version": "v0",
                    "rid": cms.RecipientIdentifier(
                        name="issuer_and_serial_number",
                        value=cms.IssuerAndSerialNumber({
                            "issuer": asn1_cert.issuer,
                            "serial_number": asn1_cert.serial_number,
                        }),
                    ),
                    "key_encryption_algorithm": cms.KeyEncryptionAlgorithm({
                        "algorithm": "rsaes_pkcs1v15",
                    }),
                    "encrypted_key": encrypted_session_key,
                }),
            ),
        ]),
        "encrypted_content_info": cms.EncryptedContentInfo({
            "content_type": "data",
            "content_encryption_algorithm": cms.EncryptionAlgorithm({
                "algorithm": "aes256_cbc",
                "parameters": iv,
            }),
            "encrypted_content": encrypted_content,
        }),
    })
    return cms.ContentInfo({
        "content_type": "enveloped_data",
        "content": enveloped,
    }).dump()


def decrypt_asymmetric(blob: bytes, credential: SigningCredential) -> bytes:
    """Decrypt a CMS EnvelopedData using the credential's private key.

    The credential may be backed either by a software private key (PKCS#12
    file via `FileProvider`) or by a hardware token via PKCS#11 (`hsm`
    field set by `PKCS11Provider`).
    """
    ci = cms.ContentInfo.load(blob)
    if ci["content_type"].native != "enveloped_data":
        raise ValueError(
            _("not an EnvelopedData file (content_type={ct!r})").format(
                ct=ci["content_type"].native
            )
        )
    enveloped: cms.EnvelopedData = ci["content"]

    # Match a recipient against our certificate (by issuer + serial).
    our_serial = credential.certificate.serial_number
    cert_der = credential.certificate.public_bytes(serialization.Encoding.DER)
    our_issuer = asn1_x509.Certificate.load(cert_der).issuer

    encrypted_key: bytes | None = None
    for ri in enveloped["recipient_infos"]:
        if ri.name != "ktri":
            continue
        ktri: cms.KeyTransRecipientInfo = ri.chosen
        rid = ktri["rid"]
        if rid.name != "issuer_and_serial_number":
            # We don't handle SubjectKeyIdentifier RIDs in v1.
            continue
        ias = rid.chosen
        if ias["serial_number"].native == our_serial and ias["issuer"] == our_issuer:
            encrypted_key = ktri["encrypted_key"].native
            break
    if encrypted_key is None:
        raise ValueError(_(
            "the file is not encrypted for the configured certificate "
            "(no matching recipient)"
        ))

    # Unwrap the session key.
    if credential.hsm is not None and hasattr(credential.hsm, "rsa_decrypt"):
        session_key = credential.hsm.rsa_decrypt(encrypted_key)
    elif credential.private_key is not None:
        session_key = credential.private_key.decrypt(
            encrypted_key, asym_padding.PKCS1v15(),
        )
    else:
        raise ValueError(_("credential has no usable private key"))

    # Decrypt the content.
    eci = enveloped["encrypted_content_info"]
    algo_name = eci["content_encryption_algorithm"]["algorithm"].native
    iv = eci["content_encryption_algorithm"]["parameters"].native
    ct = eci["encrypted_content"].native

    if algo_name in ("aes256_cbc", "aes128_cbc", "aes192_cbc"):
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        block_bits = 128
    elif algo_name in ("tripledes_3key", "des_ede3_cbc"):
        cipher = Cipher(algorithms.TripleDES(session_key), modes.CBC(iv))
        block_bits = 64
    else:
        raise ValueError(_("unsupported content encryption algorithm: {algo}").format(algo=algo_name))

    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(block_bits).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------

EncryptionFormat = Literal["symmetric", "asymmetric", "unknown"]


def detect_format(blob: bytes) -> EncryptionFormat:
    """Cheaply guess the encryption format of a blob without decrypting it."""
    if blob.startswith(_MAGIC):
        return "symmetric"
    # CMS ContentInfo starts with SEQUENCE tag 0x30. Try to parse the OID.
    if blob[:1] == b"\x30":
        try:
            ci = cms.ContentInfo.load(blob, strict=False)
            if ci["content_type"].native == "enveloped_data":
                return "asymmetric"
        except Exception:  # noqa: BLE001
            pass
    return "unknown"
