# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Credential providers: hardware tokens (PKCS#11) and file-based certificates."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    pkcs12,
)

from ..i18n import _


@dataclass(frozen=True)
class CertificateInfo:
    """Metadata about a signing certificate, displayed in the UI selector."""
    id: str
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str


@dataclass
class SigningCredential:
    """Resolved credential ready for signing.

    For file-based credentials, `private_key` is a `cryptography` private-key
    object passed directly to endesive. For PKCS#11 hardware tokens,
    `private_key` is None and `hsm` carries an object compatible with
    endesive's `BaseHSM` interface (it has `certificate()` and `sign()`),
    which performs the actual signing on the token.
    """
    certificate: x509.Certificate
    chain: Sequence[x509.Certificate]
    private_key: object | None = None
    hsm: object | None = None


class CredentialProvider(ABC):
    """Abstraction over the source of signing credentials."""

    @abstractmethod
    def list_certificates(self) -> Sequence[CertificateInfo]:
        ...

    @abstractmethod
    def unlock(self, cert_id: str, secret: str) -> SigningCredential:
        """Return a usable signing credential. `secret` is PIN or password."""
        ...

    def close(self) -> None:
        """Release resources (PKCS#11 session, etc.). Default no-op."""


class _PKCS11HSM:
    """Adapter exposing endesive's BaseHSM contract over a PyKCS11 session.

    endesive calls `certificate()` to get (keyid, cert_der_or_pem) and
    `sign(keyid, data, hashalgo)` to obtain raw RSA signature bytes. We use
    `CKM_<HASH>_RSA_PKCS` mechanisms so the token hashes and signs in a
    single operation — required for YubiKey PIV slots where the PIN policy
    is "always" (re-auth on every sign).
    """

    _MECH_BY_HASH = {
        "sha1": "CKM_SHA1_RSA_PKCS",
        "sha256": "CKM_SHA256_RSA_PKCS",
        "sha384": "CKM_SHA384_RSA_PKCS",
        "sha512": "CKM_SHA512_RSA_PKCS",
    }

    def __init__(self, session, private_key_handle, cert_der: bytes, keyid: bytes):
        self._session = session
        self._key = private_key_handle
        self._cert_der = cert_der
        self._keyid = keyid

    def certificate(self):
        return self._keyid, self._cert_der

    def sign(self, keyid, data, hashalgo):  # noqa: ARG002 — keyid unused (single key per HSM)
        import PyKCS11

        mech_name = self._MECH_BY_HASH.get(hashalgo)
        if mech_name is None:
            raise ValueError(_("unsupported hash algorithm: {hashalgo}").format(hashalgo=hashalgo))
        mech = PyKCS11.Mechanism(getattr(PyKCS11, mech_name), None)
        signature = self._session.sign(self._key, data, mech)
        return bytes(signature)

    def rsa_decrypt(self, encrypted: bytes) -> bytes:
        """RSAES-PKCS1-v1.5 decrypt on the token. Used by `crypto.decrypt_asymmetric`.

        For PIV "always-PIN" slots the user is prompted by the driver for a
        fresh PIN every call; for "once" slots the login from `unlock()` is
        enough.
        """
        import PyKCS11

        mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
        plaintext = self._session.decrypt(self._key, encrypted, mech)
        return bytes(plaintext)


class PKCS11Provider(CredentialProvider):
    """Hardware token / smartcard via PKCS#11.

    `library_path` points to the vendor's PKCS#11 driver:
      - YubiKey:    /usr/lib64/libykcs11.so.2
      - Aruba Key:  libbit4xpki.so or libaskpkcs11.so
      - OpenSC:     /usr/lib64/opensc-pkcs11.so (generic smartcards)
    """

    def __init__(self, library_path: str | Path, slot: int | None = None):
        self.library_path = str(library_path)
        self.slot = slot  # None -> first slot with a token present
        self._pkcs11 = None
        self._session = None

    def _lib(self):
        if self._pkcs11 is None:
            import PyKCS11
            self._pkcs11 = PyKCS11.PyKCS11Lib()
            self._pkcs11.load(self.library_path)
        return self._pkcs11

    def _resolve_slot(self) -> int:
        lib = self._lib()
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError(_("no PKCS#11 token plugged in"))
        if self.slot is not None:
            if self.slot not in slots:
                raise RuntimeError(_("slot {slot} not available (present: {slots})").format(
                    slot=self.slot, slots=slots))
            return self.slot
        return slots[0]

    @staticmethod
    def _make_id(cka_id_hex: str, serial_hex: str) -> str:
        """Compose a CertificateInfo.id that is unique per cert on the token.

        CKA_ID alone is not unique: PKCS#11 allows multiple certs to share an
        ID (e.g. on YubiKey slot 9c, user cert and per-slot attestation cert
        both have CKA_ID=0x02). The cert serial disambiguates.
        """
        return f"{cka_id_hex}:{serial_hex}"

    @staticmethod
    def _parse_id(composite_id: str) -> tuple[bytes, int]:
        cka_id_hex, _, serial_hex = composite_id.partition(":")
        if not cka_id_hex or not serial_hex:
            raise ValueError(_("invalid composite id: {id!r}").format(id=composite_id))
        return bytes.fromhex(cka_id_hex), int(serial_hex, 16)

    def list_certificates(self) -> Sequence[CertificateInfo]:
        """Enumerate certificates on the token without requiring a PIN.

        Most PKCS#11 drivers (including ykcs11 and OpenSC) expose certs as
        public objects, readable without login. Private keys are listed only
        after `unlock()`.
        """
        import PyKCS11

        lib = self._lib()
        slot = self._resolve_slot()
        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
        try:
            cert_handles = session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
            )
            out: list[CertificateInfo] = []
            for h in cert_handles:
                _label, key_id, der = session.getAttributeValue(
                    h, [PyKCS11.CKA_LABEL, PyKCS11.CKA_ID, PyKCS11.CKA_VALUE]
                )
                key_id_hex = bytes(key_id).hex() if key_id else ""
                cert = x509.load_der_x509_certificate(bytes(der))
                serial_hex = format(cert.serial_number, "x")
                out.append(CertificateInfo(
                    id=self._make_id(key_id_hex, serial_hex),
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    serial=serial_hex,
                    not_before=cert.not_valid_before_utc.isoformat(),
                    not_after=cert.not_valid_after_utc.isoformat(),
                ))
            return out
        finally:
            session.closeSession()

    def unlock(self, cert_id: str, secret: str) -> SigningCredential:
        """Open a R/W session, log in with PIN, locate cert + key.

        `cert_id` is the composite id produced by `_make_id` — CKA_ID for the
        private key plus the cert serial number to pick the exact certificate
        when several share the same CKA_ID.
        """
        import PyKCS11

        lib = self._lib()
        slot = self._resolve_slot()
        key_id_bytes, target_serial = self._parse_id(cert_id)

        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        try:
            session.login(secret)
        except Exception:
            session.closeSession()
            raise

        try:
            cert_objs = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_ID, key_id_bytes),
            ])
            cert_der = None
            cert = None
            for obj in cert_objs:
                der = bytes(session.getAttributeValue(obj, [PyKCS11.CKA_VALUE])[0])
                candidate = x509.load_der_x509_certificate(der)
                if candidate.serial_number == target_serial:
                    cert_der = der
                    cert = candidate
                    break
            if cert is None:
                raise RuntimeError(_("certificate {id} not found on token").format(id=cert_id))

            key_objs = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_ID, key_id_bytes),
            ])
            if not key_objs:
                raise RuntimeError(
                    _("private key for {id} not found on token").format(id=cert_id)
                )

            hsm = _PKCS11HSM(session, key_objs[0], cert_der, key_id_bytes)
        except Exception:
            session.logout()
            session.closeSession()
            raise

        self._session = session
        return SigningCredential(certificate=cert, chain=[], hsm=hsm)

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.logout()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass
            self._session.closeSession()
            self._session = None


class FileProvider(CredentialProvider):
    """Certificate + private key loaded from a PKCS#12 (.p12/.pfx) or PEM file.

    A file is treated as a single credential (its `id` is the file path). We
    cannot enumerate its contents without unlocking it, so `list_certificates`
    returns one placeholder entry; full metadata is available after `unlock`.
    """

    SUPPORTED_SUFFIXES = {".p12", ".pfx", ".pem", ".crt"}

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _format(self) -> str:
        suffix = self.path.suffix.lower()
        if suffix in (".p12", ".pfx"):
            return "pkcs12"
        if suffix in (".pem", ".crt"):
            return "pem"
        raise ValueError(_("unsupported extension: {suffix}").format(suffix=suffix))

    def list_certificates(self) -> Sequence[CertificateInfo]:
        return [CertificateInfo(
            id=str(self.path),
            subject=self.path.name,
            issuer=_("(unlock the file to see the details)"),
            serial="",
            not_before="",
            not_after="",
        )]

    def unlock(self, cert_id: str, secret: str) -> SigningCredential:
        data = self.path.read_bytes()
        password = secret.encode() if secret else None
        fmt = self._format()

        if fmt == "pkcs12":
            key, cert, chain = pkcs12.load_key_and_certificates(data, password)
            if key is None or cert is None:
                raise ValueError(_("PKCS#12 has no private key or certificate"))
            return SigningCredential(certificate=cert, chain=chain or [], private_key=key)

        # PEM: may bundle cert + key in one file, or be cert-only with a
        # sibling .key file. We support both.
        cert = x509.load_pem_x509_certificate(data)
        try:
            key = load_pem_private_key(data, password=password)
        except (ValueError, TypeError):
            key_path = self.path.with_suffix(".key")
            if not key_path.exists():
                raise ValueError(
                    _("private key not found in the PEM nor in {name}").format(name=key_path.name)
                )
            key = load_pem_private_key(key_path.read_bytes(), password=password)
        return SigningCredential(certificate=cert, chain=[], private_key=key)
