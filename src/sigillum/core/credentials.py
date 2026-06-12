# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Credential providers: hardware tokens (PKCS#11) and file-based certificates."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
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


# ---------------------------------------------------------------------------
# Cloud Signature Consortium (CSC v2) remote signing
# ---------------------------------------------------------------------------

# Hash names used inside endesive / Sigillum → IETF OIDs the QTSP wants.
_HASH_OID_BY_NAME: dict[str, str] = {
    "sha1":   "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}

# RSA + <hash> → signature-algorithm OID (RFC 8017 PKCS#1 v1.5). Used to
# fill the `signAlgo` field of `/signatures/signHash`.
_RSA_SIGN_OID_BY_HASH: dict[str, str] = {
    "sha1":   "1.2.840.113549.1.1.5",
    "sha256": "1.2.840.113549.1.1.11",
    "sha384": "1.2.840.113549.1.1.12",
    "sha512": "1.2.840.113549.1.1.13",
}

# RSA-PSS (RFC 8017 §8.1) — a single OID, hash and MGF1 hash live in the
# `signAlgoParams` payload alongside `signAlgo`. CSC v2 §11.10 expects a
# base64-DER-encoded `RSASSA-PSS-params` structure there; we pass the
# minimum (mgf=mgf1, hashAlgo=<picked>, saltLength=<digest size>) so the
# QTSP picks the canonical defaults for the chosen hash.
_RSA_PSS_OID = "1.2.840.113549.1.1.10"

# ECDSA + <hash> → signature-algorithm OID (RFC 5480).
_ECDSA_SIGN_OID_BY_HASH: dict[str, str] = {
    "sha1":   "1.2.840.10045.4.1",
    "sha256": "1.2.840.10045.4.3.2",
    "sha384": "1.2.840.10045.4.3.3",
    "sha512": "1.2.840.10045.4.3.4",
}

# RFC 8017 RSA / 5480 ECDSA, plus PSS as exposed by some QTSPs that pre-
# declare the credential is PSS-only (no choice of v1.5 vs PSS at sign
# time). Both raw RSA and PSS map to the same key type, so we tolerate
# either as a key_algo value.
_KEY_ALGO_RSA = "1.2.840.113549.1.1.1"
_KEY_ALGO_RSA_PSS = "1.2.840.113549.1.1.10"
_KEY_ALGO_EC = "1.2.840.10045.2.1"


def _digest(data: bytes, hashalgo: str) -> bytes:
    """Compute the digest of *data* under *hashalgo* (sha1/256/384/512).

    Mirrors the algorithm names endesive uses so signers can stay
    unaware of whether the bytes will be signed locally or via CSC.
    """
    algo = hashalgo.lower()
    h_obj_by_name = {
        "sha1":   hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    h = h_obj_by_name.get(algo)
    if h is None:
        raise ValueError(_("unsupported hash algorithm: {h}").format(h=hashalgo))
    digest = hashes.Hash(h)
    digest.update(data)
    return digest.finalize()


class _RemoteCSCHSM:
    """Adapter exposing endesive's BaseHSM contract over a CSC v2 service.

    endesive calls ``certificate()`` to learn the leaf cert and
    ``sign(keyid, data, hashalgo)`` to sign a SignerInfo blob with a
    given hash. We translate that into:

      1. local digest of *data*
      2. ``/credentials/authorize`` → SAD, paying an OTP each time
      3. ``/signatures/signHash`` → raw signature bytes

    The OTP is obtained lazily through *otp_provider*, a callable
    supplied by the caller (CLI prompt, GUI dialog, ...) — keeping
    the credentials layer free of any UI dependency.
    """

    def __init__(
        self,
        client,                    # CSCClient
        credential_id: str,
        info,                      # CSCCredentialInfo
        cert_der: bytes,
        otp_provider: Callable[[], str],
        pin: str = "",
        prefer_pss: bool = False,
    ) -> None:
        self._client = client
        self._cred_id = credential_id
        self._info = info
        self._cert_der = cert_der
        self._otp_provider = otp_provider
        self._pin = pin
        # Some PAdES baseline profiles require RSA-PSS (B-LTA 2023). When
        # the caller forces it via *prefer_pss* we ask the QTSP for PSS
        # even on credentials advertised as plain RSA.
        self._prefer_pss = prefer_pss

    # ----- BaseHSM contract -----

    def certificate(self):
        # PKCS#11 hands back (keyid, der) — CSC has no keyid concept so
        # we re-use the credentialID, which keeps endesive's debug logs
        # informative without affecting anything functionally.
        return self._cred_id.encode(), self._cert_der

    def sign(self, keyid, data, hashalgo):  # noqa: ARG002 — keyid unused
        h_oid = _HASH_OID_BY_NAME.get(hashalgo.lower())
        if h_oid is None:
            raise ValueError(_("unsupported hash algorithm: {h}").format(h=hashalgo))
        sign_oid = self._sign_algo_oid(hashalgo.lower())

        digest = _digest(data, hashalgo)
        otp = self._otp_provider()
        sad = self._client.authorize(
            self._cred_id, [digest], otp=otp, pin=self._pin,
        )
        sigs = self._client.sign_hash(
            self._cred_id, sad, [digest], h_oid, sign_oid,
        )
        return sigs[0]

    def _sign_algo_oid(self, hashalgo: str) -> str:
        """Pick the QTSP-side signAlgo OID matching this credential's
        key + the requested hash.

        Supports:
          - RSA (key OID 1.2.840.113549.1.1.1): RFC 8017 v1.5
            ``rsa-with-<hash>`` OIDs, or RSA-PSS (1.2.840.113549.1.1.10)
            when ``prefer_pss`` is set or the credential is registered
            as PSS-only at the QTSP.
          - ECDSA (key OID 1.2.840.10045.2.1): RFC 5480
            ``ecdsa-with-<hash>`` OIDs.
        """
        algo = self._info.key_algo
        if algo == _KEY_ALGO_RSA:
            if self._prefer_pss:
                return _RSA_PSS_OID
            oid = _RSA_SIGN_OID_BY_HASH.get(hashalgo)
            if oid is None:
                raise ValueError(_("unsupported RSA+{h} combination").format(h=hashalgo))
            return oid
        if algo == _KEY_ALGO_RSA_PSS:
            return _RSA_PSS_OID
        if algo == _KEY_ALGO_EC:
            oid = _ECDSA_SIGN_OID_BY_HASH.get(hashalgo)
            if oid is None:
                raise ValueError(_("unsupported ECDSA+{h} combination").format(h=hashalgo))
            return oid
        raise NotImplementedError(_(
            "key algorithm not yet supported by the CSC adapter: {algo}"
        ).format(algo=algo))


class RemoteCSCProvider(CredentialProvider):
    """Credentials hosted by a CSC v2-compliant QTSP (firma qualificata remota).

    Sigillum never sees the private key — every signature round-trips
    to the QTSP, authorised by a fresh SAD (one OTP per signing call).
    See :class:`_RemoteCSCHSM` for the wire format.

    *otp_provider* is called every time the signer requests a signature
    on a hash. Supply a CLI prompt or a GUI dialog from the caller.
    """

    def __init__(
        self,
        client,                    # CSCClient
        otp_provider: Callable[[], str],
        pin: str = "",
        prefer_pss: bool = False,
    ) -> None:
        self._client = client
        self._otp_provider = otp_provider
        self._pin = pin
        self._prefer_pss = prefer_pss

    def list_certificates(self) -> Sequence[CertificateInfo]:
        out: list[CertificateInfo] = []
        for cred_id in self._client.list_credentials():
            try:
                info = self._client.credential_info(cred_id)
                leaf_pem = info.cert_chain_pem[0].encode()
                cert = x509.load_pem_x509_certificate(leaf_pem)
            except Exception:  # noqa: BLE001 — skip the broken credential
                continue
            out.append(CertificateInfo(
                id=cred_id,
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial=format(cert.serial_number, "x"),
                not_before=cert.not_valid_before_utc.isoformat(),
                not_after=cert.not_valid_after_utc.isoformat(),
            ))
        return out

    def unlock(self, cert_id: str, secret: str) -> SigningCredential:
        """Resolve a remote credential into a :class:`SigningCredential`.

        *secret* is unused for CSC: the per-signature OTP is collected
        lazily via *otp_provider* (set at construction). When the QTSP
        also requires a long-term PIN alongside the OTP, set it via
        the ``pin=`` argument of the provider constructor.
        """
        del secret  # CSC has no static credential password
        info = self._client.credential_info(cert_id)
        if not info.cert_chain_pem:
            raise ValueError(_("CSC credential {id} returned an empty chain").format(id=cert_id))

        leaf = x509.load_pem_x509_certificate(info.cert_chain_pem[0].encode())
        chain = [
            x509.load_pem_x509_certificate(pem.encode())
            for pem in info.cert_chain_pem[1:]
        ]
        cert_der = leaf.public_bytes(Encoding.DER)
        hsm = _RemoteCSCHSM(
            client=self._client,
            credential_id=cert_id,
            info=info,
            cert_der=cert_der,
            otp_provider=self._otp_provider,
            pin=self._pin,
            prefer_pss=self._prefer_pss,
        )
        return SigningCredential(certificate=leaf, chain=chain, hsm=hsm)
