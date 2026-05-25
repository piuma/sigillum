# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Verifier abstractions for signed artifacts."""
from __future__ import annotations

import contextlib
import base64
import copy
import hashlib
import os
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ..i18n import _

try:
    from cryptography.utils import CryptographyDeprecationWarning
except ImportError:  # pragma: no cover — defensive, very old cryptography
    CryptographyDeprecationWarning = DeprecationWarning  # type: ignore[assignment]


@contextlib.contextmanager
def _silenced():
    """Silence noisy chatter that endesive emits during verification.

    endesive uses bare `print()` for diagnostic messages (the `**********`
    banners on cert validation failures), and loading certifi's CA bundle
    triggers CryptographyDeprecationWarning for certs with non-positive
    serials. Neither indicates a problem in our code, but both clutter the
    UI. This context manager redirects stdout to /dev/null and filters the
    crypto warning during the wrapped block.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
        with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
            yield


def _verify_cert_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trusted_roots: list[x509.Certificate],
) -> bool:
    """Walk a cert path from `leaf` to a trusted root, verifying each step.

    We use `Certificate.verify_directly_issued_by` so signatures are checked
    cryptographically (not just name-matched). cryptography's `PolicyBuilder`
    verifiers are TLS-specific (require SAN / hostname / EKU) — unsuitable for
    document-signing or TSA certs, which is why we walk manually.
    """
    if not trusted_roots:
        return False
    trusted_fps = {c.fingerprint(hashes.SHA256()) for c in trusted_roots}
    candidates = list(intermediates) + list(trusted_roots)

    current = leaf
    seen: set[bytes] = set()
    while True:
        if current.fingerprint(hashes.SHA256()) in trusted_fps:
            return True
        if current.fingerprint(hashes.SHA256()) in seen:
            return False  # cycle
        seen.add(current.fingerprint(hashes.SHA256()))

        issuer = None
        for candidate in candidates:
            try:
                current.verify_directly_issued_by(candidate)
            except Exception:  # noqa: BLE001 — try next candidate on any failure
                continue
            issuer = candidate
            break
        if issuer is None:
            return False
        current = issuer


def _verify_timestamp(
    tspdata,
    signer_signature_bytes: bytes,
    tsa_trusted_certs: list[x509.Certificate],
    info: SignerInfo,
) -> None:
    """Populate timestamp-related fields on `info` from a TSA token.

    Sets `timestamp`, `tsa_subject`, and `timestamp_trusted`. The token is
    considered trusted only when:
      1. TSTInfo is parseable and `gen_time` is present
      2. The TSA's CMS signature on TSTInfo verifies cryptographically
      3. `message_imprint` equals SHA-256 of the signer's signature bytes
      4. The TSA cert chains up to a configured TSA trust root
    """
    if tspdata is None:
        return

    try:
        if tspdata["encap_content_info"]["content_type"].native != "tst_info":
            return
        tst = tspdata["encap_content_info"]["content"].parsed
        info.timestamp = tst["gen_time"].native
    except Exception as ex:  # noqa: BLE001
        info.errors.append(_("TSTInfo parsing failed: {ex}").format(ex=ex))
        return

    # Find TSA's signing cert + intermediates in the timestamp's SignedData.
    from cryptography.x509 import load_der_x509_certificate

    try:
        signer_info_t = tspdata["signer_infos"][0]
        sid_serial = signer_info_t["sid"].native["serial_number"]
    except Exception as ex:  # noqa: BLE001
        info.errors.append(_("TSA signer_info not readable: {ex}").format(ex=ex))
        return

    tsa_cert = None
    tsa_chain: list[x509.Certificate] = []
    for asn1cert in tspdata["certificates"]:
        der = asn1cert.chosen.dump()
        cert = load_der_x509_certificate(der)
        if asn1cert.native["tbs_certificate"]["serial_number"] == sid_serial:
            tsa_cert = cert
        else:
            tsa_chain.append(cert)
    if tsa_cert is None:
        info.errors.append(_("TSA certificate is not present in the token"))
        return
    info.tsa_subject = tsa_cert.subject.rfc4514_string()

    # Re-use endesive's CMS verifier on the timestamp's SignedData. It expects
    # `datau` to be the encapsulated content for detached cases; for TST tokens
    # the SignedData is structured exactly like ours, so we can call decompose
    # via PDFVerifier (the helper is stateless w.r.t. PDF specifics here).
    try:
        from endesive.pdf.verify import PDFVerifier
        with _silenced():
            pv = PDFVerifier(b"%PDF-1.4\n%%EOF\n")  # stub; only decompose is used
            (_, _, _, _tcert, _tothercerts, _hashok, tsa_sig_ok) = (
                pv.decompose_signed_data(b"", tspdata)
            )
    except Exception as ex:  # noqa: BLE001
        info.errors.append(_("TSA signature verification failed: {ex}").format(ex=ex))
        return

    if not tsa_sig_ok:
        info.errors.append(_("TSA signature on TSTInfo is not valid"))
        return

    # Check message_imprint covers the user signature.
    try:
        algo = tst["message_imprint"]["hash_algorithm"]["algorithm"].native
        expected = hashlib.new(algo, signer_signature_bytes).digest()
        actual = tst["message_imprint"]["hashed_message"].native
    except Exception as ex:  # noqa: BLE001
        info.errors.append(_("message_imprint not readable: {ex}").format(ex=ex))
        return
    if expected != actual:
        info.errors.append(
            _("timestamp message_imprint does not match the signature")
        )
        return

    # Chain the TSA cert up to a configured TSA root.
    if _verify_cert_chain(tsa_cert, tsa_chain, tsa_trusted_certs):
        info.timestamp_trusted = True
    else:
        info.errors.append(_("TSA certificate cannot be chained to a trusted root"))


@dataclass
class SignerInfo:
    """Result for a single signature inside a document.

    Three independent flags map directly to the booleans returned by
    `endesive.verifier.verify`:
      - `hash_valid`:      message-digest covers the signed bytes
      - `signature_valid`: cryptographic signature checks out with the cert
      - `cert_trusted`:    cert chain validates against the trust store

    For -T signatures (with TSA), three more describe the timestamp:
      - `timestamp`:         the TSA `gen_time` (None if no TSA present)
      - `tsa_subject`:       the TSA's signing cert subject (RFC 4514)
      - `timestamp_trusted`: full TSA verification — signature on TSTInfo OK,
                             message_imprint covers the signer's signature,
                             and the TSA cert chains up to a trusted TSA root.

    `valid` is True only when the signature chain is fully trusted. A timestamp
    is *informational unless* `timestamp_trusted` is True.
    """
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    signing_time: datetime | None = None
    timestamp: datetime | None = None
    tsa_subject: str = ""
    hash_valid: bool = False
    signature_valid: bool = False
    cert_trusted: bool = False
    timestamp_trusted: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.hash_valid and self.signature_valid and self.cert_trusted


@dataclass
class VerifyResult:
    """Outcome of verifying a signed document.

    A document can have multiple signatures (controfirme / firme parallele):
    `signers` contains one entry per signature found.
    """
    signers: list[SignerInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return bool(self.signers) and all(s.valid for s in self.signers)


class Verifier(ABC):
    """Verify a signed artifact.

    `trusted_certs` extends the trust store used to validate the SIGNER's
    cert (certifi roots + these). `tsa_trusted_certs` is a separate trust
    store used only for validating the timestamp's TSA cert chain — typical
    deployment keeps the two completely separate (signer roots come from
    AgID/EUTL, TSA roots are explicitly enrolled by the user).
    """

    def __init__(
        self,
        trusted_certs: Sequence[x509.Certificate] | None = None,
        tsa_trusted_certs: Sequence[x509.Certificate] | None = None,
    ):
        self.trusted_certs = list(trusted_certs or [])
        self.tsa_trusted_certs = list(tsa_trusted_certs or [])

    @abstractmethod
    def verify(self, path: Path, original_path: Path | None = None) -> VerifyResult:
        """Verify a signed artifact.

        `original_path` is only consulted for detached signatures (typically
        CAdES detached); for PAdES it is ignored.
        """


class PAdESVerifier(Verifier):
    def verify(self, path: Path, original_path: Path | None = None) -> VerifyResult:
        del original_path  # PAdES signatures are always self-contained
        from endesive.pdf import verify as pdfverify
        from endesive.pdf.verify import PDFVerifier

        pdf_data = path.read_bytes()
        trusted_pem = [c.public_bytes(serialization.Encoding.PEM) for c in self.trusted_certs]

        with _silenced():
            results = pdfverify(pdf_data, trusted_pem or None)
            pv = PDFVerifier(pdf_data, trustedCerts=trusted_pem or None)
            pv.is_signed()  # populates pv.byte_ranges

        # Snapshot byte_ranges so we can re-point PDFVerifier at each one in turn.
        all_ranges = list(pv.byte_ranges)
        signers: list[SignerInfo] = []
        for idx, (hash_ok, sig_ok, _endesive_cert_ok) in enumerate(results):
            # `_endesive_cert_ok` comes from endesive's PolicyBuilder().build_client_verifier()
            # which is TLS-specific and rejects perfectly valid Italian qualified
            # signing certs that lack subjectAltName. We compute cert_trusted with
            # our own chain walker instead (same logic already used for TSA certs).
            info = SignerInfo(
                hash_valid=bool(hash_ok),
                signature_valid=bool(sig_ok),
            )
            try:
                pv.byte_ranges = [all_ranges[idx]]
                with _silenced():
                    decomposed = pv.decompose_signature()
                if decomposed:
                    signed_data, tspdata, _, cert, othercerts, _, _ = decomposed
                    info.subject = cert.subject.rfc4514_string()
                    info.issuer = cert.issuer.rfc4514_string()
                    info.serial = format(cert.serial_number, "x")
                    info.cert_trusted = _verify_cert_chain(
                        cert, list(othercerts or []), self.trusted_certs,
                    )
                    if tspdata is not None:
                        sig_bytes = signed_data["signer_infos"][0]["signature"].native
                        _verify_timestamp(
                            tspdata, sig_bytes, self.tsa_trusted_certs, info,
                        )
            except Exception as ex:  # noqa: BLE001 — surface as soft error
                info.errors.append(_("could not decode the certificate: {ex}").format(ex=ex))
            signers.append(info)

        return VerifyResult(signers=signers)


class CAdESVerifier(Verifier):
    """Verify CMS / CAdES signatures (.p7m).

    Supports both modes:
      - enveloping (attached, typical Italian .p7m): content is embedded
      - detached: caller supplies the original file via `original_path`
    """

    def verify(self, path: Path, original_path: Path | None = None) -> VerifyResult:
        from asn1crypto import cms as asn1cms, core
        from cryptography.x509 import load_der_x509_certificate
        from endesive import verifier as endesive_verifier

        p7m_bytes = path.read_bytes()
        ci = asn1cms.ContentInfo.load(p7m_bytes)
        signed_data = ci["content"]

        # Resolve the signed content: prefer embedded, fall back to external.
        encap = signed_data["encap_content_info"]
        embedded = encap["content"]
        if embedded is not None and embedded.contents:
            datau = embedded.native if isinstance(embedded.native, bytes) else bytes(embedded)
        elif original_path is not None:
            datau = original_path.read_bytes()
        else:
            return VerifyResult(
                errors=[_("detached signature: the original file is required (original_path)")],
            )

        trusted_pem = [
            c.public_bytes(serialization.Encoding.PEM) for c in self.trusted_certs
        ] or None

        # endesive's CMS verifier returns one result per call; multi-signer
        # CAdES is left as future work.
        signer_info = signed_data["signer_infos"][0]
        info = SignerInfo()
        leaf_cert: x509.Certificate | None = None
        other_certs: list[x509.Certificate] = []
        try:
            serial = signer_info["sid"].native["serial_number"]
            for asn1cert in signed_data["certificates"]:
                der = asn1cert.chosen.dump()
                cc = load_der_x509_certificate(der)
                if asn1cert.native["tbs_certificate"]["serial_number"] == serial:
                    leaf_cert = cc
                    info.subject = cc.subject.rfc4514_string()
                    info.issuer = cc.issuer.rfc4514_string()
                    info.serial = format(cc.serial_number, "x")
                else:
                    other_certs.append(cc)
        except Exception as ex:  # noqa: BLE001
            info.errors.append(_("could not decode the certificate: {ex}").format(ex=ex))

        try:
            with _silenced():
                hash_ok, sig_ok, _endesive_cert_ok = endesive_verifier.verify(
                    p7m_bytes, datau, trusted_pem
                )
            info.hash_valid = bool(hash_ok)
            info.signature_valid = bool(sig_ok)
            # `_endesive_cert_ok` uses build_client_verifier() which requires SAN on
            # the leaf — Italian qualified signing certs typically don't have SAN,
            # so we recompute cert_trusted with our own chain walker.
            if leaf_cert is not None:
                info.cert_trusted = _verify_cert_chain(
                    leaf_cert, other_certs, self.trusted_certs,
                )
        except Exception as ex:  # noqa: BLE001
            info.errors.append(_("verification failed: {ex}").format(ex=ex))

        # Verify the timestamp token if present.
        unsigned = signer_info["unsigned_attrs"]
        if unsigned is not None and not isinstance(unsigned, core.Void):
            for attr in unsigned:
                if attr["type"].native != "signature_time_stamp_token":
                    continue
                for value in attr["values"]:
                    if value["content_type"].native == "signed_data":
                        sig_bytes = signer_info["signature"].native
                        _verify_timestamp(
                            value["content"], sig_bytes,
                            self.tsa_trusted_certs, info,
                        )
                        break
                if info.timestamp:
                    break

        return VerifyResult(signers=[info])


class XAdESVerifier(Verifier):
    """Verify XAdES/XMLDSig enveloped signatures inside .xml documents."""

    def verify(self, path: Path, original_path: Path | None = None) -> VerifyResult:
        del original_path  # XAdES enveloped signatures are self-contained
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from lxml import etree

        xml_bytes = path.read_bytes()
        info = SignerInfo()
        leaf = None
        intermediates: list[x509.Certificate] = []

        try:
            root = etree.fromstring(xml_bytes)
            cert_nodes = root.xpath("//*[local-name()='X509Certificate']/text()")
            if not cert_nodes:
                return VerifyResult(errors=[_("no X.509 certificate found in the XML signature")])

            chain: list[x509.Certificate] = []
            for b64_cert in cert_nodes:
                der = base64.b64decode("".join(b64_cert.split()))
                chain.append(load_der_x509_certificate(der))

            leaf = chain[0]
            intermediates = chain[1:]
            info.subject = leaf.subject.rfc4514_string()
            info.issuer = leaf.issuer.rfc4514_string()
            info.serial = format(leaf.serial_number, "x")
        except Exception as ex:  # noqa: BLE001
            return VerifyResult(errors=[_("XML signature not readable: {ex}").format(ex=ex)])

        try:
            signature = root.xpath("//*[local-name()='Signature']")
            if not signature:
                return VerifyResult(errors=[_("XML signature not found (no ds:Signature)")])
            signature = signature[0]

            signed_info = signature.xpath("./*[local-name()='SignedInfo']")
            if not signed_info:
                return VerifyResult(errors=[_("SignedInfo missing in the XML signature")])
            signed_info = signed_info[0]

            refs = signed_info.xpath("./*[local-name()='Reference']")
            digest_map = {}
            for ref in refs:
                uri = ref.get("URI", "")
                digest_nodes = ref.xpath("./*[local-name()='DigestValue']/text()")
                if digest_nodes:
                    digest_map[uri] = "".join(digest_nodes[0].split())

            if "" not in digest_map:
                info.errors.append(_("missing document reference"))
            else:
                root_wo_sig = copy.deepcopy(root)
                for sig in root_wo_sig.xpath("//*[local-name()='Signature']"):
                    parent = sig.getparent()
                    if parent is not None:
                        parent.remove(sig)
                digest_doc = base64.b64encode(hashlib.sha256(
                    etree.tostring(root_wo_sig, method="c14n")
                ).digest()).decode()
                if digest_doc != digest_map[""]:
                    info.errors.append(_("invalid document digest"))

            sp_nodes = root.xpath("//*[local-name()='SignedProperties']")
            if not sp_nodes:
                info.errors.append(_("SignedProperties missing"))
            else:
                sp = sp_nodes[0]
                sp_id = sp.get("Id")
                if sp_id:
                    sp_uri = f"#{sp_id}"
                    expected = digest_map.get(sp_uri)
                    if expected is None:
                        info.errors.append(_("missing reference to SignedProperties"))
                    else:
                        digest_sp = base64.b64encode(hashlib.sha256(
                            etree.tostring(sp, method="c14n")
                        ).digest()).decode()
                        if digest_sp != expected:
                            info.errors.append(_("invalid SignedProperties digest"))

            info.hash_valid = not any(
                "digest" in err.lower() or "reference" in err.lower()
                for err in info.errors
            )

            sig_method_nodes = signed_info.xpath("./*[local-name()='SignatureMethod']")
            method = ""
            if sig_method_nodes:
                method = sig_method_nodes[0].get("Algorithm", "")

            hash_algo = hashes.SHA256()
            if method.endswith("rsa-sha1"):
                hash_algo = hashes.SHA1()
            elif method.endswith("rsa-sha384"):
                hash_algo = hashes.SHA384()
            elif method.endswith("rsa-sha512"):
                hash_algo = hashes.SHA512()

            sig_value_nodes = signature.xpath("./*[local-name()='SignatureValue']/text()")
            if not sig_value_nodes:
                info.errors.append(_("SignatureValue missing"))
            else:
                sig_value = base64.b64decode("".join(sig_value_nodes[0].split()))
                signed_info_c14n = etree.tostring(signed_info, method="c14n")
                pub = leaf.public_key()
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(sig_value, signed_info_c14n, padding.PKCS1v15(), hash_algo)
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(sig_value, signed_info_c14n, ec.ECDSA(hash_algo))
                else:
                    raise ValueError(_("unsupported public key algorithm"))
                info.signature_valid = True
        except Exception as ex:  # noqa: BLE001
            info.signature_valid = False
            info.errors.append(_("XAdES cryptographic verification failed: {ex}").format(ex=ex))

        info.cert_trusted = _verify_cert_chain(leaf, intermediates, self.trusted_certs)
        if self.trusted_certs and not info.cert_trusted:
            info.errors.append(_("signer certificate chain is not trusted"))

        return VerifyResult(signers=[info])
