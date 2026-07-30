# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Was the signer's certificate revoked?

`lt.py` collects OCSP responses and CRLs *at signing time* and embeds them in
the signature (CAdES unsigned attrs) or in the PDF (`/DSS`). That material is
the whole point of an LT signature — and until now nothing read it back. A
certificate revoked for key compromise still verified as trusted, because
chain building says nothing about revocation.

This module answers the question from three sources, in order of preference:

1. **embedded** OCSP responses / CRLs — offline, and the only source that
   still works years later when the responder is long gone;
2. **live** OCSP over AIA, then a CRL over CRL-DP (opt-in: it phones home);
3. nothing — reported as `unavailable` rather than silently as good.

Embedded material is signed data that travels *inside the signature*, so it is
as attacker-controlled as the signature itself: every response is verified
against the issuing CA before its verdict is believed. Material that fails
that check is discarded, not trusted.

References: RFC 6960 (OCSP), RFC 5280 §5 (CRLs), ETSI EN 319 102-1 §5.2.5
(revocation freshness checking in signature validation).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from ..i18n import _

# A CRL from an Italian QTSP can be tens of megabytes; refuse to swallow one
# unbounded just because a verification asked for a live check.
_MAX_CRL_BYTES = 20 * 1024 * 1024

# Revocation reasons that invalidate a signature no matter when it was made:
# if the key was in someone else's hands, a timestamp proves only that the
# forgery is old.
_COMPROMISE_REASONS = frozenset({"key_compromise", "ca_compromise", "aa_compromise"})


class RevocationStatus(str, Enum):
    NOT_CHECKED = "not-checked"   # no material embedded and no live check asked
    GOOD = "good"                 # a verified response says the cert is fine
    REVOKED = "revoked"           # a verified response says it is revoked
    UNKNOWN = "unknown"           # the responder does not know this cert
    UNAVAILABLE = "unavailable"   # we could not find out — not a verdict


@dataclass
class RevocationInfo:
    """Outcome of a revocation check for one certificate."""
    status: RevocationStatus = RevocationStatus.NOT_CHECKED
    source: str = ""                    # embedded-ocsp | embedded-crl | ocsp | crl
    revoked_at: datetime | None = None
    reason: str = ""
    produced_at: datetime | None = None  # when the responder issued the answer
    detail: str = ""

    @property
    def compromise(self) -> bool:
        """Revocation for a compromise, i.e. retroactive."""
        return self.reason in _COMPROMISE_REASONS

    def describe(self) -> str:
        if self.status is RevocationStatus.REVOKED:
            when = self.revoked_at.isoformat() if self.revoked_at else _("unknown date")
            if self.reason:
                return _("REVOKED on {when} ({reason})").format(when=when, reason=self.reason)
            return _("REVOKED on {when}").format(when=when)
        if self.status is RevocationStatus.GOOD:
            when = self.produced_at.isoformat() if self.produced_at else ""
            return _("not revoked ({source}{when})").format(
                source=self.source, when=f", {when}" if when else "")
        if self.status is RevocationStatus.UNKNOWN:
            return _("responder does not know this certificate ({source})").format(
                source=self.source)
        if self.status is RevocationStatus.UNAVAILABLE:
            return _("could not be checked{detail}").format(
                detail=f": {self.detail}" if self.detail else "")
        return _("not checked")


def check_certificate(
    leaf: x509.Certificate,
    issuer: x509.Certificate | None,
    *,
    ocsp_blobs: Sequence[bytes] = (),
    crl_blobs: Sequence[bytes] = (),
    live: bool = False,
    timeout: float = 10.0,
) -> RevocationInfo:
    """Decide whether `leaf` is revoked.

    `ocsp_blobs` / `crl_blobs` are DER blobs pulled out of the signature (CAdES
    `RevocationValues`, PAdES `/DSS`, XAdES `xades:RevocationValues`). OCSP
    blobs may be either a full `OCSPResponse` or a bare `BasicOCSPResponse` —
    both shapes occur in the wild, and `load_ocsp_response` takes either.

    With no material and `live=False` the answer is `NOT_CHECKED`: silence,
    rather than a claim we did not earn.
    """
    unmatched = False

    for blob in ocsp_blobs:
        info = _from_ocsp(blob, leaf, issuer, source="embedded-ocsp")
        if info is None:
            unmatched = True
            continue
        if info.status in (RevocationStatus.REVOKED, RevocationStatus.GOOD):
            return info
        unmatched = True

    for blob in crl_blobs:
        info = _from_crl(blob, leaf, issuer, source="embedded-crl")
        if info is None:
            unmatched = True
            continue
        return info

    if live:
        from .lt import fetch_ocsp

        if issuer is not None:
            der = fetch_ocsp(leaf, issuer, timeout=timeout)
            if der is not None:
                info = _from_ocsp(der, leaf, issuer, source="ocsp")
                if info is not None and info.status is not RevocationStatus.UNAVAILABLE:
                    return info
        crl_der = _fetch_crl(leaf, timeout=timeout)
        if crl_der is not None:
            info = _from_crl(crl_der, leaf, issuer, source="crl")
            if info is not None:
                return info
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE,
            detail=_("no responder answered (OCSP and CRL both unavailable)"),
        )

    if unmatched:
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE,
            detail=_("the embedded validation data does not cover this certificate"),
        )
    return RevocationInfo()


# ---------------------------------------------------------------------------
# OCSP
# ---------------------------------------------------------------------------

def load_ocsp_response(blob: bytes) -> crypto_ocsp.OCSPResponse | None:
    """Load a DER `OCSPResponse`, accepting a bare `BasicOCSPResponse` too.

    RFC 5126 stores `BasicOCSPResponse` in CAdES `RevocationValues`, while
    PAdES `/DSS` and live responders hand out a full `OCSPResponse`. Wrapping
    the former lets one code path read both.
    """
    if not blob:
        return None
    try:
        return crypto_ocsp.load_der_ocsp_response(blob)
    except Exception:  # noqa: BLE001 — try the bare BasicOCSPResponse shape
        pass
    try:
        from asn1crypto import core, ocsp as asn1_ocsp

        basic = asn1_ocsp.BasicOCSPResponse.load(blob)
        basic["tbs_response_data"]["responses"][0]  # force parsing  # noqa: B018
        # The payload has to go in as a ParsableOctetString: handed raw bytes,
        # asn1crypto tries to build a BasicOCSPResponse *from* them as a dict.
        wrapped = asn1_ocsp.OCSPResponse({
            "response_status": "successful",
            "response_bytes": {
                "response_type": "basic_ocsp_response",
                "response": core.ParsableOctetString(basic.dump()),
            },
        })
        return crypto_ocsp.load_der_ocsp_response(wrapped.dump())
    except Exception:  # noqa: BLE001 — not an OCSP response at all
        return None


def _from_ocsp(
    blob: bytes,
    leaf: x509.Certificate,
    issuer: x509.Certificate | None,
    *,
    source: str,
) -> RevocationInfo | None:
    """Read one OCSP response. None when it does not concern `leaf`."""
    resp = load_ocsp_response(blob)
    if resp is None:
        return None
    if resp.response_status is not crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return None
    try:
        if resp.serial_number != leaf.serial_number:
            return None
    except Exception:  # noqa: BLE001 — multi-response tokens aren't readable here
        return None

    if issuer is not None and not _matches_issuer(resp, issuer):
        return None
    if issuer is None:
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE, source=source,
            detail=_("issuer certificate unavailable, response not verifiable"),
        )
    if not _ocsp_signature_ok(resp, issuer):
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE, source=source,
            detail=_("the OCSP response is not signed by the issuing CA"),
        )

    produced_at = _utc(resp, "produced_at")
    if resp.certificate_status is crypto_ocsp.OCSPCertStatus.REVOKED:
        return RevocationInfo(
            status=RevocationStatus.REVOKED, source=source,
            revoked_at=_utc(resp, "revocation_time"),
            reason=resp.revocation_reason.name if resp.revocation_reason else "",
            produced_at=produced_at,
        )
    if resp.certificate_status is crypto_ocsp.OCSPCertStatus.GOOD:
        return RevocationInfo(
            status=RevocationStatus.GOOD, source=source, produced_at=produced_at,
        )
    return RevocationInfo(
        status=RevocationStatus.UNKNOWN, source=source, produced_at=produced_at,
    )


def _matches_issuer(resp: crypto_ocsp.OCSPResponse, issuer: x509.Certificate) -> bool:
    """Check the response's CertID issuer name hash against `issuer`.

    Serial numbers are only unique per issuer, so a serial match alone would
    accept a response about a different CA's certificate.
    """
    try:
        algorithm = resp.hash_algorithm
        expected = hashes.Hash(algorithm)
        expected.update(issuer.subject.public_bytes())
        return expected.finalize() == resp.issuer_name_hash
    except Exception:  # noqa: BLE001 — unsupported hash: fall back to the serial
        return True


def _ocsp_signature_ok(
    resp: crypto_ocsp.OCSPResponse, issuer: x509.Certificate,
) -> bool:
    """Verify the response signature, by the CA itself or a delegated responder."""
    candidates: list[x509.Certificate] = [issuer]
    try:
        candidates.extend(resp.certificates)
    except Exception:  # noqa: BLE001 — no embedded responder cert
        pass

    for candidate in candidates:
        if candidate is not issuer and not _is_delegated_responder(candidate, issuer):
            continue
        if _signature_ok(candidate, resp):
            return True
    return False


def _is_delegated_responder(
    candidate: x509.Certificate, issuer: x509.Certificate,
) -> bool:
    """RFC 6960 §4.2.2.2: a responder delegated by the CA that issued the cert."""
    try:
        candidate.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001
        return False
    try:
        eku = candidate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku


def _signature_ok(cert: x509.Certificate, resp: crypto_ocsp.OCSPResponse) -> bool:
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                resp.signature, resp.tbs_response_bytes,
                padding.PKCS1v15(), resp.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                resp.signature, resp.tbs_response_bytes,
                ec.ECDSA(resp.signature_hash_algorithm),
            )
        else:
            return False
    except Exception:  # noqa: BLE001 — bad signature or unsupported params
        return False
    return True


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------

def _from_crl(
    blob: bytes,
    leaf: x509.Certificate,
    issuer: x509.Certificate | None,
    *,
    source: str,
) -> RevocationInfo | None:
    """Read one CRL. None when it does not apply to `leaf`."""
    crl = _load_crl(blob)
    if crl is None or crl.issuer != leaf.issuer:
        return None
    if issuer is not None and not crl.is_signature_valid(issuer.public_key()):
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE, source=source,
            detail=_("the CRL is not signed by the issuing CA"),
        )
    if issuer is None:
        return RevocationInfo(
            status=RevocationStatus.UNAVAILABLE, source=source,
            detail=_("issuer certificate unavailable, CRL not verifiable"),
        )

    last_update = _utc(crl, "last_update")
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is None:
        return RevocationInfo(
            status=RevocationStatus.GOOD, source=source, produced_at=last_update,
        )
    reason = ""
    try:
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        pass
    return RevocationInfo(
        status=RevocationStatus.REVOKED, source=source,
        revoked_at=_utc(entry, "revocation_date"), reason=reason,
        produced_at=last_update,
    )


def _load_crl(blob: bytes) -> x509.CertificateRevocationList | None:
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(blob)
        except Exception:  # noqa: BLE001 — try the other encoding
            continue
    return None


def _fetch_crl(leaf: x509.Certificate, *, timeout: float) -> bytes | None:
    """Download the first usable CRL listed in CRL Distribution Points."""
    try:
        dps = leaf.extensions.get_extension_for_class(
            x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None

    for dp in dps:
        for name in dp.full_name or []:
            url = getattr(name, "value", "")
            if not url.startswith(("http://", "https://")):
                continue
            try:
                with requests.get(url, timeout=timeout, stream=True) as resp:
                    if resp.status_code != 200:
                        continue
                    body = bytearray()
                    for chunk in resp.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > _MAX_CRL_BYTES:
                            return None  # refuse to buffer an unbounded CRL
                    return bytes(body)
            except requests.RequestException:
                continue
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc(obj, name: str) -> datetime | None:
    """Read `<name>_utc` when present, else the naive `<name>` as UTC.

    cryptography added the timezone-aware `*_utc` properties in 42 and
    deprecated the naive ones; supporting both keeps this working across the
    versions distributions actually ship.
    """
    value = getattr(obj, f"{name}_utc", None)
    if value is None:
        value = getattr(obj, name, None)
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def find_issuer(
    leaf: x509.Certificate, candidates: Sequence[x509.Certificate],
) -> x509.Certificate | None:
    """Pick the certificate in `candidates` that actually issued `leaf`."""
    for candidate in candidates:
        try:
            leaf.verify_directly_issued_by(candidate)
            return candidate
        except Exception:  # noqa: BLE001 — not the issuer, keep looking
            continue
    return None


def issuer_from_ocsp_material(
    leaf: x509.Certificate, blobs: Sequence[bytes],
) -> x509.Certificate | None:
    """Last resort: pull the issuer out of certs embedded in OCSP responses."""
    for blob in blobs:
        resp = load_ocsp_response(blob)
        if resp is None:
            continue
        try:
            found = find_issuer(leaf, list(resp.certificates))
        except Exception:  # noqa: BLE001
            continue
        if found is not None:
            return found
    return None
