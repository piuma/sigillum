# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""ETSI Long-Term (LT) validation material for CMS-based signatures.

LT extends a T-level signature by embedding everything an offline verifier
needs to check the signature *years later*, when the original CA might be
gone or the cert expired:

  - **CertificateValues** — the full cert chain (signer + intermediates +
    root) and the TSA chain. Saved as id-aa-ets-certValues unsigned attr
    (OID 1.2.840.113549.1.9.16.2.23).
  - **RevocationValues** — OCSP responses (and/or CRLs) for every cert in
    the chain, *captured at signing time*. Saved as id-aa-ets-revocationValues
    unsigned attr (OID 1.2.840.113549.1.9.16.2.24).

We only build the post-processing logic here: the signing itself happens at
T-level via endesive, then `add_lt_attributes()` re-encodes the CMS with
the two new unsigned attributes.

References: RFC 5126 (CAdES) and ETSI TS 119 122-2.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Sequence

import requests
from asn1crypto import cms, core, crl as asn1_crl, ocsp as asn1_ocsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    AuthorityInformationAccess,
    ExtensionNotFound,
)

from ..i18n import _
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509 import ocsp as crypto_ocsp


# ---------------------------------------------------------------------------
# ASN.1 definitions for the two ETSI LT unsigned attributes.
# RFC 5126 / ETSI TS 119 122-2.
# ---------------------------------------------------------------------------

class CertificateValues(core.SequenceOf):
    _child_spec = asn1_x509.Certificate


class _OtherRevVals(core.Sequence):
    _fields = [
        ("other_rev_val_type", core.ObjectIdentifier),
        ("other_rev_vals", core.Any),
    ]


class _CrlValues(core.SequenceOf):
    _child_spec = asn1_crl.CertificateList


class _OcspValues(core.SequenceOf):
    _child_spec = asn1_ocsp.BasicOCSPResponse


class RevocationValues(core.Sequence):
    _fields = [
        ("crl_vals", _CrlValues, {"explicit": 0, "optional": True}),
        ("ocsp_vals", _OcspValues, {"explicit": 1, "optional": True}),
        ("other_rev_vals", _OtherRevVals, {"explicit": 2, "optional": True}),
    ]


# CMSAttribute.values is a SET OF, so we need to register a SetOf class
# (not the inner type directly) — same pattern as `signature_time_stamp_token`
# which registers SetOfContentInfo.
class _SetOfCertificateValues(core.SetOf):
    _child_spec = CertificateValues


class _SetOfRevocationValues(core.SetOf):
    _child_spec = RevocationValues


_CERT_VALUES_OID = "1.2.840.113549.1.9.16.2.23"
_REVOCATION_VALUES_OID = "1.2.840.113549.1.9.16.2.24"

cms.CMSAttributeType._map[_CERT_VALUES_OID] = "certificate_values"
cms.CMSAttributeType._map[_REVOCATION_VALUES_OID] = "revocation_values"
cms.CMSAttribute._oid_specs["certificate_values"] = _SetOfCertificateValues
cms.CMSAttribute._oid_specs["revocation_values"] = _SetOfRevocationValues


# ---------------------------------------------------------------------------
# AIA helpers: pull URLs out of cert extensions
# ---------------------------------------------------------------------------

def _aia_urls(cert: x509.Certificate, method_oid) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_class(AuthorityInformationAccess).value
    except ExtensionNotFound:
        return []
    out: list[str] = []
    for desc in aia:
        if desc.access_method == method_oid:
            loc = desc.access_location
            if hasattr(loc, "value"):
                out.append(loc.value)
    return out


def ocsp_url(cert: x509.Certificate) -> str | None:
    urls = _aia_urls(cert, AuthorityInformationAccessOID.OCSP)
    return urls[0] if urls else None


def ca_issuers_url(cert: x509.Certificate) -> str | None:
    urls = _aia_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)
    return urls[0] if urls else None


# ---------------------------------------------------------------------------
# Chain building via AIA caIssuers
# ---------------------------------------------------------------------------

def _looks_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001
        return False


def fetch_chain_via_aia(
    leaf: x509.Certificate,
    *,
    timeout: float = 10.0,
    max_depth: int = 6,
) -> list[x509.Certificate]:
    """Build a cert chain by following AIA caIssuers up to a self-signed root.

    Returns leaf + intermediates + root (best effort). If a hop fails (no AIA
    URL, network error, malformed cert) the chain is returned truncated — the
    caller decides whether to bail or proceed with partial revocation info.
    """
    chain = [leaf]
    current = leaf
    for _ in range(max_depth):
        if _looks_self_signed(current):
            break
        url = ca_issuers_url(current)
        if not url:
            break
        try:
            data = requests.get(url, timeout=timeout).content
        except requests.RequestException:
            break
        # Issuer responses can be DER, PEM, or PKCS#7 — try each.
        issuer = _load_cert_blob(data)
        if issuer is None:
            break
        chain.append(issuer)
        current = issuer
    return chain


def _load_cert_blob(data: bytes) -> x509.Certificate | None:
    """Try to load `data` as a single X.509 cert (DER, PEM, or PKCS#7)."""
    if not data:
        return None
    # PEM
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:  # noqa: BLE001
            pass
    # Raw DER
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:  # noqa: BLE001
        pass
    # PKCS#7 SignedData that wraps one or more certs (caIssuers often serves this)
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = pkcs7.load_der_pkcs7_certificates(data)
        if certs:
            return certs[0]
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# OCSP fetching
# ---------------------------------------------------------------------------

@dataclass
class OcspResult:
    cert: x509.Certificate
    response_der: bytes  # full OCSPResponse DER (we extract the BasicOCSPResponse later)


def fetch_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    timeout: float = 10.0,
) -> bytes | None:
    """Send an OCSP request for `cert` (signed by `issuer`) and return the
    full DER OCSPResponse bytes. Returns None when the AIA OCSP URL is
    missing or the request fails."""
    url = ocsp_url(cert)
    if not url:
        return None
    builder = crypto_ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA256())
    req = builder.build()
    body = req.public_bytes(serialization.Encoding.DER)
    headers = {"Content-Type": "application/ocsp-request"}
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=timeout)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    return resp.content


def collect_ocsp_for_chain(
    chain: Sequence[x509.Certificate],
    *,
    timeout: float = 10.0,
) -> list[bytes]:
    """For each non-root cert in the chain, fetch OCSP. Roots are skipped
    (they're self-signed, no OCSP exists for them).

    Returns a list of DER-encoded OCSPResponse blobs (variable length, may
    be shorter than len(chain)-1 if some hops have no OCSP URL).
    """
    out: list[bytes] = []
    for i in range(len(chain) - 1):
        cert = chain[i]
        issuer = chain[i + 1]
        if _looks_self_signed(cert):
            continue
        der = fetch_ocsp(cert, issuer, timeout=timeout)
        if der is not None:
            out.append(der)
    return out


# ---------------------------------------------------------------------------
# CMS post-processor
# ---------------------------------------------------------------------------

def add_lt_attributes(
    cms_bytes: bytes,
    *,
    certificates: Sequence[x509.Certificate] = (),
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> bytes:
    """Re-encode a CMS SignedData adding the LT unsigned attributes.

    `certificates` are written as id-aa-ets-certValues; `ocsp_responses`
    (each is a full DER OCSPResponse) and `crls` (each is a DER
    CertificateList) are bundled into id-aa-ets-revocationValues.

    The signature itself is preserved verbatim — LT attributes go in
    `signer_infos[0].unsigned_attrs`, which isn't covered by the signature.
    """
    ci = cms.ContentInfo.load(cms_bytes)
    if ci["content_type"].native != "signed_data":
        raise ValueError(_("not a CMS SignedData"))
    signed_data: cms.SignedData = ci["content"]
    if len(signed_data["signer_infos"]) == 0:
        raise ValueError(_("SignedData without signer_infos"))
    signer_info = signed_data["signer_infos"][0]

    new_attrs: list[cms.CMSAttribute] = []

    # asn1crypto's CMSAttribute SetOf resolves the value spec from `type`
    # via `_oid_specs`. Pass the *raw* DER of the wrapped value so the
    # framework re-parses with the correct spec; trying to assign a
    # pre-built instance trips asn1crypto's "wrap value as Sequence" path.
    if certificates:
        asn1_certs = []
        for c in certificates:
            der = c.public_bytes(serialization.Encoding.DER)
            asn1_certs.append(asn1_x509.Certificate.load(der))
        cv_der = CertificateValues(asn1_certs).dump()
        new_attrs.append(cms.CMSAttribute({
            "type": "certificate_values",
            "values": [CertificateValues.load(cv_der)],
        }))

    if ocsp_responses or crls:
        rv_dict: dict = {}
        if ocsp_responses:
            basic_responses: list[asn1_ocsp.BasicOCSPResponse] = []
            for der in ocsp_responses:
                resp = asn1_ocsp.OCSPResponse.load(der)
                status = resp["response_status"].native
                if status != "successful":
                    continue
                rb = resp["response_bytes"]
                if rb["response_type"].native != "basic_ocsp_response":
                    continue
                basic_responses.append(rb["response"].parsed)
            if basic_responses:
                rv_dict["ocsp_vals"] = basic_responses
        if crls:
            rv_dict["crl_vals"] = [
                asn1_crl.CertificateList.load(b) for b in crls
            ]
        if rv_dict:
            rv_der = RevocationValues(rv_dict).dump()
            new_attrs.append(cms.CMSAttribute({
                "type": "revocation_values",
                "values": [RevocationValues.load(rv_der)],
            }))

    if not new_attrs:
        # Nothing to embed → return the input untouched.
        return cms_bytes

    existing = signer_info["unsigned_attrs"]
    if existing is None or isinstance(existing, core.Void):
        signer_info["unsigned_attrs"] = cms.CMSAttributes(new_attrs)
    else:
        merged = list(existing) + new_attrs
        signer_info["unsigned_attrs"] = cms.CMSAttributes(merged)

    return ci.dump()


# ---------------------------------------------------------------------------
# High-level: take a B/T CMS and produce an LT CMS by fetching everything.
# ---------------------------------------------------------------------------

@dataclass
class _LTMaterial:
    chain: list[x509.Certificate]
    ocsp_responses: list[bytes]


def gather_lt_material(
    leaf: x509.Certificate,
    *,
    starting_chain: Sequence[x509.Certificate] = (),
    timeout: float = 10.0,
) -> _LTMaterial:
    """Build chain via AIA + fetch OCSP for each non-root cert in chain.

    `starting_chain` is what the caller already has (e.g. intermediates from
    a PKCS#12 file or from the CMS signedData.certificates field). We extend
    it with AIA-fetched issuers if needed.
    """
    if starting_chain:
        chain = list(starting_chain)
        if chain[0].subject != leaf.subject:
            chain = [leaf] + chain
    else:
        chain = [leaf]

    # Extend the chain up to a self-signed root via AIA.
    while not _looks_self_signed(chain[-1]):
        url = ca_issuers_url(chain[-1])
        if not url:
            break
        try:
            data = requests.get(url, timeout=timeout).content
        except requests.RequestException:
            break
        issuer = _load_cert_blob(data)
        if issuer is None or any(
            issuer.fingerprint(hashes.SHA256()) == c.fingerprint(hashes.SHA256())
            for c in chain
        ):
            break
        chain.append(issuer)

    ocsp = collect_ocsp_for_chain(chain, timeout=timeout)
    return _LTMaterial(chain=chain, ocsp_responses=ocsp)
