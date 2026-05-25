# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""XAdES Long-Term: enrich a T-level XAdES signature with the validation
material required for offline verification years later (ETSI EN 319 132-1,
clause 5.5.1 — the BES-LT level).

Per ETSI EN 319 132-1:

    <xades:UnsignedSignatureProperties>
        <xades:CertificateValues>
            <xades:EncapsulatedX509Certificate>…</xades:EncapsulatedX509Certificate>
            …
        </xades:CertificateValues>
        <xades:RevocationValues>
            <xades:OCSPValues>
                <xades:EncapsulatedOCSPValue>…</xades:EncapsulatedOCSPValue>
                …
            </xades:OCSPValues>
            <xades:CRLValues>
                <xades:EncapsulatedCRLValue>…</xades:EncapsulatedCRLValue>
                …
            </xades:CRLValues>
        </xades:RevocationValues>
    </xades:UnsignedSignatureProperties>

`UnsignedSignatureProperties` lives under `Object/QualifyingProperties` →
`UnsignedProperties`. None of those bytes are covered by the XMLDSig
signature (the signature only covers `SignedInfo`), so adding them is
non-disruptive.
"""
from __future__ import annotations

import base64
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from ..i18n import _


_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"
_NSMAP = {"ds": _DS_NS, "xades": _XADES_NS}


def add_lt_properties(
    xml_bytes: bytes,
    *,
    certificates: Sequence[x509.Certificate] = (),
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> bytes:
    """Add XAdES `CertificateValues` + `RevocationValues` to a signed XML.

    If all three lists are empty, the input is returned unchanged.
    """
    if not (certificates or ocsp_responses or crls):
        return xml_bytes

    root = etree.fromstring(xml_bytes)

    # XAdES signed XML can have one or more <ds:Signature> blocks; we
    # augment the first one (the typical single-signature case).
    sig = root.find(".//ds:Signature", _NSMAP)
    if sig is None:
        # Document might itself be the Signature element.
        if root.tag == f"{{{_DS_NS}}}Signature":
            sig = root
        else:
            raise ValueError(_("XAdES: no <ds:Signature> found in the document"))

    qp = sig.find(".//xades:QualifyingProperties", _NSMAP)
    if qp is None:
        raise ValueError(
            _("XAdES: <xades:QualifyingProperties> missing — not an XAdES?")
        )

    usp = qp.find("xades:UnsignedProperties/xades:UnsignedSignatureProperties",
                  _NSMAP)
    if usp is None:
        # Either UnsignedProperties or UnsignedSignatureProperties is missing.
        unsigned = qp.find("xades:UnsignedProperties", _NSMAP)
        if unsigned is None:
            unsigned = etree.SubElement(
                qp, f"{{{_XADES_NS}}}UnsignedProperties",
            )
        usp = etree.SubElement(
            unsigned, f"{{{_XADES_NS}}}UnsignedSignatureProperties",
        )

    if certificates:
        # Replace any existing CertificateValues so re-running is idempotent.
        for old in usp.findall("xades:CertificateValues", _NSMAP):
            usp.remove(old)
        cv = etree.SubElement(usp, f"{{{_XADES_NS}}}CertificateValues")
        for c in certificates:
            der = c.public_bytes(serialization.Encoding.DER)
            e = etree.SubElement(cv, f"{{{_XADES_NS}}}EncapsulatedX509Certificate")
            e.text = _b64(der)

    if ocsp_responses or crls:
        for old in usp.findall("xades:RevocationValues", _NSMAP):
            usp.remove(old)
        rv = etree.SubElement(usp, f"{{{_XADES_NS}}}RevocationValues")
        if ocsp_responses:
            ov = etree.SubElement(rv, f"{{{_XADES_NS}}}OCSPValues")
            for resp_der in ocsp_responses:
                e = etree.SubElement(ov, f"{{{_XADES_NS}}}EncapsulatedOCSPValue")
                e.text = _b64(resp_der)
        if crls:
            cv_node = etree.SubElement(rv, f"{{{_XADES_NS}}}CRLValues")
            for crl_der in crls:
                e = etree.SubElement(cv_node, f"{{{_XADES_NS}}}EncapsulatedCRLValue")
                e.text = _b64(crl_der)

    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _b64(data: bytes) -> str:
    # XAdES values are base64-encoded without internal newlines.
    return base64.b64encode(data).decode("ascii")
