# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Signer abstractions for PAdES, CAdES and XAdES."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

from ..i18n import _
from .credentials import SigningCredential


class SignatureLevel(Enum):
    B = "B"     # Basic (BES) — firma semplice
    T = "T"     # con marca temporale TSA
    LT = "LT"   # Long-Term: include OCSP/CRL e cert. TSA
    LTA = "LTA" # Long-Term with Archive timestamp


class SignaturePosition(Enum):
    """Corner of the page where the visible PAdES stamp is drawn."""
    BOTTOM_RIGHT = "bottom-right"
    BOTTOM_LEFT = "bottom-left"
    TOP_RIGHT = "top-right"
    TOP_LEFT = "top-left"


@dataclass
class SignOptions:
    level: SignatureLevel = SignatureLevel.B
    tsa_url: str | None = None
    tsa_username: str | None = None
    tsa_password: str | None = None
    # PAdES-only: posizione/aspetto firma visibile (None = invisibile)
    visible: bool = False
    # 0-indexed page on which to draw the visible signature stamp.
    # Use -1 to target the last page.
    signature_page: int = 0
    signature_position: SignaturePosition = SignaturePosition.BOTTOM_RIGHT
    # When set, overrides `signature_position`: explicit box in PDF points
    # (x1, y1, x2, y2) with origin at bottom-left of the page. Used by the
    # graphical picker that lets the user draw a rectangle on a preview.
    signature_box: tuple[float, float, float, float] | None = None
    # Optional path to a PNG/JPG image; when set, the stamp shows the image
    # as a logo to the left of auto-generated text (CN, date, reason).
    signature_image: str | None = None
    reason: str | None = None
    location: str | None = None
    contact: str | None = None
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.level != SignatureLevel.B and not self.tsa_url:
            raise ValueError(_("level {level} requires a TSA URL").format(level=self.level.value))


def _add_visible_appearance(dct, input_path, credential, options, signing_date_pdf):
    """Mutate the endesive signing dict to draw a visible appearance stamp.

    Selects the corner of `options.signature_page` per `options.signature_position`,
    sizes the box from the actual MediaBox of the target page (A4/Letter/...),
    and uses either text-only or text+logo appearance based on
    `options.signature_image`.
    """
    import io
    from endesive.pdf import PyPDF2

    # endesive bundles the legacy PyPDF2 1.26 API (PdfFileReader + getPage/mediaBox).
    pdf_bytes = input_path.read_bytes()
    reader = PyPDF2.PdfFileReader(io.BytesIO(pdf_bytes))
    n_pages = reader.getNumPages()
    if options.signature_page < 0:
        page_idx = n_pages - 1
    else:
        page_idx = max(0, min(options.signature_page, n_pages - 1))
    page = reader.getPage(page_idx)
    page_w = float(page.mediaBox.getWidth())
    page_h = float(page.mediaBox.getHeight())

    if options.signature_box is not None:
        # User-drawn box (from the graphical picker) — take it verbatim
        # after clamping to the page.
        bx1, by1, bx2, by2 = options.signature_box
        x1 = max(0.0, min(bx1, bx2))
        y1 = max(0.0, min(by1, by2))
        x2 = min(page_w, max(bx1, bx2))
        y2 = min(page_h, max(by1, by2))
    else:
        # ~70x28mm stamp (1 mm ≈ 2.835 pt) placed in the chosen corner.
        box_w, box_h, margin = 200.0, 80.0, 20.0
        pos = options.signature_position
        if pos is SignaturePosition.BOTTOM_RIGHT:
            x1, y1 = page_w - box_w - margin, margin
        elif pos is SignaturePosition.BOTTOM_LEFT:
            x1, y1 = margin, margin
        elif pos is SignaturePosition.TOP_RIGHT:
            x1, y1 = page_w - box_w - margin, page_h - box_h - margin
        elif pos is SignaturePosition.TOP_LEFT:
            x1, y1 = margin, page_h - box_h - margin
        else:
            x1, y1 = page_w - box_w - margin, margin  # safe default
        # Clamp to page in case of very small pages.
        x1 = max(margin, x1)
        y1 = max(margin, y1)
        x2 = min(page_w - margin, x1 + box_w)
        y2 = min(page_h - margin, y1 + box_h)

    dct.update({
        "sigflagsft": 132,
        "sigbutton": True,
        "sigpage": page_idx,
        "signaturebox": (x1, y1, x2, y2),
    })

    if options.signature_image:
        # Logo + auto-text (CN, date, reason) — Adobe-style appearance.
        # endesive's annotation layer wants either a file path (string) or a
        # PIL ImageFile from PIL.Image.open — passing an Image returned by
        # `.convert()` is rejected by its resolve_image helper. We hand it
        # the path so endesive owns the open/decode/colorspace handling.
        img_path = Path(options.signature_image)
        if not img_path.is_file():
            raise ValueError(_("image file not found: {path}").format(path=img_path))
        display = ["CN", "date"]
        if options.reason:
            display.append("reason")
        dct["signature_appearance"] = {
            "icon": str(img_path),
            "labels": True,
            "display": display,
            "border": 0,
            "outline": [0, 0, 0],
        }
    else:
        # Text-only stamp.
        from datetime import datetime, timezone
        human_date = datetime.now(timezone.utc).astimezone().strftime(
            "%Y-%m-%d %H:%M %Z"
        )
        subject = credential.certificate.subject.rfc4514_string()
        lines = [
            _("Digitally signed by:"),
            subject,
            _("Date: {date}").format(date=human_date),
        ]
        if options.reason:
            lines.append(_("Reason: {reason}").format(reason=options.reason))
        dct["signature"] = "\n".join(lines)
        dct["text"] = {"wraptext": True, "fontsize": 8, "linespacing": 1.2}


def _tsa_credentials(options: "SignOptions") -> dict | None:
    """Build the credentials dict endesive expects (HTTP Basic Auth on TSA).

    Returns None when no auth is configured, so endesive sends the request
    without Authorization header (correct for public TSAs like FreeTSA).
    """
    if options.tsa_username and options.tsa_password:
        return {"username": options.tsa_username, "password": options.tsa_password}
    return None


class Signer(ABC):
    """Sign a document, producing a signed artifact."""

    @abstractmethod
    def sign(
        self,
        input_path: Path,
        output_path: Path,
        credential: SigningCredential,
        options: SignOptions,
    ) -> Path:
        """Return the path to the signed file."""


class PAdESSigner(Signer):
    """PDF signature (ISO 32000 / ETSI EN 319 142). Level B and T."""

    def sign(self, input_path, output_path, credential, options):
        from datetime import datetime, timezone
        from endesive.pdf import cms

        if options.level not in (SignatureLevel.B, SignatureLevel.T, SignatureLevel.LT):
            raise NotImplementedError(_("signature level {level} not yet supported").format(level=options.level.value))

        signing_date = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S+00'00'")
        dct = {
            "sigflags": 3,
            "contact": options.contact or "",
            "location": options.location or "",
            "signingdate": signing_date,
            "reason": options.reason or "",
        }
        # endesive's "exact-size" path doesn't handle TSA tokens reliably (the
        # token size can vary across requests, breaking the placeholder match).
        # Reserve a fixed-size slot when timestamping is enabled. We also use
        # the fixed slot for HSM-backed signing: PIV "always-PIN" slots reject
        # the pre-sign pass that the exact-size path performs.
        if options.tsa_url or credential.hsm is not None:
            dct["aligned"] = 8192

        if options.visible:
            _add_visible_appearance(dct, input_path, credential, options, signing_date)

        datau = input_path.read_bytes()
        datas = cms.sign(
            datau,
            dct,
            credential.private_key,
            credential.certificate,
            list(credential.chain),
            "sha256",
            hsm=credential.hsm,
            timestampurl=options.tsa_url,
            timestampcredentials=_tsa_credentials(options),
        )
        # First, write the T-level signed PDF. Then, for LT, append a DSS
        # dictionary via incremental update — leaves the existing signature
        # bytes (covered by /ByteRange) untouched.
        signed_pdf = datau + datas
        if options.level is SignatureLevel.LT:
            signed_pdf = self._add_lt_layer(signed_pdf, credential)
        output_path.write_bytes(signed_pdf)
        return output_path

    @staticmethod
    def _add_lt_layer(pdf_bytes: bytes, credential) -> bytes:
        """Append an ETSI EN 319 142 DSS dictionary with the signer chain
        and OCSP material. Best effort: missing AIA URLs degrade gracefully.
        """
        from .lt import gather_lt_material
        from .pades_lt import add_dss

        material = gather_lt_material(
            credential.certificate,
            starting_chain=list(credential.chain),
        )
        return add_dss(
            pdf_bytes,
            certificates=material.chain,
            ocsp_responses=material.ocsp_responses,
        )


class CAdESSigner(Signer):
    """CMS signature producing an enveloping .p7m (ETSI EN 319 122).

    endesive produces a detached CMS (the content lives outside the structure).
    The Italian .p7m convention is *enveloping*: the original file is embedded
    in `encap_content_info.content`. We post-process the detached CMS to embed
    the content, which is what tools like Dike, ArubaSign, and FirmaCerta expect.
    """

    def sign(self, input_path, output_path, credential, options):
        from asn1crypto import cms as asn1cms, core
        from endesive import signer as endesive_signer

        if options.level not in (SignatureLevel.B, SignatureLevel.T, SignatureLevel.LT):
            raise NotImplementedError(_("signature level {level} not yet supported").format(level=options.level.value))

        datau = input_path.read_bytes()
        detached = endesive_signer.sign(
            datau,
            credential.private_key,
            credential.certificate,
            list(credential.chain),
            "sha256",
            attrs=True,
            hsm=credential.hsm,
            timestampurl=options.tsa_url,
            timestampcredentials=_tsa_credentials(options),
        )

        # Embed the content into the CMS structure to make it enveloping.
        ci = asn1cms.ContentInfo.load(detached)
        signed_data = ci["content"]
        # asn1crypto's CMS schema uses ContentInfo (PKCS#7-style) for the
        # encapsulated content info field, not EncapsulatedContentInfo.
        signed_data["encap_content_info"] = asn1cms.ContentInfo({
            "content_type": "data",
            "content": core.OctetString(datau),
        })

        out_bytes = ci.dump()

        if options.level is SignatureLevel.LT:
            out_bytes = self._add_lt_layer(out_bytes, credential)

        output_path.write_bytes(out_bytes)
        return output_path

    @staticmethod
    def _add_lt_layer(cms_bytes: bytes, credential) -> bytes:
        """Augment a T-level CAdES with long-term validation material.

        Walks the signer's chain via AIA caIssuers, fetches OCSP for every
        non-root cert, and embeds the result as id-aa-ets-certValues +
        id-aa-ets-revocationValues unsigned attrs. Network failures degrade
        gracefully: the LT envelope is added best-effort, the signature
        itself is unchanged.
        """
        from .lt import add_lt_attributes, gather_lt_material

        material = gather_lt_material(
            credential.certificate,
            starting_chain=list(credential.chain),
        )
        return add_lt_attributes(
            cms_bytes,
            certificates=material.chain,
            ocsp_responses=material.ocsp_responses,
        )


def _hash_by_name(name: str):
    algo = name.lower()
    if algo == "sha1":
        return hashes.SHA1()
    if algo == "sha256":
        return hashes.SHA256()
    if algo == "sha384":
        return hashes.SHA384()
    if algo == "sha512":
        return hashes.SHA512()
    raise ValueError(_("unsupported hash algorithm: {name}").format(name=name))


def _sign_raw(credential: SigningCredential, data: bytes, hashalgo: str) -> bytes:
    """Return raw signature bytes for XAdES signing callbacks."""
    if credential.hsm is not None:
        # Our PKCS#11 adapter ignores keyid (single active key per credential).
        return credential.hsm.sign(b"", data, hashalgo)

    pkey = credential.private_key
    if pkey is None:
        raise ValueError(_("private key not available"))

    h = _hash_by_name(hashalgo)
    if isinstance(pkey, rsa.RSAPrivateKey):
        return pkey.sign(data, padding.PKCS1v15(), h)
    if isinstance(pkey, ec.EllipticCurvePrivateKey):
        return pkey.sign(data, ec.ECDSA(h))
    if isinstance(pkey, dsa.DSAPrivateKey):
        return pkey.sign(data, h)

    raise ValueError(_("unsupported key type for XAdES: {kind!r}").format(kind=type(pkey)))


class XAdESSigner(Signer):
    """XAdES-BES enveloped XML signature (ETSI EN 319 132 baseline B)."""

    def sign(self, input_path, output_path, credential, options):
        from lxml import etree
        from endesive.xades import BES

        if options.level not in (SignatureLevel.B, SignatureLevel.T, SignatureLevel.LT):
            raise NotImplementedError(_("signature level {level} not yet supported").format(level=options.level.value))

        xml_bytes = input_path.read_bytes()
        cert_der = credential.certificate.public_bytes(serialization.Encoding.DER)
        xades = BES()
        signed_tree = xades.enveloped(
            xml_bytes,
            credential.certificate,
            cert_der,
            lambda data, hashalgo: _sign_raw(credential, data, hashalgo),
            options.tsa_url,
            _tsa_credentials(options),
        )
        out_bytes = etree.tostring(signed_tree, encoding="UTF-8", xml_declaration=True)

        if options.level is SignatureLevel.LT:
            out_bytes = self._add_lt_layer(out_bytes, credential)
        output_path.write_bytes(out_bytes)
        return output_path

    @staticmethod
    def _add_lt_layer(xml_bytes: bytes, credential) -> bytes:
        """Augment a T-level XAdES with CertificateValues + RevocationValues
        (UnsignedSignatureProperties — outside the signed region of XMLDSig)."""
        from .lt import gather_lt_material
        from .xades_lt import add_lt_properties

        material = gather_lt_material(
            credential.certificate,
            starting_chain=list(credential.chain),
        )
        return add_lt_properties(
            xml_bytes,
            certificates=material.chain,
            ocsp_responses=material.ocsp_responses,
        )
