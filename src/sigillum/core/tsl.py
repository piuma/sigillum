# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Italian eIDAS Trust List (TSL) importer with XMLDSig signature verification.

Downloads the AgID-maintained TSL (https://eidas.agid.gov.it/TL/TSL-IT.xml),
verifies the enveloped XMLDSig (ETSI TS 119 612), optionally anchors the
signing certificate against the EU List of Trusted Lists (LOTL), then extracts
the X.509 certificates of currently-active qualified trust services and writes
them as two PEM bundles under $XDG_DATA_HOME/sigillum/trusted/:
  - it-eidas-signing.pem  → CAs for qualified signatures (signers' trust store)
  - it-eidas-tsa.pem      → CAs for qualified timestamp authorities

Signature verification uses lxml for canonical XML (C14N) and the cryptography
library for the actual RSA/ECDSA check — no external xmlsec binding needed.
"""
from __future__ import annotations

import base64
import copy
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding


AGID_TSL_URL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
EU_LOTL_URL  = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

_NS  = "http://uri.etsi.org/02231/v2#"
_ADDT = "http://uri.etsi.org/02231/v2/additionaltypes#"
_DS  = "http://www.w3.org/2000/09/xmldsig#"

# AgID statuses that mean the service is currently usable.
_ACTIVE_STATUSES = {
    "granted",                   # eIDAS-qualified, in service
    "recognisedatnationallevel", # recognised by AgID at national level
}

# ServiceTypeIdentifier suffixes that classify a service into the TSA bucket.
# Everything else goes into the signing bucket. Source: ETSI TS 119 612.
_TSA_TYPE_SUFFIXES = {"TSA", "QTST", "TSS-QTST"}

# Digest URI → hash algorithm mapping (XMLDSig / xmlenc namespaces).
_DIGEST_ALGS: dict[str, hashes.HashAlgorithm] = {
    "http://www.w3.org/2001/04/xmlenc#sha256":          hashes.SHA256(),
    "http://www.w3.org/2001/04/xmlenc#sha512":          hashes.SHA512(),
    "http://www.w3.org/2001/04/xmldsig-more#sha384":    hashes.SHA384(),
    "http://www.w3.org/2000/09/xmldsig#sha1":           hashes.SHA1(),   # legacy
}

_ENVELOPED_SIG_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_EXC_C14N_URI      = "http://www.w3.org/2001/10/xml-exc-c14n#"


class TSLSignatureError(ValueError):
    """Raised when the TSL XML signature fails verification."""


@dataclass
class TSLImportResult:
    signing_count: int
    tsa_count: int
    when: datetime
    signing_path: Path
    tsa_path: Path
    country: str = "IT"
    signer_cert: x509.Certificate | None = field(default=None, repr=False)
    signer_trusted: bool = False  # True when LOTL-anchored check passed


# ---------------------------------------------------------------------------
# XMLDSig verification
# ---------------------------------------------------------------------------

def _c14n(element, *, exclusive: bool) -> bytes:
    """Return the canonical XML serialisation of *element* (lxml element)."""
    from lxml import etree as _et
    return _et.tostring(element, method="c14n", exclusive=exclusive, with_comments=False)


def _digest_bytes(data: bytes, alg_uri: str) -> bytes:
    h_alg = _DIGEST_ALGS.get(alg_uri)
    if h_alg is None:
        raise TSLSignatureError(f"Unsupported digest algorithm: {alg_uri}")
    from cryptography.hazmat.primitives.hashes import Hash
    from cryptography.hazmat.backends import default_backend
    d = Hash(h_alg, default_backend())
    d.update(data)
    return d.finalize()


def verify_tsl_signature(
    xml_bytes: bytes,
    trusted_certs: list[x509.Certificate] | None = None,
) -> x509.Certificate:
    """Verify the enveloped XMLDSig signature on a TSL document.

    1. Locates the embedded <ds:Signature> element.
    2. Checks each <ds:Reference> digest (document integrity).
    3. Verifies the signature value over the canonicalised <ds:SignedInfo>.
    4. If *trusted_certs* is given, confirms the signing certificate matches
       one of them (EU LOTL-anchored trust check).

    Returns the signing certificate.
    Raises TSLSignatureError on any failure.
    """
    try:
        from lxml import etree as _et
    except ImportError:  # pragma: no cover
        raise RuntimeError("lxml is required for TSL signature verification: pip install lxml")

    try:
        root = _et.fromstring(xml_bytes)
    except _et.XMLSyntaxError as exc:
        raise TSLSignatureError(f"XML parse error: {exc}") from exc

    # --- locate <ds:Signature> ---
    sig_el = root.find(f".//{{{_DS}}}Signature")
    if sig_el is None:
        raise TSLSignatureError("No <ds:Signature> element found in TSL")

    # --- extract signing certificate ---
    x509_els = sig_el.findall(f".//{{{_DS}}}X509Certificate")
    x509_text = next((e.text for e in x509_els if e.text), None)
    if not x509_text:
        raise TSLSignatureError("No X509Certificate in Signature KeyInfo")
    try:
        signing_cert = x509.load_der_x509_certificate(
            base64.b64decode("".join(x509_text.split()))
        )
    except Exception as exc:
        raise TSLSignatureError(f"Cannot decode signing certificate: {exc}") from exc

    # --- optional trust-anchor check against caller-supplied set ---
    if trusted_certs is not None:
        fp = signing_cert.fingerprint(hashes.SHA256())
        if fp not in {c.fingerprint(hashes.SHA256()) for c in trusted_certs}:
            raise TSLSignatureError(
                "TSL signing certificate not in trusted set "
                f"(signer: {signing_cert.subject.rfc4514_string()!r})"
            )

    # --- parse SignedInfo ---
    signed_info = sig_el.find(f"{{{_DS}}}SignedInfo")
    if signed_info is None:
        raise TSLSignatureError("<ds:SignedInfo> element missing")

    c14n_method_el = signed_info.find(f"{{{_DS}}}CanonicalizationMethod")
    c14n_alg = (c14n_method_el.get("Algorithm") or "") if c14n_method_el is not None else ""
    si_exclusive = _EXC_C14N_URI in c14n_alg

    # --- verify each Reference ---
    transforms_xpath = f"{{{_DS}}}Transforms/{{{_DS}}}Transform"
    for ref in signed_info.findall(f"{{{_DS}}}Reference"):
        uri = ref.get("URI", "")
        transforms = [
            t.get("Algorithm", "") for t in ref.findall(transforms_xpath)
        ]

        if uri == "":
            # Reference to the whole document.
            node = copy.deepcopy(root)
            if any(_ENVELOPED_SIG_URI in t for t in transforms):
                for s in node.findall(f".//{{{_DS}}}Signature"):
                    parent = s.getparent()
                    if parent is not None:
                        parent.remove(s)
        elif uri.startswith("#"):
            id_val = uri[1:]
            matches = (
                root.xpath(f'//*[@Id="{id_val}"]')
                or root.xpath(f'//*[@id="{id_val}"]')
                or root.xpath(f'//*[@ID="{id_val}"]')
            )
            if not matches:
                raise TSLSignatureError(f"Reference URI {uri!r}: ID not found")
            node = matches[0]
        else:
            raise TSLSignatureError(f"Unsupported Reference URI: {uri!r}")

        ref_exclusive = any(_EXC_C14N_URI in t for t in transforms)
        data = _c14n(node, exclusive=ref_exclusive)

        digest_el = ref.find(f"{{{_DS}}}DigestMethod")
        d_alg = (digest_el.get("Algorithm") or "") if digest_el is not None else ""
        expected_text = (ref.findtext(f"{{{_DS}}}DigestValue") or "").strip()
        expected = base64.b64decode("".join(expected_text.split()))
        actual = _digest_bytes(data, d_alg)
        if actual != expected:
            raise TSLSignatureError(
                f"Reference digest mismatch (URI={uri!r}): "
                f"expected {expected.hex()[:16]}…, got {actual.hex()[:16]}…"
            )

    # --- verify signature value over C14N(SignedInfo) ---
    sig_method_el = signed_info.find(f"{{{_DS}}}SignatureMethod")
    sig_alg = (sig_method_el.get("Algorithm") or "") if sig_method_el is not None else ""

    si_c14n = _c14n(signed_info, exclusive=si_exclusive)

    raw_sig_text = (sig_el.findtext(f"{{{_DS}}}SignatureValue") or "").strip()
    raw_sig = base64.b64decode("".join(raw_sig_text.split()))

    pubkey = signing_cert.public_key()
    sig_alg_l = sig_alg.lower()

    if "sha512" in sig_alg_l:
        h_alg: hashes.HashAlgorithm = hashes.SHA512()
    elif "sha384" in sig_alg_l:
        h_alg = hashes.SHA384()
    else:
        h_alg = hashes.SHA256()

    try:
        if "ecdsa" in sig_alg_l or ("ec" in sig_alg_l and "rsa" not in sig_alg_l):
            pubkey.verify(raw_sig, si_c14n, ec.ECDSA(h_alg))
        elif "mgf" in sig_alg_l or "pss" in sig_alg_l:
            # RSA-PSS — used by several EU TSLs (e.g. DE: sha256-rsa-MGF1).
            # ETSI/XAdES practice is salt_length == digest_size.
            pubkey.verify(
                raw_sig, si_c14n,
                padding.PSS(mgf=padding.MGF1(h_alg), salt_length=h_alg.digest_size),
                h_alg,
            )
        else:
            pubkey.verify(raw_sig, si_c14n, padding.PKCS1v15(), h_alg)
    except InvalidSignature as exc:
        raise TSLSignatureError("TSL XMLDSig cryptographic verification failed") from exc
    except Exception as exc:
        raise TSLSignatureError(f"TSL signature verification error: {exc}") from exc

    return signing_cert


# ---------------------------------------------------------------------------
# EU LOTL helpers
# ---------------------------------------------------------------------------

@dataclass
class TSLPointer:
    """One <OtherTSLPointer> entry from the EU LOTL.

    Carries everything needed to fetch and authenticate a national TSL: the
    country (ISO-3166 alpha-2), the URL of the TSL document, its declared
    MIME type, and the certificates trusted to sign it (used as anchors when
    verifying its XMLDSig).
    """
    country: str
    tsl_url: str
    mime_type: str = ""
    signing_certs: list[x509.Certificate] = field(default_factory=list, repr=False)

    @property
    def is_xml(self) -> bool:
        """True if this pointer references an XML TSL we can actually parse.

        The MIME type is authoritative when present (``application/vnd.etsi.tsl+xml``).
        We fall back to the URL suffix for entries that omit it — some TSPs
        publish the XML with ``.xtsl`` instead of ``.xml``.
        """
        if "xml" in self.mime_type.lower():
            return True
        lower = self.tsl_url.lower()
        return lower.endswith((".xml", ".xtsl"))


def parse_lotl(lotl_bytes: bytes) -> list[TSLPointer]:
    """Scan the EU LOTL and return every <OtherTSLPointer> as a TSLPointer.

    The result is raw — both XML and PDF pointers are returned, and the EU
    self-reference is included. Callers that want only usable national XML
    TSLs should use :func:`usable_national_tsls`.
    """
    root = ET.fromstring(lotl_bytes)
    pointers: list[TSLPointer] = []

    for p in root.iter(f"{{{_NS}}}OtherTSLPointer"):
        territory = (p.findtext(f".//{{{_NS}}}SchemeTerritory") or "").strip()
        tsl_url = (p.findtext(f"{{{_NS}}}TSLLocation") or "").strip()
        if not territory or not tsl_url:
            continue
        mime = (p.findtext(f".//{{{_ADDT}}}MimeType") or "").strip()
        certs: list[x509.Certificate] = []
        for x509_el in p.iter(f"{{{_NS}}}X509Certificate"):
            if not x509_el.text:
                continue
            try:
                der = base64.b64decode("".join(x509_el.text.split()))
                certs.append(x509.load_der_x509_certificate(der))
            except Exception:  # noqa: BLE001
                continue
        pointers.append(
            TSLPointer(country=territory, tsl_url=tsl_url, mime_type=mime, signing_certs=certs)
        )

    return pointers


def usable_national_tsls(lotl_bytes: bytes) -> dict[str, TSLPointer]:
    """Filtered LOTL view: one usable XML pointer per member state.

    Drops the EU self-reference (``SchemeTerritory == "EU"``) and PDF copies.
    Keyed by uppercase country code so callers can do ``pointers["DE"]``.
    """
    out: dict[str, TSLPointer] = {}
    for p in parse_lotl(lotl_bytes):
        cc = p.country.upper()
        if cc == "EU":
            continue  # the LOTL referencing itself, not a member state
        if not p.is_xml:
            continue
        # First XML pointer wins; the LOTL never lists two XML TSLs per country
        # in practice, but be defensive.
        out.setdefault(cc, p)
    return out


def find_country_pointer(lotl_bytes: bytes, country: str) -> TSLPointer | None:
    """Return the usable XML pointer for *country*, or None if absent."""
    return usable_national_tsls(lotl_bytes).get(country.upper())


def fetch_country_tsl_signers_from_lotl(
    lotl_bytes: bytes,
    country: str = "IT",
) -> list[x509.Certificate]:
    """Extract the certificates trusted to sign *country*'s national TSL."""
    pointer = find_country_pointer(lotl_bytes, country)
    return pointer.signing_certs if pointer is not None else []


def fetch_it_tsl_signers_from_lotl(lotl_bytes: bytes) -> list[x509.Certificate]:
    """Italy-specific shortcut, kept for backward compatibility."""
    return fetch_country_tsl_signers_from_lotl(lotl_bytes, "IT")


# ---------------------------------------------------------------------------
# Core parse / save / import
# ---------------------------------------------------------------------------

def fetch_tsl(url: str = AGID_TSL_URL, timeout: float = 30.0) -> bytes:
    """Download a TSL or LOTL document. Caller handles network errors."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def parse_tsl(xml_bytes: bytes) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Return (signing_cas, tsa_cas) extracted from active service entries.

    Certificates are deduplicated by SHA-256 fingerprint across the whole file
    so that operators serving multiple service types don't get duplicated.
    Historical service instances (`ServiceHistoryInstance`) are skipped.
    """
    root = ET.fromstring(xml_bytes)
    signing: dict[bytes, x509.Certificate] = {}
    tsa: dict[bytes, x509.Certificate] = {}

    for svc in root.iter(f"{{{_NS}}}TSPService"):
        si = svc.find(f"{{{_NS}}}ServiceInformation")
        if si is None:
            continue
        status = (si.findtext(f"{{{_NS}}}ServiceStatus", "") or "").rsplit("/", 1)[-1]
        if status not in _ACTIVE_STATUSES:
            continue
        type_uri = si.findtext(f"{{{_NS}}}ServiceTypeIdentifier", "") or ""
        type_suffix = type_uri.rsplit("/", 1)[-1]
        bucket = tsa if type_suffix in _TSA_TYPE_SUFFIXES else signing

        for x509_el in si.iter(f"{{{_NS}}}X509Certificate"):
            if not x509_el.text:
                continue
            try:
                der = base64.b64decode("".join(x509_el.text.split()))
                cert = x509.load_der_x509_certificate(der)
            except Exception:  # noqa: BLE001 — skip individual bad entries
                continue
            fp = cert.fingerprint(hashes.SHA256())
            bucket.setdefault(fp, cert)

    return list(signing.values()), list(tsa.values())


def trusted_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "sigillum" / "trusted"


def signing_pem_path(country: str = "IT") -> Path:
    """Per-country PEM bundle for qualified-signature CAs.

    The legacy Italian path (``it-eidas-signing.pem``) is preserved when
    ``country="IT"`` so existing installs keep working without migration.
    """
    return trusted_dir() / f"{country.lower()}-eidas-signing.pem"


def tsa_pem_path(country: str = "IT") -> Path:
    """Per-country PEM bundle for qualified TSA CAs."""
    return trusted_dir() / f"{country.lower()}-eidas-tsa.pem"


def list_imported_countries() -> list[str]:
    """Return the uppercase ISO codes of every country with a signing bundle on disk.

    Used by Settings / UI to enumerate the currently-imported national TSLs.
    """
    d = trusted_dir()
    if not d.is_dir():
        return []
    out: list[str] = []
    for f in d.glob("*-eidas-signing.pem"):
        cc = f.name.split("-", 1)[0]
        if cc and cc.isalpha():
            out.append(cc.upper())
    return sorted(out)


def save_certs_as_pem(certs: list[x509.Certificate], path: Path) -> None:
    """Write the certs as a concatenated PEM bundle, atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)


def import_country_tsl(
    country: str = "IT",
    *,
    lotl_url: str = EU_LOTL_URL,
    verify_signature: bool = True,
) -> TSLImportResult:
    """Discover, verify and import the national TSL for *country* via the EU LOTL.

    Flow:
      1. Fetch the EU LOTL.
      2. Locate the LOTL pointer for *country* — this yields both the TSL URL
         and the certificates trusted to sign it.
      3. Fetch the national TSL from the LOTL-published URL.
      4. Verify the enveloped XMLDSig against the LOTL-published signing certs
         (LOTL-anchored trust check).
      5. Extract qualified-trust-service CAs and save them to per-country PEM
         bundles.

    Raises:
        ValueError: if no XML pointer for *country* exists in the LOTL.
        TSLSignatureError: if signature verification fails.
    """
    lotl_bytes = fetch_tsl(lotl_url)
    pointer = find_country_pointer(lotl_bytes, country)
    if pointer is None:
        raise ValueError(
            f"No usable XML TSL pointer for country {country!r} in EU LOTL"
        )

    xml_bytes = fetch_tsl(pointer.tsl_url)

    signer_cert: x509.Certificate | None = None
    signer_trusted = False
    if verify_signature:
        signer_cert = verify_tsl_signature(xml_bytes, trusted_certs=pointer.signing_certs)
        signer_trusted = True  # reaching this line means the LOTL-anchored check passed

    signing, tsa = parse_tsl(xml_bytes)
    sp = signing_pem_path(country)
    tp = tsa_pem_path(country)
    save_certs_as_pem(signing, sp)
    save_certs_as_pem(tsa, tp)
    return TSLImportResult(
        signing_count=len(signing),
        tsa_count=len(tsa),
        when=datetime.now(timezone.utc),
        signing_path=sp,
        tsa_path=tp,
        country=country.upper(),
        signer_cert=signer_cert,
        signer_trusted=signer_trusted,
    )


def import_agid_tsl(
    url: str = AGID_TSL_URL,
    *,
    verify_signature: bool = True,
    lotl_url: str = EU_LOTL_URL,
) -> TSLImportResult:
    """Italy-specific shortcut, kept for backward compatibility.

    Delegates to :func:`import_country_tsl` with ``country="IT"``. The legacy
    ``url`` parameter is accepted but ignored: the URL is now discovered from
    the EU LOTL to guarantee the LOTL-anchored trust path.
    """
    del url  # legacy, superseded by LOTL discovery
    return import_country_tsl("IT", lotl_url=lotl_url, verify_signature=verify_signature)


def import_age_days(iso_timestamp: str) -> int | None:
    """Days since the given ISO 8601 timestamp; None if input is empty/invalid."""
    if not iso_timestamp:
        return None
    try:
        dt = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def load_pem_bundle(path: Path) -> list[x509.Certificate]:
    """Best-effort load of a PEM bundle; returns [] if the file is missing."""
    if not path.exists():
        return []
    try:
        return list(x509.load_pem_x509_certificates(path.read_bytes()))
    except Exception:  # noqa: BLE001
        return []


def load_active_trust_stores(
    active_countries: list[str],
) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Load the union of signing-CA and TSA-CA PEM bundles for all active countries.

    Certificates that appear in multiple countries (e.g. cross-recognised CAs)
    are deduplicated by SHA-256 fingerprint.
    """
    signing: list[x509.Certificate] = []
    tsa: list[x509.Certificate] = []
    seen_signing: set[bytes] = set()
    seen_tsa: set[bytes] = set()
    for cc in active_countries:
        for c in load_pem_bundle(signing_pem_path(cc)):
            fp = c.fingerprint(hashes.SHA256())
            if fp not in seen_signing:
                seen_signing.add(fp)
                signing.append(c)
        for c in load_pem_bundle(tsa_pem_path(cc)):
            fp = c.fingerprint(hashes.SHA256())
            if fp not in seen_tsa:
                seen_tsa.add(fp)
                tsa.append(c)
    return signing, tsa
