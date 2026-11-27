# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Regression tests for the signing time carried by each signature format.

Issue #6: ArubaSign rejected our CAdES signatures with "Signed-property
SigningTime non presente o non aderente allo standard", and flagged them as
not meeting Decision (EU) 2015/1506. The cause was endesive: its built-in
`attrs=True` leaves signing-time commented out, so the signed attributes only
carried content-type, message-digest and signing-certificate-v2.

The rules differ per format, so each is pinned here:
  * CAdES — signing-time is required among the signed attributes, as UTCTime
    (RFC 5652 mandates UTCTime for dates before 2050).
  * PAdES — signing-time is deliberately absent from the CMS; the time lives
    in the signature dictionary's /M, which must use the PDF date syntax
    (ISO 32000: "D:YYYYMMDDHHmmSS...").
  * XAdES — the time is the SigningTime element of SignedProperties.
"""
from __future__ import annotations

import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from asn1crypto import cms as asn1cms

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import (
    CAdESSigner,
    PAdESSigner,
    SignatureLevel,
    SignOptions,
    XAdESSigner,
)

from fixtures import make_minimal_pdf, make_p12_from_chain, make_test_chain


def _credential(tmp: Path):
    chain = make_test_chain()
    p12 = tmp / "test.p12"
    p12.write_bytes(make_p12_from_chain(chain, password="test"))
    return FileProvider(p12).unlock(str(p12), "test")


def _signed_attrs(p7m: Path) -> dict[str, object]:
    signer_info = asn1cms.ContentInfo.load(p7m.read_bytes())["content"]["signer_infos"][0]
    return {a["type"].native: a["values"][0] for a in signer_info["signed_attrs"]}


def test_cades_carries_signing_time():
    """The signed attributes must include signing-time (issue #6)."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "profilo.jpg"
        src.write_bytes(b"\xff\xd8\xff\xe0 jpeg \xff\xd9")
        out = tmp / "profilo.jpg.p7m"
        CAdESSigner().sign(
            input_path=src,
            output_path=out,
            credential=_credential(tmp),
            options=SignOptions(level=SignatureLevel.B),
        )

        attrs = _signed_attrs(out)
        assert "signing_time" in attrs, (
            f"signing-time missing from the signed attributes: {sorted(attrs)}"
        )
        # The other attributes must survive — we replace endesive's whole set.
        for required in ("content_type", "message_digest", "signing_certificate_v2"):
            assert required in attrs, f"{required} lost: {sorted(attrs)}"


def test_cades_signing_time_is_utctime_and_current():
    """UTCTime, not GeneralizedTime, and close to now.

    Italian verifiers reject GeneralizedTime for pre-2050 dates; asn1crypto's
    `cms.Time` is a CHOICE, so the encoding has to be pinned explicitly.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.txt"
        src.write_bytes(b"contenuto")
        out = tmp / "doc.txt.p7m"
        before = datetime.now(timezone.utc)
        CAdESSigner().sign(
            input_path=src,
            output_path=out,
            credential=_credential(tmp),
            options=SignOptions(level=SignatureLevel.B),
        )
        after = datetime.now(timezone.utc)

        value = _signed_attrs(out)["signing_time"]
        assert value.name == "utc_time", f"expected UTCTime, got {value.name}"
        # 0x17 is the ASN.1 tag for UTCTime, 0x18 for GeneralizedTime.
        assert value.dump()[0] == 0x17, f"unexpected tag {hex(value.dump()[0])}"
        # UTCTime has second granularity: allow the truncation at both ends.
        signed_at = value.native
        assert before - timedelta(seconds=1) <= signed_at <= after + timedelta(seconds=1), (
            f"signing time {signed_at} outside [{before}, {after}]"
        )


def test_pades_m_entry_uses_pdf_date_syntax():
    """/M must carry the `D:` prefix; endesive writes our string verbatim."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.pdf"
        src.write_bytes(make_minimal_pdf())
        out = tmp / "doc-signed.pdf"
        PAdESSigner().sign(
            input_path=src,
            output_path=out,
            credential=_credential(tmp),
            options=SignOptions(level=SignatureLevel.B),
        )

        raw = out.read_bytes()
        found = re.search(rb"/M\s*\(([^)]*)\)", raw)
        assert found, "no /M entry in the signature dictionary"
        # A PDF literal string may escape characters in octal: the writer emits
        # ":" as \072, "+" as \053 and "'" as \047.
        value = re.sub(
            rb"\\([0-7]{1,3})",
            lambda m: bytes([int(m.group(1), 8)]),
            found.group(1),
        )
        assert value.startswith(b"D:"), f"/M lacks the D: prefix: {found.group(1)!r}"
        assert re.fullmatch(rb"D:\d{14}[+\-]\d{2}'\d{2}'", value), (
            f"/M is not a valid PDF date: {value!r}"
        )


def test_pades_cms_has_no_signing_time():
    """PAdES deliberately keeps signing-time out of the CMS (it uses /M)."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.pdf"
        src.write_bytes(make_minimal_pdf())
        out = tmp / "doc-signed.pdf"
        PAdESSigner().sign(
            input_path=src,
            output_path=out,
            credential=_credential(tmp),
            options=SignOptions(level=SignatureLevel.B),
        )

        hexed = re.search(rb"/Contents\s*<([0-9A-Fa-f]+)>", out.read_bytes())
        assert hexed, "no /Contents in the signed PDF"
        blob = bytes.fromhex(hexed.group(1).decode().rstrip("0"))
        signer_info = asn1cms.ContentInfo.load(blob)["content"]["signer_infos"][0]
        attrs = {a["type"].native for a in signer_info["signed_attrs"]}
        assert "signing_time" not in attrs, (
            "PAdES should not carry signing-time in the CMS"
        )


def test_xades_carries_signing_time():
    """XAdES keeps its own SigningTime inside SignedProperties."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        src = tmp / "doc.xml"
        src.write_bytes(b"<?xml version='1.0'?><root><a>x</a></root>")
        out = tmp / "doc.xml.xades"
        XAdESSigner().sign(
            input_path=src,
            output_path=out,
            credential=_credential(tmp),
            options=SignOptions(level=SignatureLevel.B),
        )

        text = out.read_text(encoding="utf-8", errors="replace")
        found = re.search(r"<[^>]*SigningTime[^>]*>([^<]+)<", text)
        assert found, "SigningTime missing from the XAdES SignedProperties"
        # ISO 8601, as required by XAdES.
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?", found.group(1)), (
            f"SigningTime is not ISO 8601: {found.group(1)!r}"
        )
