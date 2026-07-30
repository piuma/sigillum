# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""PAdES Long-Term: build a Document Security Store (DSS) and append it to a
signed PDF via an *incremental update*.

PAdES (ETSI EN 319 142 Annex F) stores LT validation data in a `/DSS`
dictionary in the PDF's catalog rather than in the CMS unsigned_attrs (as
CAdES does). Updating an already-signed PDF without invalidating the
signature requires appending — never rewriting — bytes after `%%EOF`.
This module hand-rolls that incremental update.

Layout produced:

    <existing signed PDF bytes>
    <new cert/CRL/OCSP stream objects>
    <new DSS dictionary object>
    <new catalog object (clone of existing, with /DSS added)>
    xref
    <subsection for catalog override>
    <subsection for new objects>
    trailer
    << /Size N /Root <catalog> 0 R /Prev <previous xref offset> >>
    startxref
    <new xref offset>
    %%EOF
"""
from __future__ import annotations

import io
import re
import zlib
from dataclasses import dataclass, field
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..i18n import _


def add_dss(
    pdf_bytes: bytes,
    *,
    certificates: Sequence[x509.Certificate] = (),
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> bytes:
    """Append a DSS dictionary to a signed PDF and return the new bytes.

    The DSS is added via a single incremental update; the original signature's
    byte range remains valid because no bytes before `startxref` are touched.

    If all three lists are empty, the input is returned unchanged.
    """
    if not (certificates or ocsp_responses or crls):
        return pdf_bytes

    last_xref_offset = _find_last_startxref(pdf_bytes)
    trailer = _parse_trailer(pdf_bytes, last_xref_offset)
    size = int(trailer["Size"])
    catalog_ref = _parse_indirect_ref(trailer["Root"])
    catalog_num, catalog_gen = catalog_ref

    # Read the existing catalog as a substring so we can splice /DSS in.
    catalog_body = _read_indirect_object(pdf_bytes, catalog_num, catalog_gen)

    output = bytearray(pdf_bytes)
    # PDFs may or may not end with a newline after %%EOF — normalise.
    if not output.endswith(b"\n"):
        output += b"\n"

    next_obj = size  # next free object number (after the highest existing)
    new_offsets: list[tuple[int, int]] = []  # [(obj_num, byte_offset), ...]

    def _emit_object(obj_num: int, body: bytes) -> None:
        offset = len(output)
        output.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        output.extend(body)
        if not body.endswith(b"\n"):
            output.extend(b"\n")
        output.extend(b"endobj\n")
        new_offsets.append((obj_num, offset))

    def _emit_stream(data: bytes) -> int:
        obj_num = next_obj_counter()
        body = (
            f"<< /Length {len(data)} >>\nstream\n".encode("ascii")
            + data
            + b"\nendstream\n"
        )
        _emit_object(obj_num, body)
        return obj_num

    def next_obj_counter() -> int:
        nonlocal next_obj
        n = next_obj
        next_obj += 1
        return n

    # Emit cert / OCSP / CRL streams and collect their refs.
    cert_refs: list[int] = []
    for c in certificates:
        cert_refs.append(_emit_stream(c.public_bytes(serialization.Encoding.DER)))
    ocsp_refs: list[int] = []
    for blob in ocsp_responses:
        ocsp_refs.append(_emit_stream(bytes(blob)))
    crl_refs: list[int] = []
    for blob in crls:
        crl_refs.append(_emit_stream(bytes(blob)))

    # Build the DSS dictionary.
    parts = ["<< /Type /DSS"]
    if cert_refs:
        parts.append("/Certs [ " + " ".join(f"{n} 0 R" for n in cert_refs) + " ]")
    if ocsp_refs:
        parts.append("/OCSPs [ " + " ".join(f"{n} 0 R" for n in ocsp_refs) + " ]")
    if crl_refs:
        parts.append("/CRLs [ "  + " ".join(f"{n} 0 R" for n in crl_refs)  + " ]")
    parts.append(">>")
    dss_num = next_obj_counter()
    _emit_object(dss_num, "\n".join(parts).encode("ascii"))

    # Rewrite the catalog with /DSS injected and write it back at the same
    # (catalog_num, catalog_gen) so the new entry overrides the old one.
    new_catalog = _inject_dss_into_catalog(catalog_body, dss_num)
    catalog_offset = len(output)
    output.extend(f"{catalog_num} {catalog_gen} obj\n".encode("ascii"))
    output.extend(new_catalog)
    if not new_catalog.endswith(b"\n"):
        output.extend(b"\n")
    output.extend(b"endobj\n")

    # Build the incremental xref. Subsections are sorted by first-obj-num.
    # The catalog override is one subsection; the new objects are contiguous.
    new_objects_sorted = sorted(new_offsets, key=lambda t: t[0])
    subsections: list[tuple[int, list[int]]] = []
    if new_objects_sorted:
        first_num = new_objects_sorted[0][0]
        subsections.append((first_num, [off for _, off in new_objects_sorted]))
    subsections.append((catalog_num, [catalog_offset]))
    # Merge / sort by first_num for the canonical layout.
    subsections.sort(key=lambda s: s[0])

    xref_offset = len(output)
    output.extend(b"xref\n")
    for first_num, offsets in subsections:
        output.extend(f"{first_num} {len(offsets)}\n".encode("ascii"))
        for off in offsets:
            output.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    new_size = next_obj  # highest obj num + 1 (we kept catalog_num below next_obj)
    if catalog_num >= new_size:
        new_size = catalog_num + 1

    output.extend(b"trailer\n")
    output.extend(
        f"<< /Size {new_size} /Root {catalog_num} {catalog_gen} R "
        f"/Prev {last_xref_offset} >>\n".encode("ascii")
    )
    output.extend(f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii"))

    return bytes(output)


# ---------------------------------------------------------------------------
# Internal: parse just enough of the PDF to find the catalog object & xref.
# We deliberately avoid pulling in pypdf/pyhanko for a focused minimal need.
# ---------------------------------------------------------------------------

def _find_last_startxref(pdf_bytes: bytes) -> int:
    # PDFs can have a 1KB-ish trailer; scan the tail.
    tail = pdf_bytes[-4096:]
    m = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", tail))
    if not m:
        raise ValueError(_("PDF: startxref not found"))
    return int(m[-1].group(1))


def _parse_trailer(pdf_bytes: bytes, xref_offset: int) -> dict[str, str]:
    """Return the trailer dict at `xref_offset` as a {name: raw_value} map.

    Values are returned as raw byte slices, e.g. "/Root 12 0 R" → "12 0 R".
    Handles both classic `xref/trailer` blocks and cross-reference streams.
    """
    chunk = pdf_bytes[xref_offset:xref_offset + 16384]
    if chunk[:4] == b"xref":
        # classic
        m = re.search(rb"trailer\s*<<", chunk)
        if not m:
            raise ValueError(_("PDF: trailer not found after xref"))
        return _parse_dict(chunk[m.end() - 2:])
    # cross-reference stream — parsed as an indirect object whose dict has
    # the same /Size, /Root, /Prev fields.
    obj_start = re.match(rb"\s*(\d+)\s+(\d+)\s+obj\s*<<", chunk)
    if not obj_start:
        raise ValueError(_("PDF: xref-stream not parsable (header)"))
    dict_start = obj_start.end() - 2
    return _parse_dict(chunk[dict_start:])


def _parse_dict(blob: bytes) -> dict[str, str]:
    """Tiny PDF dict parser. Only handles `<<` … `>>` and the simple
    name/value pairs we need (numbers, /name, x N R refs). Strings/arrays
    are returned as raw slices.

    Keys and values strictly alternate in a PDF dictionary, which is what lets
    a name *value* (`/Type /DSS`) be told apart from the next key.
    """
    if not blob.startswith(b"<<"):
        raise ValueError(_("dict not parsable (no <<)"))
    # Find the matching '>>' at depth 0.
    depth = 0
    i = 0
    while i < len(blob) - 1:
        if blob[i:i+2] == b"<<":
            depth += 1; i += 2
        elif blob[i:i+2] == b">>":
            depth -= 1; i += 2
            if depth == 0:
                end = i
                break
        else:
            i += 1
    else:
        raise ValueError(_("dict not closed"))
    inner = blob[2:end - 2].decode("latin-1")

    _DELIMS = " \t\r\n/<>[](){}%"

    def _name_end(text: str, i: int) -> int:
        """End of the name token starting at `i` (which points at its `/`)."""
        i += 1
        while i < len(text) and text[i] not in _DELIMS:
            i += 1
        return i

    pairs: dict[str, str] = {}
    j = 0
    while j < len(inner):
        if inner[j].isspace():
            j += 1
            continue
        if inner[j] != "/":
            j += 1  # stray token where a key was expected
            continue
        key_end = _name_end(inner, j)
        name = inner[j + 1:key_end]

        start = key_end
        while start < len(inner) and inner[start].isspace():
            start += 1
        if start < len(inner) and inner[start] == "/":
            # A name *value*, e.g. `/Type /Catalog`: one token, not a new key.
            end = _name_end(inner, start)
        else:
            # Anything else runs until the next key at nesting depth 0.
            end = start
            nest = 0
            while end < len(inner):
                pair = inner[end:end + 2]
                if pair == "<<" or inner[end] in "[(":
                    nest += 1
                    end += 2 if pair == "<<" else 1
                    continue
                if pair == ">>" or inner[end] in "])":
                    nest -= 1
                    end += 2 if pair == ">>" else 1
                    continue
                if nest == 0 and inner[end] == "/":
                    break
                end += 1
        pairs[name] = inner[start:end].strip()
        j = end
    return pairs


def _parse_indirect_ref(value: str) -> tuple[int, int]:
    """Parse a "N M R" style indirect reference."""
    m = re.match(r"\s*(\d+)\s+(\d+)\s+R\s*$", value)
    if not m:
        raise ValueError(_("indirect reference not parsable: {value!r}").format(value=value))
    return int(m.group(1)), int(m.group(2))


def _read_indirect_object(pdf_bytes: bytes, obj_num: int, gen: int) -> bytes:
    """Byte content (between `obj` and `endobj`) of the *last* definition of an
    indirect object.

    Last, not first: by the time we get here the PDF has already been through
    one incremental update — endesive registers the signature by appending a
    catalog that adds `/AcroForm` — so cloning the original definition would
    silently roll that back, leaving a signed file whose signature is no longer
    listed in the form. Later definitions win in a PDF, and so they must here.
    """
    start = _last_object_start(pdf_bytes, obj_num, gen)
    if start is None:
        raise ValueError(_("object {num} {gen} R not found in the PDF").format(
            num=obj_num, gen=gen))
    end = pdf_bytes.find(b"endobj", start)
    if end < 0:
        raise ValueError(_("object {num} {gen} R has no endobj").format(
            num=obj_num, gen=gen))
    return pdf_bytes[start:end].strip()


# ---------------------------------------------------------------------------
# Reading a DSS back out
# ---------------------------------------------------------------------------

@dataclass
class DssMaterial:
    """Validation material found in a PDF's `/DSS` dictionary."""
    certificates: list[x509.Certificate] = field(default_factory=list)
    ocsp_responses: list[bytes] = field(default_factory=list)
    crls: list[bytes] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.certificates or self.ocsp_responses or self.crls)


def read_dss(pdf_bytes: bytes) -> DssMaterial:
    """Read back the LT validation material a PAdES-LT file carries.

    We locate the `/DSS` reference directly rather than walking the xref
    chain: a later incremental update overrides an earlier one, so the *last*
    `/DSS` in the file is the one in force, and reaching it this way also works
    on files whose cross-reference data we cannot parse. Anything unreadable
    is skipped — this is validation material, and missing material degrades to
    "unavailable" rather than to an error.
    """
    material = DssMaterial()
    refs = list(re.finditer(rb"/DSS\s+(\d+)\s+(\d+)\s+R", pdf_bytes))
    if not refs:
        return material
    num, gen = int(refs[-1].group(1)), int(refs[-1].group(2))
    start = _last_object_start(pdf_bytes, num, gen)
    if start is None:
        return material
    i = _skip_ws(pdf_bytes, start)
    end = _dict_end(pdf_bytes, i) if pdf_bytes[i:i + 2] == b"<<" else None
    if end is None:
        return material
    try:
        dss = _parse_dict(pdf_bytes[i:end])
    except ValueError:
        return material

    for cert_num, cert_gen in _parse_refs(dss.get("Certs", "")):
        blob = read_stream_object(pdf_bytes, cert_num, cert_gen)
        if blob is None:
            continue
        try:
            material.certificates.append(x509.load_der_x509_certificate(blob))
        except Exception:  # noqa: BLE001 — skip an unreadable entry
            continue
    for ocsp_num, ocsp_gen in _parse_refs(dss.get("OCSPs", "")):
        blob = read_stream_object(pdf_bytes, ocsp_num, ocsp_gen)
        if blob is not None:
            material.ocsp_responses.append(blob)
    for crl_num, crl_gen in _parse_refs(dss.get("CRLs", "")):
        blob = read_stream_object(pdf_bytes, crl_num, crl_gen)
        if blob is not None:
            material.crls.append(blob)
    return material


def _parse_refs(value: str) -> list[tuple[int, int]]:
    """Every `N G R` reference inside an array like `[ 7 0 R 8 0 R ]`."""
    return [(int(n), int(g)) for n, g in re.findall(r"(\d+)\s+(\d+)\s+R", value)]


def read_stream_object(pdf_bytes: bytes, num: int, gen: int) -> bytes | None:
    """Decoded payload of stream object `num gen`, or None.

    Sliced by the declared `/Length` rather than by searching for `endstream`,
    so binary payloads containing that word survive; `/FlateDecode` is undone,
    any other filter yields None (we will not vouch for a payload we cannot
    decode).
    """
    start = _last_object_start(pdf_bytes, num, gen)
    if start is None:
        return None
    i = _skip_ws(pdf_bytes, start)
    if pdf_bytes[i:i + 2] != b"<<":
        return None
    end = _dict_end(pdf_bytes, i)
    if end is None:
        return None
    try:
        keys = _parse_dict(pdf_bytes[i:end])
    except ValueError:
        return None

    j = _skip_ws(pdf_bytes, end)
    if pdf_bytes[j:j + 6] != b"stream":
        return None
    data_start = j + 6
    if pdf_bytes[data_start:data_start + 2] == b"\r\n":
        data_start += 2
    elif pdf_bytes[data_start:data_start + 1] in (b"\n", b"\r"):
        data_start += 1

    raw_length = keys.get("Length", "").strip()
    if raw_length.isdigit() and data_start + int(raw_length) <= len(pdf_bytes):
        data = pdf_bytes[data_start:data_start + int(raw_length)]
    else:
        stop = pdf_bytes.find(b"endstream", data_start)
        if stop < 0:
            return None
        data = pdf_bytes[data_start:stop].rstrip(b"\r\n")
    return decode_stream(data, keys)


def decode_stream(data: bytes, keys: dict[str, str]) -> bytes | None:
    """Undo `/FlateDecode`; None for filters we cannot undo."""
    filters = keys.get("Filter", "").strip()
    if not filters:
        return data
    names = re.findall(r"/(\w+)", filters)
    if names == ["FlateDecode"]:
        try:
            return zlib.decompress(data)
        except zlib.error:
            return None
    return None


def _last_object_start(pdf_bytes: bytes, num: int, gen: int) -> int | None:
    """Offset just past the *last* `num gen obj` header, or None.

    Last, not first: incremental updates redefine object numbers, and the
    newest definition is the one in force.
    """
    pattern = re.compile(rb"(?<![0-9])%d\s+%d\s+obj\b" % (num, gen))
    found = list(pattern.finditer(pdf_bytes))
    return found[-1].end() if found else None


def _skip_ws(blob: bytes, i: int) -> int:
    while i < len(blob) and blob[i:i + 1].isspace():
        i += 1
    return i


def _dict_end(blob: bytes, i: int) -> int | None:
    """Index just past the `>>` matching the `<<` at `i`."""
    depth = 0
    while i < len(blob) - 1:
        pair = blob[i:i + 2]
        if pair == b"<<":
            depth += 1
            i += 2
        elif pair == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return None


def _inject_dss_into_catalog(catalog_body: bytes, dss_obj_num: int) -> bytes:
    """Return a new catalog body with `/DSS <dss> 0 R` added.

    Replaces an existing /DSS entry if present, otherwise inserts before
    the final `>>`.
    """
    text = catalog_body
    # Remove any existing /DSS entry (we're overriding it).
    text = re.sub(
        rb"/DSS\s+\d+\s+\d+\s+R\s*",
        b"",
        text,
    )
    new_entry = f"/DSS {dss_obj_num} 0 R ".encode("ascii")

    # Find the matching closing `>>` for the catalog dict.
    depth = 0
    close_at = None
    i = 0
    while i < len(text) - 1:
        if text[i:i+2] == b"<<":
            depth += 1; i += 2
        elif text[i:i+2] == b">>":
            depth -= 1
            if depth == 0:
                close_at = i
                break
            i += 2
        else:
            i += 1
    if close_at is None:
        # Catalog likely has no nested dicts that confused us — append
        # before a naked `>>` at the end.
        idx = text.rfind(b">>")
        if idx < 0:
            raise ValueError(_("catalog without closing >>"))
        close_at = idx
    return text[:close_at] + new_entry + text[close_at:]
