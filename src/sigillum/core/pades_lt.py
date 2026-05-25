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
    are returned as raw slices."""
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

    # Scan name tokens at depth 0; capture the slice until the next `/Name`
    # or end. We track depth across nested arrays/dicts.
    pairs: dict[str, str] = {}
    j = 0
    cur_name: str | None = None
    cur_start = 0
    nest = 0
    while j < len(inner):
        ch = inner[j]
        # Track nesting so a `/Name` inside e.g. an array isn't mistaken
        # for a top-level key.
        if inner[j:j+2] == "<<" or ch == "[" or ch == "(":
            nest += 1; j += (2 if inner[j:j+2] == "<<" else 1); continue
        if inner[j:j+2] == ">>" or ch == "]" or ch == ")":
            nest -= 1; j += (2 if inner[j:j+2] == ">>" else 1); continue
        if nest == 0 and ch == "/":
            if cur_name is not None:
                pairs[cur_name] = inner[cur_start:j].strip()
            # Read name token until whitespace/delimiter
            k = j + 1
            while k < len(inner) and inner[k] not in " \t\r\n/<>[](){}":
                k += 1
            cur_name = inner[j + 1:k]
            cur_start = k
            j = k
            continue
        j += 1
    if cur_name is not None:
        pairs[cur_name] = inner[cur_start:].strip()
    return pairs


def _parse_indirect_ref(value: str) -> tuple[int, int]:
    """Parse a "N M R" style indirect reference."""
    m = re.match(r"\s*(\d+)\s+(\d+)\s+R\s*$", value)
    if not m:
        raise ValueError(_("indirect reference not parsable: {value!r}").format(value=value))
    return int(m.group(1)), int(m.group(2))


def _read_indirect_object(pdf_bytes: bytes, obj_num: int, gen: int) -> bytes:
    """Return the byte content (between `obj` and `endobj`) of an indirect
    object. Best effort: walks the file looking for `<num> <gen> obj`."""
    pattern = re.compile(
        rf"\b{obj_num}\s+{gen}\s+obj\s*(.*?)\s*endobj"
        .encode("ascii"),
        re.DOTALL,
    )
    m = pattern.search(pdf_bytes)
    if not m:
        raise ValueError(_("object {num} {gen} R not found in the PDF").format(num=obj_num, gen=gen))
    return m.group(1)


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
