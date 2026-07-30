# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Does a PAdES signature actually cover the whole file?

A PDF signature commits to the byte ranges listed in its `/ByteRange` array,
not to "the file". Bytes appended afterwards — an *incremental update* — leave
the signature cryptographically intact while the document a reader sees is no
longer the document that was signed. That is the family of incremental-update
/ "shadow" tricks, and reporting such a file as plainly *valid* is precisely
how a verifier misleads its user.

Not every trailing revision is an attack, though. ETSI EN 319 142-1 builds
PAdES-LT that way: validation material goes into a `/DSS` dictionary appended
after the signature, which is exactly what `pades_lt.add_dss` (and therefore
`sigillum sign --level LT`) produces. So "does not reach EOF" is not by itself
evidence of tampering — the tail has to be *accounted for*.

`analyse()` reports three facts:

  - how many bytes the signatures cover, out of the file's size;
  - whether the widest signature reaches EOF (``whole_file``);
  - what the uncovered tail holds (``trailing``): nothing, validation data
    only, or something we could not account for.

Only the last case counts as a modification. Anything unparsable counts as
unaccounted-for on purpose: a tail we cannot read is not a clean bill of
health.

This is deliberately *not* a DocMDP policy engine. It answers "is every byte
either signed or provably validation data?", which is the question a signature
tool can answer honestly without a full PDF object model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, Sequence

from cryptography import x509

from ..i18n import _
from .pades_lt import _dict_end, _parse_dict, _skip_ws, decode_stream

# `Coverage.trailing` values.
TRAILING_NONE = "none"                        # the signature reaches EOF
TRAILING_VALIDATION_DATA = "validation-data"  # DSS / cert / OCSP / CRL only
TRAILING_UNKNOWN = "unknown"                  # unaccounted-for bytes


@dataclass
class Coverage:
    """How much of a PDF the signatures actually protect."""
    total_bytes: int
    signed_bytes: int
    whole_file: bool
    trailing: str = TRAILING_NONE
    detail: str = ""

    @property
    def unsigned_bytes(self) -> int:
        return max(0, self.total_bytes - self.signed_bytes)

    @property
    def modified(self) -> bool:
        """True when bytes outside every signature could not be accounted for.

        A DSS-only tail (PAdES-LT) is *not* a modification; junk, edits and
        unparsable tails are.
        """
        return not self.whole_file and self.trailing != TRAILING_VALIDATION_DATA

    def describe(self) -> str:
        if self.whole_file:
            return _("the signature covers the whole file")
        if self.trailing == TRAILING_VALIDATION_DATA:
            return _(
                "the signature covers {signed} of {total} bytes; the appended "
                "revision only adds validation data (DSS)"
            ).format(signed=self.signed_bytes, total=self.total_bytes)
        detail = f": {self.detail}" if self.detail else ""
        return _(
            "the document was modified after signing: {n} bytes are outside "
            "the signature{detail}"
        ).format(n=self.unsigned_bytes, detail=detail)


def analyse(pdf_bytes: bytes, byte_ranges: Sequence[Sequence[int]]) -> Coverage:
    """Classify how the signatures in `pdf_bytes` cover it.

    `byte_ranges` is the list of `/ByteRange` arrays, in file order — the same
    list `endesive.pdf.verify.PDFVerifier.is_signed()` collects. Each is
    ``[start1, len1, start2, len2]``: the signature covers
    ``[start1, start1+len1)`` and ``[start2, start2+len2)``, the hole in
    between being the `/Contents` placeholder holding the signature itself.
    """
    total = len(pdf_bytes)
    usable = [br for br in byte_ranges if len(br) >= 4]
    if not usable:
        return Coverage(
            total_bytes=total, signed_bytes=0, whole_file=False,
            trailing=TRAILING_UNKNOWN, detail=_("no readable /ByteRange"),
        )

    # With several signatures each covers its own revision; the one reaching
    # furthest into the file is the one that must land on EOF.
    widest = max(usable, key=lambda br: br[2] + br[3])
    start, len1, off2, len2 = widest[0], widest[1], widest[2], widest[3]
    signed_end = off2 + len2

    if start != 0:
        return Coverage(
            total_bytes=total, signed_bytes=signed_end, whole_file=False,
            trailing=TRAILING_UNKNOWN,
            detail=_("the signature does not start at byte 0"),
        )
    # The hole between the two ranges must be exactly the /Contents hex string.
    if not (pdf_bytes[start + len1:start + len1 + 1] == b"<"
            and pdf_bytes[off2 - 1:off2] == b">"):
        return Coverage(
            total_bytes=total, signed_bytes=signed_end, whole_file=False,
            trailing=TRAILING_UNKNOWN,
            detail=_("/ByteRange does not line up with the signature contents"),
        )
    if signed_end >= total:
        return Coverage(total_bytes=total, signed_bytes=total, whole_file=True)

    kind, detail = _classify_tail(pdf_bytes, signed_end)
    return Coverage(
        total_bytes=total, signed_bytes=signed_end, whole_file=False,
        trailing=kind, detail=detail,
    )


# ---------------------------------------------------------------------------
# Tail classification
# ---------------------------------------------------------------------------

def _classify_tail(pdf_bytes: bytes, start: int) -> tuple[str, str]:
    """Account for every object defined after `start`."""
    region = pdf_bytes[start:]
    if not region.strip():
        return TRAILING_NONE, ""
    try:
        objects = list(_iter_objects(region))
    except _ParseError as ex:
        return TRAILING_UNKNOWN, str(ex)
    if not objects:
        return TRAILING_UNKNOWN, _(
            "{n} bytes appended after the signature, with no PDF object in them"
        ).format(n=len(region))

    for num, _gen, dict_text, stream in objects:
        reason = _account_for(pdf_bytes, start, num, _gen, dict_text, stream)
        if reason:
            return TRAILING_UNKNOWN, reason
    return TRAILING_VALIDATION_DATA, ""


def _account_for(
    pdf_bytes: bytes,
    start: int,
    num: int,
    gen: int,
    dict_text: bytes | None,
    stream: bytes | None,
) -> str | None:
    """Return None when this appended object is validation data, else why not."""
    keys = _keys(dict_text)
    kind = keys.get("Type", "").strip()

    # The DSS dictionary itself, and the per-signature VRI dictionaries.
    if kind == "/DSS" or (keys and set(keys) <= {"Type", "Certs", "CRLs", "OCSPs", "VRI"}):
        return None
    if _looks_like_vri(keys):
        return None
    # Cross-reference streams are structure, not content.
    if kind == "/XRef":
        return None
    # The catalog is rewritten to point at the DSS — and to nothing else.
    if kind == "/Catalog":
        return _catalog_diff(pdf_bytes, start, num, gen, dict_text)
    # Certificates, OCSP responses and CRLs travel as plain streams.
    if stream is not None and _is_validation_blob(stream, keys):
        return None

    return _(
        "object {num} in the appended revision is not validation data"
    ).format(num=num)


def _looks_like_vri(keys: dict[str, str]) -> bool:
    """A `/VRI` dictionary, or one of the per-signature entries inside it.

    The container maps 40-hex signature digests to entries; each entry holds
    `/Cert`, `/CRL`, `/OCSP`, `/TU`, `/TS`.
    """
    names = set(keys) - {"Type"}
    if not names:
        return False
    if names <= {"Cert", "CRL", "OCSP", "TU", "TS"}:
        return True
    return all(re.fullmatch(r"[0-9A-Fa-f]{40}", n) for n in names)


def _catalog_diff(
    pdf_bytes: bytes, start: int, num: int, gen: int, dict_text: bytes | None,
) -> str | None:
    """Allow a catalog rewrite only when `/DSS` is the sole difference."""
    if dict_text is None:
        return _("the appended revision replaces the document catalog")
    previous = _last_object_dict(pdf_bytes[:start], num, gen)
    if previous is None:
        return _("the appended revision replaces the document catalog")
    try:
        old = _parse_dict(previous)
        new = _parse_dict(dict_text)
    except ValueError:
        return _("the appended catalog is not parsable")

    added = set(new) - set(old) - {"DSS"}
    if added:
        return _("the appended catalog adds {keys}").format(
            keys=", ".join("/" + k for k in sorted(added)))
    removed = set(old) - set(new)
    if removed:
        return _("the appended catalog drops {keys}").format(
            keys=", ".join("/" + k for k in sorted(removed)))
    changed = sorted(
        k for k in set(new) & set(old)
        if k != "DSS" and _norm(new[k]) != _norm(old[k])
    )
    if changed:
        return _("the appended catalog changes {keys}").format(
            keys=", ".join("/" + k for k in changed))
    return None


def _norm(value: str) -> str:
    return " ".join(value.split())


def _is_validation_blob(data: bytes, keys: dict[str, str]) -> bool:
    """True when a stream's payload is an X.509 cert, a CRL or an OCSP response."""
    raw = decode_stream(data, keys)
    if raw is None:
        return False
    from .revocation import load_ocsp_response

    for loader in (x509.load_der_x509_certificate, x509.load_der_x509_crl):
        try:
            loader(raw)
            return True
        except Exception:  # noqa: BLE001 — try the next shape
            pass
    return load_ocsp_response(raw) is not None


# ---------------------------------------------------------------------------
# Minimal sequential object walker
#
# We deliberately do not follow the xref: an appended revision's objects sit
# physically in the tail, so walking the bytes finds them all — including
# objects an xref conveniently forgets to mention.
# ---------------------------------------------------------------------------

class _ParseError(Exception):
    pass


_OBJ_RE = re.compile(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b")


def _iter_objects(
    region: bytes,
) -> Iterator[tuple[int, int, bytes | None, bytes | None]]:
    """Yield `(num, gen, dict_bytes, stream_bytes)` for each object in `region`.

    Walking sequentially (rather than regex-scanning the whole buffer) matters:
    stream payloads are skipped by declared `/Length`, so binary data that
    happens to contain `N 0 obj` cannot be mistaken for an object header.
    """
    pos = 0
    while True:
        match = _OBJ_RE.search(region, pos)
        if match is None:
            return
        num, gen = int(match.group(1)), int(match.group(2))
        i = _skip_ws(region, match.end())

        dict_text: bytes | None = None
        if region[i:i + 2] == b"<<":
            end = _dict_end(region, i)
            if end is None:
                raise _ParseError(_(
                    "object {num} in the appended revision has an unterminated dictionary"
                ).format(num=num))
            dict_text = region[i:end]
            i = end

        stream: bytes | None = None
        j = _skip_ws(region, i)
        if region[j:j + 6] == b"stream":
            data_start = j + 6
            if region[data_start:data_start + 2] == b"\r\n":
                data_start += 2
            elif region[data_start:data_start + 1] in (b"\n", b"\r"):
                data_start += 1
            length = _declared_length(dict_text)
            if length is not None and data_start + length <= len(region):
                stream = region[data_start:data_start + length]
                i = data_start + length
            else:
                end_stream = region.find(b"endstream", data_start)
                if end_stream < 0:
                    raise _ParseError(_(
                        "object {num} in the appended revision has a stream "
                        "without endstream"
                    ).format(num=num))
                stream = region[data_start:end_stream]
                i = end_stream

        yield num, gen, dict_text, stream

        end_obj = region.find(b"endobj", i)
        if end_obj < 0:
            return
        pos = end_obj + len(b"endobj")


def _keys(dict_text: bytes | None) -> dict[str, str]:
    if not dict_text:
        return {}
    try:
        return _parse_dict(dict_text)
    except ValueError:
        return {}


def _declared_length(dict_text: bytes | None) -> int | None:
    raw = _keys(dict_text).get("Length", "").strip()
    return int(raw) if raw.isdigit() else None


def _last_object_dict(blob: bytes, num: int, gen: int) -> bytes | None:
    """Dictionary of the *last* definition of `num gen obj` in `blob`.

    Last, not first: an object may have been redefined by earlier incremental
    updates, and the newest definition is the one in force.
    """
    pattern = re.compile(rb"(?<![0-9])%d\s+%d\s+obj\b" % (num, gen))
    found = list(pattern.finditer(blob))
    if not found:
        return None
    i = _skip_ws(blob, found[-1].end())
    if blob[i:i + 2] != b"<<":
        return None
    end = _dict_end(blob, i)
    return blob[i:end] if end is not None else None
