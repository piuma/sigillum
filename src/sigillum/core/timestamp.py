# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Standalone time-stamping for files (RFC 3161 + ETSI TS 119 422).

Two output formats:

  - **TSR** (`.tsr`) — just the DER-encoded TimeStampToken returned by the
    TSA. Contains the hash of the original file and the TSA's signature
    over it, but NOT the file itself. To verify, the original file must
    be supplied alongside.

  - **TSD** (`.tsd`) — an ETSI TS 119 422 *TimeStampedData* envelope: a
    CMS-wrapped structure that holds both the original file's bytes and
    the TimeStampToken. Self-contained: verification needs only the .tsd.

This module talks to the TSA directly (it doesn't go through endesive's
signing path, which is signer-side). The HTTP request is the standard
RFC 3161 `application/timestamp-query` POST, optionally with HTTP Basic
Auth credentials for qualified Italian TSAs.
"""
from __future__ import annotations

import hashlib
import os
import time
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import requests
from asn1crypto import algos, cms, core, tsp
from cryptography import x509

from ..i18n import _
from .verifier import SignerInfo, VerifyResult, _verify_timestamp


# id-ct-timestampedData = 1.2.840.113549.1.9.16.1.31 (ETSI TS 119 422 / RFC 5544).
# asn1crypto's tsp module already defines TimeStampedData, MetaData, Evidence,
# TimeStampTokenEvidence, and TimeStampAndCRL, and registers the OID against
# ContentInfo._oid_specs — we reuse them verbatim for full interop.
_TIMESTAMPED_DATA_NAME = "timestamped_data"


# ----- HTTP round-trip with the TSA -----

@dataclass
class TSAConfig:
    url: str
    username: str | None = None
    password: str | None = None


def request_timestamp_token(
    file_bytes: bytes,
    tsa: TSAConfig,
    *,
    hash_algorithm: str = "sha256",
    timeout: float = 30.0,
) -> bytes:
    """Make an RFC 3161 request and return the DER-encoded TimeStampToken.

    The returned bytes are exactly the content of a `.tsr` file.
    """
    digest = hashlib.new(hash_algorithm, file_bytes).digest()
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": digest,
        }),
        # Nonce is a 64-bit random-ish int to prevent replay across requests.
        "nonce": int(time.time() * 1_000_000) ^ int.from_bytes(os.urandom(4), "big"),
        "cert_req": True,
    })
    headers = {"Content-Type": "application/timestamp-query"}
    if tsa.username and tsa.password:
        auth = b64encode(f"{tsa.username}:{tsa.password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {auth}"

    resp = requests.post(tsa.url, data=req.dump(), headers=headers, timeout=timeout)
    resp.raise_for_status()

    tsp_resp = tsp.TimeStampResp.load(resp.content)
    status = tsp_resp["status"]["status"].native
    if status != "granted":
        info = tsp_resp["status"]
        reason = info["status_string"].native if info["status_string"] is not None else ""
        raise RuntimeError(_("TSA rejected the request: status={status!r} ({reason})").format(
            status=status, reason=reason
        ))
    return tsp_resp["time_stamp_token"].dump()


# ----- TSR / TSD producers -----

def make_tsr(input_path: Path, output_path: Path, tsa: TSAConfig) -> Path:
    """Timestamp a file and save just the DER TimeStampToken (.tsr)."""
    token_der = request_timestamp_token(input_path.read_bytes(), tsa)
    output_path.write_bytes(token_der)
    return output_path


def make_tsd(input_path: Path, output_path: Path, tsa: TSAConfig) -> Path:
    """Timestamp a file and save an ETSI TS 119 422 TimeStampedData envelope.

    The envelope embeds both the original content and the TimeStampToken,
    so verification doesn't need access to the original file separately.
    """
    file_bytes = input_path.read_bytes()
    token_der = request_timestamp_token(file_bytes, tsa)

    # `time_stamp` in TimeStampAndCRL is modelled as EncapsulatedContentInfo
    # by asn1crypto. The raw TST bytes (which are RFC 3161 ContentInfo) parse
    # cleanly into ECI and round-trip identically, so this is the simplest
    # way to embed the TST without re-encoding it.
    tst_eci = cms.EncapsulatedContentInfo.load(token_der)
    tsd = tsp.TimeStampedData({
        "version": "v1",
        "meta_data": tsp.MetaData({
            # hash_protected=False means metadata are not part of the imprint
            # (the TST only signs the raw content). Matches Aruba/InfoCert.
            "hash_protected": False,
            "file_name": input_path.name,
        }),
        "content": core.OctetString(file_bytes),
        "temporal_evidence": tsp.Evidence(
            name="tst_evidence",
            value=tsp.TimeStampTokenEvidence([
                tsp.TimeStampAndCRL({"time_stamp": tst_eci}),
            ]),
        ),
    })
    ci = cms.ContentInfo({
        "content_type": _TIMESTAMPED_DATA_NAME,
        "content": tsd,
    })
    output_path.write_bytes(ci.dump())
    return output_path


# ----- Verification -----

def _verify_token_against_bytes(
    token_der: bytes,
    original_bytes: bytes,
    tsa_trusted_certs: Sequence[x509.Certificate],
) -> SignerInfo:
    """Common verification path used by both TSR and TSD.

    Re-uses the helpers in `verifier.py` so the result objects look the same
    as for embedded timestamps in PAdES/CAdES/XAdES signatures.
    """
    info = SignerInfo()

    # Re-use `_verify_timestamp` which validates message_imprint, the CMS
    # signature, and the TSA cert chain. It expects the SignedData inside
    # the TimeStampToken (a ContentInfo); for a standalone timestamp the
    # "signer signature" passed in is the original file's bytes.
    tst_ci = cms.ContentInfo.load(token_der)
    signed_data = tst_ci["content"]
    _verify_timestamp(signed_data, original_bytes, list(tsa_trusted_certs), info)

    # The helper reports hash mismatch via info.errors; promote to flags so
    # SignerInfo.valid reflects the actual state.
    info.hash_valid = info.timestamp is not None and not any(
        "message_imprint" in e or "imprint" in e for e in info.errors
    )
    info.signature_valid = info.timestamp is not None and not any(
        "firma del TSA" in e or "verifica firma TSA" in e for e in info.errors
    )
    info.cert_trusted = info.timestamp_trusted
    return info


def verify_tsr(
    tsr_path: Path,
    original_path: Path,
    *,
    tsa_trusted_certs: Sequence[x509.Certificate] = (),
) -> VerifyResult:
    """Verify a .tsr against the (separately provided) original file."""
    token_der = tsr_path.read_bytes()
    info = _verify_token_against_bytes(
        token_der, original_path.read_bytes(), tsa_trusted_certs,
    )
    return VerifyResult(signers=[info])


def verify_tsd(
    tsd_path: Path,
    *,
    tsa_trusted_certs: Sequence[x509.Certificate] = (),
) -> VerifyResult:
    """Verify a .tsd envelope: extract embedded content + token + check."""
    ci = cms.ContentInfo.load(tsd_path.read_bytes())
    if ci["content_type"].native != _TIMESTAMPED_DATA_NAME:
        return VerifyResult(errors=[_("not a TSD file (wrong content_type)")])
    tsd = ci["content"]
    content_field = tsd["content"]
    if content_field is None or isinstance(content_field, core.Void):
        return VerifyResult(errors=[_("TSD with no embedded content")])
    content_bytes = content_field.native
    evidence = tsd["temporal_evidence"]
    if evidence.name != "tst_evidence":
        return VerifyResult(errors=[_("unsupported evidence: {name}").format(name=evidence.name)])
    tst_seq = evidence.chosen
    if len(tst_seq) == 0:
        return VerifyResult(errors=[_("TSD with no TimeStampToken")])
    token_der = tst_seq[0]["time_stamp"].dump()
    info = _verify_token_against_bytes(token_der, content_bytes, tsa_trusted_certs)
    return VerifyResult(signers=[info])


def extract_tsd_content(tsd_path: Path) -> tuple[str | None, bytes]:
    """Read filename + content from a .tsd envelope (no verification)."""
    ci = cms.ContentInfo.load(tsd_path.read_bytes())
    if ci["content_type"].native != _TIMESTAMPED_DATA_NAME:
        raise ValueError(_("not a TSD file"))
    tsd = ci["content"]
    content_field = tsd["content"]
    if content_field is None or isinstance(content_field, core.Void):
        raise ValueError(_("TSD with no embedded content"))
    meta = tsd["meta_data"]
    fname = None
    if meta is not None and not isinstance(meta, core.Void):
        fn = meta["file_name"]
        if fn is not None and not isinstance(fn, core.Void):
            fname = fn.native
    return fname, content_field.native
