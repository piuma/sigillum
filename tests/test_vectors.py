# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Run the vector corpus through the verifier and check every verdict.

`vectors.py` builds the artifacts and states what each one should produce;
this file is the harness. One test per vector, so a regression names the case
it broke rather than reporting "assert False" somewhere in a loop.
"""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.verifier import CAdESVerifier, PAdESVerifier, XAdESVerifier
from vectors import Vector, build_corpus

_VERIFIERS = {
    "pades": PAdESVerifier,
    "cades": CAdESVerifier,
    "xades": XAdESVerifier,
}

# Built once: generating two test PKIs and a dozen signatures is the expensive
# part, and every vector is read-only.
_ROOT = Path(tempfile.mkdtemp(prefix="sigillum-vectors-"))
atexit.register(shutil.rmtree, _ROOT, ignore_errors=True)
CORPUS = build_corpus(_ROOT)


def verify(vector: Vector):
    verifier = _VERIFIERS[vector.fmt](CORPUS.trust_store(vector.trust))
    return verifier.verify(vector.path, vector.original)


@pytest.mark.parametrize("vector", CORPUS.vectors, ids=lambda v: v.vid)
def test_vector(vector: Vector):
    result = verify(vector)
    expect = vector.expect
    why = vector.why

    assert len(result.signers) == expect.signers, f"{why} — signer count"
    assert result.all_valid is expect.all_valid, (
        f"{why} — all_valid; errors={result.errors}")

    if expect.document_errors is not None:
        assert bool(result.errors) is expect.document_errors, (
            f"{why} — document errors: {result.errors}")

    coverage = result.coverage
    if expect.coverage_whole_file is not None:
        assert coverage is not None, f"{why} — expected coverage data"
        assert coverage.whole_file is expect.coverage_whole_file, (
            f"{why} — coverage.whole_file ({coverage.describe()})")
    if expect.coverage_modified is not None:
        assert coverage is not None, f"{why} — expected coverage data"
        assert coverage.modified is expect.coverage_modified, (
            f"{why} — coverage.modified ({coverage.describe()})")

    if not result.signers:
        return
    signer = result.signers[0]
    for attribute in ("hash_valid", "signature_valid", "cert_trusted", "revoked"):
        expected = getattr(expect, attribute)
        if expected is not None:
            assert getattr(signer, attribute) is expected, f"{why} — {attribute}"
    if expect.revocation is not None:
        assert signer.revocation.status.value == expect.revocation, (
            f"{why} — revocation: {signer.revocation.describe()}")


@pytest.mark.parametrize("vector", CORPUS.vectors, ids=lambda v: v.vid)
def test_vector_through_the_cli(vector: Vector):
    """Same verdict through `sigillum verify`, in a fresh interpreter.

    Worth the subprocess: this is the path a user actually takes, and it starts
    from a clean import state. A lazily-imported module that registers ASN.1
    OIDs, for instance, gets imported too late here and nowhere else — which is
    exactly the bug this test was written after.
    """
    trust = {
        "ca": CORPUS.root / "trust" / "ca.pem",
        "intruder": CORPUS.root / "trust" / "intruder-ca.pem",
        "none": None,
    }[vector.trust]
    command = [sys.executable, "-m", "sigillum", "verify", str(vector.path)]
    if trust is not None:
        command += ["--trusted", str(trust)]

    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    env["LANGUAGE"] = env["LANG"] = "C"
    process = subprocess.run(command, capture_output=True, text=True, env=env)

    expected_code = 0 if vector.expect.all_valid else 3
    assert process.returncode == expected_code, (
        f"{vector.why} — exit {process.returncode}, expected {expected_code}\n"
        f"{process.stdout}{process.stderr}")
    if vector.expect.revocation == "revoked":
        assert "REVOKED" in process.stdout, (
            f"{vector.why} — the CLI must say the certificate was revoked\n"
            f"{process.stdout}")
    if vector.expect.coverage_modified:
        assert "MODIFIED AFTER SIGNING" in process.stdout, (
            f"{vector.why} — the CLI must say the file was modified\n"
            f"{process.stdout}")


def test_every_signer_matches_the_verdict():
    """With several signatures, `all_valid` must reflect all of them."""
    vector = CORPUS.by_id("009-pades-two-signatures")
    result = verify(vector)
    assert len(result.signers) == 2
    assert all(s.valid for s in result.signers)


def test_corpus_covers_every_format():
    formats = {vector.fmt for vector in CORPUS.vectors}
    assert formats == {"pades", "cades", "xades"}


def test_corpus_ids_are_unique_and_ordered():
    ids = [vector.vid for vector in CORPUS.vectors]
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids), "vector ids double as the reading order"


def test_rejections_outnumber_acceptances():
    """A corpus that mostly says yes is not testing a verifier."""
    rejected = [v for v in CORPUS.vectors if not v.expect.all_valid]
    assert len(rejected) > len(CORPUS.vectors) / 2


if __name__ == "__main__":
    failures = 0
    for candidate in CORPUS.vectors:
        try:
            test_vector(candidate)
            print(f"OK   {candidate.vid}")
        except AssertionError as ex:
            failures += 1
            print(f"FAIL {candidate.vid}: {ex}")
    print(f"\n{len(CORPUS.vectors) - failures}/{len(CORPUS.vectors)} vectors OK")
    raise SystemExit(1 if failures else 0)
