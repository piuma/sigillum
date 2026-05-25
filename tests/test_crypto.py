# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Encryption roundtrip tests — symmetric (4 algos) and asymmetric (CMS)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.crypto import (
    SYMMETRIC_NAMES,
    decrypt_asymmetric,
    decrypt_symmetric,
    detect_format,
    encrypt_asymmetric,
    encrypt_symmetric,
)

from fixtures import write_fixture_files


SAMPLE = b"Contenuto da cifrare.\n" + b"x" * 4096 + b"\nFine.\n"


def test_symmetric_roundtrip_all_algorithms():
    for algo in SYMMETRIC_NAMES:
        blob = encrypt_symmetric(SAMPLE, "passw0rd!", algorithm=algo)
        assert blob.startswith(b"SIGILLUM"), f"{algo}: header mancante"
        # Ciphertext must be different from plaintext.
        assert SAMPLE not in blob, f"{algo}: il plaintext appare nel cifrato"
        # Detect should return symmetric.
        assert detect_format(blob) == "symmetric"
        # Roundtrip.
        recovered = decrypt_symmetric(blob, "passw0rd!")
        assert recovered == SAMPLE, f"{algo}: roundtrip non identico"
        print(f"OK {algo}: {len(blob)} byte (+{len(blob) - len(SAMPLE)} overhead)")


def test_symmetric_wrong_password_fails():
    blob = encrypt_symmetric(SAMPLE, "rightpass")
    try:
        decrypt_symmetric(blob, "wrongpass")
    except ValueError as ex:
        assert "password" in str(ex).lower() or "manomesso" in str(ex).lower()
        print(f"OK wrong-password rejected: {ex}")
    else:
        raise AssertionError("decifratura con password sbagliata avrebbe dovuto fallire")


def test_symmetric_tampering_detected():
    blob = bytearray(encrypt_symmetric(SAMPLE, "passw0rd"))
    # Flip a bit somewhere in the ciphertext region (after the IV).
    blob[-10] ^= 0x01
    try:
        decrypt_symmetric(bytes(blob), "passw0rd")
    except ValueError as ex:
        print(f"OK tampering detected: {ex}")
    else:
        raise AssertionError("manomissione non rilevata")


def test_asymmetric_roundtrip_with_pkcs12():
    """Encrypt to a PKCS#12 cert, decrypt with its private key."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _pdf, p12, chain = write_fixture_files(tmp, password="test")
        cred = FileProvider(p12).unlock(str(p12), "test")

        blob = encrypt_asymmetric(SAMPLE, cred.certificate)
        # The container starts with an ASN.1 SEQUENCE tag.
        assert blob.startswith(b"\x30")
        assert detect_format(blob) == "asymmetric"
        # CMS marker for EnvelopedData: OID 1.2.840.113549.1.7.3 encodes as
        # \x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03 — assert it's present.
        assert b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03" in blob

        recovered = decrypt_asymmetric(blob, cred)
        assert recovered == SAMPLE
        print(f"OK asymmetric roundtrip: {len(blob)} byte")


def test_asymmetric_with_wrong_cert_fails():
    """Encrypt to cert A, try to decrypt with cred B → rifiuta."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Two independent PKI sets.
        _pdf_a, p12_a, _chain_a = write_fixture_files(tmp, password="test")
        Path(p12_a).rename(tmp / "a.p12")
        (tmp / "b").mkdir()
        _pdf_b, p12_b, _chain_b = write_fixture_files(tmp / "b", password="test")

        cred_a = FileProvider(tmp / "a.p12").unlock(str(tmp / "a.p12"), "test")
        cred_b = FileProvider(p12_b).unlock(str(p12_b), "test")

        blob = encrypt_asymmetric(SAMPLE, cred_a.certificate)
        try:
            decrypt_asymmetric(blob, cred_b)
        except ValueError as ex:
            assert "recipient" in str(ex).lower() or "not encrypted for" in str(ex).lower()
            print(f"OK wrong-cert rejected: {ex}")
        else:
            raise AssertionError("decryption with wrong cert should have failed")


def test_detect_format_unknown():
    assert detect_format(b"not encrypted") == "unknown"
    assert detect_format(b"\x30\x82\x01\x00") == "unknown"  # ASN.1 but not enveloped
    print("OK unknown format detected")


if __name__ == "__main__":
    test_symmetric_roundtrip_all_algorithms()
    test_symmetric_wrong_password_fails()
    test_symmetric_tampering_detected()
    test_asymmetric_roundtrip_with_pkcs12()
    test_asymmetric_with_wrong_cert_fails()
    test_detect_format_unknown()
    print("\nTutti i test crypto passati.")
