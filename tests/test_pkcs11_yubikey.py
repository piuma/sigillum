# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Test live PKCS#11 con YubiKey (slot PIV 9c).

Prerequisiti:
    - YubiKey inserita
    - Lo slot 9c (Digital Signature) deve contenere una coppia chiave+cert.
      Per provisionare uno slot di test:
        yubico-piv-tool -a generate -s 9c -A RSA2048 -o /tmp/yk-pub.pem
        yubico-piv-tool -a verify-pin -a selfsign-certificate -s 9c \\
            -S '/CN=Sigillum Test YubiKey/O=Test/C=IT' \\
            -i /tmp/yk-pub.pem -o /tmp/yk-cert.pem
        yubico-piv-tool -a import-certificate -s 9c -i /tmp/yk-cert.pem

PIN: passato via env var SIGILLUM_PIN. Esempio:
    SIGILLUM_PIN=123456 .venv/bin/python tests/test_pkcs11_yubikey.py
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.hardware

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import PKCS11Provider
from sigillum.core.signer import CAdESSigner, PAdESSigner, SignatureLevel, SignOptions
from sigillum.core.verifier import CAdESVerifier, PAdESVerifier

from fixtures import make_minimal_pdf


YKCS11_LIB = "/usr/lib64/libykcs11.so.2"
# CKA_ID of the PIV slot 9c on YubiKey is always 0x02 (per yubico-piv-tool docs).
SIG_SLOT_CKA_ID = "02"
# Heuristic for picking the user cert on slot 9c: skip the YubiKey-emitted
# attestation cert (its subject contains "Attestation").


def _need_pin() -> str:
    """Il PIN dall'ambiente, o skip.

    `pytest.skip` e non `sys.exit`: quest'ultimo terminava l'intero processo,
    e pytest lo registrava come *fallimento* del test in corso — una suite
    rossa su qualunque macchina senza YubiKey, dove invece questi test vanno
    semplicemente saltati.
    """
    pin = os.environ.get("SIGILLUM_PIN")
    if not pin:
        pytest.skip(
            "variabile d'ambiente SIGILLUM_PIN non impostata; riavvia con: "
            "SIGILLUM_PIN=<pin> pytest tests/test_pkcs11_yubikey.py"
        )
    return pin


def _signing_cert(provider: PKCS11Provider):
    """Il cert utente sullo slot di firma, o skip spiegando cosa manca.

    Separato dal test che lo esercita: prima i due test di firma chiamavano
    `test_list_certs_on_yubikey()` per averne il valore di ritorno, cosa che
    pytest segnala (`PytestReturnNotNoneWarning`) perché un test deve
    asserire, non restituire.
    """
    try:
        certs = provider.list_certificates()
    except Exception as exc:  # noqa: BLE001 — nessun token: salta, non fallire
        pytest.skip(f"nessun token PKCS#11 leggibile tramite {YKCS11_LIB}: {exc}")
    target = next(
        (c for c in certs
         if c.id.startswith(f"{SIG_SLOT_CKA_ID}:") and "Attestation" not in c.subject),
        None,
    )
    if target is None:
        pytest.skip(
            f"il cert utente sullo slot di firma (CKA_ID={SIG_SLOT_CKA_ID}) non è "
            "presente; vedi le istruzioni in cima al file per provisionarlo"
        )
    return target


def test_list_certs_on_yubikey():
    provider = PKCS11Provider(YKCS11_LIB)
    try:
        target = _signing_cert(provider)
        assert target.subject, "il cert sullo slot di firma non ha un subject"
        print(f"OK: slot di firma trovato → {target.subject} (id={target.id})")
    finally:
        provider.close()


def test_pades_sign_with_yubikey():
    pin = _need_pin()

    provider = PKCS11Provider(YKCS11_LIB)
    try:
        target = _signing_cert(provider)
        cred = provider.unlock(target.id, pin)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            pdf_path = tmp / "sample.pdf"
            pdf_path.write_bytes(make_minimal_pdf())
            signed_path = tmp / "sample-signed.pdf"

            PAdESSigner().sign(
                input_path=pdf_path,
                output_path=signed_path,
                credential=cred,
                options=SignOptions(level=SignatureLevel.B, reason="YubiKey test"),
            )

            assert signed_path.exists()
            assert b"/Sig" in signed_path.read_bytes()

            # Verifica crittografica (cert_trusted sarà False: self-signed YubiKey)
            result = PAdESVerifier().verify(signed_path)
            s = result.signers[0]
            assert s.hash_valid is True, f"hash KO: {s.errors}"
            assert s.signature_valid is True, f"firma KO: {s.errors}"
            print(
                f"OK PAdES YubiKey: subject={s.subject!r}, "
                f"hash={s.hash_valid}, sig={s.signature_valid}"
            )
    finally:
        provider.close()


def test_cades_sign_with_yubikey():
    pin = _need_pin()

    provider = PKCS11Provider(YKCS11_LIB)
    try:
        target = _signing_cert(provider)
        cred = provider.unlock(target.id, pin)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "doc.txt"
            src.write_bytes(b"Firmato con YubiKey.\n")
            p7m = tmp / "doc.txt.p7m"

            CAdESSigner().sign(
                input_path=src,
                output_path=p7m,
                credential=cred,
                options=SignOptions(level=SignatureLevel.B),
            )

            result = CAdESVerifier().verify(p7m)
            s = result.signers[0]
            assert s.hash_valid is True
            assert s.signature_valid is True
            print(
                f"OK CAdES YubiKey: subject={s.subject!r}, "
                f"hash={s.hash_valid}, sig={s.signature_valid}"
            )
    finally:
        provider.close()


if __name__ == "__main__":
    # Eseguito come script (vedi il docstring in cima): fuori da pytest
    # `pytest.skip` solleva un'eccezione, che qui traduciamo nel messaggio e
    # nell'uscita pulita che prima produceva `sys.exit(0)`.
    try:
        test_list_certs_on_yubikey()
        test_pades_sign_with_yubikey()
        test_cades_sign_with_yubikey()
    except pytest.skip.Exception as exc:
        print(f"\nSKIP: {exc}")
        sys.exit(0)
    print("\nTest YubiKey completati.")
