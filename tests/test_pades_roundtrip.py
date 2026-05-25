# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Roundtrip: firma un PDF con cert self-signed e verifica la firma.

Il cert non è trusted, quindi `cert_trusted` sarà False ma hash_valid +
signature_valid devono essere True — la firma è crittograficamente valida.
Aggiungendo il cert tra i trusted_certs anche `cert_trusted` diventa True.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import PAdESSigner, SignatureLevel, SignOptions
from sigillum.core.verifier import PAdESVerifier

from fixtures import write_fixture_files


def _sign(tmp: Path):
    pdf_path, p12_path, chain = write_fixture_files(tmp, password="test")
    provider = FileProvider(p12_path)
    cred = provider.unlock(str(p12_path), "test")
    signed_path = tmp / "sample-signed.pdf"
    PAdESSigner().sign(
        input_path=pdf_path,
        output_path=signed_path,
        credential=cred,
        options=SignOptions(level=SignatureLevel.B, reason="Roundtrip"),
    )
    return signed_path, chain


def test_verify_untrusted_signature_is_cryptographically_valid():
    with tempfile.TemporaryDirectory() as td:
        signed_path, _ = _sign(Path(td))
        result = PAdESVerifier().verify(signed_path)

        assert len(result.signers) == 1, "atteso esattamente 1 firmatario"
        s = result.signers[0]
        assert s.hash_valid is True, f"hash non valido: {s.errors}"
        assert s.signature_valid is True, f"firma non valida: {s.errors}"
        assert s.cert_trusted is False, "cert self-signed non dovrebbe essere trusted"
        assert s.valid is False
        assert "Sigillum Test Signer" in s.subject
        print(f"OK (untrusted): subject={s.subject!r}")


def test_verify_with_ca_in_trust_store():
    with tempfile.TemporaryDirectory() as td:
        signed_path, chain = _sign(Path(td))
        # Trust the test CA — the signer cert chains up to it.
        result = PAdESVerifier(trusted_certs=[chain.ca_cert]).verify(signed_path)

        s = result.signers[0]
        assert s.hash_valid is True
        assert s.signature_valid is True
        assert s.cert_trusted is True, f"cert dovrebbe essere trusted: {s.errors}"
        assert s.valid is True
        assert result.all_valid is True
        print(f"OK (trusted): subject={s.subject!r}, valid={s.valid}")


def test_verify_detects_tampering():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        signed_path, _ = _sign(tmp)
        # Modifica un byte nel corpo del PDF (non nella firma) per simulare
        # un'alterazione successiva alla firma.
        data = bytearray(signed_path.read_bytes())
        # PDF header is at offset 0; toccare i primi byte dopo l'header rompe
        # la firma sicuramente. Sostituiamo il byte 50 con un altro valore.
        data[50] ^= 0x01
        signed_path.write_bytes(bytes(data))

        result = PAdESVerifier().verify(signed_path)
        s = result.signers[0]
        assert s.hash_valid is False or s.signature_valid is False, (
            "manomissione non rilevata"
        )
        print(f"OK (tampering rilevato): hash={s.hash_valid}, sig={s.signature_valid}")


if __name__ == "__main__":
    test_verify_untrusted_signature_is_cryptographically_valid()
    test_verify_with_ca_in_trust_store()
    test_verify_detects_tampering()
    print("\nTutti i test di verifica PAdES passati.")
