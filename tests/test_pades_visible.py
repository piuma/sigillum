# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Firma PAdES visibile: testo, immagine, 4 posizioni. Verifica crittografica
deve passare in tutti i casi."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import (
    PAdESSigner,
    SignatureLevel,
    SignaturePosition,
    SignOptions,
)
from sigillum.core.verifier import PAdESVerifier

from fixtures import write_fixture_files


def _setup(td: str):
    tmp = Path(td)
    pdf_path, p12_path, chain = write_fixture_files(tmp, password="test")
    cred = FileProvider(p12_path).unlock(str(p12_path), "test")
    return tmp, pdf_path, cred, chain


def _sign(tmp: Path, pdf: Path, cred, **opt) -> Path:
    out = tmp / f"signed-{abs(hash(tuple(opt.items()))) % 100000}.pdf"
    PAdESSigner().sign(
        input_path=pdf, output_path=out, credential=cred,
        options=SignOptions(level=SignatureLevel.B, visible=True, **opt),
    )
    return out


def test_visible_signature_text_only():
    with tempfile.TemporaryDirectory() as td:
        tmp, pdf, cred, chain = _setup(td)
        signed = _sign(tmp, pdf, cred, reason="Approvazione")
        data = signed.read_bytes()
        assert b"/Sig" in data and b"/Widget" in data
        result = PAdESVerifier(trusted_certs=[chain.ca_cert]).verify(signed)
        s = result.signers[0]
        assert s.hash_valid and s.signature_valid and s.cert_trusted
        print(f"OK testo: {signed.stat().st_size} byte")


def test_visible_signature_all_corners():
    with tempfile.TemporaryDirectory() as td:
        tmp, pdf, cred, chain = _setup(td)
        for pos in SignaturePosition:
            signed = _sign(tmp, pdf, cred, signature_position=pos, reason=pos.value)
            assert signed.read_bytes().count(b"/Widget") >= 1
            result = PAdESVerifier(trusted_certs=[chain.ca_cert]).verify(signed)
            assert result.signers[0].valid, f"firma non valida con posizione {pos}"
        print(f"OK 4 posizioni: {[p.value for p in SignaturePosition]}")


def test_visible_signature_with_image():
    from PIL import Image
    with tempfile.TemporaryDirectory() as td:
        tmp, pdf, cred, chain = _setup(td)
        # Logo dummy: PNG rosso 64x64 con alpha.
        logo_path = tmp / "logo.png"
        Image.new("RGBA", (64, 64), (220, 30, 30, 255)).save(logo_path)

        signed = _sign(
            tmp, pdf, cred,
            signature_position=SignaturePosition.BOTTOM_LEFT,
            signature_image=str(logo_path),
            reason="Test logo",
        )

        data = signed.read_bytes()
        # An image is embedded as XObject of /Subtype /Image.
        assert b"/Subtype /Image" in data or b"/Subtype/Image" in data, (
            "il logo non risulta embedded nel PDF"
        )
        result = PAdESVerifier(trusted_certs=[chain.ca_cert]).verify(signed)
        assert result.signers[0].valid
        print(f"OK logo: {signed.stat().st_size} byte")


if __name__ == "__main__":
    test_visible_signature_text_only()
    test_visible_signature_all_corners()
    test_visible_signature_with_image()
    print("\nTest firma visibile passati.")
