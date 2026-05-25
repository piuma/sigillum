# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""End-to-end: FileProvider (PKCS#12) -> PAdESSigner -> firma livello B su PDF."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.credentials import FileProvider
from sigillum.core.signer import PAdESSigner, SignatureLevel, SignOptions

from fixtures import write_fixture_files


def test_sign_pdf_with_pkcs12():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        pdf_path, p12_path, _chain = write_fixture_files(tmp, password="test")

        provider = FileProvider(p12_path)
        certs = provider.list_certificates()
        assert len(certs) == 1
        cred = provider.unlock(certs[0].id, "test")
        assert cred.certificate is not None
        assert cred.private_key is not None

        signed_path = tmp / "sample-signed.pdf"
        signer = PAdESSigner()
        signer.sign(
            input_path=pdf_path,
            output_path=signed_path,
            credential=cred,
            options=SignOptions(level=SignatureLevel.B, reason="Test"),
        )

        assert signed_path.exists()
        signed = signed_path.read_bytes()
        # Sanity check: the signed file still starts with the PDF header
        # and now contains a /Sig dictionary appended by endesive.
        assert signed.startswith(b"%PDF-")
        assert b"/Sig" in signed
        assert b"/ByteRange" in signed
        # Output must be strictly larger than the input.
        assert len(signed) > pdf_path.stat().st_size

        print(f"OK: firmato {pdf_path.name} ({pdf_path.stat().st_size} byte) -> "
              f"{signed_path.name} ({len(signed)} byte)")


if __name__ == "__main__":
    test_sign_pdf_with_pkcs12()
