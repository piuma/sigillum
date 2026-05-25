# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Unit tests for auto-detection of PKCS#11 drivers/tokens.

The "live" test depends on the user having a recognised token plugged in
(YubiKey, Bit4id, etc.). It's skip-soft so the test still passes on CI.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core.detection import (
    SYSTEM_DRIVER_PATHS,
    USER_DRIVER_GLOBS,
    _label_for,
    detect_tokens,
    find_available_drivers,
)


def test_constants_are_well_formed():
    # Every system path should be absolute; every user glob should start with ~/.
    for p in SYSTEM_DRIVER_PATHS:
        assert p.startswith("/"), p
    for g in USER_DRIVER_GLOBS:
        assert g.startswith("~/"), g
    print(f"OK {len(SYSTEM_DRIVER_PATHS)} system paths + {len(USER_DRIVER_GLOBS)} user globs")


def test_label_heuristics():
    assert "YubiKey" in _label_for("/usr/lib64/libykcs11.so.2")
    assert "InfoCamere" in _label_for(
        "/home/x/infocamere/sign/etc/sign_engine/libbit4xpki.so"
    )
    assert "Aruba" in _label_for("/home/x/.aruba/lib/libbit4xpki.so")
    assert "Dike" in _label_for("/home/x/dike6/lib/libbit4xpki.so")
    assert "OpenSC" in _label_for("/usr/lib64/pkcs11/opensc-pkcs11.so")
    print("OK label heuristics")


def test_find_available_drivers_returns_real_paths():
    drivers = find_available_drivers()
    assert isinstance(drivers, list)
    for p in drivers:
        assert Path(p).is_file(), f"{p} dovrebbe esistere"
    print(f"OK {len(drivers)} driver(s) trovati sul sistema")


def test_detect_tokens_live_soft():
    """Soft test: if any cert-exposing token is plugged in, we should find it."""
    tokens = detect_tokens()
    if not tokens:
        print("SKIP detect_tokens: nessun token con cert pubblici inserito")
        return
    assert all(t.library_path for t in tokens)
    assert all(len(t.certificates) > 0 for t in tokens)
    # No two reported tokens share the same set of cert ids (dedup works).
    fingerprints = [tuple(sorted(c.id for c in t.certificates)) for t in tokens]
    assert len(fingerprints) == len(set(fingerprints))
    for t in tokens:
        print(f"OK detected: {t.library_label} → {len(t.certificates)} cert via {t.library_path}")


if __name__ == "__main__":
    test_constants_are_well_formed()
    test_label_heuristics()
    test_find_available_drivers_returns_real_paths()
    test_detect_tokens_live_soft()
    print("\nTutti i test detection passati.")
