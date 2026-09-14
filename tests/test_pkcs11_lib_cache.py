# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Regression tests for the process-wide PKCS#11 module cache.

PKCS#11 modules must stay loaded for the lifetime of the process. PyKCS11
`dlclose()`s a module once the last `PyKCS11Lib` referencing it is collected,
and vendor middlewares don't necessarily survive that — Actalis' CyberMW keeps
a PC/SC monitor thread running after `C_Finalize`, so the unload pulls the code
out from under it and the *next* PKCS#11 call segfaults the process.

These tests need no token: they only assert that a module is loaded once and
never dropped.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigillum.core import credentials
from sigillum.core.credentials import PKCS11Provider


class _FakeLib:
    """Stand-in for PyKCS11.PyKCS11Lib recording every load() call."""

    def __init__(self):
        self.loaded: list[str] = []

    def load(self, path):
        self.loaded.append(path)


@pytest.fixture
def fake_pykcs11(monkeypatch):
    """Swap PyKCS11Lib for a counting fake and start from an empty cache."""
    created: list[_FakeLib] = []

    def _factory():
        lib = _FakeLib()
        created.append(lib)
        return lib

    import PyKCS11

    monkeypatch.setattr(PyKCS11, "PyKCS11Lib", _factory)
    monkeypatch.setattr(credentials, "_LIB_CACHE", {})
    return created


def test_same_path_loaded_once(fake_pykcs11):
    a = PKCS11Provider("/usr/lib64/libcybermw.so")._lib()
    b = PKCS11Provider("/usr/lib64/libcybermw.so")._lib()

    assert a is b, "the same module must be reused, not loaded twice"
    assert len(fake_pykcs11) == 1
    assert fake_pykcs11[0].loaded == ["/usr/lib64/libcybermw.so"]


def test_distinct_paths_get_distinct_libs(fake_pykcs11):
    a = PKCS11Provider("/usr/lib64/libcybermw.so")._lib()
    b = PKCS11Provider("/usr/lib64/pkcs11/opensc-pkcs11.so")._lib()

    assert a is not b
    assert len(fake_pykcs11) == 2


def test_module_survives_provider_collection(fake_pykcs11):
    """Dropping every provider must NOT release the module (that's the crash)."""
    import gc

    PKCS11Provider("/usr/lib64/libcybermw.so")._lib()
    gc.collect()

    assert credentials._LIB_CACHE.get("/usr/lib64/libcybermw.so") is not None
    # A provider created afterwards reuses the still-loaded module.
    PKCS11Provider("/usr/lib64/libcybermw.so")._lib()
    assert len(fake_pykcs11) == 1


def test_failed_load_is_not_cached(fake_pykcs11, monkeypatch):
    """A module that fails to load must be retried, not remembered as broken."""
    def _exploding_factory():
        lib = _FakeLib()

        def _load(path):
            raise OSError("undefined symbol: EVP_EncryptInit_ex2")

        lib.load = _load
        return lib

    import PyKCS11

    monkeypatch.setattr(PyKCS11, "PyKCS11Lib", _exploding_factory)
    with pytest.raises(OSError):
        PKCS11Provider("/usr/local/lib/libcybermw.so")._lib()

    assert "/usr/local/lib/libcybermw.so" not in credentials._LIB_CACHE
