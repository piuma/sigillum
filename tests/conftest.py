# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Pytest config: makes the in-tree `src/` importable without `pip install -e .`
and lets the test files import the local `fixtures` module."""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))                 # tests/fixtures
sys.path.insert(0, str(_HERE.parent / "src"))  # source package
