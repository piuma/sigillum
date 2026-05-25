# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Internationalization for Sigillum.

Source language is English. Translations live in `po/` (one `.po` file per
language) and are compiled to `.mo` files at install time. Use the exported
`_()` for marking translatable strings:

    from sigillum.i18n import _
    print(_("Hello, world"))

For plurals use `ngettext()`:

    print(ngettext("1 file", "{n} files", n).format(n=n))

The runtime looks for `.mo` files in three places, in order:

1. `$SIGILLUM_LOCALEDIR` — explicit override (handy for development).
2. `<repo>/po/build/` — populated by `make compile-po` when working from
   a source checkout.
3. The OS-wide `gettext` search path (`/usr/share/locale`, …) — what
   distro packages install into.
"""
from __future__ import annotations

import gettext
import os
from pathlib import Path

DOMAIN = "sigillum"


def _locale_dir() -> str | None:
    """Find a directory that contains `LC_MESSAGES/sigillum.mo` files."""
    env = os.environ.get("SIGILLUM_LOCALEDIR")
    if env:
        return env

    # When running from a `git clone` (e.g. `PYTHONPATH=src python -m sigillum`),
    # the .mo files compiled by `make compile-po` live under <repo>/po/build/.
    here = Path(__file__).resolve()
    repo_candidate = here.parents[2] / "po" / "build"
    if repo_candidate.is_dir():
        return str(repo_candidate)

    return None


_translation = gettext.translation(DOMAIN, localedir=_locale_dir(), fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext
