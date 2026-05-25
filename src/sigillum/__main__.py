# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Entry point: dispatches between CLI subcommands and the GTK GUI.

`sigillum`                  → GUI (legacy default)
`sigillum <subcommand> ...` → CLI subcommand (see `sigillum --help`)
"""
from __future__ import annotations

import sys


def main() -> int:
    from sigillum.cli import main as cli_main
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
