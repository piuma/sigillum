# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Cloud Signature Consortium (CSC) v2 — ETSI TS 119 432.

A REST/JSON protocol every Italian QTSP exposes for remote qualified
signature (Aruba Remote Sign, InfoCert IRIS, Namirial FirmaCerta Remote,
Cyberneid, …). This subpackage implements the *client* side: Sigillum
talks to the remote service to enumerate credentials, request a
Signature Activation Data (SAD) authorised by the user's OTP, and have
the service sign a hash on its hardware.

The credential abstraction (``RemoteCSCProvider``) plugs into the same
``CredentialProvider`` interface as ``FileProvider`` and
``PKCS11Provider`` so the existing signer code can stay agnostic of
where the key actually lives.

Spec home: https://cloudsignatureconsortium.org/resources/
ETSI TS 119 432: https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/
"""
from __future__ import annotations

from .client import (
    CSCClient,
    CSCConfig,
    CSCCredentialInfo,
    CSCError,
    SAD,
)

__all__ = [
    "CSCClient",
    "CSCConfig",
    "CSCCredentialInfo",
    "CSCError",
    "SAD",
]
