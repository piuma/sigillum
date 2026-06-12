# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""CSC v2 client — skeleton.

This module is the *contract* we'll fill in across the next commits on
this branch. It defines the public types (config, credential info, SAD,
errors) and the ``CSCClient`` surface, with method bodies left
``NotImplementedError`` so the rest of Sigillum can import-against this
file without picking up half-implemented behaviour.

The four endpoints we'll cover (in order):

  1. ``POST /oauth2/token``         — OAuth 2.0 access token (Bearer)
  2. ``POST /credentials/list``     — enumerate the user's credentials
  3. ``POST /credentials/info``     — cert chain + key algorithm
  4. ``POST /credentials/authorize``— request a SAD (consumes the OTP)
  5. ``POST /signatures/signHash``  — sign a precomputed hash, spends 1 SAD

Endpoints 4 and 5 form a pair: every signing call needs a fresh SAD,
authorised by the user with an OTP / push notification handled by the
QTSP. This is the UX bottleneck called out in the roadmap.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from ...i18n import _


class CSCError(RuntimeError):
    """Anything wrong while talking to a CSC v2 service.

    Wraps both transport-level failures (network, TLS) and protocol-level
    ones (HTTP 4xx/5xx, malformed JSON, missing fields). The original
    cause is kept on ``__cause__`` when applicable.
    """


@dataclass(frozen=True)
class CSCConfig:
    """Static configuration of a single CSC v2 service.

    *base_url* is the issuer URL, e.g. ``https://api.qtsp.example/csc/v2``
    (no trailing slash). *client_id* / *client_secret* identify Sigillum
    to the QTSP — they come from a one-off registration step the user
    does on the QTSP portal.
    """
    base_url: str
    client_id: str
    client_secret: str = ""

    def __post_init__(self) -> None:
        if self.base_url.endswith("/"):
            raise ValueError(_("base_url must not end with a trailing slash"))


@dataclass(frozen=True)
class CSCCredentialInfo:
    """Subset of ``/credentials/info`` we actually need at signing time.

    Mirrors the CSC v2 schema but flattened to plain Python types — full
    field set is intentionally omitted: we'll add fields here only when a
    consumer needs them, to keep the type close to actual use.
    """
    credential_id: str
    cert_chain_pem: list[str]   # leaf first, ordered per CSC §11.5
    key_algo: str               # e.g. "1.2.840.113549.1.1.1" (RSA), "1.2.840.10045.2.1" (EC)
    key_length: int             # bits
    hash_algos: list[str]       # supported digest OIDs, e.g. ["2.16.840.1.101.3.4.2.1"] (SHA-256)
    multisign: int = 1          # max number of hashes accepted in one signHash call
    description: str = ""


@dataclass(frozen=True)
class SAD:
    """Signature Activation Data — a short-lived authorisation token.

    Bound to (credential, hashes-to-be-signed, OTP) tuple. Single use per
    CSC v2 §11.6: the next ``signHash`` consumes it. ``expires_in`` is
    the lifetime in seconds, typically 300.
    """
    value: str
    expires_in: int


class CSCClient:
    """Thin client over a CSC v2 service.

    All methods raise :class:`CSCError` on failure. None of them are
    implemented yet — see the docstring of each method for the spec
    section it must conform to.
    """

    def __init__(self, config: CSCConfig) -> None:
        self.config = config

    # ----- OAuth 2.0 -----

    def authenticate(self, scope: str = "service") -> str:
        """Obtain an OAuth 2.0 access token (Bearer) — CSC v2 §8.

        Returns the bearer token to set on subsequent requests as
        ``Authorization: Bearer <token>``. Caller is expected to cache
        it until expiry (response includes ``expires_in``; this method
        does not yet expose that — to be revisited when we implement
        refresh handling).
        """
        raise NotImplementedError

    # ----- credentials -----

    def list_credentials(self) -> Sequence[str]:
        """List the credential IDs visible to the authenticated user.

        CSC v2 §11.4 — ``POST /credentials/list``.
        """
        raise NotImplementedError

    def credential_info(self, credential_id: str) -> CSCCredentialInfo:
        """Fetch metadata for one credential — CSC v2 §11.5.

        ``POST /credentials/info`` with ``certificates=chain`` so we
        also pull the cert chain (needed to build PAdES-LT later).
        """
        raise NotImplementedError

    # ----- signature activation + signing -----

    def authorize(
        self,
        credential_id: str,
        hashes: Sequence[bytes],
        otp: str,
        pin: str = "",
    ) -> SAD:
        """Exchange an OTP for a SAD bound to *hashes* — CSC v2 §11.6.

        ``POST /credentials/authorize``. The hashes list is what the
        SAD will be *valid for*: trying to signHash a different hash
        afterwards is a protocol error and the QTSP will refuse.
        """
        raise NotImplementedError

    def sign_hash(
        self,
        credential_id: str,
        sad: SAD,
        hashes: Sequence[bytes],
        hash_algo_oid: str,
        sign_algo_oid: str,
    ) -> list[bytes]:
        """Have the QTSP sign each hash — CSC v2 §11.10.

        ``POST /signatures/signHash``. Returns one signature per hash,
        same order. SAD is single-use: subsequent calls must obtain a
        fresh one via :meth:`authorize`.
        """
        raise NotImplementedError
