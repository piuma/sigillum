# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""CSC v2 client.

Implements the five HTTP calls Sigillum needs to drive a remote
qualified signature against any CSC v2-compliant QTSP:

  1. ``POST /oauth2/token``          — OAuth 2.0 access token (Bearer)
  2. ``POST /credentials/list``      — enumerate the user's credentials
  3. ``POST /credentials/info``      — cert chain + key algorithm
  4. ``POST /credentials/authorize`` — request a SAD (consumes an OTP)
  5. ``POST /signatures/signHash``   — sign a precomputed hash, spends 1 SAD

The access token is cached in-memory until it expires; signing
endpoints transparently re-authenticate when the cached token is
within 30s of expiry. SADs are *not* cached: each call to
``authorize()`` returns a fresh single-use token, which is the QTSP
side of the spec — every signature pays the cost of one OTP push.

OAuth flow: only ``client_credentials`` is implemented in this commit.
The authorization-code flow (browser dance + redirect) lands later
when we wire in the GUI.
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any, Sequence

import requests

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
    timeout: float = 30.0  # seconds, applied to every HTTP call

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


# Skew applied to the cached OAuth token: refresh proactively when we're
# within this many seconds of expiry so a long-running signing call
# doesn't race the 401.
_TOKEN_REFRESH_SKEW = 30.0


class CSCClient:
    """Thin client over a CSC v2 service.

    All methods raise :class:`CSCError` on failure.
    """

    def __init__(self, config: CSCConfig) -> None:
        self.config = config
        # (token, expiry_epoch). Empty token = unauthenticated.
        self._access_token: str = ""
        self._token_expiry: float = 0.0

    # ----- OAuth 2.0 -----

    def authenticate(self, scope: str = "service") -> str:
        """Obtain an OAuth 2.0 access token via the *client_credentials*
        grant — CSC v2 §8.4. The token is cached in memory; subsequent
        calls within its lifetime return the cached one.

        Returns the bearer token. The caller does not normally need to
        invoke this directly: every signing endpoint calls
        :meth:`_authorized_request` which authenticates on demand.
        """
        if self._access_token and time.monotonic() < self._token_expiry:
            return self._access_token

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "scope": scope,
        }
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        try:
            r = requests.post(
                f"{self.config.base_url}/oauth2/token",
                data=data,
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
            )
        except requests.RequestException as ex:
            raise CSCError(_("OAuth transport error: {ex}").format(ex=ex)) from ex
        if not r.ok:
            raise CSCError(self._format_http_error(r, _("OAuth")))
        try:
            payload = r.json()
        except ValueError as ex:
            raise CSCError(_("malformed OAuth response (not JSON)")) from ex

        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise CSCError(_("OAuth response missing access_token"))
        # `expires_in` is optional in the spec; default to 5 minutes when
        # the QTSP omits it so we don't end up caching forever.
        expires_in = float(payload.get("expires_in", 300))
        self._access_token = token
        self._token_expiry = time.monotonic() + max(0.0, expires_in - _TOKEN_REFRESH_SKEW)
        return token

    # ----- credentials -----

    def list_credentials(self) -> list[str]:
        """List the credential IDs visible to the authenticated user.

        CSC v2 §11.4 — ``POST /credentials/list``.
        """
        payload = self._authorized_request("/credentials/list", {})
        ids = payload.get("credentialIDs")
        if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
            raise CSCError(_("invalid response: credentialIDs missing or malformed"))
        return ids

    def credential_info(self, credential_id: str) -> CSCCredentialInfo:
        """Fetch metadata for one credential — CSC v2 §11.5.

        ``POST /credentials/info`` with ``certificates=chain`` so we
        also pull the cert chain (needed to build PAdES-LT later).
        """
        payload = self._authorized_request("/credentials/info", {
            "credentialID": credential_id,
            "certificates": "chain",
            "certInfo": True,
            "authInfo": False,
        })
        cert = payload.get("cert", {})
        key = payload.get("key", {})
        raw_chain = cert.get("certificates")
        if not isinstance(raw_chain, list) or not raw_chain:
            raise CSCError(_("credential {id} has no certificate chain").format(id=credential_id))
        chain_pem = [_b64_to_pem_cert(c) for c in raw_chain]

        algo_list = key.get("algo", [])
        if not isinstance(algo_list, list) or not algo_list:
            raise CSCError(_("credential {id} has no key algorithm").format(id=credential_id))
        hash_algos = cert.get("hashAlgos") or key.get("hashAlgo") or []
        if isinstance(hash_algos, str):
            hash_algos = [hash_algos]

        return CSCCredentialInfo(
            credential_id=credential_id,
            cert_chain_pem=chain_pem,
            key_algo=str(algo_list[0]),
            key_length=int(key.get("len", 0)),
            hash_algos=[str(h) for h in hash_algos],
            multisign=int(payload.get("multisign", 1)),
            description=str(cert.get("subjectDN", "")),
        )

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
        body: dict[str, Any] = {
            "credentialID": credential_id,
            "numSignatures": len(hashes),
            "hash": [base64.b64encode(h).decode("ascii") for h in hashes],
            "OTP": otp,
        }
        if pin:
            body["PIN"] = pin
        payload = self._authorized_request("/credentials/authorize", body)
        sad = payload.get("SAD")
        if not isinstance(sad, str) or not sad:
            raise CSCError(_("authorize response missing SAD"))
        return SAD(value=sad, expires_in=int(payload.get("expiresIn", 300)))

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
        body = {
            "credentialID": credential_id,
            "SAD": sad.value,
            "hash": [base64.b64encode(h).decode("ascii") for h in hashes],
            "hashAlgo": hash_algo_oid,
            "signAlgo": sign_algo_oid,
        }
        payload = self._authorized_request("/signatures/signHash", body)
        sigs = payload.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != len(hashes):
            raise CSCError(_(
                "signHash response has {got} signatures, expected {exp}"
            ).format(got=len(sigs) if isinstance(sigs, list) else 0,
                     exp=len(hashes)))
        try:
            return [base64.b64decode(s) for s in sigs]
        except (TypeError, ValueError) as ex:
            raise CSCError(_("signHash returned non-base64 signature")) from ex

    # ----- internals -----

    def _authorized_request(self, path: str, body: dict) -> dict:
        """POST *body* to *path* with the current Bearer token, retrying
        once after a forced re-authentication on HTTP 401 (the QTSP may
        have revoked the cached token earlier than its advertised
        lifetime)."""
        for attempt in (1, 2):
            token = self.authenticate()
            try:
                r = requests.post(
                    f"{self.config.base_url}{path}",
                    json=body,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {token}",
                    },
                    timeout=self.config.timeout,
                )
            except requests.RequestException as ex:
                raise CSCError(_("transport error on {path}: {ex}").format(
                    path=path, ex=ex)) from ex
            if r.status_code == 401 and attempt == 1:
                # Invalidate cache and retry once with a fresh token.
                self._access_token = ""
                self._token_expiry = 0.0
                continue
            if not r.ok:
                raise CSCError(self._format_http_error(r, path))
            try:
                return r.json()
            except ValueError as ex:
                raise CSCError(_("malformed JSON from {path}").format(path=path)) from ex
        # Unreachable: the loop either returns or raises on attempt 2.
        raise CSCError(_("re-authentication did not converge on {path}").format(path=path))

    @staticmethod
    def _format_http_error(r: requests.Response, ctx: str) -> str:
        try:
            payload = r.json()
            detail = (payload.get("error_description")
                      or payload.get("error")
                      or payload.get("message")
                      or r.text or "")
        except ValueError:
            detail = r.text or ""
        return _("{ctx} failed (HTTP {code}): {detail}").format(
            ctx=ctx, code=r.status_code, detail=detail[:300])


def _b64_to_pem_cert(b64: str) -> str:
    """Wrap a base64-encoded DER certificate (CSC v2 schema) in PEM
    armour so the rest of Sigillum can feed it to ``cryptography``."""
    chunked = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{chunked}\n-----END CERTIFICATE-----\n"
