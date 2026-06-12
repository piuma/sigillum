# SPDX-License-Identifier: GPL-3.0-or-later
# Behavioural tests for the CSC v2 client. Every HTTP call is mocked at
# the `requests.post` level so the suite stays hermetic; live tests
# against a real QTSP sandbox land in a separate test_client_live.py
# gated by a `network` marker.
import base64
from unittest.mock import MagicMock, patch

import pytest
import requests

from sigillum.core.csc import CSCClient, CSCConfig, CSCError, SAD, generate_pkce


# -----------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------

def _resp(status_code: int, json_payload=None, text: str = ""):
    """Stand-in for a requests.Response with the attributes the client
    actually reads. `json_payload=None` makes `.json()` raise so we can
    test the malformed-JSON branch."""
    r = MagicMock(spec=requests.Response)
    r.status_code = status_code
    r.ok = 200 <= status_code < 300
    if json_payload is None:
        r.json.side_effect = ValueError("not json")
    else:
        r.json.return_value = json_payload
    r.text = text
    return r


def _client(**overrides) -> CSCClient:
    cfg = CSCConfig(
        base_url=overrides.get("base_url", "https://qtsp.test/csc/v2"),
        client_id=overrides.get("client_id", "cid"),
        client_secret=overrides.get("client_secret", "csecret"),
    )
    return CSCClient(cfg)


_TOKEN_OK = {"access_token": "tok-1", "expires_in": 3600}


# -----------------------------------------------------------------------
# authenticate
# -----------------------------------------------------------------------

@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_returns_token(mock_post):
    mock_post.return_value = _resp(200, _TOKEN_OK)
    assert _client().authenticate() == "tok-1"
    assert mock_post.call_count == 1
    args, kwargs = mock_post.call_args
    assert args[0] == "https://qtsp.test/csc/v2/oauth2/token"
    assert kwargs["data"]["grant_type"] == "client_credentials"
    assert kwargs["data"]["client_id"] == "cid"
    assert kwargs["data"]["client_secret"] == "csecret"


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_caches_token(mock_post):
    mock_post.return_value = _resp(200, _TOKEN_OK)
    cli = _client()
    cli.authenticate()
    cli.authenticate()
    cli.authenticate()
    assert mock_post.call_count == 1  # cached after the first


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_http_error(mock_post):
    mock_post.return_value = _resp(401, {"error": "invalid_client"})
    with pytest.raises(CSCError) as exc:
        _client().authenticate()
    assert "401" in str(exc.value)


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_missing_token(mock_post):
    mock_post.return_value = _resp(200, {"expires_in": 3600})
    with pytest.raises(CSCError, match="access_token"):
        _client().authenticate()


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_transport_error(mock_post):
    mock_post.side_effect = requests.ConnectionError("dns fail")
    with pytest.raises(CSCError, match="transport"):
        _client().authenticate()


# -----------------------------------------------------------------------
# list_credentials
# -----------------------------------------------------------------------

@patch("sigillum.core.csc.client.requests.post")
def test_list_credentials_ok(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"credentialIDs": ["c-1", "c-2"]}),
    ]
    cli = _client()
    assert cli.list_credentials() == ["c-1", "c-2"]
    # second call must have included the Bearer header
    args, kwargs = mock_post.call_args_list[1]
    assert kwargs["headers"]["Authorization"] == "Bearer tok-1"


@patch("sigillum.core.csc.client.requests.post")
def test_list_credentials_malformed(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"unrelated": "blob"}),
    ]
    with pytest.raises(CSCError, match="credentialIDs"):
        _client().list_credentials()


# -----------------------------------------------------------------------
# credential_info
# -----------------------------------------------------------------------

_CERT_B64 = base64.b64encode(b"x" * 200).decode("ascii")

_INFO_OK = {
    "cert": {
        "certificates": [_CERT_B64, _CERT_B64],
        "subjectDN": "CN=Test Signer,O=Test,C=IT",
    },
    "key": {
        "algo": ["1.2.840.113549.1.1.1"],
        "len": 2048,
        "hashAlgo": "2.16.840.1.101.3.4.2.1",
    },
    "multisign": 5,
}


@patch("sigillum.core.csc.client.requests.post")
def test_credential_info_ok(mock_post):
    mock_post.side_effect = [_resp(200, _TOKEN_OK), _resp(200, _INFO_OK)]
    info = _client().credential_info("cred-1")
    assert info.credential_id == "cred-1"
    assert info.key_algo == "1.2.840.113549.1.1.1"
    assert info.key_length == 2048
    assert info.hash_algos == ["2.16.840.1.101.3.4.2.1"]
    assert info.multisign == 5
    assert all(p.startswith("-----BEGIN CERTIFICATE-----\n") for p in info.cert_chain_pem)
    assert all(p.rstrip().endswith("-----END CERTIFICATE-----") for p in info.cert_chain_pem)
    # body of the POST /credentials/info
    args, kwargs = mock_post.call_args_list[1]
    assert kwargs["json"] == {
        "credentialID": "cred-1",
        "certificates": "chain",
        "certInfo": True,
        "authInfo": False,
    }


@patch("sigillum.core.csc.client.requests.post")
def test_credential_info_empty_chain(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"cert": {"certificates": []}, "key": {"algo": ["x"]}}),
    ]
    with pytest.raises(CSCError, match="no certificate chain"):
        _client().credential_info("cred-1")


# -----------------------------------------------------------------------
# authorize
# -----------------------------------------------------------------------

@patch("sigillum.core.csc.client.requests.post")
def test_authorize_ok(mock_post):
    h1 = b"\x01" * 32
    h2 = b"\x02" * 32
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"SAD": "sad-1", "expiresIn": 600}),
    ]
    sad = _client().authorize("cred-1", [h1, h2], otp="123456")
    assert sad == SAD(value="sad-1", expires_in=600)
    body = mock_post.call_args_list[1].kwargs["json"]
    assert body["credentialID"] == "cred-1"
    assert body["numSignatures"] == 2
    assert body["OTP"] == "123456"
    assert body["hash"] == [base64.b64encode(h1).decode(),
                             base64.b64encode(h2).decode()]
    assert "PIN" not in body  # not provided


@patch("sigillum.core.csc.client.requests.post")
def test_authorize_includes_pin_when_set(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"SAD": "sad", "expiresIn": 300}),
    ]
    _client().authorize("c", [b"\x00" * 32], otp="123456", pin="9999")
    body = mock_post.call_args_list[1].kwargs["json"]
    assert body["PIN"] == "9999"


@patch("sigillum.core.csc.client.requests.post")
def test_authorize_missing_sad(mock_post):
    mock_post.side_effect = [_resp(200, _TOKEN_OK), _resp(200, {"expiresIn": 300})]
    with pytest.raises(CSCError, match="missing SAD"):
        _client().authorize("c", [b"\x00" * 32], otp="123456")


# -----------------------------------------------------------------------
# sign_hash
# -----------------------------------------------------------------------

@patch("sigillum.core.csc.client.requests.post")
def test_sign_hash_ok(mock_post):
    h = b"\x05" * 32
    sig_b64 = base64.b64encode(b"signature-bytes").decode("ascii")
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"signatures": [sig_b64]}),
    ]
    result = _client().sign_hash(
        credential_id="cred-1",
        sad=SAD(value="sad", expires_in=300),
        hashes=[h],
        hash_algo_oid="2.16.840.1.101.3.4.2.1",
        sign_algo_oid="1.2.840.113549.1.1.11",
    )
    assert result == [b"signature-bytes"]
    body = mock_post.call_args_list[1].kwargs["json"]
    assert body["SAD"] == "sad"
    assert body["hashAlgo"] == "2.16.840.1.101.3.4.2.1"
    assert body["signAlgo"] == "1.2.840.113549.1.1.11"
    assert body["hash"] == [base64.b64encode(h).decode()]


@patch("sigillum.core.csc.client.requests.post")
def test_sign_hash_count_mismatch(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(200, {"signatures": []}),
    ]
    with pytest.raises(CSCError, match="expected 1"):
        _client().sign_hash(
            "cred", SAD(value="s", expires_in=300),
            [b"\x00" * 32], "h", "s",
        )


# -----------------------------------------------------------------------
# 401 retry
# -----------------------------------------------------------------------

@patch("sigillum.core.csc.client.requests.post")
def test_401_triggers_one_reauth(mock_post):
    """First request after authenticate returns 401: the client must
    invalidate the cached token, re-authenticate, and retry the call
    exactly once."""
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),                       # initial auth
        _resp(401, {"error": "invalid_token"}),      # revoked
        _resp(200, {"access_token": "tok-2",
                    "expires_in": 3600}),            # re-auth
        _resp(200, {"credentialIDs": ["c"]}),        # retry succeeds
    ]
    assert _client().list_credentials() == ["c"]
    assert mock_post.call_count == 4


# -----------------------------------------------------------------------
# authorization-code flow (PKCE)
# -----------------------------------------------------------------------

def test_generate_pkce_pair_is_valid():
    """RFC 7636 §4: challenge = base64url(sha256(verifier)), 43+ chars
    of url-safe alphabet for both."""
    import base64
    import hashlib
    import re

    pkce = generate_pkce()
    assert pkce.method == "S256"
    assert re.fullmatch(r"[A-Za-z0-9_\-]{43,128}", pkce.verifier)
    assert re.fullmatch(r"[A-Za-z0-9_\-]{43}", pkce.challenge)
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(pkce.verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert pkce.challenge == expected


def test_build_authorize_url_includes_pkce_and_state():
    cli = _client()
    pkce = generate_pkce()
    url = cli.build_authorize_url(
        redirect_uri="http://127.0.0.1:9999/cb",
        scope="service",
        state="st-xyz",
        code_challenge=pkce.challenge,
    )
    assert url.startswith("https://qtsp.test/csc/v2/oauth2/authorize?")
    assert "response_type=code" in url
    assert "client_id=cid" in url
    assert "code_challenge_method=S256" in url
    assert "state=st-xyz" in url
    assert f"code_challenge={pkce.challenge}" in url


@patch("sigillum.core.csc.client.requests.post")
def test_exchange_code_populates_tokens(mock_post):
    mock_post.return_value = _resp(200, {
        "access_token": "tok-acc",
        "refresh_token": "tok-ref",
        "expires_in": 3600,
    })
    cli = _client()
    tokens = cli.exchange_code(
        "auth-code", "http://127.0.0.1:9999/cb", code_verifier="ver",
    )
    assert tokens.access_token == "tok-acc"
    assert tokens.refresh_token == "tok-ref"
    # The client adopted them — a follow-up authenticate() returns the
    # cached access token without making a second request.
    assert cli.authenticate() == "tok-acc"
    assert cli.refresh_token == "tok-ref"
    # POST body sanity-check
    args, kwargs = mock_post.call_args
    assert kwargs["data"]["grant_type"] == "authorization_code"
    assert kwargs["data"]["code"] == "auth-code"
    assert kwargs["data"]["code_verifier"] == "ver"


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_uses_refresh_token_when_available(mock_post):
    """When a refresh token is set, authenticate() must use the
    refresh_token grant before falling back to client_credentials."""
    mock_post.return_value = _resp(200, {
        "access_token": "tok-refreshed",
        "refresh_token": "tok-ref-2",
        "expires_in": 3600,
    })
    cli = _client()
    cli.set_refresh_token("tok-ref-original")
    assert cli.authenticate() == "tok-refreshed"
    assert mock_post.call_count == 1
    assert mock_post.call_args.kwargs["data"]["grant_type"] == "refresh_token"
    # The new refresh token returned by the QTSP replaces the old one
    # (RFC 6749 §6 allows rotation).
    assert cli.refresh_token == "tok-ref-2"


@patch("sigillum.core.csc.client.requests.post")
def test_authenticate_falls_back_when_refresh_rejected(mock_post):
    """If the saved refresh token is dead, the client discards it and
    falls back to client_credentials transparently."""
    mock_post.side_effect = [
        _resp(400, {"error": "invalid_grant"}),
        _resp(200, {"access_token": "tok-cc", "expires_in": 3600}),
    ]
    cli = _client()
    cli.set_refresh_token("dead-token")
    assert cli.authenticate() == "tok-cc"
    assert mock_post.call_count == 2
    assert cli.refresh_token == ""  # wiped after the rejection


@patch("sigillum.core.csc.client.requests.post")
def test_401_twice_gives_up(mock_post):
    mock_post.side_effect = [
        _resp(200, _TOKEN_OK),
        _resp(401, {"error": "x"}),
        _resp(200, {"access_token": "tok-2", "expires_in": 3600}),
        _resp(401, {"error": "x"}),
    ]
    with pytest.raises(CSCError, match="401"):
        _client().list_credentials()
