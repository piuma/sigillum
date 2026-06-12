# SPDX-License-Identifier: GPL-3.0-or-later
# Live integration tests for the CSC v2 client against a real QTSP
# sandbox (Aruba, Namirial, InfoCert, …).
#
# These are *not* executed by the default `pytest -m "not network and
# not hardware"` invocation we use locally and in CI. To run them,
# point the following environment variables at a sandbox account and
# explicitly enable the `network` marker:
#
#     export CSC_TEST_URL=https://api-sandbox.qtsp.example/csc/v2
#     export CSC_TEST_CLIENT_ID=...
#     export CSC_TEST_CLIENT_SECRET=...        # optional
#     export CSC_TEST_REFRESH_TOKEN=...        # optional, but recommended
#     export CSC_TEST_CREDENTIAL_ID=...        # optional
#     pytest tests/csc/test_client_live.py -m network -v
#
# What the suite checks (zero OTP consumed):
#   - authenticate() returns a Bearer token
#   - list_credentials() yields at least one entry
#   - credential_info() on the configured CID returns a parseable chain
#
# Signing endpoints are deliberately left out because every signHash
# burns a fresh OTP — automating them here would spam the user's
# phone. Add a manual `make smoke-csc-sign` target if you need that.
import os

import pytest
from cryptography import x509

from sigillum.core.csc import CSCClient, CSCConfig

pytestmark = pytest.mark.network


def _cfg_or_skip() -> CSCConfig:
    url = os.environ.get("CSC_TEST_URL")
    cid = os.environ.get("CSC_TEST_CLIENT_ID")
    if not (url and cid):
        pytest.skip("CSC_TEST_URL and CSC_TEST_CLIENT_ID not set")
    return CSCConfig(
        base_url=url.rstrip("/"),
        client_id=cid,
        client_secret=os.environ.get("CSC_TEST_CLIENT_SECRET", ""),
    )


def _client_or_skip() -> CSCClient:
    cli = CSCClient(_cfg_or_skip())
    refresh = os.environ.get("CSC_TEST_REFRESH_TOKEN", "")
    if refresh:
        cli.set_refresh_token(refresh)
    return cli


def test_authenticate_returns_bearer():
    cli = _client_or_skip()
    token = cli.authenticate()
    assert isinstance(token, str) and len(token) > 8


def test_list_credentials_returns_at_least_one():
    cli = _client_or_skip()
    ids = cli.list_credentials()
    assert ids, "the sandbox account has no credentials"


def test_credential_info_returns_parseable_chain():
    cid = os.environ.get("CSC_TEST_CREDENTIAL_ID")
    if not cid:
        pytest.skip("CSC_TEST_CREDENTIAL_ID not set")
    cli = _client_or_skip()
    info = cli.credential_info(cid)
    assert info.cert_chain_pem, "empty cert chain from credential_info"
    leaf = x509.load_pem_x509_certificate(info.cert_chain_pem[0].encode())
    # Subject DN is the bare minimum any CA hands out
    assert leaf.subject.rfc4514_string()
    # Key algorithm should be one we understand
    assert info.key_algo in {
        "1.2.840.113549.1.1.1",    # RSA
        "1.2.840.113549.1.1.10",   # RSA-PSS
        "1.2.840.10045.2.1",       # ECDSA
    }
    assert info.key_length >= 256
