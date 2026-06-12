# SPDX-License-Identifier: GPL-3.0-or-later
# Contract-only smoke tests for the CSC client public types. Behavioural
# tests against a mocked HTTP transport live in test_client.py.
import pytest

from sigillum.core.csc import (
    CSCClient,
    CSCConfig,
    CSCCredentialInfo,
    CSCError,
    SAD,
)


def test_config_rejects_trailing_slash():
    with pytest.raises(ValueError):
        CSCConfig(base_url="https://example.test/csc/v2/", client_id="x")


def test_config_minimal_fields():
    c = CSCConfig(base_url="https://example.test/csc/v2", client_id="x")
    assert c.client_secret == ""  # secret is optional (PKCE / public clients)


def test_credential_info_dataclass_immutable():
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=["-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"],
        key_algo="1.2.840.113549.1.1.1",
        key_length=2048,
        hash_algos=["2.16.840.1.101.3.4.2.1"],
    )
    with pytest.raises((AttributeError, TypeError)):
        info.credential_id = "other"  # type: ignore[misc]


def test_csc_error_is_runtime_error():
    assert issubclass(CSCError, RuntimeError)


def test_client_constructible():
    """Smoke: the client builds and starts with an empty token cache."""
    cli = CSCClient(CSCConfig(base_url="https://example.test/csc/v2",
                              client_id="x"))
    assert cli._access_token == ""
    assert isinstance(SAD(value="x", expires_in=300), SAD)
