# SPDX-License-Identifier: GPL-3.0-or-later
# Smoke tests covering only the contract (types + signatures) of the CSC
# client skeleton. Real network behaviour lives in test_client_live.py
# (to be added in the next commit on this branch).
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


@pytest.mark.parametrize("method,args", [
    ("authenticate", ()),
    ("list_credentials", ()),
    ("credential_info", ("cred-1",)),
    ("authorize", ("cred-1", [b"\x00" * 32], "123456")),
    ("sign_hash", (
        "cred-1",
        SAD(value="sad", expires_in=300),
        [b"\x00" * 32],
        "2.16.840.1.101.3.4.2.1",   # SHA-256
        "1.2.840.113549.1.1.11",    # sha256WithRSAEncryption
    )),
])
def test_client_methods_are_skeletons(method, args):
    """Every method must be present and raise NotImplementedError until
    the next commit fills it in. Guarantees the public surface is stable
    before we ship behaviour."""
    cli = CSCClient(CSCConfig(base_url="https://example.test/csc/v2",
                              client_id="x"))
    with pytest.raises(NotImplementedError):
        getattr(cli, method)(*args)
