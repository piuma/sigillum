# SPDX-License-Identifier: GPL-3.0-or-later
# Tests for RemoteCSCProvider — verifies the provider plugs into the
# CredentialProvider interface and that signing calls translate
# correctly into the CSC client API (authorize → signHash, with one
# OTP per request).
import base64
import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sigillum.core.credentials import (
    CertificateInfo,
    RemoteCSCProvider,
    SigningCredential,
)
from sigillum.core.csc import CSCCredentialInfo, SAD


# -----------------------------------------------------------------------
# fixtures: a real self-signed certificate so x509.load_pem_x509_certificate
# can parse it during the test.
# -----------------------------------------------------------------------

def _make_cert_pem() -> tuple[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CSC Test Signer"),
    ])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1234567890ABCDEF)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        cert.public_bytes(serialization.Encoding.DER),
    )


@pytest.fixture(scope="module")
def cert_material():
    return _make_cert_pem()


def _make_info(cert_pem: str) -> CSCCredentialInfo:
    return CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[cert_pem],
        key_algo="1.2.840.113549.1.1.1",
        key_length=2048,
        hash_algos=["2.16.840.1.101.3.4.2.1"],
    )


# -----------------------------------------------------------------------
# list_certificates
# -----------------------------------------------------------------------

def test_list_certificates_pulls_info_for_each_id(cert_material):
    cert_pem, _ = cert_material
    client = MagicMock()
    client.list_credentials.return_value = ["cred-1", "cred-2"]
    client.credential_info.side_effect = lambda cid: _make_info(cert_pem)

    provider = RemoteCSCProvider(client, otp_provider=lambda: "000000")
    out = provider.list_certificates()

    assert [c.id for c in out] == ["cred-1", "cred-2"]
    assert all(isinstance(c, CertificateInfo) for c in out)
    assert all("CSC Test Signer" in c.subject for c in out)
    assert all(c.not_before and c.not_after for c in out)


def test_list_certificates_skips_broken(cert_material):
    cert_pem, _ = cert_material
    good = _make_info(cert_pem)
    broken = CSCCredentialInfo(
        credential_id="bad",
        cert_chain_pem=["-----BEGIN CERTIFICATE-----\nNOT-A-CERT\n-----END CERTIFICATE-----"],
        key_algo="1.2.840.113549.1.1.1",
        key_length=2048,
        hash_algos=[],
    )
    client = MagicMock()
    client.list_credentials.return_value = ["good", "bad"]
    client.credential_info.side_effect = lambda cid: good if cid == "good" else broken

    out = RemoteCSCProvider(client, otp_provider=lambda: "0").list_certificates()
    assert [c.id for c in out] == ["good"]


# -----------------------------------------------------------------------
# unlock + sign roundtrip via the HSM adapter
# -----------------------------------------------------------------------

def test_unlock_returns_signing_credential_with_hsm(cert_material):
    cert_pem, cert_der = cert_material
    client = MagicMock()
    client.credential_info.return_value = _make_info(cert_pem)

    cred = RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
    assert isinstance(cred, SigningCredential)
    assert cred.private_key is None              # remote: key never local
    assert cred.hsm is not None
    keyid, der = cred.hsm.certificate()
    assert keyid == b"cred-1"
    assert der == cert_der


def test_hsm_sign_authorizes_and_calls_signhash(cert_material):
    cert_pem, _ = cert_material
    info = _make_info(cert_pem)

    client = MagicMock()
    client.credential_info.return_value = info
    client.authorize.return_value = SAD(value="sad-1", expires_in=300)
    client.sign_hash.return_value = [b"raw-signature-bytes"]

    otp_calls: list[None] = []
    def otp_provider():
        otp_calls.append(None)
        return "123456"

    cred = RemoteCSCProvider(client, otp_provider=otp_provider, pin="abcd").unlock("cred-1", "")
    sig = cred.hsm.sign(b"keyid-ignored", b"signedAttributes blob", "sha256")

    assert sig == b"raw-signature-bytes"
    assert len(otp_calls) == 1  # one OTP per sign() call — CSC v2 §11.6

    # Compute the expected hash locally and verify the API was called with it.
    h = hashes.Hash(hashes.SHA256())
    h.update(b"signedAttributes blob")
    expected_digest = h.finalize()

    client.authorize.assert_called_once_with(
        "cred-1", [expected_digest], otp="123456", pin="abcd",
    )
    client.sign_hash.assert_called_once_with(
        "cred-1",
        SAD(value="sad-1", expires_in=300),
        [expected_digest],
        "2.16.840.1.101.3.4.2.1",       # SHA-256 OID
        "1.2.840.113549.1.1.11",        # sha256WithRSAEncryption OID
    )


def test_hsm_sign_rejects_unknown_hash(cert_material):
    cert_pem, _ = cert_material
    client = MagicMock()
    client.credential_info.return_value = _make_info(cert_pem)
    cred = RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
    with pytest.raises(ValueError, match="unsupported hash"):
        cred.hsm.sign(b"", b"data", "md5")


def test_hsm_sign_uses_ecdsa_oid_for_ec_credential(cert_material):
    cert_pem, _ = cert_material
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[cert_pem],
        key_algo="1.2.840.10045.2.1",   # id-ecPublicKey (RFC 5480)
        key_length=256,
        hash_algos=["2.16.840.1.101.3.4.2.1"],
    )
    client = MagicMock()
    client.credential_info.return_value = info
    client.authorize.return_value = SAD(value="sad", expires_in=300)
    client.sign_hash.return_value = [b"ecdsa-sig"]

    cred = RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
    assert cred.hsm.sign(b"", b"data", "sha256") == b"ecdsa-sig"
    # The signAlgo must be the ECDSA-with-SHA-256 OID, not the RSA one.
    args, _kw = client.sign_hash.call_args
    assert args[4] == "1.2.840.10045.4.3.2"


def test_hsm_sign_uses_pss_oid_when_key_is_pss(cert_material):
    cert_pem, _ = cert_material
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[cert_pem],
        key_algo="1.2.840.113549.1.1.10",   # id-RSASSA-PSS
        key_length=2048,
        hash_algos=["2.16.840.1.101.3.4.2.1"],
    )
    client = MagicMock()
    client.credential_info.return_value = info
    client.authorize.return_value = SAD(value="sad", expires_in=300)
    client.sign_hash.return_value = [b"pss-sig"]

    cred = RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
    cred.hsm.sign(b"", b"data", "sha256")
    args, _kw = client.sign_hash.call_args
    assert args[4] == "1.2.840.113549.1.1.10"


def test_hsm_sign_prefer_pss_overrides_rsa_credential(cert_material):
    """If the QTSP advertises plain RSA but the user (or a profile)
    asks for PSS, the signAlgo OID must switch to id-RSASSA-PSS."""
    cert_pem, _ = cert_material
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[cert_pem],
        key_algo="1.2.840.113549.1.1.1",    # plain RSA
        key_length=2048,
        hash_algos=["2.16.840.1.101.3.4.2.1"],
    )
    client = MagicMock()
    client.credential_info.return_value = info
    client.authorize.return_value = SAD(value="sad", expires_in=300)
    client.sign_hash.return_value = [b"pss-sig"]

    cred = RemoteCSCProvider(
        client, otp_provider=lambda: "0", prefer_pss=True,
    ).unlock("cred-1", "")
    cred.hsm.sign(b"", b"data", "sha256")
    args, _kw = client.sign_hash.call_args
    assert args[4] == "1.2.840.113549.1.1.10"


def test_hsm_sign_rejects_unsupported_key_algo(cert_material):
    cert_pem, _ = cert_material
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[cert_pem],
        key_algo="1.2.3.4.5",   # bogus
        key_length=256,
        hash_algos=[],
    )
    client = MagicMock()
    client.credential_info.return_value = info
    cred = RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
    with pytest.raises(NotImplementedError, match="key algorithm"):
        cred.hsm.sign(b"", b"data", "sha256")


def test_unlock_rejects_empty_chain():
    info = CSCCredentialInfo(
        credential_id="cred-1",
        cert_chain_pem=[],
        key_algo="1.2.840.113549.1.1.1",
        key_length=2048,
        hash_algos=[],
    )
    client = MagicMock()
    client.credential_info.return_value = info
    with pytest.raises(ValueError, match="empty chain"):
        RemoteCSCProvider(client, otp_provider=lambda: "0").unlock("cred-1", "")
