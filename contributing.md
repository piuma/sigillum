## Installation with development tools

For development tools (pytest, ruff):

```bash
pip install -e .[dev]
```

## Trust stores and TSL

The PEM bundles derived from the AgID TSL (https://eidas.agid.gov.it/TL/TSL-IT.xml) are saved in:

- `~/.local/share/sigillum/trusted/it-eidas-signing.pem` — Italian Qualified Signatory CA (~356 certs)
- `~/.local/share/sigillum/trusted/it-eidas-tsa.pem` — Italian Qualified TSA CA (~29 certs)

The parser filters out the `withdrawn` and `deprecatedatnationallevel` states, separates by service type (signature vs. timestamping), and deduplicates by SHA-256 fingerprint.

The TSL XML is not cryptographically validated in this release (TOFU over HTTPS to AgID). Adding XAdES validation of the TSL itself according to ETSI TS 119 612 is the next natural step for a hardened deployment.

Chain validation (both signer and TSA) uses a manual walker (`_verify_cert_chain` in `core/verifier.py`) based on `Certificate.verify_directly_issued_by()`. This is necessary because `cryptography.x509.verification.PolicyBuilder().build_client_verifier()` (used by `endesive`) is TLS-specific and requires `subjectAltName` on the leaf—which is absent in most Italian qualified certificates.

## Translations (i18n)

The interface (GUI + CLI) is internationalized via [GNU gettext](https://www.gnu.org/software/gettext/).
The source language is English; translations live in `po/<lang>.po`.
Italian (`po/it.po`) is currently available.

Workflow:

```bash
# Regenerate the template after source changes
make -C po pot

# Synchronize existing .po files with new msgid files
make -C po po

# Compile to .mo for local testing (without installing the package)
make -C po compile
PYTHONPATH=src LANG=it_IT.UTF-8 python -m sigillum --help
PYTHONPATH=src LANG=en_US.UTF-8 python -m sigillum --help
```

Add a new language (e.g., German `de`):

```bash
msginit --input=po/sigillum.pot --locale=de --output=po/de.po
echo de >> po/LANGUAGES
# … translate po/de.po …
make -C po compile
```

The distro packages (RPMs and DEB) automatically compiles and installs the `.mo` files
under `/usr/share/locale/<lang>/LC_MESSAGES/sigillum.mo`.

### Man page

The manual page is in `docs/sigillum.1` (English, source). Translations
are managed with [po4a](https://po4a.org/): the Italian translation lives in
`docs/po4a/it.po` and is compiled into `docs/build/it/sigillum.1` when
packages are built.

```bash
-C docs pot # regenerates the template after modifying sigillum.1
make -C docs po # synchronizes existing .po files
make -C docs man # produces docs/build/<lang>/sigillum.1
```

Packages install English under `/usr/share/man/man1/` and any
translations under `/usr/share/man/<lang>/man1/`. `man sigillum` automatically chooses
the language based on `$LANG`.

## Creating native-distro packages

- **RPM (Fedora):** spec in `packaging/fedora/sigillum.spec` — compliant with the
Fedora Packaging Guidelines (macros `%pyproject_*`, rpmautospec, `%check`
which excludes network/hardware tests).

```bash 
TAG=v0.1.0 
git archive --format=tar.gz --prefix=sigillum-${TAG#v}/ HEAD \ 
-o ~/rpmbuild/SOURCES/sigillum-${TAG#v}.tar.gz 
rpmbuild -ba packaging/fedora/sigillum.spec 
```

- **DEB (Debian / Ubuntu / Mint):** `debian/` directory in the root — 
debhelper 13 + `pybuild-plugin-pyproject`, copyright in DEP-5 format. 

```bash
dpkg-buildpackage -us -uc -b
```

`python3-endesive` is not yet in the official Debian/Fedora repositories —
the packaging scaffolds are in `packaging/python3-endesive/`
(Debian) and `packaging/fedora/python-endesive.spec` (Fedora).

For prerequisites, details, and distro review workflow, see `packaging/README.md`.

## Test

Complete execution:

```bash
pytest -q
```

Offline tests that run without external dependencies:

```bash
pytest -q tests/test_pades_sign.py
pytest -q tests/test_pades_roundtrip.py
pytest -q tests/test_pades_visible.py
pytest -q tests/test_cades_roundtrip.py
pytest -q tests/test_xades_roundtrip.py
pytest -q tests/test_settings.py
pytest -q tests/test_detection.py
pytest -q tests/test_crypto.py
```

Tests requiring networking:

```bash
pytest -q tests/test_tsl.py # download the AgID TSL
pytest -q tests/test_tsa_live.py # B/T signature to FreeTSA
pytest -q tests/test_timestamp.py # timestamp Standalone TSR + TSD via FreeTSA
```

Live YubiKey test (requires hardware + PIN via env):

```bash
SIGILLUM_PIN=<pin> .venv/bin/python tests/test_pkcs11_yubikey.py
```

## Project Structure

```text
src/sigillum/
__main__.py # entry point: dispatcher CLI/GUI
cli.py # CLI argparse with subcommands (sign/verify/encrypt/…)
core/
credentials.py # provider file (PKCS#12/PEM) and PKCS#11 (with sign + rsa_decrypt)
crypto.py # symmetric (AES/3DES/Blowfish) + asymmetric (CMS EnvelopedData) encryption
detection.py # auto-detection token + PKCS#11 driver
settings.py # configuration persistence (JSON in XDG_CONFIG)
signer.py # PAdES/CAdES/XAdES signing + visible appearance
timestamp.py # standalone TSR timestamp (RFC 3161) + TSD (ETSI TS 119 422)
tsa.py # TSA stub (timestamping in signatures goes from end-to-end)
tsl.py # download and parse TSL AgID
verifier.py # verification + chain walker (PAdES/CAdES/XAdES + TSA)
gui/
app.py # GTK application (Signature/Mark/Encrypt/Verify/Settings)
signature_picker.py # Poppler+Cairo dialog to draw the signature box
tests/
fixtures.py # helper: minimal PDF, self-signed CA→signer chain
test_pades_*.py # PAdES signature/verification/visible signature
test_cades_*.py # signature/verificationica CAdES enveloping
test_xades_*.py # XAdES enveloped signing/verification
test_settings.py # JSON roundtrip + 0600 permissions
test_detection.py # Driver/token auto-detection
test_crypto.py # Symmetric + asymmetric roundtrip encryption
test_tsl.py # AgID TSL parsing (network)
test_tsa_live.py # T-level signing against FreeTSA (network)
test_timestamp.py # Standalone TSR + TSD timestamp via FreeTSA (network)
test_pkcs11_yubikey.py # Signing with a real YubiKey (hardware)
```

## Steps to create new release

For example if v0.2.1 is the new version, the sequence is:

Steps:

1. Bump the version in all files (the only double-check worth doing — the workflow will fail the version check if one is misaligned):
  - pyproject.toml => version = "0.2.1"
  - src/sigillum/__init__.py → __version__ = "0.2.1"
  - docs/Makefile => --package-version 0.2.1
  - docs/sigillum.1 => sigillum 0.2.1
  - packaging/fedora/sigillum.spec → Version: 0.2.1 (was still 0.1.0)
  - debian/changelog => new sigillum entry (0.2.1-1) ... (was still 0.1.0-1)
  - (opt.) packaging/flatpak/io.github.sigillum.metainfo.xml => new <release version="0.2.1" date="...">
2. Commit + tag v0.2.1.
3. Push the commit and tag => automatically triggers the workflow.
4. GitHub Actions: The pypi job will pause pending approval (pypi environment with required reviewer). You approve by clicking "Review deployments" on the workflow page.
5. Draft release: As soon as the rpm and deb are finished, you'll find a draft at https://github.com/piuma/sigillum/releases with the 4 assets (sigillum-*.rpm, python3-endesive-*.rpm, sigillum_*.deb, python3-endesive_*.deb). Review it and click **Publish release**.