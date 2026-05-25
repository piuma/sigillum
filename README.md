# Sigillum

Sigillum is a desktop application for digitally signing, timestamping, encrypting, and verifying documents in the following formats:

- **PAdES** (signed PDFs)
- **CAdES** (.p7m enveloping)
- **XAdES** (enveloped XML)
- **TSR / TSD** (standalone timestamp — RFC 3161 / ETSI TS 119 422)
- **Symmetric (`.enc`) and asymmetric (CMS EnvelopedData `.p7e`) encryption

It supports credentials from files (PKCS#12) and hardware tokens via PKCS#11 (YubiKey, Bit4id Digital-DNA Key, smartcards via OpenSC), RFC 3161 timestamping (level T for signatures, standalone timestamp for files), even on qualified TSAs with HTTP Basic Auth, and chain validation against the imported AgID Trust List. locally.

## Project Status

Available Features:

- PAdES Level B and T Signature
- CAdES Level B and T Signature (`.p7m` Enveloping)
- XAdES Level B and T Signature (enveloped in XML)
- Standalone Timestamp of any file: `.tsr` (evidence only, requires the original for verification) or `.tsd` (self-consistent ETSI TS 119 422 envelope with content + embedded evidence)
- Encryption of file in four ways: symmetric with password (AES-256/AES-128/3DES/Blowfish in CBC + PKCS#7 + PBKDF2-SHA256), asymmetric against the configured certificate (token or file), asymmetric against a certificate from a PKCS#12 file
- Verification of PAdES/CAdES/XAdES signatures and timestamps `.tsr` / `.tsd` with separate checks for hash, signature, signer chain, timestamp, TSA chain
- **Visible signature** on PDF: preset angle, page, optional logo, and graphical selection of the frame with the mouse on the PDF preview
- **Auto-detection** of the PKCS#11 token + compatible driver
- **Preview of the signature frame** in the settings
- Device configuration, TSA (URL + optional Basic Auth) and logo persisted in `~/.config/sigillum/settings.json` (0600 because it may contain TSA passwords)
- Import of the AgID Trust List (TSL) in local PEM bundles for validation of the signer chain and qualified Italian TSAs
- Background auto-refresh of the TSL at startup if missing or older than 30 days
- Validation of the cert chain via manual walker (necessary because qualified Italian certs often do not have the required `subjectAltName`) (`cryptography.PolicyBuilder`)

Current limitations:

- LTA levels not yet implemented in the signer
- The `sigillum.core.tsa` module is a stub: signature timestamping is passed through `endesive`; The standalone timestamp (`.tsr` / `.tsd`) is in `sigillum.core.timestamp`
- TSL XML is not cryptographically validated (HTTPS is trusted to AgID — TOFU)

## Requirements

- Linux
- Python ≥ 3.11
- GTK 3 + GObject introspection (`PyGObject`)
- Poppler with GI bindings (for PDF preview in the visible signature picker)

Python dependencies (defined in `pyproject.toml`):

- `endesive` — PAdES/CAdES signing/verification
- `PyKCS11` — token access via PKCS#11
- `cryptography` — cryptographic primitives and X.509 parsing
- `asn1crypto` — low-level CMS/X.509 manipulation
- `PyGObject` — GTK / GLib / Cairo / Poppler binding
- `requests` — HTTP calls (TSL AgID, FreeTSA CA)
- `lxml` — XAdES (XML signing)

### System packages (indicative)

On Debian/Ubuntu:

```bash
sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-poppler-0.18
```

On Fedora:

```bash
sudo dnf install python3-gobject gtk3 poppler-glib
```

## Installation

`PyGObject` is normally installed as a system package; To avoid duplication, use a virtualenv with `--system-site-packages`:

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

For development tools (pytest, ruff):

```bash
pip install -e .[dev]
```

## Startup

After installation:

```bash
sigillum # starts the GUI (default)
sigillum --help # lists CLI subcommands
sigillum gui # explicitly starts the GUI
```

Or without an install script:

```bash
PYTHONPATH=src python -m sigillum [subcommand]
```

## CLI

All GUI functions are also available from the command line. Without
subcommands, `sigillum` launches the GUI; with a subcommand, it performs the operation
and exits. PINs and passwords can be passed via an environment variable or an
interactive prompt.

| Variable | For what |
|---|---|
| `SIGILLUM_PIN` | PKCS#11 token PIN |
| `SIGILLUM_PASSWORD` | PKCS#12 file password / symmetric password |
| `SIGILLUM_TSA_PASSWORD` | TSA HTTP Basic Password |

Available subcommands:

```bash
sigillum sign <file> [-o OUT] [--level B|T|LT] [--visible] [--position …] 
[--image LOGO] [--reason …] [--cert P12 | --lib LIB --cert-id ID] 
[--tsa URL --tsa-user U --tsa-password P]
sigillum verify <file> [--original FILE] [--trusted CA.pem] [--tsa-trusted CA.pem] [--json]
sigillum timestamp <file> [-o OUT] [--format tsr|tsd] [--tsa URL …]
sigillum encrypt <file> [-o OUT] [--mode sym|asym] [--algo AES-256|AES-128|3DES|Blowfish] 
[--recipient CERT.p12]
sigillum decrypt <file> [-o OUT] [--cert P12 | --lib LIB --cert-id ID]
sigillum tsl-import
sigillum detect [--json]
sigillum config show [--json]
sigillum config set [--cert P12 | --lib LIB --cert-id ID]
[--tsa URL --tsa-user U --tsa-password P]
[--image LOGO --position …]
sigillum gui
```

The signature format is derived from the file extension (`.pdf` → PAdES,
`.xml` → XAdES, otherwise CAdES). Credentials and the TSA use the
saved configuration if explicit flags are not passed. At level B,
no TSA is contacted, even if one is present in the Settings — to
apply a timestamp, use `--level T` (or `--level LT`).

Examples:

```bash
# PAdES B signature with .p12
SIGILLUM_PASSWORD=secret sigillum sign document.pdf --cert my.p12 -o document.signed.pdf

# PAdES T signature with visibility in the lower right corner + logo
SIGILLUM_PASSWORD=secret sigillum sign report.pdf --cert my.p12 \
--level T --tsa https://freetsa.org/tsr \
--visible --position bottom-right --image logo.png --reason "Approved"

# PAdES LT signature with YubiKey token
SIGILLUM_PIN=123456 sigillum sign report.pdf \
--lib /usr/lib64/libykcs11.so.2 --cert-id 02:9c67ef95f0e64305 \
--level LT --tsa https://freetsa.org/tsr

# Verify with JSON output (parseable by script)
sigillum verify document.signed.pdf --json

# Standalone timestamp .tsd with TSA configured
sigillum timestamp document.pdf --format tsd

# AES-256 symmetric encryption + decryption
SIGILLUM_PASSWORD=pwd sigillum encrypt secret.txt -o secret.enc
SIGILLUM_PASSWORD=pwd sigillum decrypt secret.enc -o secret.recovered.txt

# Asymmetric encryption to a recipient (cert in .p12, public key)
sigillum encrypt secret.txt --mode asym --recipient recipient.p12

# Import TSL AgID and token detection
sigillum tsl-import
sigillum detect
```

Exit code: `0` success, `1` User error (incorrect argument, missing file),
`2` Service error (TSA unreachable, network), `3` Signature verification failed
(untrusted chain, invalid hash, etc.).

## Quick Use

1. Open the **Settings** tab.
2. **Signing Device**: Choose PKCS#12 File or PKCS#11 Token.
- For the token: click **"🔍Automatically detect token"** — Sigillum tries known PKCS#11 drivers (YubiKey, Bit4id, OpenSC, and Bit4id installed under `~/infocamere`, `~/aruba`, `~/dike*`) and select the first one that returns certificates.
3. **Timestamp (TSA)**: Optional. Choose a preset (FreeTSA, Aruba PEC, InfoCert, Namirial, DigiCert) or enter a custom URL. If the TSA requires HTTP Basic Auth (qualified Italian TSAs), enter your username and password.
4. **Visible signature**: Optional PNG/JPG logo that will appear to the left of the signature text. The preview shows how the box will look.
5. **AgID Trust List**: Click "Import from TSL AgID" to download the certificates of qualified Italian CAs. Sigillum can also do this automatically if the file is more than 30 days old or has never been imported.
6. Save.
7. Go to **Sign**: select the file, optionally enable timestamping and visible signature (with position presets or "🖱 Draw on PDF..." to select with the mouse), enter your PIN/password, and sign.
8. **Standalone Timestamp** (without signature): go to the **Timestamp** tab, select any file, choose TSR or TSD format (see the dedicated section below), and click "Timestamp." The output is saved alongside the source as `documento.ext.tsr` or `documento.ext.tsd`.
9. Verify signed or stamped files from the **Verify** tab: the format is deduced from the extension (`.pdf`, `.p7m`, `.xml`, `.tsr`, `.tsd`). For `.tsr` files, the original file is also requested. The trust store uses the imported AgID TSL by default; additional CAs (including for the TSA) can be added from the "Additional Options" tab.

## PKCS#11 Token

Auto-detection proven on:

- **YubiKey** PIV — `libykcs11.so.2`
- **Bit4id Digital-DNA Key** (CCIAA / InfoCamere / Aruba / Namirial token) — proprietary `libbit4xpki.so`, from Aruba Sign / InfoCamere Sign Desktop / Dike
- Generic **CNS / CIE Smartcards** via `opensc-pkcs11.so` (OpenSC)

Note: OpenSC 0.27 has a known bug with the ATMEL Athena CNS cert container — it sees keys but cannot read certificates. Sigillum uses the proprietary Bit4id driver if available (this is what `detect_tokens()` prefers if both are present). The scanned paths are in `src/sigillum/core/detection.py`.

For live testing with YubiKey (requires hardware + PIN via env):

```bash
SIGILLUM_PIN=<pin> .venv/bin/python tests/test_pkcs11_yubikey.py
```

## Standalone Timestamp (TSR / TSD)

In addition to timestamping **within a signature** (PAdES/CAdES/XAdES level T), Sigillum can timestamp any file without signing it—useful for proof-of-existence, audit trail, archiving, etc.

The output format is optional:

- **TSR** (`.tsr`) — the file contains only the TSA response (DER `TimeStampToken` RFC 3161): the SHA-256 fingerprint of the document, the `gen_time` certified by the TSA, and the TSA signature itself. It's small (~4-5 KB), but you need the original file to verify it.
- TSD (`.tsd`) — ETSI TS 119 422 TimeStampedData envelope (CMS ContentInfo with OID `1.2.840.113549.1.9.16.1.31`) containing both the TSR and the complete original file. It's self-consistent: verification doesn't require any additional files.

| Feature | TSR | TSD |
|---|---|---|
| Size | small (TST only, ~4-5 KB) | TST + original file + metadata |
| File to verify | the `.tsr` + the original | the `.tsd` only |
| Interop | Pure RFC 3161 | ETSI TS 119 422 (Aruba/InfoCert/Namirial) |
| When to use it | You already have the file and just want to timestamp it | Long-term preservation, archiving |

To generate a timestamp: **Timestamp** tab → file → TSR/TSD radio → "Timestamp". The TSA URL is read from the Settings ("Timestamp" section); if the TSA is an Italian QTSP with HTTP Basic Auth, the username/password must also be entered.

To verify it: **Verify** tab → select the `.tsr` or `.tsd` file like any other signed file. If it is a `.tsr`, a second file chooser will appear where you can specify the corresponding original document. Verification produces the same flags as signatures: hash valid, signature valid, cert trusted, timestamp gen_time, TSA trusted.

Extracting content from a `.tsd` (without verification) — useful from a script:

```python
from sigillum.core.timestamp import extract_tsd_content
fname, content = extract_tsd_content("document.txt.tsd")
# fname == "document.txt" (if present in the MetaData)
# content == bytes of the original file
```

## Encryption

Sigillum encrypts one or more files with four modes, accessible from the **Encrypt** tab:

### Symmetric with password

Container in **SIGILLUM** format (custom, well-defined): magic `SIGILLUM` + version + algorithm name + salt (16B) + IV + ciphertext. Key derivation via **PBKDF2-SHA256 with 600,000 iterations** (NIST SP 800-132 2024 recommendation). **PKCS#7** padding, **CBC** mode.

Selectable algorithms:

| Algorithm | Key | Block | Note |
|---|---|---|---|
| **AES-256** *(default)* | 256 bit | 128 bit | recommended |
| **AES-128** | 128 bit | 128 bit | fastest,Adequate security |
| **3DES** | 168 effective bits | 64 bits | legacy, accepted for interop |
| **Blowfish** | 128 bits | 64 bits | legacy |

Output: `<original>.enc`.

### Asymmetric (CMS EnvelopedData)

Compatible with **RFC 5652 EnvelopedData** (the same one produced by Aruba Sign, Dike, and InfoCamere when "Encrypt for recipient X"). Outer layer: ContentInfo with `content_type=enveloped_data`. Content encrypted with a random AES-256-CBC session key; the session key is wrapped with the recipient's public RSA key via **RSAES-PKCS1-v1.5**.

Two flows:

- **To the certificate configured** in Settings — useful for "self-encryption" (archive use, preservation)
- **To a certificate from a `.p12` file** — useful for encrypting to a third party (upload the `.p12` with the recipient's public key)

Output: `<original>.p7e`.

### Decryption

Auto-detect the format from the file contents:

- Magic `SIGILLUM` → the password is requested and the algorithm name is read from the container
- ContentInfo with `enveloped_data` → the credential (PKCS#11 token or `.p12` file) is used to unenvelope the session key and then decrypt the contents

Output: `<original>.dec` (`.enc`/`.p7e` extension removed).

Python API (scriptable use):

```python
from sigillum.core.crypto import encrypt_symmetric, decrypt_symmetric
blob = encrypt_symmetric(b"secret data", "passw0rd", algorithm="AES-256")
recovered = decrypt_symmetric(blob, "passw0rd")
```

```python
from sigillum.core.crypto import encrypt_asymmetric, decrypt_asymmetric
from sigillum.core.credentials import FileProvider
cred = FileProvider("destinatario.p12").unlock("destinatario.p12", "pwd")
blob = encrypt_asymmetric(b"secret data", cred.certificate)
# … who has the private key:
recovered = decrypt_asymmetric(blob, cred)
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

## License

GPL-3.0-or-later.

