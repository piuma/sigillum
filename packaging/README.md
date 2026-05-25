# Packaging Linux

Sigillum supporta tre canali di distribuzione:

| Canale | Quando preferirlo | Sorgenti |
|---|---|---|
| **Flatpak** (Flathub) | distribuzione cross-distro, sandbox, auto-update | `packaging/flatpak/`, `scripts/build_flatpak.sh` |
| **RPM** (Fedora) | repo Fedora / COPR, integrazione nativa | `packaging/fedora/sigillum.spec` |
| **DEB** (Debian/Ubuntu) | Debian main, Ubuntu, Mint | `debian/` nella root del repo |
| **PyPI + pipx** | sviluppatori / sistemisti senza sandbox | `python -m build` + `twine upload` |

Tutti includono l'app con supporto a PAdES, CAdES, XAdES e marca temporale standalone TSR/TSD.

---

## A) Flatpak

L'opzione consigliata per "gira su tutte le distro" — un'unica build copre Fedora, Ubuntu, Debian, Mint, Arch, openSUSE, ecc. attraverso Flathub.

### Prerequisiti

```bash
sudo dnf install -y flatpak flatpak-builder       # Fedora
sudo apt install -y flatpak flatpak-builder       # Debian/Ubuntu/Mint
```

Aggiungi Flathub se non presente:

```bash
flatpak remote-add --if-not-exists --user flathub \
    https://dl.flathub.org/repo/flathub.flatpakrepo
```

Runtime e SDK GNOME 47 (versione del manifest):

```bash
flatpak install -y --user flathub org.gnome.Platform//47 org.gnome.Sdk//47
```

### Build + install locale

```bash
scripts/build_flatpak.sh
```

Lo script:

1. Alla prima esecuzione (o con `--regen-deps`) genera
   `packaging/flatpak/python3-deps.yaml` usando `flatpak-pip-generator`
   (scaricato automaticamente in `scripts/.flatpak-pip-generator` se non
   è nel PATH). Le dipendenze Python sono lette da `pyproject.toml`.
2. Esegue `flatpak-builder` con installazione user.

Lancia poi l'app:

```bash
flatpak run io.github.sigillum
```

### Bundle distribuibile

```bash
scripts/build_flatpak.sh --bundle
```

Produce `dist/packages/sigillum.flatpak` — un singolo file installabile
su qualsiasi sistema con flatpak:

```bash
flatpak install --user ./sigillum.flatpak
```

### Permessi sandbox

Configurati nel manifest `packaging/flatpak/io.github.sigillum.yml`
(sezione `finish-args`):

- `--socket=pcsc` — accesso al daemon `pcscd` dell'host per smartcard
- `--device=all` — token USB diretti (YubiKey, Bit4id Digital-DNA Key)
- `--filesystem=home` — lettura dei driver vendor (`libbit4xpki.so` sotto
   `~/infocamere/…`) e dei documenti da firmare
- `--share=network` — chiamate TSA e download della TSL AgID
- `--socket=wayland` / `--socket=fallback-x11` — display server

### Driver PKCS#11 inclusi nel bundle

Il sandbox di Flatpak non vede i driver installati su `/usr/lib64` dell'host,
quindi i driver **open source** vengono compilati e inclusi direttamente nel
Flatpak (path `/app/lib/...`, scansionati da `core/detection.py`):

| Driver | Cosa serve | Path nel sandbox |
|---|---|---|
| **pcsc-lite** (libpcsclite client) | comunica col `pcscd` dell'host via `--socket=pcsc` | `/app/lib/libpcsclite.so.1` |
| **OpenSC** | smartcard generiche (CNS, CIE, ecc.) | `/app/lib/pkcs11/opensc-pkcs11.so` |
| **yubico-piv-tool** (libykcs11) | YubiKey PIV via USB diretto | `/app/lib/libykcs11.so.2` |

I driver **proprietari Bit4id** (`libbit4xpki.so` distribuito da Aruba,
InfoCamere, Namirial, Dike) non sono ridistribuibili: l'utente li installa
sull'host nel proprio `$HOME` e il sandbox li vede via `--filesystem=home`.
La libreria ha solo dipendenze base (`libc`, `libm`, `libdl`, `libpthread`)
che sono nel runtime GNOME, quindi `dlopen()` funziona dall'interno del
sandbox senza problemi.

### Pubblicazione su Flathub

Una volta validato localmente:

1. Fork del repo `flathub/flathub`
2. PR con manifest + AppStream + icona in una nuova directory `io.github.sigillum/`
3. Il bot Flathub valida e suggerisce eventuali correzioni
4. Dopo l'approvazione, l'app appare su Flathub e diventa installabile
   da qualsiasi distribuzione con un click

---

## B) RPM (Fedora)

Lo `.spec` nativo è in `packaging/fedora/sigillum.spec`, scritto secondo le
[Fedora Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/)
e [Python](https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/):
macro `%pyproject_*`, `%license`, `%check` con `pytest -m "not network and not hardware"`,
`%autorelease`/`%autochangelog` (rpmautospec).

### Prerequisiti

```bash
sudo dnf install -y rpm-build rpmlint rpmautospec pyproject-rpm-macros \
                    python3-hatchling python3-devel \
                    desktop-file-utils libappstream-glib \
                    fedpkg mock
```

### Build

```bash
# 1. Crea il tarball della release (qualsiasi tag/commit):
TAG=v0.1.0
git archive --format=tar.gz --prefix=sigillum-${TAG#v}/ HEAD \
    -o ~/rpmbuild/SOURCES/sigillum-${TAG#v}.tar.gz

# 2. Lint dello spec (deve essere silenzioso):
rpmlint packaging/fedora/sigillum.spec

# 3. SRPM e RPM binario:
rpmbuild -bs packaging/fedora/sigillum.spec
rpmbuild -bb packaging/fedora/sigillum.spec
```

### Mock (chroot pulito, riproducibile)

```bash
sudo usermod -a -G mock $USER     # logout/login dopo la prima volta
mock -r fedora-43-x86_64 --rebuild ~/rpmbuild/SRPMS/sigillum-*.src.rpm
```

### Dipendenza non in Fedora: `python3-endesive`

`endesive` non è ancora in Fedora. Lo spec scaffold per pacchettizzarla è in
`packaging/fedora/python-endesive.spec`. Build identica:

```bash
spectool -g -R packaging/fedora/python-endesive.spec
rpmbuild -ba packaging/fedora/python-endesive.spec
```

Dettagli del processo di review Fedora in `packaging/fedora/README.md`.

## C) DEB (Debian / Ubuntu / Mint)

I file `debian/` sono nella root del repository, scritti per debhelper 13 +
`pybuild-plugin-pyproject`. La pacchettizzazione di endesive
(`python3-endesive`, non ancora in Debian) è scaffoldata in
`packaging/python3-endesive/`.

### Prerequisiti (Debian/Ubuntu)

```bash
sudo apt install build-essential debhelper dh-python pybuild-plugin-pyproject \
                 python3-all python3-hatchling devscripts lintian
```

### Build

```bash
dpkg-buildpackage -us -uc -b
lintian ../sigillum_*.deb
```

Dettagli nel file `debian/README.source`.

---

## D) PyPI + pipx

Per pubblicare su PyPI:

```bash
pip install build twine
python -m build              # genera dist/sigillum-*.whl e .tar.gz
twine upload dist/sigillum-*
```

L'utente finale lo installa con `pipx`, che crea una venv isolata
e mette il comando `sigillum` nel PATH:

```bash
pipx install sigillum
sigillum
```

Funziona su ogni distro con Python ≥ 3.11. Richiede però che PyGObject + GTK + Poppler
siano disponibili come pacchetti di sistema (vedi il `README.md` principale).
