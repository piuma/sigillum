# Sigillum — Fedora packaging

This directory ships native RPM spec files for Fedora, conforming to the
[Fedora Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/)
and the [Python guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/).

Files:

- `sigillum.spec` — the application itself
- `python-endesive.spec` — required dependency, **not yet in Fedora**
- `changelog` — fed to `%autochangelog`/`%autorelease` by `rpmautospec`

## Building locally

Required tools on Fedora ≥ 41:

```bash
sudo dnf install rpm-build rpmdevtools rpmlint rpmautospec \
                 pyproject-rpm-macros python3-hatchling python3-devel \
                 desktop-file-utils libappstream-glib \
                 fedora-packager mock po4a gettext
rpmdev-setuptree   # creates ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
```

If `rpmlint` warns about
`sh: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)`,
install the corresponding glibc langpack:

```bash
sudo dnf install glibc-langpack-en
```

### `python-endesive` (build first — sigillum's build-deps require it)

`endesive` is not in Fedora. The spec uses `%forgemeta` to fetch the
source from GitHub by tag (upstream ships wheel-only on PyPI, no sdist).
Build the RPM **once**, install it system-wide, and keep using it; when
upstream releases a new version, bump `Version:` in the spec and repeat.

```bash
cd packaging/fedora

# 1. Download the upstream tarball at the version pinned in the spec
#    into ~/rpmbuild/SOURCES/ (spectool reads %forgesource).
spectool -g -R python-endesive.spec

# 2. Install endesive's own build deps (cryptography, asn1crypto, lxml,
#    pillow, pykcs11, requests, paramiko, attrs, pytest, …).
sudo dnf builddep -y python-endesive.spec

# 3. Spec lint (must be silent — warnings about en_US.UTF-8 are
#    environmental, not from the spec; see the note above).
LC_ALL=C.UTF-8 rpmlint python-endesive.spec

# 4. Build the binary RPM.
rpmbuild -bb python-endesive.spec

# 5. Install it so sigillum's build can resolve python3dist(endesive).
sudo dnf install -y ~/rpmbuild/RPMS/noarch/python3-endesive-*.rpm
```

The spec explicitly declares `Requires: python3-attrs` because endesive
bundles `PyPDF2_annotate` (Autodesk 2019) which imports `attr` but is
not listed in upstream's `pyproject.toml`. Drop that line once upstream
fixes the metadata.

### `sigillum`

```bash
cd packaging/fedora

# 1. Install build deps. With python3-endesive installed (see above),
#    %pyproject_buildrequires now resolves cleanly.
sudo dnf builddep -y sigillum.spec

# 2. Fetch the source tarball from GitHub (the spec uses %forgemeta —
#    NOT a local working-tree archive).
spectool -g -R sigillum.spec

# 3. Spec lint.
LC_ALL=C.UTF-8 rpmlint sigillum.spec

# 4. Source RPM + binary RPM.
rpmbuild -bs sigillum.spec
rpmbuild -bb sigillum.spec
```

The output is in `~/rpmbuild/RPMS/noarch/sigillum-<ver>.fc<NN>.noarch.rpm`.

### Reproducible chroot build with `mock`

```bash
sudo dnf install mock
# Add your user to the `mock` group (logout/login required after first time):
sudo usermod -a -G mock $USER

# Build endesive first.
mock -r fedora-44-x86_64 --rebuild \
     ~/rpmbuild/SRPMS/python-endesive-2.19.3-1*.src.rpm

# Build sigillum, exposing the endesive result repo to the chroot.
mock -r fedora-44-x86_64 \
     --addrepo file:///var/lib/mock/fedora-44-x86_64/result \
     --rebuild ~/rpmbuild/SRPMS/sigillum-0.1.0-1*.src.rpm
```

The `--addrepo` step makes the freshly-built `python3-endesive` available
to the Sigillum build inside the chroot, since the dependency isn't in
Fedora's repos yet.

## Submitting to Fedora

The recommended order for going through Fedora's review:

1. Open a review request for `python-endesive` first on bugzilla.redhat.com,
   product "Fedora", component "Package Review". Attach the SRPM.
2. Once `python-endesive` is sponsored, accepted and pushed to a side-tag,
   open a review request for `sigillum` referencing it.
3. Use `fedpkg` for the actual import.

See: https://docs.fedoraproject.org/en-US/package-maintainers/Package_Review_Process/

## Why this replaces `scripts/build_packages.sh`

The previous `build_packages.sh` used `fpm` to turn the wheel into a `.rpm`
and a `.deb`. That approach produces "informal" packages: they install but
are rejected by both Debian and Fedora's review processes because they
bypass the official packaging macros (`%pyproject_*`, `dh_python3`),
skip `%license`/`%check`, and don't produce verifiable changelogs.

The official packaging now lives under `packaging/fedora/` (this directory)
and `debian/` (Debian source package). Both are validated by their
respective linters (`rpmlint`, `lintian`) and use the standard macros
required for upload.
