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
sudo dnf install rpm-build rpmlint rpmautospec pyproject-rpm-macros \
                 python3-hatchling python3-devel \
                 desktop-file-utils libappstream-glib \
                 fedpkg mock
```

### `sigillum`

Lint the spec, build the source RPM, then build the binary RPM:

```bash
cd packaging/fedora

# Create a tarball matching the spec's Source0:
TAG=v0.1.0
git -C ../.. archive --format=tar.gz \
    --prefix=sigillum-${TAG#v}/ HEAD \
    -o ~/rpmbuild/SOURCES/sigillum-${TAG#v}.tar.gz

# Spec lint (must be silent):
rpmlint sigillum.spec

# Source RPM:
rpmautospec process-distgit sigillum.spec /tmp/sigillum.spec
rpmbuild -bs --define "_sourcedir $HOME/rpmbuild/SOURCES" /tmp/sigillum.spec

# Binary RPM (uses your system as the chroot):
rpmbuild -ba /tmp/sigillum.spec
```

### `python-endesive`

```bash
TAG=2.17.0
spectool -g -R python-endesive.spec   # pulls from PyPI
rpmlint python-endesive.spec
rpmautospec process-distgit python-endesive.spec /tmp/python-endesive.spec
rpmbuild -ba /tmp/python-endesive.spec
```

### Reproducible chroot build with `mock`

```bash
sudo dnf install mock
# Add your user to the `mock` group (logout/login required after first time):
sudo usermod -a -G mock $USER

mock -r fedora-43-x86_64 --rebuild ~/rpmbuild/SRPMS/python-endesive-2.17.0-1*.src.rpm
mock -r fedora-43-x86_64 --addrepo /var/lib/mock/fedora-43-x86_64/result \
      --rebuild ~/rpmbuild/SRPMS/sigillum-0.1.0-1*.src.rpm
```

The `--addrepo` step makes the freshly-built `python3-endesive` available to
the Sigillum build inside the chroot, since the dependency isn't in Fedora's
repos yet.

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
