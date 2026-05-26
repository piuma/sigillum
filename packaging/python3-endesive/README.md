# python3-endesive (Debian packaging template)

This directory contains a Debian packaging template for **endesive**
(upstream: <https://github.com/m32/endesive>), the Python library Sigillum
depends on for PAdES/CAdES/XAdES signing.

`endesive` is **not in Debian** as of 2026-05. Sigillum can't enter Debian
main until this dependency is packaged. This template is meant to bootstrap
that effort; it is **not** a complete source package — you need to clone
the upstream source and drop these files into it.

## Upstream license

MIT (see <https://github.com/m32/endesive/blob/master/LICENSE>). DFSG-free.

## Quick local build (recommended for users)

If you only need a working `python3-endesive_X.Y.Z-1_all.deb` to satisfy
Sigillum's `Depends: python3-endesive`, run the snippet below. It does
**not** include the Debian-mentoring workflow (ITP bug, lintian audit,
sponsor upload) — see [Full upstream workflow](#full-upstream-workflow)
for that.

```bash
# Work outside the sigillum checkout to keep its source tree clean.
mkdir -p ~/work/endesive && cd ~/work/endesive
VERSION=2.19.3

# 1. Extra build deps for endesive (everything else is already in
#    sigillum's build-deps).
sudo apt install python3-pil python3-paramiko python3-wheel \
                 debhelper dh-python pybuild-plugin-pyproject \
                 python3-setuptools devscripts

# 2. Fetch upstream tarball — endesive ships wheel-only on PyPI, so we
#    pull the source from GitHub by tag.
curl -sL -o endesive_${VERSION}.orig.tar.gz \
    https://github.com/m32/endesive/archive/refs/tags/v${VERSION}.tar.gz

# 3. Extract + overlay the debian/ template shipped with sigillum.
tar xf endesive_${VERSION}.orig.tar.gz
cd endesive-${VERSION}
cp -r /path/to/sigillum/packaging/python3-endesive/debian .

# 4. Build the .deb.
dpkg-buildpackage -us -uc -b

# 5. Install it system-wide so sigillum can pick it up at build time.
sudo dpkg -i ../python3-endesive_${VERSION}-1_all.deb \
    || sudo apt install -f -y

# 6. Now sigillum builds.
cd /path/to/sigillum
dpkg-buildpackage -us -uc -b
```

The endesive `.deb` is not maintained by apt — when upstream releases a
new version you have to repeat steps 2-5 with the new `VERSION`.

## Full upstream workflow

Steps for proposing `python3-endesive` for inclusion in Debian (ITP →
review → sponsor upload). Skip this if you only need the local `.deb`.

```bash
# 1. File an ITP (Intent To Package) bug:
#    https://www.debian.org/devel/wnpp/being_packaged
reportbug --no-config-files wnpp
# Subject:  ITP: python3-endesive -- ...
# Severity: wishlist

# 2. Get the upstream tarball. NOTE: endesive ships wheel-only on PyPI
#    (no sdist), so the tarball must come from GitHub by tag.
VERSION=2.19.3
mkdir -p ~/work/endesive && cd ~/work/endesive
curl -sL -o endesive_${VERSION}.orig.tar.gz \
    https://github.com/m32/endesive/archive/refs/tags/v${VERSION}.tar.gz

# 3. Extract and copy this debian/ over:
tar xf endesive_${VERSION}.orig.tar.gz
cd endesive-${VERSION}
cp -r /path/to/sigilum/packaging/python3-endesive/debian .

# 4. (optional) Refresh the changelog with your name/email and an ITP bug:
debchange --release "" --distribution unstable
# Replace #XXXXXX in debian/changelog with the real ITP bug number.

# 5. Build:
apt build-dep .
dpkg-buildpackage -us -uc -b
lintian ../python3-endesive_${VERSION}-1_all.deb

# 6. Install locally so sigillum can build against it:
dpkg -i ../python3-endesive_${VERSION}-1_all.deb || apt install -f -y

# 7. Find a sponsor, upload via mentors.debian.net:
#    https://wiki.debian.org/Mentors
```

## What still needs verification

When you go through the upstream code, double-check that:

1. There are no bundled binary blobs (some PDF libs embed fonts).
2. The `tests/` directory doesn't include non-redistributable PDFs.
3. The vendored dependencies (if any) are all DFSG-clean.
4. The reverse-deps mentioned in `debian/control` are all in Debian.

In particular, recent endesive versions started bundling test PDFs that
contain digital signatures by other parties — verify with:

```bash
licensecheck -r .
```

If any files turn out non-free, list them in `debian/copyright` under a
separate stanza and exclude them via `debian/source/include-binaries`
plus `Files-Excluded` in `debian/copyright`.

## Reverse-dependency

Sigillum's `debian/control` declares `Depends: python3-endesive`. Until
this package lands in Debian, Sigillum can be built only against a
locally-built `python3-endesive_X.Y.Z-1_all.deb`.
