%global pypi_name sigillum
%global forgeurl https://github.com/piuma/sigillum
# %%{tag} resolves the GitHub release tag whose name is `v<version>`.
# When you tag a new release, update `Version:` and rebuild.
%global tag v%{version}

Name:           %{pypi_name}
Version:        0.2.2
%forgemeta -i
Release:        %autorelease
Summary:        Italian eIDAS digital signature tool (PAdES/CAdES/XAdES)

License:        GPL-3.0-or-later
URL:            %{forgeurl}
Source0:        %{forgesource}

BuildArch:      noarch

# Minimal explicit BRs. Everything else — the runtime deps from
# pyproject.toml's `[project] dependencies` (cryptography, asn1crypto,
# lxml, pykcs11, requests, endesive) and the test deps from the `dev`
# extra (pytest) — is pulled by %%pyproject_buildrequires below.
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
BuildRequires:  gettext
BuildRequires:  po4a

# Needed by %%pyproject_check_import for the GUI modules: PyCairo and the
# GTK3/Poppler typelibs (gtk3 pulls in gdk-pixbuf2 and pango as deps, which
# provide the GdkPixbuf-2.0 and Pango-1.0 typelibs imported by gui/app.py).
BuildRequires:  python3-cairo
BuildRequires:  gtk3
BuildRequires:  poppler-glib

# Runtime GTK stack
Requires:       python3-gobject
Requires:       gtk3
Requires:       poppler-glib

# Workaround for upstream endesive: its bundled PyPDF2_annotate / email /
# verify modules import `attr`, `certifi` and `fontTools` but endesive's
# pyproject.toml doesn't declare any of them. Once that's fixed upstream
# and reflected in python-endesive's spec, these explicit Requires can be
# dropped.
Requires:       python3-attrs
Requires:       python3-certifi
Requires:       python3-fonttools

# Recommend the open-source PKCS#11 drivers users will most likely need.
Recommends:     opensc
Recommends:     yubico-piv-tool

%description
Sigillum is a GTK desktop application for digital signature, time-stamping
and encryption of documents according to ETSI/eIDAS standards.

Features:
 * PAdES (signed PDF), CAdES (.p7m enveloping), XAdES (signed XML)
 * Levels B (basic), T (with TSA timestamp) and LT (long-term: chain
   and revocation data embedded for offline verification)
 * Standalone RFC 3161 timestamps (.tsr) and ETSI TS 119 422
   TimeStampedData (.tsd)
 * File encryption: symmetric (AES-256/AES-128/3DES/Blowfish) with
   password and asymmetric (CMS EnvelopedData) with recipient certificate
 * PKCS#12 file credentials and PKCS#11 hardware tokens
   (YubiKey, smartcards via OpenSC, Bit4id Digital-DNA Key with the
   vendor driver if the user installs it from the vendor's site)
 * Italian eIDAS Trusted List (AgID TSL) for qualified signers and TSAs

Both a GTK GUI and a feature-complete CLI for batch workflows are included.

%prep
%forgeautosetup -p1

%generate_buildrequires
# `-x dev` pulls pytest + ruff from pyproject.toml's optional-dependencies.
%pyproject_buildrequires -x dev

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files -L %{pypi_name}

# Desktop entry, AppStream metainfo and SVG icon are kept under
# packaging/flatpak/ but are not flatpak-specific — install them from there.
install -Dpm 0644 packaging/flatpak/io.github.piuma.sigillum.desktop \
    %{buildroot}%{_datadir}/applications/io.github.piuma.sigillum.desktop
install -Dpm 0644 packaging/flatpak/io.github.piuma.sigillum.metainfo.xml \
    %{buildroot}%{_datadir}/metainfo/io.github.piuma.sigillum.metainfo.xml
install -Dpm 0644 packaging/flatpak/io.github.piuma.sigillum.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.piuma.sigillum.svg

# Shell completion (pre-generated with `make completion`, committed in repo).
install -Dpm 0644 completion/bash/sigillum \
    %{buildroot}%{_datadir}/bash-completion/completions/sigillum
install -Dpm 0644 completion/zsh/_sigillum \
    %{buildroot}%{_datadir}/zsh/site-functions/_sigillum

# Man pages: docs/Makefile builds the localised versions via po4a and
# installs both the English original and every translation under the
# proper man tree.
make -C docs install DESTDIR=%{buildroot} prefix=%{_prefix}

# Compile and install gettext message catalogs.
# `make install` puts them under $(localedir) = $(prefix)/share/locale.
make -C po install DESTDIR=%{buildroot} prefix=%{_prefix}
%find_lang %{pypi_name}

%check
%pyproject_check_import
# Network and hardware-bound tests are excluded from the build chroot.
%pytest tests/ -m "not network and not hardware"
desktop-file-validate \
    %{buildroot}%{_datadir}/applications/io.github.piuma.sigillum.desktop
appstream-util validate-relax --nonet \
    %{buildroot}%{_datadir}/metainfo/io.github.piuma.sigillum.metainfo.xml

# %%{pypi_name}.lang (from %%find_lang) pulls in every
# locale/*/LC_MESSAGES/sigillum.mo built by `make install`.
%files -f %{pyproject_files} -f %{pypi_name}.lang
%license LICENSE
%doc README.md
%{_bindir}/sigillum
%{_mandir}/man1/sigillum.1*
%lang(it) %{_mandir}/it/man1/sigillum.1*
%{_datadir}/applications/io.github.piuma.sigillum.desktop
%{_datadir}/metainfo/io.github.piuma.sigillum.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/io.github.piuma.sigillum.svg
%{_datadir}/bash-completion/completions/sigillum
%{_datadir}/zsh/site-functions/_sigillum

%changelog
%autochangelog
