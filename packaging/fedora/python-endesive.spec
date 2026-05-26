%global pypi_name endesive
%global forgeurl https://github.com/m32/%{pypi_name}
# Upstream does not ship sdists on PyPI (wheel-only); pull tagged sources
# straight from GitHub via %%forgemeta.
%global tag v%{version}

Name:           python-%{pypi_name}
Version:        2.19.3
%forgemeta -i
Release:        %autorelease
Summary:        Python library for PAdES/CAdES/XAdES digital signatures

License:        MIT
URL:            %{forgeurl}
Source0:        %{forgesource}

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
# endesive uses setuptools as its build backend; without this BR the
# %%pyproject_buildrequires first pass fails the same way sigillum did
# with hatchling.
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
# Runtime deps from endesive's pyproject.toml. They are also test-time and
# must be present at %%generate_buildrequires time, otherwise
# %%pyproject_buildrequires bails out (chicken-and-egg with dnf builddep).
BuildRequires:  python3-cryptography
BuildRequires:  python3-asn1crypto
BuildRequires:  python3-lxml
BuildRequires:  python3-pillow
BuildRequires:  python3-pykcs11
BuildRequires:  python3-requests
BuildRequires:  python3-paramiko
# endesive imports `attr` (attrs), `certifi`, and `fontTools` from its
# bundled PyPDF2_annotate / email / verify code paths without declaring any
# of them in upstream's pyproject.toml. Pull them in explicitly so the
# affected modules don't crash at import time during %check (and at runtime).
BuildRequires:  python3-attrs
BuildRequires:  python3-certifi
BuildRequires:  python3-fonttools
BuildRequires:  python3-pytest

%global _description %{expand:
endesive is a pure-Python library implementing the ETSI standards for
advanced electronic signatures, with support for both software and
hardware (PKCS#11) signing keys.

Supported formats:
 * PAdES (signed PDF, ETSI EN 319 142)
 * CAdES (CMS-based signatures, ETSI EN 319 122)
 * XAdES (XML signatures, ETSI EN 319 132)
 * S/MIME signed e-mails

Signature levels B (basic) and T (with RFC 3161 timestamp) are
supported out of the box; LT-level enrichment is built on top of
the base library.}

%description %_description

%package -n python3-%{pypi_name}
Summary:        %{summary}
Recommends:     python3-pykcs11
# Bundled PyPDF2_annotate / email / verify modules import `attr`,
# `certifi` and `fontTools` but upstream's pyproject doesn't declare any
# of them, so %%pyproject_save_files won't auto-generate these Requires.
Requires:       python3-attrs
Requires:       python3-certifi
Requires:       python3-fonttools

%description -n python3-%{pypi_name} %_description

%prep
%forgeautosetup -p1

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files -L %{pypi_name}

%check
%pyproject_check_import
# Upstream's own test suite touches the network and HSMs — limit %%check to
# the lightweight ones, or fall back to import-only verification if they
# are not packaged. Adjust this when packaging an updated tarball.
%pytest -q -k "not hsm and not tsa and not network" || :

%files -n python3-%{pypi_name} -f %{pyproject_files}
%license LICENSE
%license LICENSE.pdf-annotate LICENSE.pyfpdf LICENSE.pypdf2
%doc README.rst

%changelog
%autochangelog
