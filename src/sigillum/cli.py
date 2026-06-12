# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""Command-line interface for Sigillum.

Wraps the same `core/*` modules used by the GUI under a `sigillum <subcommand>`
argparse front-end. The CLI is meant to be feature-complete with the GUI so
batch/automation workflows don't need to script-drive the GTK app.

PIN and passwords are read in this priority order:
  1. The matching environment variable (`SIGILLUM_PIN`, `SIGILLUM_PASSWORD`,
     `SIGILLUM_TSA_PASSWORD`, `SIGILLUM_OTP`).
  2. Interactive `getpass` prompt on a TTY.

Exit codes:
  0   success
  1   user error (bad args, missing file, validation failed)
  2   network/external service error (TSA unreachable, TSL fetch failed)
  3   verification failed (signature invalid, untrusted cert, etc.)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from cryptography import x509

from . import __version__
from .i18n import _


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _err(msg: str, code: int = 1) -> int:
    print(_("error: {msg}").format(msg=msg), file=sys.stderr)
    return code


def _read_secret(env_var: str, prompt: str, *, optional: bool = False) -> str:
    """Resolve a secret from env var, then interactive prompt.

    `optional=True` returns an empty string when neither source provides one
    (used for TSA passwords on public TSAs).
    """
    val = os.environ.get(env_var)
    if val is not None:
        return val
    if not sys.stdin.isatty():
        if optional:
            return ""
        raise RuntimeError(
            _("{env_var} is not set and no terminal is available for the prompt").format(
                env_var=env_var
            )
        )
    try:
        return getpass.getpass(prompt)
    except (KeyboardInterrupt, EOFError):
        raise RuntimeError(_("input interrupted"))


def _load_trusted_pem(path: Path) -> list[x509.Certificate]:
    if not path.exists():
        return []
    try:
        return list(x509.load_pem_x509_certificates(path.read_bytes()))
    except Exception as ex:  # noqa: BLE001
        raise RuntimeError(_("could not read {path}: {ex}").format(path=path, ex=ex)) from ex


def _default_trust_stores() -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Read the union of TSL bundles for all active countries.

    Returns ``([signing CAs], [TSA CAs])`` — the union of every country listed
    in ``Settings.active_countries()`` (falls back to the locale-derived
    primary country when nothing has been customised).
    """
    from .core.settings import load_settings
    from .core.tsl import load_active_trust_stores
    return load_active_trust_stores(load_settings().active_countries())


def _resolve_credential_from_args(args, settings):
    """Build a SigningCredential from the CLI args, falling back to settings.

    CLI flags `--cert FILE` and `--lib PATH --cert-id ID` override the saved
    configuration. With no flags, the saved configuration in
    `~/.config/sigillum/settings.json` is used.
    """
    from .core.credentials import FileProvider, PKCS11Provider

    cert_file = getattr(args, "cert", None)
    lib = getattr(args, "lib", None)
    cert_id = getattr(args, "cert_id", None)

    if cert_file:
        provider = FileProvider(cert_file)
        password = _read_secret(
            "SIGILLUM_PASSWORD",
            _("Password for {name}: ").format(name=Path(cert_file).name),
        )
        cred = provider.unlock(str(cert_file), password)
        return cred, provider

    if lib or cert_id:
        if not (lib and cert_id):
            raise RuntimeError(_("--lib and --cert-id must be passed together"))
        provider = PKCS11Provider(lib)
        pin = _read_secret("SIGILLUM_PIN", _("Token PIN: "))
        cred = provider.unlock(cert_id, pin)
        return cred, provider

    # No CLI override → fall back to saved settings.
    if settings.source == "file":
        if not settings.file_path:
            raise RuntimeError(_("no PKCS#12 file configured in Settings"))
        provider = FileProvider(settings.file_path)
        password = _read_secret(
            "SIGILLUM_PASSWORD",
            _("Password for {name}: ").format(name=Path(settings.file_path).name),
        )
        cred = provider.unlock(settings.file_path, password)
        return cred, provider
    if settings.source == "pkcs11":
        if not (settings.pkcs11_library and settings.pkcs11_cert_id):
            raise RuntimeError(_("PKCS#11 token not fully configured"))
        provider = PKCS11Provider(settings.pkcs11_library)
        pin = _read_secret("SIGILLUM_PIN", _("Token PIN: "))
        cred = provider.unlock(settings.pkcs11_cert_id, pin)
        return cred, provider
    if settings.source == "csc":
        if not (settings.csc_url and settings.csc_client_id
                and settings.csc_credential_id):
            raise RuntimeError(_(
                "CSC remote signing not fully configured. "
                "Run `sigillum config set --csc-url … --csc-client-id … "
                "--csc-credential-id …` first."
            ))
        from .core.credentials import RemoteCSCProvider
        from .core.csc import CSCClient, CSCConfig

        cfg = CSCConfig(
            base_url=settings.csc_url,
            client_id=settings.csc_client_id,
            client_secret=settings.csc_client_secret,
        )
        # OTP is fetched from $SIGILLUM_OTP or prompted at sign time —
        # the lambda defers the lookup until endesive actually calls
        # `hsm.sign()`, which is when the SMS / push has just landed.
        otp_provider = lambda: _read_secret(  # noqa: E731
            "SIGILLUM_OTP", _("OTP (signature activation): "),
        )
        provider = RemoteCSCProvider(
            CSCClient(cfg), otp_provider=otp_provider, pin=settings.csc_pin,
        )
        cred = provider.unlock(settings.csc_credential_id, "")
        return cred, provider

    raise RuntimeError(_(
        "no credential configured. "
        "Pass --cert FILE or --lib LIB --cert-id ID, "
        "or configure the device via `sigillum config set`."
    ))


def _tsa_config_from_args(args, settings):
    """Resolve TSA URL/credentials with CLI flags overriding settings."""
    from .core.timestamp import TSAConfig

    url = getattr(args, "tsa", None) or settings.tsa_url
    user = getattr(args, "tsa_user", None) or settings.tsa_username
    pwd = getattr(args, "tsa_password", None) or settings.tsa_password
    if user and not pwd:
        pwd = _read_secret(
            "SIGILLUM_TSA_PASSWORD", _("TSA password: "), optional=True,
        )
    if not url:
        return None
    return TSAConfig(url=url, username=user or None, password=pwd or None)


def _format_for_path(path: Path) -> str:
    """Classify a file by extension into one of pades/cades/xades/tsr/tsd."""
    s = path.suffix.lower()
    if s == ".pdf":
        return "pades"
    if s in (".p7m", ".p7s"):
        return "cades"
    if s == ".xml":
        return "xades"
    if s == ".tsr":
        return "tsr"
    if s == ".tsd":
        return "tsd"
    raise ValueError(_("unrecognized extension: {ext}").format(ext=s))


# ---------------------------------------------------------------------------
# `sign` subcommand
# ---------------------------------------------------------------------------

def _cmd_sign(args) -> int:
    from .core.settings import load_settings
    from .core.signer import (
        CAdESSigner, PAdESSigner, SignatureLevel, SignaturePosition,
        SignOptions, XAdESSigner,
    )

    settings = load_settings()
    input_path = Path(args.input)
    if not input_path.is_file():
        return _err(_("file not found: {path}").format(path=input_path))

    suffix = input_path.suffix.lower()
    if suffix == ".pdf":
        signer = PAdESSigner()
        default_out = input_path.with_name(input_path.stem + ".signed.pdf")
    elif suffix == ".xml":
        signer = XAdESSigner()
        default_out = input_path.with_name(input_path.stem + ".signed.xml")
    else:
        signer = CAdESSigner()
        default_out = input_path.with_name(input_path.name + ".p7m")

    output_path = Path(args.output) if args.output else default_out

    try:
        level = SignatureLevel(args.level)
    except ValueError:
        return _err(_("invalid level: {level}").format(level=args.level))

    explicit_tsa = bool(getattr(args, "tsa", None))
    tsa = _tsa_config_from_args(args, settings)
    # At level B we don't auto-timestamp from saved settings; the user has to
    # opt in via --tsa or by choosing level T/LT.
    if level == SignatureLevel.B and not explicit_tsa:
        tsa = None
    if level != SignatureLevel.B and tsa is None:
        return _err(
            _("level {level} requires a TSA "
              "(--tsa URL or configure it via `sigillum config set`)").format(level=level.value)
        )

    visible = bool(args.visible) and suffix == ".pdf"
    position = SignaturePosition(args.position) if args.position else (
        SignaturePosition(settings.signature_position)
        if settings.signature_position else SignaturePosition.BOTTOM_RIGHT
    )
    box: tuple[float, float, float, float] | None = None
    if args.box:
        try:
            parts = [float(x) for x in args.box.split(",")]
        except ValueError:
            return _err(_("--box: use format x1,y1,x2,y2 in PDF points"))
        if len(parts) != 4:
            return _err(_("--box: needs exactly 4 values x1,y1,x2,y2"))
        box = (parts[0], parts[1], parts[2], parts[3])

    options = SignOptions(
        level=level,
        tsa_url=tsa.url if tsa else None,
        tsa_username=tsa.username if tsa else None,
        tsa_password=tsa.password if tsa else None,
        visible=visible,
        signature_page=args.page,
        signature_position=position,
        signature_box=box,
        signature_image=args.image or (settings.signature_image or None),
        reason=args.reason,
        location=args.location,
        contact=args.contact,
    )

    try:
        cred, provider = _resolve_credential_from_args(args, settings)
    except RuntimeError as ex:
        return _err(str(ex))

    try:
        out = signer.sign(input_path, output_path, cred, options)
    except Exception as ex:  # noqa: BLE001 — surface user-readable error
        return _err(_("signing failed: {ex}").format(ex=ex), code=2)
    finally:
        provider.close()

    print(str(out))
    return 0


# ---------------------------------------------------------------------------
# `verify` subcommand
# ---------------------------------------------------------------------------

def _signer_info_to_dict(s) -> dict:
    return {
        "subject": s.subject,
        "issuer": s.issuer,
        "serial": s.serial,
        "hash_valid": s.hash_valid,
        "signature_valid": s.signature_valid,
        "cert_trusted": s.cert_trusted,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        "tsa_subject": s.tsa_subject,
        "timestamp_trusted": s.timestamp_trusted,
        "valid": s.valid,
        "errors": list(s.errors),
    }


def _cmd_verify(args) -> int:
    from .core.timestamp import verify_tsd, verify_tsr
    from .core.verifier import CAdESVerifier, PAdESVerifier, XAdESVerifier

    path = Path(args.input)
    if not path.is_file():
        return _err(f"file non trovato: {path}")

    try:
        fmt = _format_for_path(path)
    except ValueError as ex:
        return _err(str(ex))

    signing_certs, tsa_certs = _default_trust_stores()
    # Extra trust roots from --trusted (signer chain) and --tsa-trusted.
    for extra in args.trusted or []:
        signing_certs.extend(_load_trusted_pem(Path(extra)))
    for extra in args.tsa_trusted or []:
        tsa_certs.extend(_load_trusted_pem(Path(extra)))

    original = Path(args.original) if args.original else None

    try:
        if fmt == "pades":
            result = PAdESVerifier(signing_certs, tsa_certs).verify(path)
        elif fmt == "cades":
            result = CAdESVerifier(signing_certs, tsa_certs).verify(path, original)
        elif fmt == "xades":
            result = XAdESVerifier(signing_certs, tsa_certs).verify(path)
        elif fmt == "tsr":
            if original is None:
                return _err(_(".tsr verification requires --original FILE"))
            result = verify_tsr(path, original, tsa_trusted_certs=tsa_certs)
        elif fmt == "tsd":
            result = verify_tsd(path, tsa_trusted_certs=tsa_certs)
        else:
            return _err(_("unhandled format: {fmt}").format(fmt=fmt))
    except Exception as ex:  # noqa: BLE001
        return _err(_("verification failed: {ex}").format(ex=ex), code=2)

    payload = {
        "file": str(path),
        "format": fmt,
        "all_valid": result.all_valid,
        "signers": [_signer_info_to_dict(s) for s in result.signers],
        "errors": list(result.errors),
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        _print_verify_human(payload)
    return 0 if result.all_valid and not result.errors else 3


def _print_verify_human(payload: dict) -> None:
    print(_("File:    {value}").format(value=payload["file"]))
    print(_("Format:  {value}").format(value=payload["format"]))
    if payload["errors"]:
        for e in payload["errors"]:
            print(f"  ! {e}")
    if not payload["signers"]:
        print(_("  No signer found."))
        return
    for i, s in enumerate(payload["signers"], 1):
        print()
        print(_("Signer #{n}").format(n=i))
        print(_("  Subject: {value}").format(value=s["subject"]))
        print(_("  Issuer:  {value}").format(value=s["issuer"]))
        print(_("  Serial:  {value}").format(value=s["serial"]))
        print(_("  Hash:        {state}").format(
            state=_("OK") if s["hash_valid"] else _("INVALID")))
        print(_("  Signature:   {state}").format(
            state=_("OK") if s["signature_valid"] else _("INVALID")))
        print(_("  Chain:       {state}").format(
            state=_("trusted") if s["cert_trusted"] else _("UNTRUSTED")))
        if s["timestamp"]:
            ts_state = _("trusted") if s["timestamp_trusted"] else _("not trusted")
            print(_("  Timestamp:   {ts} (TSA {state})").format(
                ts=s["timestamp"], state=ts_state))
            if s["tsa_subject"]:
                print(_("    TSA: {value}").format(value=s["tsa_subject"]))
        for e in s["errors"]:
            print(f"    ! {e}")
    print()
    print(_("Overall: {state}").format(
        state=_("VALID") if payload["all_valid"] else _("INVALID")))


# ---------------------------------------------------------------------------
# `timestamp` subcommand
# ---------------------------------------------------------------------------

def _cmd_timestamp(args) -> int:
    from .core.settings import load_settings
    from .core.timestamp import make_tsd, make_tsr

    settings = load_settings()
    input_path = Path(args.input)
    if not input_path.is_file():
        return _err(_("file not found: {path}").format(path=input_path))

    tsa = _tsa_config_from_args(args, settings)
    if tsa is None:
        return _err(_(
            "no TSA configured. "
            "Pass --tsa URL or save it via `sigillum config set --tsa URL`."
        ))

    fmt = args.format
    suffix = ".tsr" if fmt == "tsr" else ".tsd"
    out = Path(args.output) if args.output else input_path.with_name(input_path.name + suffix)

    try:
        if fmt == "tsr":
            make_tsr(input_path, out, tsa)
        else:
            make_tsd(input_path, out, tsa)
    except Exception as ex:  # noqa: BLE001
        return _err(_("timestamping failed: {ex}").format(ex=ex), code=2)
    print(str(out))
    return 0


# ---------------------------------------------------------------------------
# `extract` subcommand
# ---------------------------------------------------------------------------

def _cmd_extract(args) -> int:
    from .core.verifier import extract_p7m_content

    src = Path(args.input)
    if not src.is_file():
        return _err(_("file not found: {path}").format(path=src))

    # Default output strips the trailing `.p7m` so `report.pdf.p7m` becomes
    # `report.pdf`. If the source doesn't end in `.p7m`, fall back to
    # `<stem>-extracted<suffix>` so we never overwrite the source.
    if args.output:
        out = Path(args.output)
    elif src.suffix.lower() == ".p7m":
        out = src.with_name(src.stem)
    else:
        out = src.with_name(f"{src.stem}-extracted{src.suffix}")

    try:
        out.write_bytes(extract_p7m_content(src, recursive=not args.shallow))
    except ValueError as ex:
        return _err(str(ex))
    except OSError as ex:
        return _err(_("could not write output: {ex}").format(ex=ex), code=2)
    print(str(out))
    return 0


# ---------------------------------------------------------------------------
# `encrypt` subcommand
# ---------------------------------------------------------------------------

def _cmd_encrypt(args) -> int:
    from .core.crypto import (
        SYMMETRIC_NAMES, encrypt_asymmetric, encrypt_symmetric,
    )
    from .core.settings import load_settings

    settings = load_settings()
    input_path = Path(args.input)
    if not input_path.is_file():
        return _err(_("file not found: {path}").format(path=input_path))

    mode = args.mode
    if mode == "sym":
        if args.algo not in SYMMETRIC_NAMES:
            return _err(
                _("unsupported algorithm: {algo!r}. Valid: {valid}").format(
                    algo=args.algo, valid=", ".join(SYMMETRIC_NAMES)
                )
            )
        try:
            password = _read_secret("SIGILLUM_PASSWORD", _("Password: "))
        except RuntimeError as ex:
            return _err(str(ex))
        out = Path(args.output) if args.output else input_path.with_name(
            input_path.name + ".enc"
        )
        try:
            blob = encrypt_symmetric(input_path.read_bytes(), password, args.algo)
        except Exception as ex:  # noqa: BLE001
            return _err(_("encryption failed: {ex}").format(ex=ex))
        out.write_bytes(blob)
        print(str(out))
        return 0

    # mode == "asym"
    out = Path(args.output) if args.output else input_path.with_name(
        input_path.name + ".p7e"
    )
    if args.recipient:
        # Recipient cert from a .p12/.pem file (no PIN needed — public key only).
        from .core.credentials import FileProvider
        prov = FileProvider(args.recipient)
        secret = os.environ.get("SIGILLUM_PASSWORD")
        if secret is None and sys.stdin.isatty():
            try:
                secret = getpass.getpass(_("Password for {name} (empty if PEM): ").format(
                    name=Path(args.recipient).name))
            except (KeyboardInterrupt, EOFError):
                return _err(_("input interrupted"))
        try:
            cred = prov.unlock(args.recipient, secret or "")
        except Exception as ex:  # noqa: BLE001
            return _err(_("could not open recipient certificate: {ex}").format(ex=ex))
        recipient_cert = cred.certificate
        prov.close()
    else:
        # Use the configured credential as recipient (cifra a se stessi).
        try:
            cred, provider = _resolve_credential_from_args(args, settings)
        except RuntimeError as ex:
            return _err(str(ex))
        recipient_cert = cred.certificate
        provider.close()

    try:
        blob = encrypt_asymmetric(input_path.read_bytes(), recipient_cert)
    except Exception as ex:  # noqa: BLE001
        return _err(_("asymmetric encryption failed: {ex}").format(ex=ex))
    out.write_bytes(blob)
    print(str(out))
    return 0


# ---------------------------------------------------------------------------
# `decrypt` subcommand
# ---------------------------------------------------------------------------

def _cmd_decrypt(args) -> int:
    from .core.crypto import decrypt_asymmetric, decrypt_symmetric, detect_format
    from .core.settings import load_settings

    settings = load_settings()
    input_path = Path(args.input)
    if not input_path.is_file():
        return _err(_("file not found: {path}").format(path=input_path))
    blob = input_path.read_bytes()
    fmt = detect_format(blob)

    if args.output:
        out = Path(args.output)
    else:
        # Strip .enc/.p7e if present; else append .dec.
        if input_path.suffix.lower() in (".enc", ".p7e"):
            out = input_path.with_suffix("")
        else:
            out = input_path.with_name(input_path.name + ".dec")

    if fmt == "symmetric":
        try:
            password = _read_secret("SIGILLUM_PASSWORD", _("Password: "))
        except RuntimeError as ex:
            return _err(str(ex))
        try:
            plain = decrypt_symmetric(blob, password)
        except Exception as ex:  # noqa: BLE001
            return _err(_("decryption failed: {ex}").format(ex=ex))
    elif fmt == "asymmetric":
        try:
            cred, provider = _resolve_credential_from_args(args, settings)
        except RuntimeError as ex:
            return _err(str(ex))
        try:
            plain = decrypt_asymmetric(blob, cred)
        except Exception as ex:  # noqa: BLE001
            provider.close()
            return _err(_("asymmetric decryption failed: {ex}").format(ex=ex))
        provider.close()
    else:
        return _err(_("unrecognized format (neither SIGILLUM nor CMS EnvelopedData)"))

    out.write_bytes(plain)
    print(str(out))
    return 0


# ---------------------------------------------------------------------------
# `tsl-import` subcommand
# ---------------------------------------------------------------------------

def _cmd_tsl_import(args) -> int:
    from .core.settings import load_settings, save_settings, LOTL_COUNTRIES
    from .core.tsl import import_country_tsl

    settings = load_settings()
    country = (args.country or settings.effective_country()).upper()
    if country not in LOTL_COUNTRIES:
        return _err(_("Unknown country code: {cc}").format(cc=country), code=2)

    try:
        result = import_country_tsl(country)
    except Exception as ex:  # noqa: BLE001
        return _err(_("TSL import failed: {ex}").format(ex=ex), code=2)

    settings.record_import(result.country, result.when.isoformat())
    if result.country not in settings.tsl_active_countries:
        # First import of a new country → enable it for verification.
        if not settings.tsl_active_countries:
            settings.tsl_active_countries = [result.country]
        else:
            settings.tsl_active_countries.append(result.country)
    save_settings(settings)

    print(_("Country:     {cc}").format(cc=result.country))
    print(_("Signing CAs: {n} → {path}").format(n=result.signing_count, path=result.signing_path))
    print(_("TSA CAs:     {n} → {path}").format(n=result.tsa_count, path=result.tsa_path))
    print(_("Last import: {when}").format(when=result.when.isoformat()))
    if result.signer_trusted:
        print(_("Signature:   verified (LOTL-anchored)"))
    elif result.signer_cert is not None:
        subj = result.signer_cert.subject.rfc4514_string()
        print(_("Signature:   verified — signer: {subj}").format(subj=subj))
    return 0


def _cmd_tsl_list(args) -> int:
    """Show every imported national TSL with its age and active state."""
    from .core.settings import load_settings
    from .core.tsl import import_age_days, list_imported_countries

    settings = load_settings()
    countries = list_imported_countries()
    if not countries:
        print(_("No TSL imported. Run: sigillum tsl-import"))
        return 0

    primary = settings.effective_country()
    active = set(settings.active_countries())

    for cc in countries:
        ts = settings.last_import_for(cc)
        age = import_age_days(ts)
        markers = []
        if cc == primary:
            markers.append(_("primary"))
        if cc in active:
            markers.append(_("active"))
        suffix = f"  [{', '.join(markers)}]" if markers else ""
        if age is None:
            print(f"  {cc}: {_('(no timestamp)')}{suffix}")
        else:
            print(_("  {cc}: imported {days} days ago ({ts}){suffix}").format(
                cc=cc, days=age, ts=ts, suffix=suffix,
            ))
    return 0


# ---------------------------------------------------------------------------
# `detect` subcommand
# ---------------------------------------------------------------------------

def _cmd_detect(args) -> int:
    from .core.detection import (
        detect_tokens, detect_usb_tokens, find_available_drivers, suggest_driver,
    )
    from .core.settings import load_settings

    extra = load_settings().extra_pkcs11_search_paths
    drivers = find_available_drivers(extra)
    tokens = detect_tokens(extra)
    usb = detect_usb_tokens()

    if args.json:
        payload = {
            "drivers": drivers,
            "tokens": [
                {
                    "library_path": t.library_path,
                    "library_label": t.library_label,
                    "certificates": [
                        {
                            "id": c.id,
                            "subject": c.subject,
                            "issuer": c.issuer,
                            "serial": c.serial,
                            "not_before": c.not_before,
                            "not_after": c.not_after,
                        }
                        for c in t.certificates
                    ],
                }
                for t in tokens
            ],
            "usb_devices": [
                {
                    "vendor_id": u.vendor_id,
                    "product_id": u.product_id,
                    "vendor_name": u.vendor_name,
                    "driver_hint": u.driver_hint,
                    "driver_kind": u.driver_kind,
                }
                for u in usb
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(_("PKCS#11 drivers available on the system:"))
    if drivers:
        for d in drivers:
            print(f"  - {d}")
    else:
        print(_("  (none)"))

    print()
    print(_("Detected USB devices:"))
    if usb:
        for u in usb:
            print(f"  - {u.vendor_name} (vid {u.vendor_id} pid {u.product_id})")
            print(_("    driver: {hint} [{kind}]").format(hint=u.driver_hint, kind=u.driver_kind))
    else:
        print(_("  (none recognized)"))

    print()
    print(_("Tokens with visible certificates:"))
    if not tokens:
        print(_("  (none)"))
        if usb:
            print()
            print(_("Driver suggestions:"))
            for u in usb:
                sug = suggest_driver(u)
                print(f"  {u.vendor_name}:")
                if sug.install_command:
                    print(_("    install: {cmd}").format(cmd=sug.install_command))
                for label, url in sug.vendor_links:
                    print(f"    {label}: {url}")
        return 0
    for t in tokens:
        print(f"  {t.library_label}  ({t.library_path})")
        for c in t.certificates:
            print(f"    - {c.subject}")
            print(_("      id={id}  serial={serial}  expires={exp}").format(
                id=c.id, serial=c.serial, exp=c.not_after))
    return 0


# ---------------------------------------------------------------------------
# `csc-list` subcommand
# ---------------------------------------------------------------------------

def _cmd_csc_list(args) -> int:
    """Enumerate remote credentials available at the configured CSC service.

    Intended for the one-time setup loop: after `sigillum config set
    --csc-url … --csc-client-id … --csc-client-secret …`, call this to
    see which `credential_id` to pin via `--csc-credential-id`.
    """
    from .core.csc import CSCClient, CSCConfig, CSCError
    from .core.settings import load_settings

    s = load_settings()
    if not (s.csc_url and s.csc_client_id):
        return _err(_(
            "CSC service not configured. Run `sigillum config set "
            "--csc-url URL --csc-client-id ID [--csc-client-secret SECRET]` "
            "first."
        ))

    cfg = CSCConfig(
        base_url=s.csc_url,
        client_id=s.csc_client_id,
        client_secret=s.csc_client_secret,
    )
    client = CSCClient(cfg)
    try:
        ids = client.list_credentials()
    except CSCError as ex:
        return _err(_("CSC list failed: {ex}").format(ex=ex), code=2)

    if args.json:
        out = []
        for cid in ids:
            try:
                info = client.credential_info(cid)
                out.append({
                    "credential_id": cid,
                    "description": info.description,
                    "key_algo": info.key_algo,
                    "key_length": info.key_length,
                    "multisign": info.multisign,
                })
            except CSCError as ex:
                out.append({"credential_id": cid, "error": str(ex)})
        print(json.dumps(out, indent=2))
        return 0

    if not ids:
        print(_("No CSC credentials visible to this client."))
        return 0
    print(_("Credentials at {url}:").format(url=s.csc_url))
    for cid in ids:
        try:
            info = client.credential_info(cid)
            print(f"  - {cid}")
            if info.description:
                print(f"      {info.description}")
            print(f"      key={info.key_algo} ({info.key_length} bit), "
                  f"multisign={info.multisign}")
        except CSCError as ex:
            print(f"  - {cid}  (info failed: {ex})")
    return 0


# ---------------------------------------------------------------------------
# `config` subcommand
# ---------------------------------------------------------------------------

def _cmd_config(args) -> int:
    from .core.settings import load_settings, save_settings, settings_path
    from .core.tsl import import_age_days

    settings = load_settings()

    if args.action == "show" or args.action is None:
        primary = settings.effective_country()
        active = settings.active_countries()
        if args.json:
            payload = {
                "path": str(settings_path()),
                "source": settings.source,
                "file_path": settings.file_path,
                "pkcs11_library": settings.pkcs11_library,
                "pkcs11_cert_id": settings.pkcs11_cert_id,
                "pkcs11_cert_subject": settings.pkcs11_cert_subject,
                "extra_pkcs11_search_paths": list(settings.extra_pkcs11_search_paths),
                "csc_url": settings.csc_url,
                "csc_client_id": settings.csc_client_id,
                "csc_client_secret_set": bool(settings.csc_client_secret),
                "csc_credential_id": settings.csc_credential_id,
                "csc_pin_set": bool(settings.csc_pin),
                "csc_cert_subject": settings.csc_cert_subject,
                "tsa_url": settings.tsa_url,
                "tsa_username": settings.tsa_username,
                "tsa_password_set": bool(settings.tsa_password),
                "signature_position": settings.signature_position,
                "signature_image": settings.signature_image,
                "country": settings.country,
                "primary_country": primary,
                "active_countries": active,
                "tsl_imports": {
                    cc: {"timestamp": ts, "age_days": import_age_days(ts)}
                    for cc, ts in settings.tsl_imports.items()
                },
                "tsl_last_import": settings.tsl_last_import,
                "tsl_age_days": import_age_days(settings.tsl_last_import),
            }
            print(json.dumps(payload, indent=2))
            return 0
        print(_("File:            {path}").format(path=settings_path()))
        print(_("Device:          {value}").format(value=settings.describe()))
        if settings.tsa_url:
            auth = _(" (auth)") if settings.tsa_username else ""
            print(_("TSA:             {url}{auth}").format(url=settings.tsa_url, auth=auth))
        else:
            print(_("TSA:             (not set)"))
        print(_("Visible signature: pos={pos}, logo={logo}").format(
            pos=settings.signature_position,
            logo=settings.signature_image or _("(none)"),
        ))
        if settings.extra_pkcs11_search_paths:
            print(_("Extra PKCS#11 search paths:"))
            for d in settings.extra_pkcs11_search_paths:
                print(f"  - {d}")
        if settings.csc_url:
            auth = _(" (secret set)") if settings.csc_client_secret else ""
            print(_("CSC URL:         {url}").format(url=settings.csc_url))
            print(_("CSC client_id:   {cid}{auth}").format(
                cid=settings.csc_client_id or _("(not set)"), auth=auth))
            print(_("CSC credential:  {cred}").format(
                cred=settings.csc_credential_id or _("(not set)")))
        print(_("Primary country: {cc}").format(cc=primary))
        print(_("Active for verify: {cc}").format(cc=", ".join(active)))
        if settings.tsl_imports:
            for cc in sorted(settings.tsl_imports):
                ts = settings.tsl_imports[cc]
                age = import_age_days(ts)
                age_s = _("{n} days").format(n=age) if age is not None else _("?")
                print(_("  TSL {cc}:        {when} ({age})").format(
                    cc=cc, when=ts, age=age_s))
        else:
            print(_("TSL:             never imported"))
        return 0

    # action == "set"
    changed = False
    if args.cert is not None:
        settings.source = "file"
        settings.file_path = str(Path(args.cert).expanduser())
        settings.pkcs11_library = ""
        settings.pkcs11_cert_id = ""
        settings.pkcs11_cert_subject = ""
        changed = True
    if args.lib is not None or args.cert_id is not None:
        if not (args.lib and args.cert_id):
            return _err(_("--lib and --cert-id must be passed together"))
        settings.source = "pkcs11"
        settings.pkcs11_library = args.lib
        settings.pkcs11_cert_id = args.cert_id
        settings.file_path = ""
        changed = True
    csc_touched = any(
        getattr(args, name, None) is not None
        for name in ("csc_url", "csc_client_id", "csc_client_secret",
                     "csc_credential_id", "csc_pin")
    )
    if csc_touched:
        if args.csc_url is not None:
            url = args.csc_url.rstrip("/")
            settings.csc_url = url
        if args.csc_client_id is not None:
            settings.csc_client_id = args.csc_client_id
        if args.csc_client_secret is not None:
            settings.csc_client_secret = args.csc_client_secret
        if args.csc_credential_id is not None:
            settings.csc_credential_id = args.csc_credential_id
            settings.csc_cert_subject = ""   # invalidate cached display
        if args.csc_pin is not None:
            settings.csc_pin = args.csc_pin
        # Switching to CSC clears the file/PKCS#11 source so the next
        # `sigillum sign` doesn't accidentally fall back to a stale local
        # configuration.
        if settings.csc_url and settings.csc_client_id and settings.csc_credential_id:
            settings.source = "csc"
            settings.file_path = ""
            settings.pkcs11_library = ""
            settings.pkcs11_cert_id = ""
            settings.pkcs11_cert_subject = ""
        changed = True
    if args.tsa is not None:
        settings.tsa_url = args.tsa
        changed = True
    if args.tsa_user is not None:
        settings.tsa_username = args.tsa_user
        changed = True
    if args.tsa_password is not None:
        settings.tsa_password = args.tsa_password
        changed = True
    if args.image is not None:
        settings.signature_image = args.image
        changed = True
    if args.position is not None:
        settings.signature_position = args.position
        changed = True
    if getattr(args, "country", None) is not None:
        from .core.settings import LOTL_COUNTRIES
        cc = args.country.strip().upper()
        if cc == "":
            settings.country = ""  # clear → fall back to $LANG
        elif cc in LOTL_COUNTRIES:
            settings.country = cc
        else:
            return _err(_("Unknown country code: {cc}").format(cc=cc))
        changed = True
    if getattr(args, "add_driver", None):
        for p in args.add_driver:
            if p and p not in settings.extra_pkcs11_search_paths:
                settings.extra_pkcs11_search_paths.append(p)
                changed = True
    if getattr(args, "remove_driver", None):
        for p in args.remove_driver:
            if p in settings.extra_pkcs11_search_paths:
                settings.extra_pkcs11_search_paths.remove(p)
                changed = True
    if getattr(args, "active_countries", None) is not None:
        from .core.settings import LOTL_COUNTRIES
        raw = args.active_countries.strip()
        if raw == "":
            settings.tsl_active_countries = []
        else:
            codes = [c.strip().upper() for c in raw.split(",") if c.strip()]
            bad = [c for c in codes if c not in LOTL_COUNTRIES]
            if bad:
                return _err(_("Unknown country code(s): {bad}").format(bad=", ".join(bad)))
            settings.tsl_active_countries = codes
        changed = True

    if not changed:
        return _err(_("no option to modify passed to `config set`"))
    save_settings(settings)
    print(_("settings updated: {path}").format(path=settings_path()))
    return 0


# ---------------------------------------------------------------------------
# `gui` subcommand
# ---------------------------------------------------------------------------

def _cmd_gui(args) -> int:
    from .gui.app import SigillumApp
    return SigillumApp().run([sys.argv[0]] + (args.gui_args or []))


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------

def _add_credential_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--cert", help=_("PKCS#12 (.p12/.pfx) or PEM file to use"))
    p.add_argument("--lib", help=_("path to the token's PKCS#11 (.so) module"))
    p.add_argument("--cert-id", dest="cert_id",
                   help=_("composite id of the certificate on the token (see `sigillum detect`)"))


def _add_tsa_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tsa", help=_("TSA URL (overrides settings)"))
    p.add_argument("--tsa-user", dest="tsa_user", help=_("HTTP Basic username for the TSA"))
    p.add_argument("--tsa-password", dest="tsa_password",
                   help=_("HTTP Basic password for the TSA (alt: $SIGILLUM_TSA_PASSWORD)"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigillum",
        description=_("Sign, verify, timestamp and encrypt documents."),
    )
    p.add_argument("-V", "--version", action="version", version=f"sigillum {__version__}")
    sub = p.add_subparsers(dest="command", metavar=_("command"))

    # sign
    p_sign = sub.add_parser(
        "sign", help=_("sign a PDF/XML/file (PAdES/XAdES/CAdES)"),
        description=_("Sign the input file. The format is derived from the extension."),
    )
    p_sign.add_argument("input", help=_("file to sign"))
    p_sign.add_argument("-o", "--output", help=_("output file (default: derived from input)"))
    p_sign.add_argument("--level", default="B", choices=["B", "T", "LT"],
                        help=_("signature level (default: B)"))
    p_sign.add_argument("--visible", action="store_true",
                        help=_("PAdES: add a graphical appearance"))
    p_sign.add_argument("--page", type=int, default=0,
                        help=_("page for the visible signature (0=first, -1=last)"))
    p_sign.add_argument("--position", choices=[
        "bottom-right", "bottom-left", "top-right", "top-left",
    ], help=_("corner preset for the visible signature"))
    p_sign.add_argument("--box", help=_("explicit rectangle in PDF points: x1,y1,x2,y2"))
    p_sign.add_argument("--image", help=_("PNG/JPG logo for the visible signature"))
    p_sign.add_argument("--reason", help=_("reason for the signature (PAdES)"))
    p_sign.add_argument("--location", help=_("location of the signing (PAdES)"))
    p_sign.add_argument("--contact", help=_("signer's contact (PAdES)"))
    _add_credential_flags(p_sign)
    _add_tsa_flags(p_sign)
    p_sign.set_defaults(func=_cmd_sign)

    # verify
    p_ver = sub.add_parser(
        "verify", help=_("verify a signature or a timestamp"),
        description=_("Verify a .pdf, .p7m, .xml, .tsr or .tsd file."),
    )
    p_ver.add_argument("input", help=_("signed/timestamped file"))
    p_ver.add_argument("--original",
                       help=_("original file (required for .tsr and detached CAdES)"))
    p_ver.add_argument("--trusted", action="append",
                       help=_("PEM with extra CAs for the signer chain (repeatable)"))
    p_ver.add_argument("--tsa-trusted", dest="tsa_trusted", action="append",
                       help=_("PEM with extra CAs for the TSA chain (repeatable)"))
    p_ver.add_argument("--json", action="store_true", help=_("machine-readable JSON output"))
    p_ver.set_defaults(func=_cmd_verify)

    # timestamp
    p_ts = sub.add_parser(
        "timestamp", help=_("standalone timestamp (TSR / TSD)"),
        description=_("Timestamp any file via RFC 3161."),
    )
    p_ts.add_argument("input", help=_("file to timestamp"))
    p_ts.add_argument("-o", "--output", help=_("output file (default: <input>.tsr/.tsd)"))
    p_ts.add_argument("--format", choices=["tsr", "tsd"], default="tsd",
                      help=_("output format (default: tsd)"))
    _add_tsa_flags(p_ts)
    p_ts.set_defaults(func=_cmd_timestamp)

    # extract
    p_ext = sub.add_parser(
        "extract",
        help=_("extract the embedded payload from a .p7m (CMS enveloping)"),
        description=_(
            "Extract the original document carried inside a CAdES "
            "enveloping signature. Fails on detached signatures."
        ),
    )
    p_ext.add_argument("input", help=_(".p7m file to extract"))
    p_ext.add_argument("-o", "--output",
                       help=_("output file (default: strip the .p7m suffix)"))
    p_ext.add_argument("--shallow", action="store_true",
                       help=_("extract only one CMS layer instead of "
                              "recursing into nested .p7m wrappers"))
    p_ext.set_defaults(func=_cmd_extract)

    # encrypt
    p_enc = sub.add_parser(
        "encrypt", help=_("encrypt a file (symmetric or asymmetric)"),
        description=_("Encrypt the input file. Default: symmetric AES-256 with password."),
    )
    p_enc.add_argument("input", help=_("plaintext file"))
    p_enc.add_argument("-o", "--output", help=_("output encrypted file"))
    p_enc.add_argument("--mode", choices=["sym", "asym"], default="sym",
                       help=_("symmetric (password) or asymmetric (certificate)"))
    p_enc.add_argument("--algo", default="AES-256",
                       choices=["AES-256", "AES-128", "3DES", "Blowfish"],
                       help=_("symmetric algorithm (default: AES-256)"))
    p_enc.add_argument("--recipient",
                       help=_("recipient certificate (.p12/.pem file); "
                              "if omitted, encrypts to the configured cert"))
    _add_credential_flags(p_enc)
    p_enc.set_defaults(func=_cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser(
        "decrypt", help=_("decrypt a file (format auto-detected)"),
        description=_("Decrypt a .enc (symmetric) or .p7e (CMS EnvelopedData) file."),
    )
    p_dec.add_argument("input", help=_("encrypted file"))
    p_dec.add_argument("-o", "--output", help=_("output plaintext file"))
    _add_credential_flags(p_dec)
    p_dec.set_defaults(func=_cmd_decrypt)

    # tsl-import
    p_tsl = sub.add_parser(
        "tsl-import",
        help=_("download a national Trust List into local bundles via EU LOTL"),
    )
    p_tsl.add_argument(
        "--country",
        metavar="CC",
        default="",
        help=_("ISO country code (e.g. IT, DE, FR). Defaults to the primary "
               "country derived from settings or $LANG."),
    )
    p_tsl.set_defaults(func=_cmd_tsl_import)

    # tsl-list
    p_tsll = sub.add_parser(
        "tsl-list", help=_("list every imported national Trust List with its age"),
    )
    p_tsll.set_defaults(func=_cmd_tsl_list)

    # detect
    p_det = sub.add_parser(
        "detect", help=_("detect PKCS#11 drivers, USB tokens and certificates"),
    )
    p_det.add_argument("--json", action="store_true", help=_("JSON output"))
    p_det.set_defaults(func=_cmd_detect)

    # csc-list
    p_csc = sub.add_parser(
        "csc-list",
        help=_("list credentials available at the configured CSC v2 QTSP"),
        description=_(
            "Enumerate remote credentials at the QTSP set via "
            "`sigillum config set --csc-url … --csc-client-id …`. "
            "Use the resulting credential ID with "
            "`sigillum config set --csc-credential-id ID` to make "
            "Sigillum sign through it."
        ),
    )
    p_csc.add_argument("--json", action="store_true", help=_("JSON output"))
    p_csc.set_defaults(func=_cmd_csc_list)

    # config
    p_cfg = sub.add_parser(
        "config", help=_("show or modify persistent settings"),
    )
    cfg_sub = p_cfg.add_subparsers(dest="action", metavar=_("action"))
    cfg_show = cfg_sub.add_parser("show", help=_("print the current configuration"))
    cfg_show.add_argument("--json", action="store_true", help=_("JSON output"))
    cfg_set = cfg_sub.add_parser("set", help=_("modify a value"))
    cfg_set.add_argument("--cert", help=_("use this PKCS#12 file as the device"))
    cfg_set.add_argument("--lib", help=_("path to the token's PKCS#11 module"))
    cfg_set.add_argument("--cert-id", dest="cert_id",
                         help=_("composite id of the certificate on the token"))
    cfg_set.add_argument("--tsa", help=_("TSA URL"))
    cfg_set.add_argument("--tsa-user", dest="tsa_user", help=_("TSA username"))
    cfg_set.add_argument("--tsa-password", dest="tsa_password", help=_("TSA password"))
    cfg_set.add_argument("--image", help=_("logo for the visible signature"))
    cfg_set.add_argument("--position", choices=[
        "bottom-right", "bottom-left", "top-right", "top-left",
    ], help=_("corner preset for the visible signature"))
    cfg_set.add_argument("--country", metavar="CC",
                         help=_("primary eIDAS country (e.g. IT, DE). "
                                "Empty string clears it (fall back to $LANG)."))
    cfg_set.add_argument("--active-countries", metavar="CC,CC",
                         help=_("comma-separated list of country codes to "
                                "include in the verification trust store. "
                                "Empty string falls back to the primary country."))
    cfg_set.add_argument("--add-driver", dest="add_driver", metavar="PATH",
                         action="append",
                         help=_("add a directory (recursively scanned), glob, "
                                "or file to the PKCS#11 autodetect search list. "
                                "Tried before the built-in paths. Repeatable."))
    cfg_set.add_argument("--remove-driver", dest="remove_driver", metavar="PATH",
                         action="append",
                         help=_("remove a previously added entry. Repeatable."))
    cfg_set.add_argument("--csc-url", dest="csc_url", metavar="URL",
                         help=_("base URL of the CSC v2 QTSP service "
                                "(without trailing slash)"))
    cfg_set.add_argument("--csc-client-id", dest="csc_client_id", metavar="ID",
                         help=_("OAuth 2.0 client_id registered on the QTSP portal"))
    cfg_set.add_argument("--csc-client-secret", dest="csc_client_secret",
                         metavar="SECRET",
                         help=_("OAuth 2.0 client_secret (omit for public clients)"))
    cfg_set.add_argument("--csc-credential-id", dest="csc_credential_id",
                         metavar="CID",
                         help=_("CSC credential identifier; enumerate with "
                                "`sigillum csc-list`"))
    cfg_set.add_argument("--csc-pin", dest="csc_pin", metavar="PIN",
                         help=_("long-term PIN if the QTSP requires one alongside "
                                "the per-signature OTP"))
    p_cfg.set_defaults(func=_cmd_config, action=None, json=False)

    # gui
    p_gui = sub.add_parser("gui", help=_("launch the graphical interface"))
    p_gui.add_argument("gui_args", nargs=argparse.REMAINDER,
                       help=_("arguments passed to GtkApplication"))
    p_gui.set_defaults(func=_cmd_gui)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        # No subcommand → launch GUI for backwards-compat with the old entry point.
        return _cmd_gui(argparse.Namespace(gui_args=[]))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(_("\ninterrupted."), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
