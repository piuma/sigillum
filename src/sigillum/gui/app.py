# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
"""GTK 3 application shell for Sigillum.

Three tabs: Firma, Verifica, Impostazioni.
The signing device (file vs PKCS#11 token) is configured once in Impostazioni
and persisted to ~/.config/sigillum/settings.json. The Firma tab reads from
settings and only prompts for the password/PIN at sign time.

Backend calls run synchronously: PDF/CMS work is fast enough that an async
layer isn't worth the complexity yet.
"""
from __future__ import annotations

from pathlib import Path

import cairo  # noqa: E402  (PyGObject re-exports it for Cairo drawing)
import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, Gtk, Pango  # noqa: E402

from sigillum.i18n import _
from sigillum.core.credentials import FileProvider, PKCS11Provider
from sigillum.core.crypto import (
    SYMMETRIC_NAMES,
    decrypt_asymmetric,
    decrypt_symmetric,
    detect_format as detect_encryption_format,
    encrypt_asymmetric,
    encrypt_symmetric,
)
from sigillum.core.settings import Settings, load_settings, save_settings
from sigillum.core.signer import (
    CAdESSigner,
    PAdESSigner,
    XAdESSigner,
    SignatureLevel,
    SignaturePosition,
    Signer,
    SignOptions,
)


# Visible signature corner combobox: (label, enum).
# `_()` is applied lazily where the labels are rendered, so the source strings
# stay translatable.
SIGNATURE_POSITIONS: list[tuple[str, SignaturePosition]] = [
    (_("Bottom right"), SignaturePosition.BOTTOM_RIGHT),
    (_("Bottom left"), SignaturePosition.BOTTOM_LEFT),
    (_("Top right"), SignaturePosition.TOP_RIGHT),
    (_("Top left"), SignaturePosition.TOP_LEFT),
]
from sigillum.core.detection import (
    detect_tokens,
    detect_usb_tokens,
    find_available_drivers,
    suggest_driver,
)
from sigillum.core.timestamp import (
    TSAConfig,
    extract_tsd_content,
    make_tsd,
    make_tsr,
    verify_tsd,
    verify_tsr,
)
from sigillum.core.tsl import (
    import_age_days,
    signing_pem_path,
    tsa_pem_path,
)
from sigillum.core.verifier import CAdESVerifier, PAdESVerifier, Verifier, XAdESVerifier


# After this many days the imported TSL is shown as stale.
TSL_STALE_AFTER_DAYS = 30


# Human-readable country names for the EU LOTL country codes. Used purely for
# dropdown labels and tooltips — the codes themselves are what we persist.
LOTL_COUNTRY_LABELS: dict[str, str] = {
    "AT": "Austria",         "BE": "Belgium",        "BG": "Bulgaria",
    "CY": "Cyprus",          "CZ": "Czech Republic", "DE": "Germany",
    "DK": "Denmark",         "EE": "Estonia",        "EL": "Greece",
    "ES": "Spain",           "FI": "Finland",        "FR": "France",
    "HR": "Croatia",         "HU": "Hungary",        "IE": "Ireland",
    "IS": "Iceland",         "IT": "Italy",          "LI": "Liechtenstein",
    "LT": "Lithuania",       "LU": "Luxembourg",     "LV": "Latvia",
    "MT": "Malta",           "NL": "Netherlands",    "NO": "Norway",
    "PL": "Poland",          "PT": "Portugal",       "RO": "Romania",
    "SE": "Sweden",          "SI": "Slovenia",       "SK": "Slovakia",
    "UK": "United Kingdom",
}


def _country_label(cc: str) -> str:
    """Format ``"IT — Italy"`` for dropdown / list display."""
    cc = cc.upper()
    name = LOTL_COUNTRY_LABELS.get(cc)
    return f"{cc} — {name}" if name else cc


DEFAULT_PKCS11_LIBS = [
    "/usr/lib64/libykcs11.so.2",      # YubiKey (PIV)
    "/usr/lib64/opensc-pkcs11.so",    # Generic smartcards via OpenSC
    "/usr/lib/x86_64-linux-gnu/libykcs11.so.2",   # Debian/Ubuntu YubiKey
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", # Debian/Ubuntu OpenSC
]


# Preset Time-Stamp Authorities. Italian QTSAs (Aruba, InfoCert, Namirial)
# require a contract/credentials for production use — they're listed for
# convenience but signing against them will fail without proper auth setup.
TSA_PRESETS: list[tuple[str, str]] = [
    (_("FreeTSA — free, non-qualified"),
     "https://freetsa.org/tsr"),
    (_("Aruba PEC — IT qualified (contract required)"),
     "https://servizi.arubapec.it/tsa/ngrequest.php"),
    (_("InfoCert — IT qualified (contract required)"),
     "https://stamper.infocert.it/tsa/ngrequest.php"),
    (_("Namirial — IT qualified (contract required)"),
     "https://timestamp.namirialtsp.com"),
    (_("DigiCert — free, non-qualified"),
     "http://timestamp.digicert.com"),
]


def _default_pkcs11_lib() -> str:
    """First candidate that exists on disk, or the YubiKey default."""
    for lib in DEFAULT_PKCS11_LIBS:
        if Path(lib).exists():
            return lib
    return DEFAULT_PKCS11_LIBS[0]


def _detect_format(path: Path) -> str:
    """Detect the signature/timestamp family from file extension.

    Returns one of: "PAdES", "XAdES", "CAdES", "TSR", "TSD". The two
    timestamp formats are only meaningful in the Verify flow.
    """
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return "PAdES"
    if suffix == ".xml":
        return "XAdES"
    if suffix == ".p7m":
        return "CAdES"
    if suffix == ".tsr":
        return "TSR"
    if suffix == ".tsd":
        return "TSD"
    return "CAdES"


def _build_signer(fmt: str) -> Signer:
    if fmt == "PAdES":
        return PAdESSigner()
    if fmt == "XAdES":
        return XAdESSigner()
    return CAdESSigner()


def _build_verifier(fmt: str, trusted: list, tsa_trusted: list) -> Verifier:
    if fmt == "PAdES":
        cls = PAdESVerifier
    elif fmt == "XAdES":
        cls = XAdESVerifier
    else:
        cls = CAdESVerifier
    return cls(trusted_certs=trusted, tsa_trusted_certs=tsa_trusted)


def _default_output_path(input_path: Path, fmt: str) -> Path:
    if fmt == "PAdES":
        return input_path.with_name(input_path.stem + "-signed.pdf")
    if fmt == "XAdES":
        return input_path.with_name(input_path.stem + "-signed.xml")
    # CAdES: avoid the double `.p7m.p7m` extension when the source is
    # already a .p7m (countersignature / re-enveloping of a signed file).
    if input_path.suffix.lower() == ".p7m":
        return input_path.with_name(input_path.stem + "-signed.p7m")
    return input_path.with_name(input_path.name + ".p7m")


def _make_password_entry(toggle_handler) -> Gtk.Entry:
    entry = Gtk.Entry(visibility=False)
    entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
    entry.set_icon_from_icon_name(
        Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic"
    )
    entry.connect("icon-press", toggle_handler)
    return entry


def _toggle_password_visibility(entry, _pos, _event):
    visible = not entry.get_visibility()
    entry.set_visibility(visible)
    entry.set_icon_from_icon_name(
        Gtk.EntryIconPosition.SECONDARY,
        "view-conceal-symbolic" if visible else "view-reveal-symbolic",
    )


def _show_error(parent: Gtk.Window, message: str):
    dlg = Gtk.MessageDialog(
        transient_for=parent,
        modal=True,
        message_type=Gtk.MessageType.ERROR,
        buttons=Gtk.ButtonsType.OK,
        text=_("Error"),
        secondary_text=message,
    )
    dlg.run()
    dlg.destroy()


# =====================================================================
#  SettingsView — configure & persist the signing device
# =====================================================================

class SettingsView(Gtk.Box):
    def __init__(self, parent_window: Gtk.Window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=18)
        self._parent = parent_window

        # --- Sidebar + section stack ---
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self._section_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self._section_stack.add_titled(self._build_device_page(),
                                       "device", _("Signing device"))
        self._section_stack.add_titled(self._build_tsa_page(),
                                       "tsa", _("Timestamp"))
        self._section_stack.add_titled(self._build_visible_signature_page(),
                                       "visible", _("Visible signature"))
        self._section_stack.add_titled(self._build_tsl_page(),
                                       "tsl", _("AgID Trust List"))
        self._section_stack.add_titled(self._build_about_page(),
                                       "about", _("About"))
        sidebar = Gtk.StackSidebar()
        sidebar.set_stack(self._section_stack)
        body.pack_start(sidebar, False, False, 0)
        body.pack_start(self._section_stack, True, True, 0)
        self.pack_start(body, True, True, 0)

        # --- Save button ---
        self.pack_start(Gtk.Separator(), False, False, 8)
        self._save_button = Gtk.Button(label=_("Save"))
        self._save_button.get_style_context().add_class("suggested-action")
        self._save_button.connect("clicked", self._on_save_clicked)
        self.pack_start(self._save_button, False, False, 0)

        # --- Unsaved-changes tracking ---
        # `_dirty` is flipped by `_mark_dirty` whenever an editable widget
        # changes. Reset to False after a successful save or a reload from
        # disk. `confirm_leave()` reads it when the user switches tab.
        self._dirty = False
        self._wire_dirty_signals()

        self.refresh_from_settings()

    def _mark_dirty(self, *_args) -> None:
        self._dirty = True

    def _wire_dirty_signals(self) -> None:
        """Connect ``_mark_dirty`` to every editable widget whose state is
        committed by the Save button. Widgets that persist on change (TSL
        primary country combo, active-country checkboxes) are intentionally
        left out — they don't produce unsaved state."""
        self._radio_file.connect("toggled", self._mark_dirty)
        self._radio_token.connect("toggled", self._mark_dirty)
        self._cert_chooser.connect("file-set", self._mark_dirty)
        self._vis_sig_image.connect("file-set", self._mark_dirty)
        for entry in (self._pkcs11_lib, self._tsa_url,
                      self._tsa_username, self._tsa_password):
            entry.connect("changed", self._mark_dirty)
        self._token_cert_combo.connect("changed", self._mark_dirty)
        self._tsa_preset_combo.connect("changed", self._mark_dirty)

    def confirm_leave(self) -> bool:
        """Called when the user tries to leave the Settings tab.

        Returns ``True`` if the switch should proceed, ``False`` to keep the
        user on Settings (i.e. they cancelled). Pops a Save/Discard/Cancel
        dialog only if there are unsaved changes.
        """
        if not self._dirty:
            return True
        dlg = Gtk.MessageDialog(
            transient_for=self._parent,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            text=_("Unsaved changes"),
            secondary_text=_(
                "You have unsaved changes in Settings. "
                "Save them before leaving?"
            ),
        )
        dlg.add_buttons(
            _("Discard"), Gtk.ResponseType.NO,
            _("Cancel"), Gtk.ResponseType.CANCEL,
            _("Save"), Gtk.ResponseType.YES,
        )
        dlg.set_default_response(Gtk.ResponseType.YES)
        response = dlg.run()
        dlg.destroy()
        if response == Gtk.ResponseType.YES:
            s = self._collect()
            if s is None:
                # Validation error already shown by _collect — stay here so
                # the user can fix it.
                return False
            try:
                save_settings(s)
            except OSError as ex:
                _show_error(self._parent,
                            _("Could not save settings: {ex}").format(ex=ex))
                return False
            self._dirty = False
            return True
        if response == Gtk.ResponseType.NO:
            # Discard: reload widgets from disk and let the switch proceed.
            self._load_into_widgets(load_settings())
            self._dirty = False
            return True
        return False  # Cancel / dialog closed

    def refresh_from_settings(self):
        """Re-read settings.json and sync all widgets to the saved state.

        Called both at construction and whenever the user switches back to
        this tab. Without this resync, transient widget state (e.g. a radio
        the user toggled but never saved) would persist across tab switches
        and confuse the user about what is actually persisted on disk.
        """
        self._load_into_widgets(load_settings())

    # ----- section page builders -----

    def _build_device_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        src_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        src_row.pack_start(Gtk.Label(label=_("Source:"), xalign=0), False, False, 0)
        self._radio_file = Gtk.RadioButton.new_with_label_from_widget(None, "File")
        self._radio_token = Gtk.RadioButton.new_with_label_from_widget(
            self._radio_file, _("PKCS#11 token")
        )
        self._radio_file.connect("toggled", self._on_source_changed)
        src_row.pack_start(self._radio_file, False, False, 0)
        src_row.pack_start(self._radio_token, False, False, 0)
        page.pack_start(src_row, False, False, 0)

        self._source_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.NONE)
        self._source_stack.add_named(self._build_file_view(), "file")
        self._source_stack.add_named(self._build_token_view(), "pkcs11")
        page.pack_start(self._source_stack, False, False, 0)

        # Status label for device configuration messages
        page.pack_start(Gtk.Separator(), False, False, 6)
        self._device_status = Gtk.Label(xalign=0, wrap=True)
        page.pack_start(self._device_status, False, False, 0)

        return page

    def _build_tsa_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        page.pack_start(
            Gtk.Label(
                label=_("URL of the RFC 3161 service for level T. "
                      "Enabled or disabled at signing time."),
                xalign=0, wrap=True,
            ),
            False, False, 0,
        )

        preset_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        preset_row.pack_start(Gtk.Label(label=_("Preset:"), xalign=0), False, False, 0)
        self._tsa_preset_combo = Gtk.ComboBoxText()
        self._tsa_preset_combo.append_text(_("(custom)"))
        for label, _url in TSA_PRESETS:
            self._tsa_preset_combo.append_text(label)
        self._tsa_preset_combo.set_active(0)
        self._tsa_preset_combo.connect("changed", self._on_tsa_preset_changed)
        preset_row.pack_start(self._tsa_preset_combo, True, True, 0)
        page.pack_start(preset_row, False, False, 0)

        url_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        url_row.pack_start(Gtk.Label(label=_("URL:"), xalign=0), False, False, 0)
        self._tsa_url = Gtk.Entry()
        self._tsa_url.set_placeholder_text("https://freetsa.org/tsr")
        # Update the preset combo back to _("(custom)") if the user edits the URL.
        self._tsa_url.connect("changed", self._on_tsa_url_edited)
        self._tsa_url_syncing = False
        url_row.pack_start(self._tsa_url, True, True, 0)
        page.pack_start(url_row, False, False, 0)

        # TSA credentials — most qualified Italian TSAs (Aruba/InfoCert/Namirial)
        # require HTTP Basic Auth. Free TSAs (FreeTSA, DigiCert) ignore them.
        page.pack_start(
            Gtk.Label(
                label=_("HTTP Basic credentials (required by qualified IT TSAs)"),
                xalign=0,
            ),
            False, False, 4,
        )
        user_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        user_row.pack_start(Gtk.Label(label=_("Username:"), xalign=0), False, False, 0)
        self._tsa_username = Gtk.Entry()
        user_row.pack_start(self._tsa_username, True, True, 0)
        page.pack_start(user_row, False, False, 0)

        pw_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        pw_row.pack_start(Gtk.Label(label=_(_("Password:")), xalign=0), False, False, 0)
        self._tsa_password = _make_password_entry(_toggle_password_visibility)
        pw_row.pack_start(self._tsa_password, True, True, 0)
        page.pack_start(pw_row, False, False, 0)

        return page

    def _build_tsl_page(self) -> Gtk.Widget:
        from sigillum.core.settings import LOTL_COUNTRIES

        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.pack_start(
            Gtk.Label(
                label=_("Download national Trust Lists from the EU LOTL. "
                        "The primary country is auto-imported at startup; "
                        "additional countries can be enabled for verification."),
                xalign=0, wrap=True,
            ),
            False, False, 0,
        )

        # --- Primary country dropdown ---
        primary_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        primary_row.pack_start(
            Gtk.Label(label=_("Primary country:"), xalign=0), False, False, 0,
        )
        self._tsl_primary_combo = Gtk.ComboBoxText()
        self._tsl_primary_codes: list[str] = sorted(LOTL_COUNTRIES)
        for cc in self._tsl_primary_codes:
            self._tsl_primary_combo.append_text(_country_label(cc))
        self._tsl_primary_combo.connect("changed", self._on_primary_country_changed)
        primary_row.pack_start(self._tsl_primary_combo, False, False, 0)
        page.pack_start(primary_row, False, False, 0)

        # --- Status of the primary country (legacy label kept for set_tsl_busy) ---
        self._tsl_age_label = Gtk.Label(xalign=0)
        page.pack_start(self._tsl_age_label, False, False, 0)

        page.pack_start(Gtk.Separator(), False, False, 6)

        # --- Imported TSLs list ---
        page.pack_start(
            Gtk.Label(label=_("Imported national TSLs:"), xalign=0),
            False, False, 0,
        )
        self._tsl_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        page.pack_start(self._tsl_list_box, False, False, 0)

        # --- Buttons row: + Add country, refresh primary ---
        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._tsl_add_button = Gtk.Button(label=_("+ Add EU country"))
        self._tsl_add_button.connect("clicked", self._on_add_country_clicked)
        action_row.pack_start(self._tsl_add_button, False, False, 0)

        # Backward-compat with set_tsl_busy: this is the "main" refresh button,
        # bound to the primary country.
        self._tsl_import_button = Gtk.Button(label=_("Refresh primary country"))
        self._tsl_import_button.connect("clicked", self._on_tsl_import_clicked)
        action_row.pack_start(self._tsl_import_button, False, False, 0)
        page.pack_start(action_row, False, False, 0)

        # Buttons that set_tsl_busy() should disable while a refresh is running.
        # Per-row refresh buttons are added to this list as the rows are built.
        self._tsl_busy_widgets: list[Gtk.Widget] = [
            self._tsl_add_button,
            self._tsl_import_button,
            self._tsl_primary_combo,
        ]
        return page

    def _build_about_page(self) -> Gtk.Widget:
        from sigillum import __version__

        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        title = Gtk.Label(xalign=0)
        title.set_markup(f"<span size='xx-large' weight='bold'>Sigillum</span>")
        page.pack_start(title, False, False, 0)

        version = Gtk.Label(xalign=0)
        version.set_markup(_("<small>version {v}</small>").format(v=__version__))
        page.pack_start(version, False, False, 0)

        desc = Gtk.Label(xalign=0, wrap=True)
        desc.set_markup(
            _("Tool for digital signature (PAdES, CAdES, XAdES) with "
              "support for PKCS#11 hardware tokens and RFC 3161 timestamping. "
              "Designed for the Italian eIDAS/AgID context.")
        )
        page.pack_start(desc, False, False, 6)

        # Issues link — opens the default browser when clicked.
        issues_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        issues_row.pack_start(
            Gtk.Label(label=_("Report a bug:"), xalign=0), False, False, 0,
        )
        issues_btn = Gtk.LinkButton.new_with_label(
            "https://github.com/piuma/sigillum/issues",
            _("Open an issue on GitHub"),
        )
        issues_row.pack_start(issues_btn, False, False, 0)
        page.pack_start(issues_row, False, False, 0)

        credits_title = Gtk.Label(xalign=0)
        credits_title.set_markup(_("<b>Credits</b>"))
        page.pack_start(credits_title, False, False, 6)

        credits_grid = Gtk.Grid()
        credits_grid.set_column_spacing(12)
        credits_grid.set_row_spacing(4)
        credits_grid.set_margin_start(12)
        for row, (role, name, url) in enumerate([
            (_("Author"),      "Danilo Abbasciano",  "https://piumalab.org"),
            (_("PAdES/CAdES"), "endesive",           "https://github.com/m32/endesive"),
            (_("Crypto"),      "cryptography",       "https://cryptography.io"),
            (_("PKCS#11"),     "PyKCS11",            "https://github.com/LudovicRousseau/PyKCS11"),
            (_("UI toolkit"),  "GTK 3 / PyGObject",  "https://pygobject.gnome.org"),
        ]):
            lbl_role = Gtk.Label(label=role + ":", xalign=1)
            lbl_role.get_style_context().add_class("dim-label")
            credits_grid.attach(lbl_role, 0, row, 1, 1)
            if url:
                lbl_name = Gtk.LinkButton.new_with_label(url, name)
                lbl_name.set_halign(Gtk.Align.START)
            else:
                lbl_name = Gtk.Label(label=name, xalign=0)
            credits_grid.attach(lbl_name, 1, row, 1, 1)
        page.pack_start(credits_grid, False, False, 0)

        license_row = Gtk.Label(xalign=0)
        license_row.set_markup(
            _("<small>License: GPL-3.0-or-later · "
              "Sources: <a href='https://github.com/piuma/sigillum'>"
              "github.com/piuma/sigillum</a></small>")
        )
        page.pack_start(license_row, False, False, 6)

        return page

    def _build_visible_signature_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        page.pack_start(
            Gtk.Label(
                label=_("Logo for the visible signature on PDFs (PAdES). "
                      "The box position is chosen in the Sign tab each "
                      "time you sign."),
                xalign=0, wrap=True,
            ),
            False, False, 0,
        )

        img_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        img_row.pack_start(Gtk.Label(label=_("Logo (PNG/JPG, optional):"), xalign=0),
                           False, False, 0)
        self._vis_sig_image = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        img_filter = Gtk.FileFilter()
        img_filter.set_name(_("Images"))
        for pat in ("*.png", "*.jpg", "*.jpeg"):
            img_filter.add_pattern(pat)
        self._vis_sig_image.add_filter(img_filter)
        self._vis_sig_image.connect("file-set", lambda _w: self._refresh_preview())
        img_row.pack_start(self._vis_sig_image, True, True, 0)
        clear = Gtk.Button.new_from_icon_name("edit-clear-symbolic",
                                              Gtk.IconSize.BUTTON)
        clear.set_tooltip_text(_("Remove the image"))

        def _on_clear(_b):
            self._vis_sig_image.unselect_all()
            self._refresh_preview()
        clear.connect("clicked", _on_clear)
        img_row.pack_start(clear, False, False, 0)
        page.pack_start(img_row, False, False, 0)

        # --- Preview: a Cairo-drawn approximation of how the stamp will look.
        # Aspect ratio matches the actual stamp on the PDF (~70×28 mm).
        # The text is illustrative (generic placeholder + the configured cert
        # CN when known) — exact rendering is endesive's responsibility at
        # sign time, but the preview makes obvious wrong-aspect logos and
        # missing-logo cases.
        page.pack_start(Gtk.Label(label=_("Signature box preview:"), xalign=0),
                        False, False, 6)
        self._sig_preview = Gtk.DrawingArea()
        # 70×28 mm at ~3.4 px/mm → 240×96 px (matches signature_picker scaling)
        self._sig_preview.set_size_request(280, 110)
        self._sig_preview.connect("draw", self._on_draw_sig_preview)
        page.pack_start(self._sig_preview, False, False, 0)

        # Cached pixbuf of the loaded logo; refreshed via `_refresh_preview()`.
        self._logo_pixbuf: GdkPixbuf.Pixbuf | None = None

        return page

    # ----- signature preview -----

    @staticmethod
    def _extract_cn(rfc4514_subject: str) -> str:
        """Pull just the CN= attribute from an RFC 4514 subject string."""
        if not rfc4514_subject:
            return ""
        import re
        # CN values can contain commas if escaped (`\,`); for Italian certs
        # they don't, so a simple split is fine.
        for part in rfc4514_subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:].strip()
        return ""

    def _refresh_preview(self):
        """Reload the logo pixbuf from disk and redraw the preview."""
        path = self._vis_sig_image.get_filename()
        if not path:
            self._logo_pixbuf = None
        else:
            try:
                self._logo_pixbuf = GdkPixbuf.Pixbuf.new_from_file(path)
            except Exception:  # noqa: BLE001 — invalid image → no logo
                self._logo_pixbuf = None
        self._sig_preview.queue_draw()

    def _on_draw_sig_preview(self, area: Gtk.DrawingArea, cr) -> bool:
        from datetime import datetime, timezone

        w = area.get_allocated_width()
        h = area.get_allocated_height()
        pad = 6

        # White background + thin gray border to suggest the stamp boundary.
        cr.set_source_rgb(1.0, 1.0, 1.0)
        cr.rectangle(0, 0, w, h)
        cr.fill()
        cr.set_source_rgb(0.7, 0.7, 0.7)
        cr.set_line_width(1)
        cr.rectangle(0.5, 0.5, w - 1, h - 1)
        cr.stroke()

        text_x = pad
        if self._logo_pixbuf is not None:
            target_h = h - 2 * pad
            scale = target_h / max(1, self._logo_pixbuf.get_height())
            target_w = int(self._logo_pixbuf.get_width() * scale)
            # Don't let the logo dominate the box — leave at least 55% for text.
            target_w = min(target_w, int(w * 0.4))
            target_h = int(target_h)
            scaled = self._logo_pixbuf.scale_simple(
                max(1, target_w), max(1, target_h),
                GdkPixbuf.InterpType.BILINEAR,
            )
            if scaled is not None:
                Gdk.cairo_set_source_pixbuf(cr, scaled, pad, pad)
                cr.paint()
            text_x = pad + target_w + 6

        # Sample text. Use the CN of the configured cert if we have it cached
        # in settings (no network/PIN required), otherwise a placeholder.
        cn = self._extract_cn(load_settings().pkcs11_cert_subject) or _("Name Surname")
        date = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
        lines = [
            (_("Digitally signed by:"), False),
            (cn, True),
            (f"Data: {date}", False),
        ]
        cr.set_source_rgb(0.1, 0.1, 0.1)
        cr.select_font_face("sans", cairo.FONT_SLANT_NORMAL,
                            cairo.FONT_WEIGHT_NORMAL)
        cr.set_font_size(10)
        line_h = 14
        y = pad + 12
        for line, bold in lines:
            cr.select_font_face(
                "sans", cairo.FONT_SLANT_NORMAL,
                cairo.FONT_WEIGHT_BOLD if bold else cairo.FONT_WEIGHT_NORMAL,
            )
            # Truncate if it overflows the available width.
            avail = w - text_x - pad
            text = line
            ext = cr.text_extents(text)
            while ext.width > avail and len(text) > 1:
                text = text[:-2] + "…"
                ext = cr.text_extents(text)
            cr.move_to(text_x, y)
            cr.show_text(text)
            y += line_h
        return False

    # ----- subview construction -----

    def _build_file_view(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=6)
        box.pack_start(
            Gtk.Label(label=_("Certificate (.p12 / .pfx / .pem):"), xalign=0),
            False, False, 0,
        )
        self._cert_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        cert_filter = Gtk.FileFilter()
        cert_filter.set_name(_("Certificates"))
        for pat in ("*.p12", "*.pfx", "*.pem", "*.crt"):
            cert_filter.add_pattern(pat)
        self._cert_chooser.add_filter(cert_filter)
        box.pack_start(self._cert_chooser, False, False, 0)
        return box

    def _build_token_view(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=6)

        # --- One-click auto-detect: tries every known PKCS#11 driver on disk
        # and picks the first that enumerates ≥1 certificate. Removes the need
        # for the user to know the exact .so path.
        detect_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        detect = Gtk.Button(label=_("🔍  Auto-detect token"))
        detect.get_style_context().add_class("suggested-action")
        detect.connect("clicked", self._on_autodetect_token)
        detect_row.pack_start(detect, False, False, 0)
        self._detect_status = Gtk.Label(xalign=0)
        detect_row.pack_start(self._detect_status, True, True, 6)
        box.pack_start(detect_row, False, False, 0)

        # --- Manual fallback: driver path + refresh
        lib_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        lib_row.pack_start(Gtk.Label(label=_("PKCS#11 driver:"), xalign=0),
                           False, False, 0)
        self._pkcs11_lib = Gtk.Entry()
        self._pkcs11_lib.set_text(_default_pkcs11_lib())
        lib_row.pack_start(self._pkcs11_lib, True, True, 0)
        refresh = Gtk.Button.new_from_icon_name("view-refresh-symbolic",
                                                Gtk.IconSize.BUTTON)
        refresh.set_tooltip_text(_("Re-read certificates from the token"))
        refresh.connect("clicked", self._on_refresh_tokens)
        lib_row.pack_start(refresh, False, False, 0)
        box.pack_start(lib_row, False, False, 0)

        # --- Extra search paths (autodetect fallback)
        # Hidden by default. Revealed by _on_autodetect_token() when scanning
        # finds nothing, or by _load_into_widgets() if Settings already
        # contain user-supplied entries.
        self._extra_search_paths: list[str] = []
        self._extra_search_frame = self._build_extra_search_section()
        box.pack_start(self._extra_search_frame, False, False, 0)

        box.pack_start(Gtk.Label(label=_("Certificate on the token:"), xalign=0),
                       False, False, 0)
        self._token_cert_combo = Gtk.ComboBoxText()
        box.pack_start(self._token_cert_combo, False, False, 0)
        # Hint shown when settings reference a cert not yet enumerated this session.
        self._saved_cert_hint = Gtk.Label(xalign=0)
        box.pack_start(self._saved_cert_hint, False, False, 0)

        self._token_cert_ids: list[str] = []
        self._token_cert_subjects: list[str] = []
        return box

    def _build_extra_search_section(self) -> Gtk.Widget:
        """Fallback panel: directories to scan when auto-detect finds nothing.

        Each directory is searched recursively for ``*.so`` files by
        ``find_available_drivers()`` (tried *before* the built-in paths).
        Hidden by default — surface it only when the user actually needs
        it, otherwise the Settings tab is noisier than necessary.
        """
        frame = Gtk.Frame()
        frame.set_label(_("Auto-detect: extra search directories"))
        frame.set_no_show_all(True)  # caller decides when to reveal

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        outer.set_margin_top(6)
        outer.set_margin_bottom(6)
        outer.set_margin_start(10)
        outer.set_margin_end(10)

        hint = Gtk.Label(xalign=0, wrap=True)
        hint.set_markup(
            _("<small>Add directories where Sigillum should recursively look "
              "for a vendor PKCS#11 module when auto-detect fails. If you "
              "already know the exact <tt>.so</tt> file, type it in the "
              "<b>PKCS#11 driver</b> field above instead.</small>")
        )
        outer.pack_start(hint, False, False, 0)

        self._extra_search_list = Gtk.ListBox()
        self._extra_search_list.set_selection_mode(Gtk.SelectionMode.NONE)
        outer.pack_start(self._extra_search_list, False, False, 0)

        add_btn = Gtk.Button.new_with_label(_("＋ Add directory…"))
        add_btn.connect("clicked", self._on_add_extra_search_clicked)
        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        add_row.pack_start(add_btn, False, False, 0)
        outer.pack_start(add_row, False, False, 0)

        frame.add(outer)
        # Children must be ready to show as soon as the frame is revealed.
        outer.show_all()
        return frame

    def _refresh_extra_search_list(self) -> None:
        for child in list(self._extra_search_list.get_children()):
            self._extra_search_list.remove(child)
        for path in self._extra_search_paths:
            row = Gtk.ListBoxRow()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            hbox.pack_start(Gtk.Label(label=path, xalign=0, hexpand=True,
                                      ellipsize=Pango.EllipsizeMode.MIDDLE),
                            True, True, 0)
            rm = Gtk.Button.new_from_icon_name("list-remove-symbolic",
                                               Gtk.IconSize.BUTTON)
            rm.set_tooltip_text(_("Remove this directory"))
            rm.connect("clicked", self._on_remove_extra_search, path)
            hbox.pack_start(rm, False, False, 0)
            row.add(hbox)
            self._extra_search_list.add(row)
        self._extra_search_list.show_all()

    def _reveal_extra_search_section(self) -> None:
        self._extra_search_frame.set_no_show_all(False)
        self._extra_search_frame.show()

    def _on_add_extra_search_clicked(self, _button):
        dlg = Gtk.FileChooserDialog(
            title=_("Select a directory to scan for PKCS#11 drivers"),
            transient_for=self._parent,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        dlg.add_buttons(
            _("Cancel"), Gtk.ResponseType.CANCEL,
            _("Add"), Gtk.ResponseType.OK,
        )
        try:
            if dlg.run() == Gtk.ResponseType.OK:
                path = dlg.get_filename()
                if path and path not in self._extra_search_paths:
                    self._extra_search_paths.append(path)
                    self._refresh_extra_search_list()
                    self._mark_dirty()
        finally:
            dlg.destroy()

    def _on_remove_extra_search(self, _button, path: str):
        if path in self._extra_search_paths:
            self._extra_search_paths.remove(path)
            self._refresh_extra_search_list()
            self._mark_dirty()

    # ----- event handlers -----

    def _on_source_changed(self, _radio):
        name = "file" if self._radio_file.get_active() else "pkcs11"
        self._source_stack.set_visible_child_name(name)

    def _on_refresh_tokens(self, _button):
        self._token_cert_combo.remove_all()
        self._token_cert_ids = []
        self._token_cert_subjects = []
        self._saved_cert_hint.set_text("")
        lib = self._pkcs11_lib.get_text().strip()
        if not lib:
            _show_error(self._parent, _("Provide the PKCS#11 driver path."))
            return
        try:
            certs = PKCS11Provider(lib).list_certificates()
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent, _("Reading the token failed: {ex}").format(ex=ex))
            return
        if not certs:
            self._token_cert_combo.append_text(_("(no certificate)"))
            self._token_cert_combo.set_active(0)
            return
        for c in certs:
            self._token_cert_combo.append_text(f"{c.subject}  [{c.id}]")
            self._token_cert_ids.append(c.id)
            self._token_cert_subjects.append(c.subject)
        self._token_cert_combo.set_active(0)

    def _on_autodetect_token(self, _button):
        """Scan every known PKCS#11 driver and pick the first that works.

        If multiple distinct tokens are found, ask the user to choose. If none
        is found, hint at the manual fallback (path + refresh).
        """
        self._detect_status.set_markup(_("<i>Scanning…</i>"))
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        try:
            tokens = detect_tokens(self._extra_search_paths)
        except Exception as ex:  # noqa: BLE001
            self._detect_status.set_markup("")
            _show_error(self._parent, _("Scan failed: {ex}").format(ex=ex))
            return

        if not tokens:
            available = find_available_drivers(self._extra_search_paths)
            # Autodetect failed: surface the "extra search directories" panel
            # so the user has somewhere to point us at without rebuilding
            # the Settings tab.
            self._reveal_extra_search_section()
            # We didn't find a working PKCS#11 driver — look at the USB bus
            # to see if any *recognised* token is plugged in for which we
            # know how to fetch a driver.
            usb_tokens = detect_usb_tokens()
            if usb_tokens:
                self._detect_status.set_markup(
                    _("<span foreground='#c33'>Missing driver for the detected token.</span>")
                )
                if self._show_driver_help(usb_tokens):
                    # User added a search directory in the popup — try again.
                    self._on_autodetect_token(None)
                    return
            else:
                self._detect_status.set_markup(
                    _("<span foreground='#c33'>No token detected.</span> "
                      "<small>Drivers tried: {n}. Enter the path manually if "
                      "your token's driver isn't among the known ones.</small>").format(
                        n=len(available)
                    )
                )
            return

        picked = tokens[0] if len(tokens) == 1 else self._choose_token(tokens)
        if picked is None:
            self._detect_status.set_markup("")
            return

        # Populate the manual fields so they reflect what was detected, and
        # repopulate the cert combo with the certs we already enumerated
        # (avoiding a second round-trip to the token).
        self._pkcs11_lib.set_text(picked.library_path)
        self._token_cert_combo.remove_all()
        self._token_cert_ids = []
        self._token_cert_subjects = []
        self._saved_cert_hint.set_text("")
        for c in picked.certificates:
            self._token_cert_combo.append_text(f"{c.subject}  [{c.id}]")
            self._token_cert_ids.append(c.id)
            self._token_cert_subjects.append(c.subject)
        self._token_cert_combo.set_active(0)
        self._detect_status.set_markup(
            _("<span foreground='#2a7'>✓ Detected</span> <b>{label}</b> — "
              "{n} certificate(s)").format(
                label=picked.library_label, n=len(picked.certificates)
            )
        )

    # Custom response id used when the user picks a directory from inside
    # the "Missing driver" popup — tells _on_autodetect_token to re-scan.
    _RETRY_AUTODETECT = 1

    def _show_driver_help(self, usb_tokens) -> bool:
        """Pop a dialog explaining which driver is needed for each USB token.

        For open-source drivers we show the install command for the current
        distro. For proprietary drivers (Bit4id, SafeNet) we can't bundle the
        binary, so we list the vendor download pages (clickable links).

        Returns ``True`` if the user added a search directory and the caller
        should re-run auto-detect; ``False`` if they just closed the dialog.
        """
        from gi.repository import Pango as _Pango  # local import: top-level done elsewhere

        dlg = Gtk.Dialog(
            title=_("Missing token driver"),
            transient_for=self._parent,
            flags=Gtk.DialogFlags.MODAL,
        )
        dlg.add_button(_("Close"), Gtk.ResponseType.CLOSE)
        dlg.set_default_size(640, -1)

        content = dlg.get_content_area()
        content.set_spacing(10)
        content.set_margin_start(14)
        content.set_margin_end(14)
        content.set_margin_top(10)
        content.set_margin_bottom(10)

        intro = Gtk.Label(xalign=0, wrap=True)
        intro.set_markup(
            _("Sigillum detected a USB token but did not find a working "
              "PKCS#11 driver.\n"
              "Install the driver and then press <b>“Auto-detect token”</b> again.")
        )
        content.pack_start(intro, False, False, 0)

        for tok in usb_tokens:
            sug = suggest_driver(tok)
            frame = Gtk.Frame(label=tok.vendor_name)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                          margin_top=8, margin_bottom=8,
                          margin_start=10, margin_end=10)
            kind_label = Gtk.Label(xalign=0, wrap=True)
            if sug.kind == "open_source":
                kind_label.set_markup(
                    _("<small>Recommended driver: <tt>{hint}</tt> "
                      "(open source, installable from your distro's repository).</small>").format(
                        hint=sug.driver_hint
                    )
                )
            else:
                kind_label.set_markup(
                    _("<small>Driver: <tt>{hint}</tt> — "
                      "proprietary, not redistributable. Download it from the "
                      "issuer of your certificate.</small>").format(
                        hint=sug.driver_hint
                    )
                )
            box.pack_start(kind_label, False, False, 0)

            # Install command (open source) — selectable & copyable.
            if sug.install_command:
                cmd_label = Gtk.Label(xalign=0)
                cmd_label.set_markup(f"<tt>{sug.install_command}</tt>")
                cmd_label.set_selectable(True)
                cmd_label.set_line_wrap(True)
                cmd_label.set_line_wrap_mode(_Pango.WrapMode.WORD_CHAR)
                box.pack_start(cmd_label, False, False, 0)
            elif sug.kind == "open_source":
                hint = Gtk.Label(xalign=0, wrap=True)
                hint.set_markup(
                    _("<small><i>Distro not recognized — look for a package "
                      "called <tt>{hint}</tt> in your repos.</i></small>").format(
                        hint=sug.driver_hint
                    )
                )
                box.pack_start(hint, False, False, 0)

            # Vendor download links (proprietary).
            for label, url in sug.vendor_links:
                link = Gtk.LinkButton.new_with_label(url, _("Download from {label}").format(label=label))
                link.set_halign(Gtk.Align.START)
                box.pack_start(link, False, False, 0)

            frame.add(box)
            content.pack_start(frame, False, False, 0)

        # "Already installed elsewhere?" — quick shortcut to add a directory
        # to the autodetect search list without leaving the dialog. Common
        # case: the driver is on disk but in a path Sigillum doesn't know
        # about (vendor installer in $HOME, custom prefix, etc.).
        content.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL),
                           False, False, 4)
        installed = Gtk.Label(xalign=0, wrap=True)
        installed.set_markup(
            _("<b>Driver already installed in a non-standard location?</b>\n"
              "<small>Point Sigillum at a directory — it will be scanned "
              "recursively for <tt>.so</tt> files before the built-in paths.</small>")
        )
        content.pack_start(installed, False, False, 0)
        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        add_dir_btn = Gtk.Button.new_with_label(_("＋ Add directory and re-scan…"))
        add_dir_btn.connect("clicked", self._on_quick_add_search_dir, dlg)
        add_row.pack_start(add_dir_btn, False, False, 0)
        content.pack_start(add_row, False, False, 0)

        dlg.show_all()
        result = dlg.run()
        dlg.destroy()
        return result == self._RETRY_AUTODETECT

    def _on_quick_add_search_dir(self, _button, parent_dlg: Gtk.Dialog):
        """File chooser opened from the "Missing driver" popup. On success,
        appends the directory to the in-memory search list, refreshes the
        Settings panel, and closes the popup with RETRY so auto-detect
        runs again immediately."""
        fc = Gtk.FileChooserDialog(
            title=_("Select a directory to scan for PKCS#11 drivers"),
            transient_for=parent_dlg,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        fc.add_buttons(
            _("Cancel"), Gtk.ResponseType.CANCEL,
            _("Add and re-scan"), Gtk.ResponseType.OK,
        )
        try:
            if fc.run() == Gtk.ResponseType.OK:
                path = fc.get_filename()
                if path and path not in self._extra_search_paths:
                    self._extra_search_paths.append(path)
                    self._refresh_extra_search_list()
                    self._reveal_extra_search_section()
                    self._mark_dirty()
                if path:
                    parent_dlg.response(self._RETRY_AUTODETECT)
        finally:
            fc.destroy()

    def _choose_token(self, tokens):
        """Modal chooser when multiple distinct tokens are detected."""
        dlg = Gtk.Dialog(
            title=_("Multiple tokens found"),
            transient_for=self._parent,
            flags=Gtk.DialogFlags.MODAL,
        )
        dlg.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        dlg.add_button(_("Use this one"), Gtk.ResponseType.OK)

        content = dlg.get_content_area()
        content.set_spacing(6)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.pack_start(
            Gtk.Label(label=_("Multiple tokens found. Which one do you want to use?"),
                      xalign=0),
            False, False, 0,
        )
        radios: list[Gtk.RadioButton] = []
        first: Gtk.RadioButton | None = None
        for tok in tokens:
            text = _("{label}\n   {n} cert — {subjects}").format(
                label=tok.library_label,
                n=len(tok.certificates),
                subjects=", ".join(c.subject[:50] for c in tok.certificates[:2]),
            )
            r = Gtk.RadioButton.new_with_label_from_widget(first, text)
            radios.append(r)
            content.pack_start(r, False, False, 0)
            if first is None:
                first = r
        dlg.show_all()
        try:
            if dlg.run() != Gtk.ResponseType.OK:
                return None
            for r, tok in zip(radios, tokens):
                if r.get_active():
                    return tok
            return tokens[0]
        finally:
            dlg.destroy()

    def _on_tsa_preset_changed(self, combo):
        idx = combo.get_active()
        if idx <= 0:
            return  # _("(custom)") — leave the URL alone
        _label, url = TSA_PRESETS[idx - 1]
        self._tsa_url_syncing = True
        try:
            self._tsa_url.set_text(url)
        finally:
            self._tsa_url_syncing = False

    def _on_tsa_url_edited(self, _entry):
        if self._tsa_url_syncing:
            return
        # User typed manually: reset combo to _("(custom)") unless the
        # current text exactly matches a known preset.
        url = self._tsa_url.get_text().strip()
        for i, (_label, preset_url) in enumerate(TSA_PRESETS, start=1):
            if preset_url == url:
                self._tsa_preset_combo.set_active(i)
                return
        self._tsa_preset_combo.set_active(0)

    def _on_tsl_import_clicked(self, _button):
        # All TSL refreshes go through the window-level coordinator so the
        # at-startup auto-refresh, the Settings button, and the Verify-tab
        # "Importa ora" button can share threading + re-entrancy protection.
        self._parent.start_tsl_refresh(silent=False)

    def set_tsl_busy(self, busy: bool):
        """Called by the coordinator to disable controls + show progress."""
        for w in self._tsl_busy_widgets:
            w.set_sensitive(not busy)
        if busy:
            self._tsl_age_label.set_markup(
                _("<i>Refreshing national TSL…</i>")
            )
        else:
            s = load_settings()
            self._refresh_tsl_age(s.last_import_for(s.effective_country()))
            self._rebuild_tsl_country_list()

    def _rebuild_tsl_country_list(self):
        """Rebuild the per-country rows from disk + Settings.

        One row per imported country, with a checkbox controlling
        ``tsl_active_countries`` membership, an age label, and a refresh
        button. The "+ Add" button below the list opens the chooser dialog.
        """
        from sigillum.core.tsl import list_imported_countries

        # Clear existing rows.
        for child in list(self._tsl_list_box.get_children()):
            self._tsl_list_box.remove(child)
        # Drop stale references from the busy list (per-row refresh buttons).
        keep = {
            id(self._tsl_add_button),
            id(self._tsl_import_button),
            id(self._tsl_primary_combo),
        }
        self._tsl_busy_widgets = [w for w in self._tsl_busy_widgets if id(w) in keep]

        s = load_settings()
        primary = s.effective_country()
        active = set(s.active_countries())
        countries = list_imported_countries()

        if not countries:
            self._tsl_list_box.pack_start(
                Gtk.Label(label=_("(none yet — use the button below)"), xalign=0),
                False, False, 0,
            )
            self._tsl_list_box.show_all()
            self._sync_primary_combo(primary)
            return

        for cc in countries:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)

            chk = Gtk.CheckButton()
            chk.set_active(cc in active)
            # Always-on for the primary country: removing it would silently
            # break verification on the user's own TSL.
            chk.set_sensitive(cc != primary)
            chk.set_tooltip_text(
                _("Use this country's certificates when verifying signatures.")
            )
            chk.connect("toggled", self._on_active_country_toggled, cc)
            row.pack_start(chk, False, False, 0)

            lbl = Gtk.Label(xalign=0)
            ts = s.last_import_for(cc)
            age = import_age_days(ts)
            name = _country_label(cc)
            if cc == primary:
                name = f"<b>{name}</b>"
            if age is None:
                age_txt = _("never")
                color = "#c33"
            elif age <= TSL_STALE_AFTER_DAYS:
                age_txt = _("imported {days}d ago").format(days=age)
                color = "#2a7"
            else:
                age_txt = _("imported {days}d ago — stale").format(days=age)
                color = "#c33"
            lbl.set_markup(
                f"{name}  <span foreground='{color}'><small>{age_txt}</small></span>"
            )
            row.pack_start(lbl, True, True, 0)

            refresh = Gtk.Button.new_from_icon_name(
                "view-refresh-symbolic", Gtk.IconSize.BUTTON,
            )
            refresh.set_tooltip_text(_("Re-download this country's TSL."))
            refresh.connect("clicked", self._on_refresh_country_clicked, cc)
            row.pack_start(refresh, False, False, 0)
            self._tsl_busy_widgets.append(refresh)

            remove = Gtk.Button.new_from_icon_name(
                "edit-delete-symbolic", Gtk.IconSize.BUTTON,
            )
            remove.set_tooltip_text(_("Remove this country's TSL from disk."))
            remove.set_sensitive(cc != primary)
            remove.connect("clicked", self._on_remove_country_clicked, cc)
            row.pack_start(remove, False, False, 0)
            self._tsl_busy_widgets.append(remove)

            self._tsl_list_box.pack_start(row, False, False, 0)

        self._tsl_list_box.show_all()
        self._sync_primary_combo(primary)

    def _sync_primary_combo(self, primary: str):
        """Position the dropdown on *primary* without re-firing 'changed'."""
        try:
            idx = self._tsl_primary_codes.index(primary.upper())
        except ValueError:
            idx = self._tsl_primary_codes.index("IT")
        # Guard against the signal handler reacting to a programmatic update.
        self._primary_combo_syncing = True
        try:
            self._tsl_primary_combo.set_active(idx)
        finally:
            self._primary_combo_syncing = False

    def _on_primary_country_changed(self, combo: Gtk.ComboBoxText):
        if getattr(self, "_primary_combo_syncing", False):
            return
        idx = combo.get_active()
        if idx < 0 or idx >= len(self._tsl_primary_codes):
            return
        cc = self._tsl_primary_codes[idx]
        s = load_settings()
        if s.country == cc:
            return
        s.country = cc
        # When the user picks a new primary, make sure it's enabled in the
        # active set — otherwise their own country would silently drop out.
        if s.tsl_active_countries and cc not in s.tsl_active_countries:
            s.tsl_active_countries.append(cc)
        save_settings(s)
        self._rebuild_tsl_country_list()
        # If the new primary hasn't been imported yet, trigger one now.
        from sigillum.core.tsl import signing_pem_path
        if not signing_pem_path(cc).exists():
            self._parent.start_tsl_refresh(silent=False, country=cc)

    def _on_active_country_toggled(self, chk: Gtk.CheckButton, cc: str):
        s = load_settings()
        active = list(s.tsl_active_countries) if s.tsl_active_countries else list(s.active_countries())
        if chk.get_active():
            if cc not in active:
                active.append(cc)
        else:
            active = [c for c in active if c != cc]
        s.tsl_active_countries = active
        save_settings(s)

    def _on_refresh_country_clicked(self, _button, cc: str):
        self._parent.start_tsl_refresh(silent=False, country=cc)

    def _on_remove_country_clicked(self, _button, cc: str):
        from sigillum.core.tsl import signing_pem_path, tsa_pem_path
        for p in (signing_pem_path(cc), tsa_pem_path(cc)):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError as ex:
                _show_error(self._parent,
                            _("Could not remove {p}: {ex}").format(p=p, ex=ex))
                return
        s = load_settings()
        s.tsl_imports.pop(cc, None)
        if cc in s.tsl_active_countries:
            s.tsl_active_countries = [c for c in s.tsl_active_countries if c != cc]
        save_settings(s)
        self._rebuild_tsl_country_list()

    def _on_add_country_clicked(self, _button):
        from sigillum.core.settings import LOTL_COUNTRIES
        from sigillum.core.tsl import list_imported_countries

        already = set(list_imported_countries())
        candidates = sorted(LOTL_COUNTRIES - already)
        if not candidates:
            _show_error(self._parent,
                        _("All EU countries are already imported."))
            return

        dialog = Gtk.Dialog(
            title=_("Add EU country"),
            transient_for=self._parent,
            flags=Gtk.DialogFlags.MODAL,
        )
        dialog.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        ok_btn = dialog.add_button(_("Import"), Gtk.ResponseType.OK)
        ok_btn.get_style_context().add_class("suggested-action")

        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_margin_start(12); box.set_margin_end(12)
        box.set_margin_top(8); box.set_margin_bottom(8)
        box.add(Gtk.Label(
            label=_("Pick a country to download its national TSL via the EU LOTL."),
            xalign=0, wrap=True,
        ))
        combo = Gtk.ComboBoxText()
        for cc in candidates:
            combo.append_text(_country_label(cc))
        combo.set_active(0)
        box.add(combo)
        dialog.show_all()

        try:
            if dialog.run() == Gtk.ResponseType.OK:
                idx = combo.get_active()
                if 0 <= idx < len(candidates):
                    self._parent.start_tsl_refresh(silent=False, country=candidates[idx])
        finally:
            dialog.destroy()

    def _refresh_tsl_age(self, iso_timestamp: str):
        days = import_age_days(iso_timestamp)
        if days is None:
            self._tsl_age_label.set_markup(
                _("<span foreground='#c33'>Never imported.</span>")
            )
        elif days <= TSL_STALE_AFTER_DAYS:
            self._tsl_age_label.set_markup(
                _("<span foreground='#2a7'>Imported {days} days ago.</span>").format(days=days)
            )
        else:
            self._tsl_age_label.set_markup(
                _("<span foreground='#c33'>"
                  "Imported {days} days ago — refresh it.</span>").format(days=days)
            )

    def _on_save_clicked(self, _button):
        s = self._collect()
        if s is None:
            return  # validation error already shown
        try:
            save_settings(s)
        except OSError as ex:
            _show_error(self._parent, _("Could not save settings: {ex}").format(ex=ex))
            return
        self._dirty = False
        self._device_status.set_markup(
            _("<span foreground='#2a7'>✓ Saved</span>: {value}").format(value=s.describe())
        )

    # ----- load/save plumbing -----

    def _load_into_widgets(self, s: Settings):
        if s.source == "pkcs11":
            self._radio_token.set_active(True)
            self._source_stack.set_visible_child_name("pkcs11")
            if s.pkcs11_library:
                self._pkcs11_lib.set_text(s.pkcs11_library)
            if s.pkcs11_cert_id:
                # The actual cert subject is already shown by the global
                # _("Configured:") label; here we just remind the user how to
                # change it.
                self._saved_cert_hint.set_markup(
                    _("<i>Press refresh to change the certificate.</i>")
                )
        else:
            self._radio_file.set_active(True)
            self._source_stack.set_visible_child_name("file")
            if s.file_path and Path(s.file_path).exists():
                self._cert_chooser.set_filename(s.file_path)

        # TSA: populate URL entry; let _on_tsa_url_edited pick the preset combo.
        if s.tsa_url:
            self._tsa_url.set_text(s.tsa_url)
        self._tsa_username.set_text(s.tsa_username)
        self._tsa_password.set_text(s.tsa_password)

        # Visible signature logo (position is chosen at sign time in the Firma tab)
        if s.signature_image:
            self._vis_sig_image.set_filename(s.signature_image)
        else:
            self._vis_sig_image.unselect_all()
        # set_filename / unselect_all don't fire `file-set`, so refresh manually.
        self._refresh_preview()

        # Extra search paths (autodetect fallback). Reveal the panel only if
        # the user already configured something — otherwise it stays hidden
        # until autodetect fails.
        self._extra_search_paths = list(s.extra_pkcs11_search_paths)
        self._refresh_extra_search_list()
        if self._extra_search_paths:
            self._reveal_extra_search_section()

        # TSL age — for the primary country
        self._refresh_tsl_age(s.last_import_for(s.effective_country()))
        # Multi-country panel: dropdown + per-row list.
        self._rebuild_tsl_country_list()

        self._device_status.set_text(_("Configured: {value}").format(value=s.describe()))

        # Programmatic widget mutations above fire `changed`/`toggled`
        # signals, which would otherwise flip `_dirty` on every refresh.
        # Reset the flag here so it only reflects real user input.
        self._dirty = False

    def _collect(self) -> Settings | None:
        """Build a Settings from the UI controls.

        We start from a copy of the on-disk settings so anything the
        SettingsView doesn't expose (TSL timestamps, country choice,
        active-countries list, signature position) is preserved verbatim.
        Only the fields actually editable here are overwritten.
        """
        from copy import deepcopy
        s = deepcopy(load_settings())
        s.tsa_url = self._tsa_url.get_text().strip()
        s.tsa_username = self._tsa_username.get_text()
        s.tsa_password = self._tsa_password.get_text()
        s.signature_image = self._vis_sig_image.get_filename() or ""
        s.extra_pkcs11_search_paths = list(self._extra_search_paths)

        if self._radio_file.get_active():
            cert = self._cert_chooser.get_filename()
            if not cert:
                _show_error(self._parent, _("Select a certificate file."))
                return None
            s.source = "file"
            s.file_path = cert
            s.pkcs11_library = ""
            s.pkcs11_cert_id = ""
            s.pkcs11_cert_subject = ""
            return s

        # pkcs11
        lib = self._pkcs11_lib.get_text().strip()
        if not lib:
            _show_error(self._parent, _("Provide the PKCS#11 driver path."))
            return None

        active = self._token_cert_combo.get_active()
        s.source = "pkcs11"
        s.file_path = ""
        s.pkcs11_library = lib
        # If the combo wasn't populated this session, keep whatever was saved
        # before (so re-opening Settings and saving again doesn't wipe it).
        if active < 0 or active >= len(self._token_cert_ids):
            if not s.pkcs11_cert_id:
                _show_error(self._parent,
                            _("Press refresh and choose a certificate on the token."))
                return None
        else:
            s.pkcs11_cert_id = self._token_cert_ids[active]
            s.pkcs11_cert_subject = self._token_cert_subjects[active]
        return s


# =====================================================================
#  SignView — sign a document with the configured device
# =====================================================================

class SignView(Gtk.Box):
    def __init__(self, parent_window: Gtk.Window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=18)
        self._parent = parent_window
        self._current_settings = Settings()

        # Document picker
        self.pack_start(Gtk.Label(label=_("Document to sign:"), xalign=0),
                        False, False, 0)
        self._doc_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        self._doc_chooser.connect("file-set", self._on_doc_chosen)
        self.pack_start(self._doc_chooser, False, False, 0)

        # Signature format selector. Default auto-picked from the file
        # extension, but the user can override: CAdES is always available
        # (envelopes any file as `.p7m`), PAdES needs a `.pdf`, XAdES a
        # `.xml`. PAdES/XAdES rows are desensitised when the source file
        # doesn't match.
        fmt_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        fmt_row.pack_start(Gtk.Label(label=_("Format:"), xalign=0),
                           False, False, 0)
        self._fmt_cades = Gtk.RadioButton.new_with_label_from_widget(
            None, "CAdES (.p7m)")
        self._fmt_pades = Gtk.RadioButton.new_with_label_from_widget(
            self._fmt_cades, "PAdES (PDF)")
        self._fmt_xades = Gtk.RadioButton.new_with_label_from_widget(
            self._fmt_cades, "XAdES (XML)")
        for r in (self._fmt_cades, self._fmt_pades, self._fmt_xades):
            r.connect("toggled", self._on_format_toggled)
            fmt_row.pack_start(r, False, False, 0)
        self.pack_start(fmt_row, False, False, 0)
        # Guard so _on_format_toggled doesn't re-enter while we're flipping
        # the radios programmatically from _on_doc_chosen.
        self._fmt_syncing = False
        # Until the user picks a file: CAdES is the only universally
        # applicable option.
        self._fmt_pades.set_sensitive(False)
        self._fmt_xades.set_sensitive(False)

        # Editable output file name — pre-populated when the source is chosen.
        out_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        out_row.pack_start(
            Gtk.Label(label=_("Output file name:"), xalign=0),
            False, False, 0,
        )
        self._sign_output_name = Gtk.Entry()
        self._sign_output_name.set_placeholder_text(
            _("<will be filled in when you choose a file>")
        )
        out_row.pack_start(self._sign_output_name, True, True, 0)
        self.pack_start(out_row, False, False, 0)

        self.pack_start(Gtk.Separator(), False, False, 6)

        # Device description (from settings)
        self._device_label = Gtk.Label(xalign=0, wrap=True)
        self.pack_start(self._device_label, False, False, 0)

        # Secret entry — label adapts to source kind
        self._secret_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._secret_label = Gtk.Label(label=_(_("Password:")), xalign=0)
        self._secret_row.pack_start(self._secret_label, False, False, 0)
        self._secret = _make_password_entry(_toggle_password_visibility)
        self._secret_row.pack_start(self._secret, True, True, 0)
        self.pack_start(self._secret_row, False, False, 0)

        self.pack_start(Gtk.Separator(), False, False, 6)
        opts = Gtk.Label(xalign=0)
        opts.set_markup(_("<b>Options</b>"))
        self.pack_start(opts, False, False, 0)

        self._reason = self._add_entry_row(_("Reason (optional):"))

        self._visible_checkbox = Gtk.CheckButton(
            label=_("Visible signature in the PDF (PAdES only)")
        )
        self._visible_checkbox.set_tooltip_text(
            _("Use the defaults from Settings > Visible signature.")
        )
        self._visible_checkbox.connect("toggled", self._on_visible_toggled)
        self.pack_start(self._visible_checkbox, False, False, 0)

        # Sub-controls revealed only when the checkbox is active.
        self._visible_revealer = Gtk.Revealer()
        self._visible_revealer.set_transition_type(
            Gtk.RevealerTransitionType.SLIDE_DOWN
        )
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                       margin_start=24, margin_top=4)

        page_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        page_row.pack_start(Gtk.Label(label=_("Page:"), xalign=0), False, False, 0)
        self._visible_page = Gtk.SpinButton.new_with_range(1, 9999, 1)
        self._visible_page.set_value(1)
        page_row.pack_start(self._visible_page, False, False, 0)
        self._visible_last_page = Gtk.CheckButton(label=_("Last page"))
        self._visible_last_page.set_tooltip_text(
            _("Place the signature on the last page of the PDF.")
        )
        self._visible_last_page.connect("toggled", self._on_last_page_toggled)
        page_row.pack_start(self._visible_last_page, False, False, 0)
        vbox.pack_start(page_row, False, False, 0)

        # --- Position: pick a preset corner OR draw a custom rectangle on
        # the PDF. The two paths are alternatives: choosing a preset clears
        # any previously drawn box, and drawing a box marks the "preset"
        # combo as inactive (the position label shows what's currently in
        # effect).
        pos_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        pos_row.pack_start(Gtk.Label(label=_("Position:"), xalign=0), False, False, 0)
        self._sig_position = Gtk.ComboBoxText()
        for label, _enum in SIGNATURE_POSITIONS:
            self._sig_position.append_text(label)
        self._sig_position.set_active(0)
        self._sig_position.connect("changed", self._on_position_preset_changed)
        pos_row.pack_start(self._sig_position, True, True, 0)
        self._pick_box_button = Gtk.Button(label=_("🖱 Draw on PDF…"))
        self._pick_box_button.set_tooltip_text(
            _("Open a preview of the PDF and drag with the mouse to choose "
              "where the signature box will appear.")
        )
        self._pick_box_button.connect("clicked", self._on_pick_box_clicked)
        pos_row.pack_start(self._pick_box_button, False, False, 0)
        vbox.pack_start(pos_row, False, False, 0)

        # Status row showing which option is currently in effect.
        self._pick_box_status = Gtk.Label(xalign=0)
        self._pick_box_status.set_margin_start(24)
        vbox.pack_start(self._pick_box_status, False, False, 0)

        # Per-document custom box (None = use the preset combo).
        self._custom_box: tuple[float, float, float, float] | None = None
        self._custom_page: int | None = None
        # Flag to silence reset-on-preset-change while we're programmatically
        # syncing the combo (e.g. on settings reload).
        self._preset_syncing = False

        self._visible_revealer.add(vbox)
        self.pack_start(self._visible_revealer, False, False, 0)

        self.pack_start(Gtk.Label(label=_("Signature level:"), xalign=0),
                        False, False, 0)
        level_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                            margin_start=12)
        self._level_radios: list[tuple[SignatureLevel, Gtk.RadioButton]] = []
        first: Gtk.RadioButton | None = None
        for level, label in (
            (SignatureLevel.B,  _("B — without timestamp")),
            (SignatureLevel.T,  _("T — with timestamp")),
            (SignatureLevel.LT, _("LT — Long Term (embedded chain + revocation)")),
        ):
            r = Gtk.RadioButton.new_with_label_from_widget(first, label)
            if first is None:
                first = r
            r.connect("toggled", self._on_level_toggled)
            level_box.pack_start(r, False, False, 0)
            self._level_radios.append((level, r))
        self.pack_start(level_box, False, False, 0)

        self._tsa_hint = Gtk.Label(xalign=0, wrap=True)
        self._tsa_hint.set_margin_start(12)
        self.pack_start(self._tsa_hint, False, False, 0)

        self._sign_button = Gtk.Button(label=_("Sign"))
        self._sign_button.get_style_context().add_class("suggested-action")
        self._sign_button.connect("clicked", self._on_sign_clicked)
        self.pack_start(self._sign_button, False, False, 12)

        self._status = Gtk.Label(xalign=0, wrap=True)
        self.pack_start(self._status, False, False, 0)

        self.refresh_from_settings()

    def refresh_from_settings(self):
        """Re-read settings and update labels / button state."""
        self._current_settings = load_settings()
        s = self._current_settings
        if s.is_configured():
            self._device_label.set_markup(_("<b>Device:</b> {value}").format(value=s.describe()))
            self._sign_button.set_sensitive(True)
            self._secret.set_sensitive(True)
            self._secret_label.set_text(_("PIN:") if s.source == "pkcs11" else _("Password:"))
        else:
            self._device_label.set_markup(
                _("<span foreground='#c33'>No device configured — "
                  "go to the <b>Settings</b> tab.</span>")
            )
            self._sign_button.set_sensitive(False)
            self._secret.set_sensitive(False)

        # Refresh the signature-level hint (depends on TSA configuration).
        self._refresh_level_hint()

        # Sync the position preset combo to the last-saved default. The
        # combo signal would clear `_custom_box`, which we don't want when
        # we're just refreshing — guard with `_preset_syncing`.
        self._preset_syncing = True
        try:
            for i, (_label, enum_val) in enumerate(SIGNATURE_POSITIONS):
                if enum_val.value == s.signature_position:
                    self._sig_position.set_active(i)
                    break
            else:
                self._sig_position.set_active(0)
        finally:
            self._preset_syncing = False
        self._refresh_position_status()

    # ----- helpers -----

    def _add_entry_row(self, label: str) -> Gtk.Entry:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        row.pack_start(Gtk.Label(label=label, xalign=0), False, False, 0)
        entry = Gtk.Entry()
        row.pack_start(entry, True, True, 0)
        self.pack_start(row, False, False, 0)
        return entry

    def _selected_signature_level(self) -> SignatureLevel:
        """Return the SignatureLevel matching the currently active radio."""
        for level, radio in self._level_radios:
            if radio.get_active():
                return level
        return SignatureLevel.B  # safety fallback (always reached above)

    def _on_level_toggled(self, radio: Gtk.RadioButton):
        # GTK fires `toggled` on both the deactivated and the newly activated
        # radio; refresh only on the activation event to avoid double work.
        if radio.get_active():
            self._refresh_level_hint()

    def _refresh_level_hint(self):
        """Show whether the selected level is usable with the current TSA
        configuration. T and LT both require a TSA URL in Settings."""
        level = self._selected_signature_level()
        has_tsa = bool(self._current_settings.tsa_url)
        if level is SignatureLevel.B:
            self._tsa_hint.set_markup(
                _("<small>Basic signature, without timestamp.</small>")
            )
        elif level is SignatureLevel.T:
            if has_tsa:
                self._tsa_hint.set_markup(
                    _("<small>Timestamp via TSA: <tt>{url}</tt></small>").format(
                        url=self._current_settings.tsa_url)
                )
            else:
                self._tsa_hint.set_markup(
                    _("<small><span foreground='#c33'>No TSA configured — set one "
                      "in Settings to use level T.</span></small>")
                )
        elif level is SignatureLevel.LT:
            if has_tsa:
                self._tsa_hint.set_markup(
                    _("<small><b>LT</b>: signature + timestamp + embedded "
                      "certificate chain and OCSP responses. "
                      "TSA: <tt>{url}</tt>. "
                      "Requires a network connection at signing time "
                      "(AIA + OCSP fetch).</small>").format(
                        url=self._current_settings.tsa_url)
                )
            else:
                self._tsa_hint.set_markup(
                    _("<small><span foreground='#c33'>LT requires a TSA "
                      "configured in Settings.</span></small>")
                )

    def _on_doc_chosen(self, chooser: Gtk.FileChooserButton):
        path = chooser.get_filename()
        if not path:
            return
        doc_path = Path(path)
        self._sync_format_radios(doc_path)
        fmt = self._selected_signature_format()
        self._sign_output_name.set_text(_default_output_path(doc_path, fmt).name)
        self._sync_visible_sensitivity(fmt)
        # The custom box is tied to a specific document — discard on doc change
        # because page sizes / count may differ.
        self._reset_custom_box()

    def _sync_format_radios(self, doc_path: Path) -> None:
        """Enable/disable PAdES/XAdES based on the file extension and select
        the most natural default. CAdES is always available."""
        suffix = doc_path.suffix.lower()
        is_pdf = suffix == ".pdf"
        is_xml = suffix == ".xml"
        self._fmt_syncing = True
        try:
            self._fmt_pades.set_sensitive(is_pdf)
            self._fmt_xades.set_sensitive(is_xml)
            if is_pdf:
                self._fmt_pades.set_active(True)
            elif is_xml:
                self._fmt_xades.set_active(True)
            else:
                self._fmt_cades.set_active(True)
        finally:
            self._fmt_syncing = False

    def _selected_signature_format(self) -> str:
        if self._fmt_pades.get_active():
            return "PAdES"
        if self._fmt_xades.get_active():
            return "XAdES"
        return "CAdES"

    def _sync_visible_sensitivity(self, fmt: str) -> None:
        """The 'visible signature' checkbox is PAdES-only."""
        if fmt == "PAdES":
            self._visible_checkbox.set_sensitive(True)
        else:
            self._visible_checkbox.set_active(False)
            self._visible_checkbox.set_sensitive(False)
            self._visible_revealer.set_reveal_child(False)

    def _on_format_toggled(self, radio: Gtk.RadioButton):
        # Gtk fires `toggled` on both the radio losing activation and the
        # one gaining it. Only act when this is the new active button (and
        # not in the middle of a programmatic sync).
        if self._fmt_syncing or not radio.get_active():
            return
        fmt = self._selected_signature_format()
        self._sync_visible_sensitivity(fmt)
        # Refresh the suggested output name so it matches the new format
        # (e.g. PDF → CAdES turns `report-signed.pdf` into `report.pdf.p7m`).
        doc = self._doc_chooser.get_filename()
        if doc:
            self._sign_output_name.set_text(
                _default_output_path(Path(doc), fmt).name
            )

    def _on_visible_toggled(self, checkbox):
        self._visible_revealer.set_reveal_child(checkbox.get_active())
        if not checkbox.get_active():
            self._reset_custom_box()

    def _on_last_page_toggled(self, checkbox):
        self._visible_page.set_sensitive(not checkbox.get_active())
        # Page selector controls which page the custom box would target; if
        # the user changes it, the previous box no longer makes sense.
        self._reset_custom_box()

    def _on_pick_box_clicked(self, _button):
        doc = self._doc_chooser.get_filename()
        if not doc or self._selected_signature_format() != "PAdES":
            _show_error(self._parent, _("Select a PDF document first."))
            return
        from sigillum.gui.signature_picker import pick_signature_box

        initial_page = 0  # ignored: picker resolves last-page intent itself
        if self._visible_last_page.get_active():
            initial_page = -1  # signal: load last page when dialog opens
        else:
            initial_page = max(0, int(self._visible_page.get_value()) - 1)
        try:
            result = pick_signature_box(
                self._parent, doc,
                initial_page=initial_page if initial_page >= 0 else 0,
                initial_box=self._custom_box,
            )
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent, _("Could not open preview: {ex}").format(ex=ex))
            return
        if result is None:
            return
        self._custom_page, self._custom_box = result
        # Sync the page selector so what we'll sign matches what the user saw.
        self._visible_last_page.set_active(False)
        self._visible_page.set_value(self._custom_page + 1)
        self._refresh_position_status()

    def _on_position_preset_changed(self, _combo):
        # Triggered both by user clicks and by programmatic syncs. Skip the
        # reset in the latter case so loading settings doesn't wipe a fresh
        # custom box (in practice the two never coexist, but be defensive).
        if self._preset_syncing:
            return
        # The preset is the alternative path: discard any previously drawn box.
        self._custom_box = None
        self._custom_page = None
        self._refresh_position_status()

    def _refresh_position_status(self):
        """Show which of the two position paths is currently in effect."""
        if self._custom_box is not None:
            x1, y1, x2, y2 = self._custom_box
            w_mm = (x2 - x1) / 2.835
            h_mm = (y2 - y1) / 2.835
            page_num = (self._custom_page or 0) + 1
            self._pick_box_status.set_markup(
                _("<small><span foreground='#2a7'>✓ Custom position</span> — "
                  "page {page}, {w:.0f}×{h:.0f} mm</small>").format(
                    page=page_num, w=w_mm, h=h_mm)
            )
        else:
            idx = max(0, self._sig_position.get_active())
            label, _enum = SIGNATURE_POSITIONS[idx]
            self._pick_box_status.set_markup(
                _("<small>Preset position: <b>{label}</b></small>").format(label=label)
            )

    def _reset_custom_box(self):
        if self._custom_box is None and self._custom_page is None:
            return
        self._custom_box = None
        self._custom_page = None
        self._refresh_position_status()

    def _on_sign_clicked(self, _button):
        s = self._current_settings
        if not s.is_configured():
            _show_error(self._parent,
                        _("Configure a device in Settings first."))
            return

        doc = self._doc_chooser.get_filename()
        if not doc:
            _show_error(self._parent, _("Select a document to sign."))
            return
        secret = self._secret.get_text()
        if not secret:
            _show_error(self._parent,
                        _("Enter the PIN") if s.source == "pkcs11" else _("Enter the password"))
            return

        doc_path = Path(doc)
        fmt = self._selected_signature_format()
        out_name = self._sign_output_name.get_text().strip()
        if not out_name:
            _show_error(self._parent, _("Provide the output file name."))
            return
        out_path = doc_path.parent / out_name
        if out_path == doc_path:
            _show_error(self._parent,
                        _("The output file is the same as the source — change the name."))
            return
        level = self._selected_signature_level()
        # T and LT both need a TSA — refuse early with a clear message.
        if level is not SignatureLevel.B and not s.tsa_url:
            _show_error(self._parent,
                        _("Level {level} requires a TSA configured in Settings.").format(
                            level=level.value))
            return
        # The visible flag is only meaningful for PAdES; the CAdES signer ignores it.
        visible = self._visible_checkbox.get_active() and fmt == "PAdES"
        
        # Position preset comes from the SignView combo; the custom box (if
        # any) overrides both the preset and the page selector.
        pos_idx = max(0, self._sig_position.get_active())
        _label, position_enum = SIGNATURE_POSITIONS[pos_idx]
        signature_page = int(self._visible_page.get_value()) - 1
        if self._visible_last_page.get_active():
            signature_page = -1
        custom_box = self._custom_box if visible else None
        if visible and self._custom_page is not None:
            signature_page = self._custom_page

        use_tsa = level is not SignatureLevel.B
        options = SignOptions(
            level=level,
            tsa_url=s.tsa_url if use_tsa else None,
            tsa_username=s.tsa_username if use_tsa else None,
            tsa_password=s.tsa_password if use_tsa else None,
            reason=self._reason.get_text().strip() or None,
            visible=visible,
            signature_page=signature_page if visible else 0,
            signature_position=position_enum,
            signature_box=custom_box,
            signature_image=s.signature_image if visible else None,
        )

        provider = None
        try:
            if s.source == "file":
                provider = FileProvider(s.file_path)
                credential = provider.unlock(s.file_path, secret)
            else:
                provider = PKCS11Provider(s.pkcs11_library)
                credential = provider.unlock(s.pkcs11_cert_id, secret)
            _build_signer(fmt).sign(doc_path, out_path, credential, options)
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent, _("Signing failed: {ex}").format(ex=ex))
            return
        finally:
            if provider is not None:
                provider.close()

        self._status.set_markup(
            _("<span foreground='#2a7'>✓ Signed</span>: {path}").format(path=out_path)
        )
        # Clear secret so it isn't reused unintentionally.
        self._secret.set_text("")


# =====================================================================
#  MarkView — standalone time-stamping (TSR / TSD)
# =====================================================================

class MarkView(Gtk.Box):
    """Apply an RFC 3161 timestamp to a file, output as .tsr or .tsd.

    Uses the TSA configured in Impostazioni (URL + optional HTTP Basic auth).
    The actual TSA call runs in a background thread so the GUI stays
    responsive while the request travels.
    """

    def __init__(self, parent_window: Gtk.Window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=18)
        self._parent = parent_window

        self.pack_start(
            Gtk.Label(label=_("File to timestamp:"), xalign=0),
            False, False, 0,
        )
        self._file_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        self.pack_start(self._file_chooser, False, False, 0)

        self.pack_start(Gtk.Separator(), False, False, 6)

        # Format radios with explanatory tooltips.
        fmt_title = Gtk.Label(xalign=0)
        fmt_title.set_markup(_("<b>Format</b>"))
        self.pack_start(fmt_title, False, False, 0)
        self._radio_tsr = Gtk.RadioButton.new_with_label_from_widget(
            None, _("TSR — evidence only (requires the original file to verify)"),
        )
        self._radio_tsr.set_tooltip_text(
            _("Saves only the TSA response (DER TimeStampToken). "
              "Contains the file hash but not the file. Verification "
              "needs the original file separately.")
        )
        self._radio_tsd = Gtk.RadioButton.new_with_label_from_widget(
            self._radio_tsr,
            _("TSD — self-contained envelope (evidence + embedded file)"),
        )
        self._radio_tsd.set_tooltip_text(
            _("ETSI TS 119 422 envelope: contains both the timestamp and "
              "the original file. Verifiable on its own, without separate files.")
        )
        self._radio_tsr.set_active(True)
        self.pack_start(self._radio_tsr, False, False, 0)
        self.pack_start(self._radio_tsd, False, False, 0)

        self.pack_start(Gtk.Separator(), False, False, 6)

        # Read-only TSA summary fed from settings.
        self._tsa_label = Gtk.Label(xalign=0, wrap=True)
        self.pack_start(self._tsa_label, False, False, 0)

        self._mark_button = Gtk.Button(label=_("Timestamp"))
        self._mark_button.get_style_context().add_class("suggested-action")
        self._mark_button.connect("clicked", self._on_mark_clicked)
        self.pack_start(self._mark_button, False, False, 12)

        self._status = Gtk.Label(xalign=0, wrap=True)
        self.pack_start(self._status, False, False, 0)

        self.refresh_from_settings()

    # ----- public API used by the window coordinator -----

    def refresh_from_settings(self):
        """Update the TSA label + enable/disable the Marca button."""
        s = load_settings()
        if s.tsa_url:
            auth = _(" (with credentials)") if s.tsa_username and s.tsa_password else ""
            self._tsa_label.set_markup(
                _("<small><b>TSA configured:</b> {url}{auth}</small>").format(
                    url=s.tsa_url, auth=auth)
            )
            self._mark_button.set_sensitive(True)
        else:
            self._tsa_label.set_markup(
                _("<small><span foreground='#c33'>No TSA configured — "
                  "set a URL in Settings → Timestamp.</span></small>")
            )
            self._mark_button.set_sensitive(False)

    # ----- handlers -----

    def _on_mark_clicked(self, _button):
        s = load_settings()
        if not s.tsa_url:
            _show_error(self._parent,
                        _("Set a TSA in Settings before timestamping."))
            return
        src_path = self._file_chooser.get_filename()
        if not src_path:
            _show_error(self._parent, _("Select a file to timestamp first."))
            return
        src = Path(src_path)
        as_tsd = self._radio_tsd.get_active()
        output = src.with_name(src.name + (".tsd" if as_tsd else ".tsr"))

        # Block re-entry while the network round-trip is happening.
        self._mark_button.set_sensitive(False)
        self._status.set_markup(_("<i>Sending request to the TSA…</i>"))

        tsa_cfg = TSAConfig(
            url=s.tsa_url,
            username=s.tsa_username or None,
            password=s.tsa_password or None,
        )

        import threading

        def worker():
            try:
                if as_tsd:
                    make_tsd(src, output, tsa_cfg)
                else:
                    make_tsr(src, output, tsa_cfg)
                ok, msg = True, str(output)
            except Exception as ex:  # noqa: BLE001
                ok, msg = False, str(ex)
            GLib.idle_add(self._on_mark_done, ok, msg)

        threading.Thread(target=worker, daemon=True, name="tsa-mark").start()

    def _on_mark_done(self, ok: bool, message: str) -> bool:
        self._mark_button.set_sensitive(True)
        if ok:
            self._status.set_markup(
                _("<span foreground='#2a7'>✓ Timestamp saved</span>: {msg}").format(msg=message)
            )
        else:
            self._status.set_text("")
            _show_error(self._parent, _("Timestamping failed: {msg}").format(msg=message))
        return False  # don't repeat


# =====================================================================
#  CryptView — encryption and decryption (symmetric password + asymmetric cert)
# =====================================================================

class CryptView(Gtk.Box):
    """Encrypt/decrypt one or more files in four modes:

      1. Symmetric with password (AES-256-CBC + PKCS#7 + PBKDF2)
      2. Symmetric with selectable algorithm (AES-128/256, 3DES, Blowfish)
      3. Asymmetric to the cert configured in Settings
      4. Asymmetric to a cert from a PKCS#12 file

    Decryption: auto-detect the format from the file content.
    """

    def __init__(self, parent_window: Gtk.Window, mode: str = "encrypt"):
        """`mode` is "encrypt" or "decrypt" — set once and never toggled.

        The two directions live in separate tabs so the layout is determined
        at construction; no in-view toggle, no branching of mutable state.
        """
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=18)
        self._parent = parent_window
        if mode not in ("encrypt", "decrypt"):
            raise ValueError(f"mode invalido: {mode!r}")
        self._mode = mode

        # --- File chooser: single file for both modes. Encrypt adds an
        # editable output filename pre-populated when the source is chosen.
        if self._is_encrypt():
            self.pack_start(Gtk.Label(label=_("File to encrypt:"), xalign=0),
                            False, False, 0)
            self._enc_file_chooser = Gtk.FileChooserButton(
                action=Gtk.FileChooserAction.OPEN,
            )
            self._enc_file_chooser.connect("file-set", self._on_enc_file_chosen)
            self.pack_start(self._enc_file_chooser, False, False, 0)

            out_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            out_row.pack_start(
                Gtk.Label(label=_("Output file name:"), xalign=0),
                False, False, 0,
            )
            self._enc_output_name = Gtk.Entry()
            self._enc_output_name.set_placeholder_text(
                _("<will be filled in when you choose a file>")
            )
            out_row.pack_start(self._enc_output_name, True, True, 0)
            self.pack_start(out_row, False, False, 0)
        else:
            # Decrypt: single-file picker.
            self.pack_start(Gtk.Label(label=_("Encrypted file:"), xalign=0),
                            False, False, 0)
            self._dec_file_chooser = Gtk.FileChooserButton(
                action=Gtk.FileChooserAction.OPEN,
            )
            enc_filter = Gtk.FileFilter()
            enc_filter.set_name(_("Encrypted files"))
            for pat in ("*.enc", "*.p7e", "*.p7m"):
                enc_filter.add_pattern(pat)
            self._dec_file_chooser.add_filter(enc_filter)
            any_filter = Gtk.FileFilter()
            any_filter.set_name(_("All files"))
            any_filter.add_pattern("*")
            self._dec_file_chooser.add_filter(any_filter)
            # Detect the encryption format on selection and switch the mode
            # radio accordingly: this way the PIN / password field becomes
            # visible without the user having to know which kind of file it is.
            self._dec_file_chooser.connect("file-set", self._on_dec_file_chosen)
            self.pack_start(self._dec_file_chooser, False, False, 0)

        self.pack_start(Gtk.Separator(), False, False, 6)

        if self._is_encrypt():
            self._build_encrypt_options()
        else:
            self._build_decrypt_options()

        # --- Action button + status ---
        self._action_btn = Gtk.Button(label=_("Encrypt"))
        self._action_btn.get_style_context().add_class("suggested-action")
        self._action_btn.connect("clicked", self._on_action_clicked)
        self.pack_start(self._action_btn, False, False, 12)

        self._status = Gtk.Label(xalign=0, wrap=True)
        self._status.set_line_wrap(True)
        self.pack_start(self._status, False, False, 0)

        self._refresh_layout()

    # ----- mode-specific layout builders -----

    def _build_encrypt_options(self):
        """Encrypt mode: type radios + sym options + asym device hint."""
        mode_title = Gtk.Label(xalign=0)
        mode_title.set_markup(_("<b>Type</b>"))
        self.pack_start(mode_title, False, False, 0)

        self._radio_sym = Gtk.RadioButton.new_with_label_from_widget(
            None, _("Symmetric with password"),
        )
        self._radio_asym_device = Gtk.RadioButton.new_with_label_from_widget(
            self._radio_sym,
            _("Asymmetric with the device configured in Settings"),
        )
        for r in (self._radio_sym, self._radio_asym_device):
            r.connect("toggled", self._on_mode_changed)
            self.pack_start(r, False, False, 0)

        opts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                       margin_start=24)

        # Symmetric: algorithm combo + password
        sym_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        sym_row.pack_start(Gtk.Label(label=_("Algorithm:"), xalign=0), False, False, 0)
        self._sym_algo = Gtk.ComboBoxText()
        for name in SYMMETRIC_NAMES:
            self._sym_algo.append_text(name)
        self._sym_algo.set_active(0)
        sym_row.pack_start(self._sym_algo, False, False, 0)
        sym_row.pack_start(Gtk.Label(label=_("  Password:"), xalign=0), False, False, 0)
        self._sym_password = _make_password_entry(_toggle_password_visibility)
        sym_row.pack_start(self._sym_password, True, True, 0)
        opts.pack_start(sym_row, False, False, 0)

        # Asymmetric (device): just a hint label.
        self._asym_dev_hint = Gtk.Label(xalign=0, wrap=True)
        opts.pack_start(self._asym_dev_hint, False, False, 0)

        self.pack_start(opts, False, False, 0)
        self._sym_row = sym_row

    def _build_decrypt_options(self):
        """Decrypt mode: a single secret field whose label tracks the
        format auto-detected from the selected file. No type radios — the
        file content tells us everything we need.
        """
        # Cached detection result; set by _on_dec_file_chosen.
        self._dec_format = None  # "symmetric" | "asymmetric" | "unknown" | None

        # Format hint shown below the file chooser.
        self._dec_format_hint = Gtk.Label(xalign=0, wrap=True)
        self._dec_format_hint.set_markup(
            _("<small><i>Choose a file to detect the format.</i></small>")
        )
        self.pack_start(self._dec_format_hint, False, False, 0)

        # Single secret field — label adapts to detected format.
        secret_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._dec_secret_label = Gtk.Label(label=_(_("Password / PIN:")), xalign=0)
        secret_row.pack_start(self._dec_secret_label, False, False, 0)
        self._dec_secret = _make_password_entry(_toggle_password_visibility)
        secret_row.pack_start(self._dec_secret, True, True, 0)
        self.pack_start(secret_row, False, False, 0)

    # ----- public API -----

    def refresh_from_settings(self):
        """Re-read settings (called on tab switch) so the device-cert hint
        reflects the configured cert."""
        self._refresh_layout()

    # ----- internal helpers -----

    def _is_encrypt(self) -> bool:
        return self._mode == "encrypt"

    def _selected_file(self) -> Path | None:
        chooser = self._enc_file_chooser if self._is_encrypt() else self._dec_file_chooser
        p = chooser.get_filename()
        return Path(p) if p else None

    def _default_ext(self) -> str:
        return ".enc" if self._radio_sym.get_active() else ".p7e"

    def _suggested_output_name(self) -> str:
        src = self._selected_file()
        if src is None:
            return ""
        return src.name + self._default_ext()

    def _on_enc_file_chosen(self, _chooser):
        # Auto-populate the output filename; user can edit afterwards.
        self._enc_output_name.set_text(self._suggested_output_name())

    def _on_dec_file_chosen(self, chooser):
        """Detect the format from the file and update label/hint to match."""
        p = chooser.get_filename()
        if not p:
            self._dec_format = None
        else:
            try:
                blob = Path(p).read_bytes()
                self._dec_format = detect_encryption_format(blob)
            except OSError:
                self._dec_format = None
        self._refresh_decrypt_layout(load_settings())

    def _on_mode_changed(self, _radio):
        # If the user hasn't customised the output filename (it still matches
        # either default), refresh its extension when the cipher changes.
        if self._is_encrypt():
            src = self._selected_file()
            if src is not None:
                cur = self._enc_output_name.get_text().strip()
                defaults = {src.name + ".enc", src.name + ".p7e"}
                if not cur or cur in defaults:
                    self._enc_output_name.set_text(self._suggested_output_name())
        self._refresh_layout()

    def _refresh_layout(self):
        s = load_settings()
        if self._is_encrypt():
            self._action_btn.set_label(_("Encrypt"))
            self._refresh_encrypt_layout(s)
        else:
            self._action_btn.set_label(_("Decrypt"))
            self._refresh_decrypt_layout(s)

    def _refresh_encrypt_layout(self, s: Settings):
        configured = s.is_configured()
        self._radio_asym_device.set_sensitive(configured)
        if not configured and self._radio_asym_device.get_active():
            self._radio_sym.set_active(True)

        is_sym = self._radio_sym.get_active()
        is_asym_dev = self._radio_asym_device.get_active()

        self._sym_row.set_no_show_all(not is_sym)
        self._sym_row.set_visible(is_sym)

        if is_asym_dev:
            self._asym_dev_hint.set_no_show_all(False)
            self._asym_dev_hint.set_visible(True)
            if not configured:
                self._asym_dev_hint.set_markup(
                    _("<small><span foreground='#c33'>No device "
                      "configured.</span></small>")
                )
            else:
                self._asym_dev_hint.set_markup(
                    _("<small>Will encrypt to: <b>{value}</b></small>").format(value=s.describe())
                )
        else:
            self._asym_dev_hint.set_visible(False)
            self._asym_dev_hint.set_no_show_all(True)

    def _refresh_decrypt_layout(self, s: Settings):
        """Update the secret-field label and the format hint based on the
        format cached by `_on_dec_file_chosen`. Called at startup and on
        each tab switch (settings changes don't otherwise matter here).
        """
        if self._dec_format is None:
            self._dec_format_hint.set_markup(
                _("<small><i>Choose a file to detect the format.</i></small>")
            )
            self._dec_secret_label.set_text(_("Password / PIN:"))
            return
        if self._dec_format == "symmetric":
            self._dec_format_hint.set_markup(
                _("<small>Detected format: "
                  "<b>symmetric encryption with password</b></small>")
            )
            self._dec_secret_label.set_text(_("Password:"))
        elif self._dec_format == "asymmetric":
            who = s.describe() if s.is_configured() else _("<i>(no device)</i>")
            self._dec_format_hint.set_markup(
                _("<small>Detected format: <b>asymmetric encryption</b> "
                  "(will decrypt with {who})</small>").format(who=who)
            )
            label = _("Token PIN:") if s.source == "pkcs11" else _("Certificate password:")
            self._dec_secret_label.set_text(label)
        else:
            self._dec_format_hint.set_markup(
                _("<small><span foreground='#c33'>Unrecognized format</span></small>")
            )
            self._dec_secret_label.set_text(_("Password / PIN:"))

    # ----- action -----

    def _on_action_clicked(self, _btn):
        src = self._selected_file()
        if src is None:
            _show_error(self._parent, _("Select a file."))
            return
        if self._is_encrypt():
            self._encrypt_file(src)
        else:
            self._decrypt_files([src])

    # ----- encrypt path -----

    def _encrypt_file(self, src: Path):
        out_name = self._enc_output_name.get_text().strip()
        if not out_name:
            _show_error(self._parent, _("Provide the output file name."))
            return
        out = src.with_name(out_name)
        if out.resolve() == src.resolve():
            _show_error(self._parent,
                        _("The output file is the same as the source — change the name."))
            return

        try:
            if self._radio_sym.get_active():
                password = self._sym_password.get_text()
                if not password:
                    _show_error(self._parent, _("Enter a password."))
                    return
                algo = self._sym_algo.get_active_text() or "AES-256"
                out.write_bytes(encrypt_symmetric(
                    src.read_bytes(), password, algorithm=algo,
                ))
            else:
                recipient_cert = self._resolve_recipient_cert()
                if recipient_cert is None:
                    return
                out.write_bytes(encrypt_asymmetric(
                    src.read_bytes(), recipient_cert,
                ))
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent, _("Encryption failed: {ex}").format(ex=ex))
            return

        self._status.set_markup(
            _("<span foreground='#2a7'>✓ Encrypted</span>: {path}").format(path=out)
        )

    def _resolve_recipient_cert(self):
        """Return the x509.Certificate to encrypt to (from Settings), or None.

        For a token the cert is a public PKCS#11 object readable without PIN;
        for a file-based credential we need the PKCS#12 password (asked inline).
        """
        s = load_settings()
        if not s.is_configured():
            _show_error(self._parent,
                        _("Configure a device in Settings first."))
            return None
        try:
            if s.source == "pkcs11":
                import PyKCS11
                from cryptography import x509 as _x
                provider = PKCS11Provider(s.pkcs11_library)
                lib = provider._lib()  # noqa: SLF001
                slot = provider._resolve_slot()  # noqa: SLF001
                session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
                try:
                    key_id_bytes, target_serial = PKCS11Provider._parse_id(  # noqa: SLF001
                        s.pkcs11_cert_id,
                    )
                    objs = session.findObjects([
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                        (PyKCS11.CKA_ID, key_id_bytes),
                    ])
                    for obj in objs:
                        der = bytes(session.getAttributeValue(
                            obj, [PyKCS11.CKA_VALUE])[0])
                        cand = _x.load_der_x509_certificate(der)
                        if cand.serial_number == target_serial:
                            return cand
                finally:
                    session.closeSession()
                _show_error(self._parent, _("Certificate not found on the token."))
                return None
            # file-based PKCS#12: need the password to extract the cert
            pwd = _ask_password(self._parent, _("Certificate password"))
            if pwd is None:
                return None
            cred = FileProvider(s.file_path).unlock(s.file_path, pwd)
            return cred.certificate
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent,
                        _("Could not read the certificate: {ex}").format(ex=ex))
            return None

    # ----- decrypt path -----

    def _decrypt_files(self, files: list[Path]):
        # The decrypt UI is single-file by construction, so len(files) == 1.
        src = files[0]
        blob = src.read_bytes()
        # Re-detect from the bytes (in case the file changed since the
        # chooser fired its signal) and update the cache.
        fmt = detect_encryption_format(blob)
        self._dec_format = fmt
        if fmt == "unknown":
            _show_error(self._parent,
                        _("Unrecognized format (neither SIGILLUM nor CMS EnvelopedData)."))
            return

        secret = self._dec_secret.get_text()
        if not secret:
            _show_error(self._parent, _("Enter the password or PIN."))
            return

        # Strip the encryption suffix so the decrypted file recovers the
        # original name (`doc.pdf.enc` → `doc.pdf`). For inputs without a
        # recognised suffix we fall back to a `_decifrato` infix to avoid
        # overwriting the source.
        if src.suffix.lower() in (".enc", ".p7e", ".p7m"):
            out = src.with_name(src.stem)
        else:
            out = src.with_name(f"{src.stem}_decrypted{src.suffix}")

        if fmt == "symmetric":
            try:
                out.write_bytes(decrypt_symmetric(blob, secret))
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Decryption failed: {ex}").format(ex=ex))
                return
        else:  # asymmetric
            cred, provider = self._open_device_credential(secret)
            if cred is None:
                return
            try:
                out.write_bytes(decrypt_asymmetric(blob, cred))
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Decryption failed: {ex}").format(ex=ex))
                return
            finally:
                if provider is not None:
                    provider.close()

        self._status.set_markup(
            _("<span foreground='#2a7'>✓ Decrypted</span>: {path}").format(path=out)
        )

    def _open_device_credential(self, secret: str):
        """Open the configured device (PKCS#11 or PKCS#12) for decryption.

        Returns (SigningCredential, provider) — the provider is returned so
        the caller can close() it after use (for PKCS#11 sessions).
        Returns (None, None) on validation error.
        """
        s = load_settings()
        if not s.is_configured():
            _show_error(self._parent, _("No device configured."))
            return None, None
        try:
            if s.source == "pkcs11":
                provider = PKCS11Provider(s.pkcs11_library)
                cred = provider.unlock(s.pkcs11_cert_id, secret)
            else:
                provider = FileProvider(s.file_path)
                cred = provider.unlock(s.file_path, secret)
            return cred, provider
        except Exception as ex:  # noqa: BLE001
            _show_error(self._parent, _("Opening credential failed: {ex}").format(ex=ex))
            return None, None


def _ask_password(parent: Gtk.Window, prompt: str) -> str | None:
    """Tiny one-shot password dialog. Returns None if the user cancels."""
    dlg = Gtk.Dialog(title=prompt, transient_for=parent, modal=True)
    dlg.add_buttons(_("Cancel"), Gtk.ResponseType.CANCEL,
                    "OK", Gtk.ResponseType.OK)
    dlg.set_default_size(360, -1)
    entry = _make_password_entry(_toggle_password_visibility)
    entry.set_activates_default(True)
    box = dlg.get_content_area()
    box.set_spacing(6)
    box.set_margin_start(12)
    box.set_margin_end(12)
    box.set_margin_top(12)
    box.set_margin_bottom(12)
    box.pack_start(Gtk.Label(label=prompt, xalign=0), False, False, 0)
    box.pack_start(entry, False, False, 0)
    dlg.show_all()
    try:
        if dlg.run() != Gtk.ResponseType.OK:
            return None
        return entry.get_text()
    finally:
        dlg.destroy()


# =====================================================================
#  VerifyView — handles signed documents AND TSR/TSD files
# =====================================================================

class VerifyView(Gtk.Box):
    def __init__(self, parent_window: Gtk.Window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=18)
        self._parent = parent_window

        self.pack_start(
            Gtk.Label(label=_("Signed or timestamped file (.pdf, .p7m, .xml, .tsr, .tsd):"),
                      xalign=0),
            False, False, 0,
        )
        self._file_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        self._file_chooser.connect("file-set", self._on_verify_file_chosen)
        self.pack_start(self._file_chooser, False, False, 0)

        # For .tsr verification we also need the original file (the marca
        # temporale only contains its hash). We wrap the row in a Revealer
        # so it's properly initialised by show_all() and can be toggled
        # later with set_reveal_child().
        self._orig_revealer = Gtk.Revealer()
        self._orig_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        self._orig_revealer.set_reveal_child(False)
        orig_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        orig_box.pack_start(
            Gtk.Label(label=_("Original file (for TSR):"), xalign=0),
            False, False, 0,
        )
        self._orig_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        orig_box.pack_start(self._orig_chooser, True, True, 0)
        self._orig_revealer.add(orig_box)
        self.pack_start(self._orig_revealer, False, False, 0)

        # Always-visible TSL summary so the user knows what trust store is
        # active without opening the advanced section. When the TSL is missing
        # or stale, a small "Importa ora" button appears next to the status
        # for a one-click fix.
        tsl_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._tsl_status = Gtk.Label(xalign=0, wrap=True)
        tsl_row.pack_start(self._tsl_status, True, True, 0)
        self._tsl_import_now = Gtk.Button(label=_("Import now"))
        self._tsl_import_now.set_no_show_all(True)
        self._tsl_import_now.connect(
            "clicked", lambda _b: self._parent.start_tsl_refresh(silent=False),
        )
        tsl_row.pack_start(self._tsl_import_now, False, False, 0)
        self.pack_start(tsl_row, False, False, 4)

        # --- Advanced options (collapsed by default) ---
        expander = Gtk.Expander(label=_("Advanced options"))
        adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                      margin_top=6, margin_start=12)

        adv.pack_start(
            Gtk.Label(label=_("Additional trusted CA (.pem):"), xalign=0),
            False, False, 0,
        )
        self._ca_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        adv.pack_start(self._ca_chooser, False, False, 0)

        adv.pack_start(
            Gtk.Label(label=_("TSA CA (.pem):"), xalign=0),
            False, False, 0,
        )
        self._tsa_ca_chooser = Gtk.FileChooserButton(action=Gtk.FileChooserAction.OPEN)
        adv.pack_start(self._tsa_ca_chooser, False, False, 0)

        self._use_tsl_check = Gtk.CheckButton(
            label=_("Use the imported AgID TSL")
        )
        adv.pack_start(self._use_tsl_check, False, False, 6)

        expander.add(adv)
        self.pack_start(expander, False, False, 4)

        # Initialize TSL state — uses both the inline status and the checkbox.
        self.refresh_tsl_status()

        self._verify_button = Gtk.Button(label=_("Verify"))
        self._verify_button.get_style_context().add_class("suggested-action")
        self._verify_button.connect("clicked", self._on_verify_clicked)
        self.pack_start(self._verify_button, False, False, 12)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._results_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroll.add(self._results_box)
        self.pack_start(scroll, True, True, 0)

    def refresh_tsl_status(self):
        """Update the inline status row + the checkbox state in advanced options.

        The default behavior is to use the imported TSL bundles automatically;
        the checkbox in the expander only needs to be touched to opt out.
        """
        s = load_settings()
        primary = s.effective_country()
        signing_exists = signing_pem_path(primary).exists()
        tsa_exists = tsa_pem_path(primary).exists()
        days = import_age_days(s.last_import_for(primary))

        # Stale or missing → show the inline "Importa ora" button.
        stale = (days is None) or (days > TSL_STALE_AFTER_DAYS)
        if not (signing_exists or tsa_exists):
            self._use_tsl_check.set_active(False)
            self._use_tsl_check.set_sensitive(False)
            self._tsl_status.set_markup(
                _("<small>Trust store: <span foreground='#c33'>"
                  "{cc} TSL not imported.</span></small>").format(cc=primary)
            )
            self._tsl_import_now.set_visible(True)
            return

        self._use_tsl_check.set_sensitive(True)
        # Default: TSL on. The user can still uncheck in Opzioni aggiuntive.
        if not self._use_tsl_check.get_active():
            self._use_tsl_check.set_active(True)

        active_cc = ", ".join(s.active_countries())
        if days is None:
            self._tsl_status.set_markup(
                _("<small>Trust store: {cc} TSL (import date unknown).</small>").format(cc=active_cc)
            )
        elif days <= TSL_STALE_AFTER_DAYS:
            self._tsl_status.set_markup(
                _("<small>Trust store: {cc} TSL, primary imported {days} days ago.</small>").format(
                    cc=active_cc, days=days)
            )
        else:
            self._tsl_status.set_markup(
                _("<small>Trust store: <span foreground='#c33'>"
                  "{cc} TSL from {days} days ago — refresh it.</span></small>").format(
                    cc=active_cc, days=days)
            )
        self._tsl_import_now.set_visible(stale)

    def set_tsl_busy(self, busy: bool):
        """Called by the window coordinator during a TSL refresh."""
        if busy:
            self._tsl_status.set_markup(
                _("<small><i>Refreshing AgID TSL…</i></small>")
            )
            self._tsl_import_now.set_sensitive(False)
        else:
            self._tsl_import_now.set_sensitive(True)
            # Status text will be reset by the next refresh_tsl_status call.

    def _clear_results(self):
        for child in self._results_box.get_children():
            self._results_box.remove(child)

    def _on_verify_file_chosen(self, chooser: Gtk.FileChooserButton):
        """Reveal the 'file originale' picker only for .tsr files."""
        p = chooser.get_filename()
        is_tsr = bool(p) and _detect_format(Path(p)) == "TSR"
        self._orig_revealer.set_reveal_child(is_tsr)
        if not is_tsr:
            self._orig_chooser.unselect_all()

    def _on_verify_clicked(self, _button):
        path = self._file_chooser.get_filename()
        if not path:
            return
        path = Path(path)
        fmt = _detect_format(path)

        from cryptography.x509 import load_pem_x509_certificates

        def _load_pem_certs(p: str | None, what: str):
            if not p:
                return []
            try:
                return load_pem_x509_certificates(Path(p).read_bytes())
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Could not read {what}: {ex}").format(what=what, ex=ex))
                return None

        trusted = _load_pem_certs(self._ca_chooser.get_filename(), _("the CA"))
        if trusted is None:
            return
        tsa_trusted = _load_pem_certs(self._tsa_ca_chooser.get_filename(), _("the TSA CA"))
        if tsa_trusted is None:
            return

        # Augment with the imported national TSL bundles if requested —
        # union across every country in Settings.active_countries().
        if self._use_tsl_check.get_active():
            from sigillum.core.tsl import load_active_trust_stores
            tsl_signing, tsl_tsa = load_active_trust_stores(
                load_settings().active_countries()
            )
            trusted = trusted + tsl_signing
            tsa_trusted = tsa_trusted + tsl_tsa

        # TSR / TSD don't go through the Signer/Verifier abstraction (they
        # aren't document signatures, just timestamps). Use the dedicated
        # functions in core.timestamp.
        if fmt == "TSR":
            orig = self._orig_chooser.get_filename()
            if not orig:
                _show_error(self._parent,
                            _("Verifying a .tsr file requires the original file."))
                return
            try:
                result = verify_tsr(path, Path(orig), tsa_trusted_certs=tsa_trusted)
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Verification failed: {ex}").format(ex=ex))
                return
        elif fmt == "TSD":
            try:
                result = verify_tsd(path, tsa_trusted_certs=tsa_trusted)
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Verification failed: {ex}").format(ex=ex))
                return
        else:
            try:
                result = _build_verifier(fmt, trusted, tsa_trusted).verify(path)
            except Exception as ex:  # noqa: BLE001
                _show_error(self._parent, _("Verification failed: {ex}").format(ex=ex))
                return

        self._clear_results()
        if not result.signers:
            self._results_box.pack_start(
                Gtk.Label(label=_("No signature found."), xalign=0),
                False, False, 0,
            )
        for i, signer in enumerate(result.signers, 1):
            self._results_box.pack_start(self._render_signer(i, signer), False, False, 0)
        self._results_box.show_all()

    def _render_signer(self, index: int, info) -> Gtk.Widget:
        frame = Gtk.Frame()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin=8)
        frame.add(box)

        def _wrap_label(*, text: str | None = None, markup: str | None = None) -> Gtk.Label:
            """Left-aligned label that wraps long content (DNs, errors, ...)."""
            lbl = Gtk.Label(xalign=0)
            lbl.set_line_wrap(True)
            lbl.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
            # Selectable so the user can copy long DNs / serial numbers.
            lbl.set_selectable(True)
            if markup is not None:
                lbl.set_markup(markup)
            elif text is not None:
                lbl.set_text(text)
            return lbl

        color = "#2a7" if info.valid else "#c33"
        symbol = "✓" if info.valid else "✗"
        # Standalone timestamp results have no signer subject — show them as
        # _("Timestamp") instead of "Firma N" so the user isn't confused
        # by an empty signer name.
        kind = _("Timestamp") if not info.subject and info.timestamp else _("Signature {n}").format(n=index)
        box.pack_start(
            _wrap_label(markup=f"<b><span foreground='{color}'>{symbol} {kind}</span></b>"),
            False, False, 0,
        )

        if info.subject:
            box.pack_start(_wrap_label(text=_("Signer: {value}").format(value=info.subject)),
                           False, False, 0)
        if info.issuer:
            box.pack_start(_wrap_label(text=_("Issuer: {value}").format(value=info.issuer)),
                           False, False, 0)

        flags = _("hash {hash}    signature {sig}    certificate {chain}").format(
            hash=_("OK") if info.hash_valid else _("KO"),
            sig=_("OK") if info.signature_valid else _("KO"),
            chain=_("trusted") if info.cert_trusted else _("untrusted"),
        )
        box.pack_start(_wrap_label(text=flags), False, False, 0)

        if info.timestamp is not None:
            box.pack_start(Gtk.Separator(), False, False, 4)
            box.pack_start(
                _wrap_label(text=_("Timestamp: {when}").format(when=info.timestamp.isoformat())),
                False, False, 0,
            )
            if info.tsa_subject:
                box.pack_start(_wrap_label(text=_("TSA: {value}").format(value=info.tsa_subject)),
                               False, False, 0)
            tsa_color = "#2a7" if info.timestamp_trusted else "#c33"
            tsa_text = _("trusted TSA") if info.timestamp_trusted else _("untrusted TSA")
            box.pack_start(
                _wrap_label(markup=f"<span foreground='{tsa_color}'>{tsa_text}</span>"),
                False, False, 0,
            )

        for err in info.errors:
            box.pack_start(
                _wrap_label(markup=f"<span foreground='#c33'>{err}</span>"),
                False, False, 0,
            )

        return frame


# =====================================================================
#  Window + Application
# =====================================================================

class _IconLabelStackSwitcher(Gtk.Box):
    """Tab switcher that shows icon + label for each Stack child.

    Gtk.StackSwitcher (GTK 3) collapses to icon-only when ``icon-name`` is
    set on the child. We need both, so build a row of linked toggle buttons
    ourselves and keep them in lock-step with the underlying Stack.
    """

    def __init__(self, stack: Gtk.Stack, tabs: list[tuple[Gtk.Widget, str, str, str]]):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.get_style_context().add_class("linked")
        self._stack = stack
        self._buttons: dict[str, Gtk.RadioButton] = {}
        self._syncing = False

        first: Gtk.RadioButton | None = None
        for _view, name, title, icon_name in tabs:
            btn = Gtk.RadioButton.new_from_widget(first)
            btn.set_mode(False)  # render as a toggle button, not a radio dot
            if first is None:
                first = btn
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            row.pack_start(
                Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.BUTTON),
                False, False, 0,
            )
            row.pack_start(Gtk.Label(label=title), False, False, 0)
            btn.add(row)
            btn.connect("toggled", self._on_button_toggled, name)
            self._buttons[name] = btn
            self.pack_start(btn, False, False, 0)

        # Keep the buttons in sync if the Stack is switched programmatically.
        stack.connect("notify::visible-child", self._on_stack_changed)
        current = stack.get_visible_child_name()
        if current in self._buttons:
            self._buttons[current].set_active(True)

    def _on_button_toggled(self, btn: Gtk.RadioButton, name: str):
        # GTK fires `toggled` on both the deactivated and the newly active
        # radio; act only on the activation event.
        if self._syncing or not btn.get_active():
            return
        if self._stack.get_visible_child_name() != name:
            self._stack.set_visible_child_name(name)

    def _on_stack_changed(self, stack: Gtk.Stack, _pspec):
        name = stack.get_visible_child_name()
        btn = self._buttons.get(name)
        if btn is None or btn.get_active():
            return
        # Guard against the button's `toggled` handler firing us back.
        self._syncing = True
        try:
            btn.set_active(True)
        finally:
            self._syncing = False


class SigillumWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app, title="Sigillum")
        self.set_default_size(760, 600)

        header = Gtk.HeaderBar(show_close_button=True, title="Sigillum")
        self.set_titlebar(header)

        self._sign_view = SignView(self)
        self._mark_view = MarkView(self)
        self._encrypt_view = CryptView(self, mode="encrypt")
        self._decrypt_view = CryptView(self, mode="decrypt")
        self._verify_view = VerifyView(self)
        self._settings_view = SettingsView(self)

        self._stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        # (view, name, title, icon-name). Icons use the freedesktop symbolic
        # set — Adwaita and every mainstream Linux theme ship them.
        tabs: list[tuple[Gtk.Widget, str, str, str]] = [
            (self._sign_view,     "sign",     _("Sign"),      "document-edit-symbolic"),
            (self._verify_view,   "verify",   _("Verify"),    "emblem-ok-symbolic"),
            (self._mark_view,     "mark",     _("Timestamp"), "document-open-recent-symbolic"),
            (self._encrypt_view,  "encrypt",  _("Encrypt"),   "system-lock-screen-symbolic"),
            (self._decrypt_view,  "decrypt",  _("Decrypt"),   "changes-allow-symbolic"),
            (self._settings_view, "settings", _("Settings"),  "preferences-system-symbolic"),
        ]
        for view, name, title, _icon in tabs:
            self._stack.add_titled(view, name, title)
        # Track the previously-selected tab so we can intercept "leaving
        # Settings with unsaved changes" in _on_tab_changed.
        self._prev_tab: str = self._stack.get_visible_child_name() or "sign"
        # Set when we programmatically restore the stack after a cancelled
        # leave — prevents the resulting notify from re-firing the dialog.
        self._reverting_tab = False
        # Refresh tabs that depend on settings whenever the user returns.
        self._stack.connect("notify::visible-child", self._on_tab_changed)

        # Custom switcher — Gtk.StackSwitcher in GTK 3 shows EITHER the icon
        # OR the label, never both. Build a row of toggle buttons that pack
        # icon + label side by side and stay in sync with the Stack.
        switcher = _IconLabelStackSwitcher(self._stack, tabs)
        header.set_custom_title(switcher)

        self.add(self._stack)

        # Schedule the at-startup auto-refresh after the window is fully
        # realised. GLib.idle_add ensures we don't block do_activate() and
        # the views are already constructed when set_tsl_busy() is called.
        self._tsl_refresh_active = False
        GLib.idle_add(self._maybe_auto_refresh_tsl)

    def set_active_tab(self, name: str) -> None:
        """Switch the main stack to the tab with the given name. Used by the
        ``app.tab`` action (bound to Ctrl+1…6 / Ctrl+,)."""
        self._stack.set_visible_child_name(name)

    def _on_tab_changed(self, stack, _pspec):
        name = stack.get_visible_child_name()
        if self._reverting_tab:
            # We just restored the previous tab after a cancelled leave —
            # swallow the resulting notify without running the dialog again.
            self._reverting_tab = False
            self._prev_tab = name
            return
        # Leaving Settings with unsaved changes → ask Save / Discard / Cancel.
        if self._prev_tab == "settings" and name != "settings":
            if not self._settings_view.confirm_leave():
                self._reverting_tab = True
                self._stack.set_visible_child_name("settings")
                return
        self._prev_tab = name
        if name == "sign":
            self._sign_view.refresh_from_settings()
        elif name == "mark":
            self._mark_view.refresh_from_settings()
        elif name == "encrypt":
            self._encrypt_view.refresh_from_settings()
        elif name == "decrypt":
            self._decrypt_view.refresh_from_settings()
        elif name == "verify":
            self._verify_view.refresh_tsl_status()
        elif name == "settings":
            self._settings_view.refresh_from_settings()

    # ----- TSL refresh coordinator -----

    def _maybe_auto_refresh_tsl(self) -> bool:
        """Trigger a silent background refresh if the primary country's TSL
        is missing or stale."""
        s = load_settings()
        primary = s.effective_country()
        days = import_age_days(s.last_import_for(primary))
        if days is None or days > TSL_STALE_AFTER_DAYS:
            self.start_tsl_refresh(silent=True, country=primary)
        return False  # one-shot idle source

    def start_tsl_refresh(self, silent: bool = False, country: str | None = None):
        """Run a national TSL import in a background thread.

        *country* defaults to the user's primary country. Re-entrant: if a
        refresh is already running, this is a no-op so two triggers (auto +
        manual) don't race. ``silent=True`` suppresses error dialogs — used by
        the at-startup auto-refresh, where the user did not explicitly ask
        for an update and a network failure is no big deal.
        """
        if self._tsl_refresh_active:
            return
        from sigillum.core.tsl import import_country_tsl

        cc = (country or load_settings().effective_country()).upper()
        self._tsl_refresh_active = True
        self._settings_view.set_tsl_busy(True)
        self._verify_view.set_tsl_busy(True)

        import threading

        def worker():
            try:
                result = import_country_tsl(cc)
                current = load_settings()
                current.record_import(result.country, result.when.isoformat())
                # First import of a fresh country auto-enables it for verify.
                if (
                    result.country not in current.tsl_active_countries
                    and result.country == current.effective_country()
                ):
                    if not current.tsl_active_countries:
                        current.tsl_active_countries = [result.country]
                save_settings(current)
                if result.signer_trusted:
                    sig_note = _("✓ signature verified (LOTL-anchored)")
                elif result.signer_cert is not None:
                    sig_note = _("✓ signature verified (no LOTL)")
                else:
                    sig_note = _("⚠ signature not verified")
                message = _("{cc}: {n_sign} signing CAs, {n_tsa} TSA CAs — {sig}").format(
                    cc=result.country,
                    n_sign=result.signing_count,
                    n_tsa=result.tsa_count,
                    sig=sig_note,
                )
                ok = True
            except Exception as ex:  # noqa: BLE001 — reported via UI
                message = str(ex)
                ok = False
            GLib.idle_add(self._on_tsl_refresh_done, ok, message, silent)

        threading.Thread(target=worker, daemon=True, name="tsl-refresh").start()

    def _on_tsl_refresh_done(self, ok: bool, message: str, silent: bool):
        self._tsl_refresh_active = False
        self._settings_view.set_tsl_busy(False)
        self._verify_view.set_tsl_busy(False)
        # Always refresh the views — refresh_tsl_status reads from disk and
        # picks up the new state (or shows the old state if the import failed).
        self._settings_view.refresh_from_settings()
        self._verify_view.refresh_tsl_status()
        if not ok and not silent:
            _show_error(self, _("TSL import failed: {msg}").format(msg=message))
        return False  # don't repeat the idle source


class SigillumApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="io.github.sigillum")

    def do_startup(self):
        Gtk.Application.do_startup(self)

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Primary>Q", "<Primary>W"])

        tab_action = Gio.SimpleAction.new("tab", GLib.VariantType.new("s"))
        tab_action.connect("activate", self._on_tab_action)
        self.add_action(tab_action)
        self.set_accels_for_action("app.tab::sign",     ["<Primary>1"])
        self.set_accels_for_action("app.tab::verify",   ["<Primary>2"])
        self.set_accels_for_action("app.tab::mark",     ["<Primary>3"])
        self.set_accels_for_action("app.tab::encrypt",  ["<Primary>4"])
        self.set_accels_for_action("app.tab::decrypt",  ["<Primary>5"])
        self.set_accels_for_action("app.tab::settings", ["<Primary>6", "<Primary>comma"])

    def _on_tab_action(self, _action, param):
        win = self.props.active_window
        if win is not None:
            win.set_active_tab(param.get_string())

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = SigillumWindow(self)
        win.show_all()
        win.present()
