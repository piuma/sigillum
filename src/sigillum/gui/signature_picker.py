# SPDX-License-Identifier: GPL-3.0-or-later
<<<<<<< HEAD
# Copyright (C) 2026 Danilo Abbasciano <danilo@piumalab.org>
=======
# Copyright (C) 2026 Danilo Abbasciano <danilo.abbasciano@par-tec.it>
>>>>>>> 597b9e4 (add: Debian packaging e prerequisiti DFSG)
"""Modal dialog: render a PDF page and let the user drag a rectangle on it.

Used by `SignView` to give the user a graphical way to choose where the
visible PAdES signature stamp will appear. Returns the chosen page and
the rectangle in PDF points (origin = bottom-left, the convention used
by `endesive` and our `_add_visible_appearance`).

Rendering goes through Poppler (system library, GNOME-native) → Cairo →
Gtk.DrawingArea. No extra Python dependency: PyGObject already exposes
the `Poppler` namespace once `gir1.2-poppler-0.18` (or equivalent) is
installed, which is the case on any Fedora/GNOME desktop.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("Poppler", "0.18")
from gi.repository import Gdk, Gtk, Poppler  # noqa: E402

from ..i18n import _


# Bounding box of the rendered preview area inside the dialog. Sized so an
# A4 portrait page lands at ~75% of its natural size — small enough to fit
# comfortably on a 1080p laptop screen alongside other Sigillum windows.
_MAX_PREVIEW_W = 540
_MAX_PREVIEW_H = 660
# Hard cap on the rendering scale: never enlarge a tiny page beyond 75%.
_MAX_SCALE = 0.75


Box = tuple[float, float, float, float]


def pick_signature_box(
    parent: Gtk.Window,
    pdf_path: str | Path,
    initial_page: int = 0,
    initial_box: Optional[Box] = None,
) -> Optional[tuple[int, Box]]:
    """Run the picker; return (page_index, box_in_pdf_points) or None on cancel.

    `box_in_pdf_points` is `(x1, y1, x2, y2)` with `x1<x2, y1<y2` and PDF
    coordinate system (origin bottom-left, y up).
    """
    dlg = _SignaturePickerDialog(parent, Path(pdf_path), initial_page, initial_box)
    try:
        result = dlg.run()
        if result != Gtk.ResponseType.OK or dlg.selected_rect_px is None:
            return None
        return dlg.page_index, dlg.px_box_to_pt(dlg.selected_rect_px)
    finally:
        dlg.destroy()


class _SignaturePickerDialog(Gtk.Dialog):
    def __init__(
        self,
        parent: Gtk.Window,
        pdf_path: Path,
        initial_page: int,
        initial_box: Optional[Box],
    ):
        super().__init__(
            title=_("Draw the signature position"),
            transient_for=parent,
            flags=Gtk.DialogFlags.MODAL,
        )
        self.set_default_size(_MAX_PREVIEW_W + 60, _MAX_PREVIEW_H + 140)
        self.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        ok = self.add_button(_("OK"), Gtk.ResponseType.OK)
        ok.get_style_context().add_class("suggested-action")
        ok.set_sensitive(initial_box is not None)
        self._ok_button = ok

        self._doc = Poppler.Document.new_from_file(pdf_path.resolve().as_uri())
        n_pages = self._doc.get_n_pages()
        self.page_index = max(0, min(initial_page, n_pages - 1))
        self._page: Poppler.Page = self._doc.get_page(self.page_index)
        self._page_w_pt = 0.0
        self._page_h_pt = 0.0
        self._scale = 1.0
        self.selected_rect_px: Optional[Box] = None
        self._drag_start: Optional[tuple[float, float]] = None

        content = self.get_content_area()
        content.set_spacing(8)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.set_margin_top(6)
        content.set_margin_bottom(6)

        # Page selector (only useful if the PDF has more than one page).
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        top.pack_start(Gtk.Label(label=_("Page:"), xalign=0), False, False, 0)
        self._page_spin = Gtk.SpinButton.new_with_range(1, n_pages, 1)
        self._page_spin.set_value(self.page_index + 1)
        self._page_spin.set_sensitive(n_pages > 1)
        self._page_spin.connect("value-changed", self._on_page_changed)
        top.pack_start(self._page_spin, False, False, 0)
        top.pack_start(Gtk.Label(label=_(" of {n}").format(n=n_pages), xalign=0), False, False, 0)
        content.pack_start(top, False, False, 0)

        # Hint label.
        hint = Gtk.Label(xalign=0)
        hint.set_markup(
            _("<small>Drag with the mouse to draw the signature box "
              "position.</small>")
        )
        content.pack_start(hint, False, False, 0)

        # Drawing area inside a scroller (in case the page is bigger than viewport).
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_hexpand(True)
        scroller.set_vexpand(True)

        self._area = Gtk.DrawingArea()
        self._area.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK
            | Gdk.EventMask.BUTTON_RELEASE_MASK
            | Gdk.EventMask.POINTER_MOTION_MASK
        )
        self._area.connect("draw", self._on_draw)
        self._area.connect("button-press-event", self._on_button_press)
        self._area.connect("motion-notify-event", self._on_motion)
        self._area.connect("button-release-event", self._on_button_release)
        scroller.add(self._area)
        content.pack_start(scroller, True, True, 0)

        # Live coords feedback.
        self._coord_label = Gtk.Label(xalign=0)
        content.pack_start(self._coord_label, False, False, 0)

        self._load_current_page()
        if initial_box is not None:
            self.selected_rect_px = self._pt_box_to_px(initial_box)
            self._update_coord_label()

        self.show_all()

    # ----- page loading -----

    def _load_current_page(self):
        self._page = self._doc.get_page(self.page_index)
        self._page_w_pt, self._page_h_pt = self._page.get_size()
        self._scale = min(
            _MAX_PREVIEW_W / self._page_w_pt,
            _MAX_PREVIEW_H / self._page_h_pt,
            _MAX_SCALE,
        )
        canvas_w = int(self._page_w_pt * self._scale)
        canvas_h = int(self._page_h_pt * self._scale)
        self._area.set_size_request(canvas_w, canvas_h)
        self._area.queue_draw()
        self._update_coord_label()

    def _on_page_changed(self, spin: Gtk.SpinButton):
        new_idx = int(spin.get_value()) - 1
        if new_idx == self.page_index:
            return
        self.page_index = new_idx
        self.selected_rect_px = None  # box is page-specific
        self._ok_button.set_sensitive(False)
        self._load_current_page()

    # ----- coordinate transforms -----

    def _pt_box_to_px(self, box_pt: Box) -> Box:
        """Convert a PDF-point rectangle (bottom-left origin, y up) to
        DrawingArea pixel coordinates (top-left origin, y down)."""
        x1, y1, x2, y2 = box_pt
        px1 = min(x1, x2) * self._scale
        px2 = max(x1, x2) * self._scale
        py_top = (self._page_h_pt - max(y1, y2)) * self._scale
        py_bot = (self._page_h_pt - min(y1, y2)) * self._scale
        return (px1, py_top, px2, py_bot)

    def px_box_to_pt(self, box_px: Box) -> Box:
        """Inverse of `_pt_box_to_px`, normalised so x1<x2 and y1<y2."""
        px1, py1, px2, py2 = box_px
        x_lo = min(px1, px2) / self._scale
        x_hi = max(px1, px2) / self._scale
        # The smaller pixel-y corresponds to the larger PDF-y.
        y_hi = self._page_h_pt - (min(py1, py2) / self._scale)
        y_lo = self._page_h_pt - (max(py1, py2) / self._scale)
        return (x_lo, y_lo, x_hi, y_hi)

    # ----- drawing -----

    def _on_draw(self, _area: Gtk.DrawingArea, cr) -> bool:
        # White page background then the PDF rendering scaled to fit.
        cr.set_source_rgb(1.0, 1.0, 1.0)
        cr.paint()
        cr.save()
        cr.scale(self._scale, self._scale)
        self._page.render(cr)
        cr.restore()

        if self.selected_rect_px is not None:
            x1, y1, x2, y2 = self.selected_rect_px
            rx = min(x1, x2)
            ry = min(y1, y2)
            rw = abs(x2 - x1)
            rh = abs(y2 - y1)
            # Semi-transparent orange fill + solid border.
            cr.set_source_rgba(1.0, 0.55, 0.0, 0.25)
            cr.rectangle(rx, ry, rw, rh)
            cr.fill_preserve()
            cr.set_source_rgba(0.85, 0.35, 0.0, 0.95)
            cr.set_line_width(2)
            cr.stroke()
        return False

    # ----- mouse handling -----

    def _on_button_press(self, area, event) -> bool:
        if event.button != 1:
            return False
        self._drag_start = (event.x, event.y)
        self.selected_rect_px = (event.x, event.y, event.x, event.y)
        self._update_coord_label()
        area.queue_draw()
        return True

    def _on_motion(self, area, event) -> bool:
        if self._drag_start is None:
            return False
        x0, y0 = self._drag_start
        self.selected_rect_px = (x0, y0, event.x, event.y)
        self._update_coord_label()
        area.queue_draw()
        return True

    def _on_button_release(self, area, event) -> bool:
        if self._drag_start is None or event.button != 1:
            return False
        x0, y0 = self._drag_start
        self.selected_rect_px = (x0, y0, event.x, event.y)
        self._drag_start = None
        self._update_coord_label()
        # Require a non-degenerate rectangle before enabling OK.
        x1, y1, x2, y2 = self.selected_rect_px
        big_enough = abs(x2 - x1) > 5 and abs(y2 - y1) > 5
        self._ok_button.set_sensitive(big_enough)
        area.queue_draw()
        return True

    def _update_coord_label(self):
        if self.selected_rect_px is None:
            self._coord_label.set_markup(
                _("<small><i>Drag to draw the box.</i></small>")
            )
            return
        pt = self.px_box_to_pt(self.selected_rect_px)
        w_pt = pt[2] - pt[0]
        h_pt = pt[3] - pt[1]
        # 1 mm ≈ 2.835 pt
        w_mm = w_pt / 2.835
        h_mm = h_pt / 2.835
        self._coord_label.set_markup(
            _("<small>Box: <b>{w_mm:.0f} × {h_mm:.0f} mm</b>"
              " ({w_pt:.0f}×{h_pt:.0f} pt)"
              " — page origin (PDF): ({x:.0f}, {y:.0f})</small>").format(
                w_mm=w_mm, h_mm=h_mm, w_pt=w_pt, h_pt=h_pt, x=pt[0], y=pt[1])
        )
