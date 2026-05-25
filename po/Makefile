# SPDX-License-Identifier: GPL-3.0-or-later
# Translator workflow for Sigillum.
#
#   make pot      → regenerate sigillum.pot from the source files
#   make po       → merge updated msgids into every existing language .po
#   make compile  → compile each .po into po/build/<lang>/LC_MESSAGES/sigillum.mo
#                   (so `PYTHONPATH=src python -m sigillum` uses them locally)
#   make install  → install .mo files into $(DESTDIR)$(localedir)
#                   (used by debian/rules and Fedora's %install)
#
# Adding a new language `xx`:
#   1. msginit --input=po/sigillum.pot --locale=xx --output=po/xx.po
#   2. append `xx` to po/LINGUAS
#   3. translate, then `make compile && make install`

DOMAIN     = sigillum
SRCROOT    = ..
POTFILE    = $(DOMAIN).pot
LINGUAS    = $(shell cat LINGUAS)
PO_FILES   = $(LINGUAS:%=%.po)
prefix     = /usr/local
datarootdir = $(prefix)/share
localedir  = $(datarootdir)/locale
BUILD_DIR  = build

# Files scanned by xgettext (kept in POTFILES.in for `make pot`).
POTFILES_IN = POTFILES.in

XGETTEXT_OPTS = --language=Python \
                --keyword=_ \
                --keyword=ngettext:1,2 \
                --from-code=UTF-8 \
                --package-name=$(DOMAIN) \
                --package-version=0.1.0 \
                --msgid-bugs-address=danilo@piumalab.org \
                --copyright-holder="Danilo Abbasciano"


.PHONY: pot po compile install clean

pot:
	cd $(SRCROOT) && xgettext $(XGETTEXT_OPTS) \
	    --output=po/$(POTFILE) \
	    --files-from=po/$(POTFILES_IN)

po: pot
	@for lang in $(LINGUAS); do \
	    echo "merging $$lang.po"; \
	    msgmerge --update --quiet $$lang.po $(POTFILE); \
	done

compile:
	@mkdir -p $(BUILD_DIR)
	@for lang in $(LINGUAS); do \
	    dir=$(BUILD_DIR)/$$lang/LC_MESSAGES; \
	    mkdir -p $$dir; \
	    msgfmt $$lang.po -o $$dir/$(DOMAIN).mo; \
	    echo "  $$dir/$(DOMAIN).mo"; \
	done

install: compile
	@for lang in $(LINGUAS); do \
	    install -d $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES; \
	    install -m 0644 $(BUILD_DIR)/$$lang/LC_MESSAGES/$(DOMAIN).mo \
	        $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(DOMAIN).mo; \
	done

clean:
	rm -rf $(BUILD_DIR)
