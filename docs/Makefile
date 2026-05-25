# SPDX-License-Identifier: GPL-3.0-or-later
# Build localised man pages from the English master via po4a.
#
#   make pot       → refresh docs/po4a/sigillum.pot from sigillum.1
#   make po        → merge the new msgids into every existing translation
#   make man       → render docs/build/<lang>/sigillum.1 for every language
#                    (English stays untouched at docs/sigillum.1)
#   make install   → install both English and translated man pages into
#                    $(DESTDIR)$(mandir)/... — used by debian/rules and the
#                    Fedora spec.
#   make clean     → remove docs/build/
#
# Adding a new language `xx`:
#   1. msginit --input=po4a/sigillum.pot --locale=xx --output=po4a/xx.po
#   2. append `xx` to po4a/LINGUAS (or just create the .po — it is auto-picked
#      up below via the wildcard).
#   3. translate po4a/xx.po
#   4. `make man && make install`

PACKAGE    = sigillum
MAN1       = $(PACKAGE).1
MASTER     = $(MAN1)
POT        = po4a/$(PACKAGE).pot
PO_FILES   = $(wildcard po4a/*.po)
LANGUAGES  = $(patsubst po4a/%.po,%,$(PO_FILES))

BUILD_DIR  = build
TRANS_MAN  = $(LANGUAGES:%=$(BUILD_DIR)/%/$(MAN1))

prefix     = /usr/local
datarootdir = $(prefix)/share
mandir     = $(datarootdir)/man

PO4A_OPTS  = --master-charset UTF-8 --localized-charset UTF-8

.PHONY: all pot po man install clean

all: man

pot: $(POT)

$(POT): $(MASTER)
	po4a-updatepo --format=man --master=$(MASTER) --po=$@ \
	    --copyright-holder "Danilo Abbasciano" \
	    --package-name $(PACKAGE) \
	    --package-version 0.1.0 \
	    --msgid-bugs-address danilo@piumalab.org

po: pot
	@for lang in $(LANGUAGES); do \
	    echo "merging po4a/$$lang.po"; \
	    msgmerge --update --quiet po4a/$$lang.po $(POT); \
	done

man: $(TRANS_MAN)

$(BUILD_DIR)/%/$(MAN1): po4a/%.po $(MASTER)
	@mkdir -p $(@D)
	po4a-translate --format=man $(PO4A_OPTS) \
	    --master=$(MASTER) --po=$< --localized=$@ --keep 0

install: man
	install -d $(DESTDIR)$(mandir)/man1
	install -m 0644 $(MASTER) $(DESTDIR)$(mandir)/man1/$(MAN1)
	@for lang in $(LANGUAGES); do \
	    install -d $(DESTDIR)$(mandir)/$$lang/man1; \
	    install -m 0644 $(BUILD_DIR)/$$lang/$(MAN1) \
	        $(DESTDIR)$(mandir)/$$lang/man1/$(MAN1); \
	done

clean:
	rm -rf $(BUILD_DIR)
