CC ?= cc
PKG_CONFIG ?= pkg-config
PACKAGES = yaml-0.1 libpsl libidn2 libcrypto
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags $(PACKAGES))
CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS += $(shell $(PKG_CONFIG) --libs $(PACKAGES))

pac.cgi: pac.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

.PHONY: check test
check: pac.cgi
	./pac.cgi --check rules.yaml

test: pac.cgi
	python3 test.py
