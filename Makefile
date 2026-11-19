CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wformat=2 -fstack-protector-strong
LDLIBS += $(shell pkg-config --libs ldap libsasl2) -lresolv
PREFIX ?= /usr
.PHONY: all clean install check
all: ldaplist
ldaplist: src/ldaplist.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
check: ldaplist
	./ldaplist -V
	./ldaplist -? >/dev/null
install: ldaplist
	install -D -m 0755 ldaplist $(DESTDIR)$(PREFIX)/bin/ldaplist
	install -D -m 0644 man/ldaplist.1 $(DESTDIR)$(PREFIX)/share/man/man1/ldaplist.1
clean:
	rm -f ldaplist
