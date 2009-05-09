### Build flags for all targets
CFLAGS         ?= -O2 -ggdb -Wall
CF_ALL          = $(CFLAGS) -Wextra -std=gnu99 -I.
LF_ALL          = -rdynamic -Wl,--as-needed -Wl,-z,defs

### Build tools
CC              = gcc
COMP            = $(CC) $(CF_ALL) $(CF_TGT) -o $@ -c $<
LINK            = $(CC) $(LF_ALL) $(LF_TGT) -o $@ $^ $(LL_TGT) $(LL_ALL)
COMPLINK        = $(CC) $(CF_ALL) $(CF_TGT) $(LF_ALL) $(LF_TGT) -o $@ $< $(LL_TGT) $(LL_ALL)
ARCH            = $(AR) rcs $@ $^
MAKEDEP         = @set -e; rm -f $@; $(CC) $(CF_ALL) $(CFG_TGT) -MM $(CPPFLAGS) $< > $@.$$$$; \
			sed 's,.*:,$(patsubst %.d,%.o,$@) $@ : ,g' < $@.$$$$ > $@; \
	 		rm -f $@.$$$$
DEBCHANGELOG    = @sed -i \
			-e 's/@@PKGNAME@@/$(PKGNAME)/' \
			-e 's/@@PKGVER@@/$(PKGVER)/' \
			-e 's/@@DEBFULLNAME@@/$(DEBFULLNAME)/' \
			-e 's/@@DEBEMAIL@@/$(DEBEMAIL)/' \
			-e 's/@@DATE@@/$(shell date -R)/' \
			$(EXPORT)/debian/changelog

### Standard parts
include Rules.mk
