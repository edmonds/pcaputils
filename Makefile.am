bin_PROGRAMS =
EXTRA_DIST =
CLEANFILES =

AM_CPPFLAGS = -include $(top_builddir)/config.h
AM_CFLAGS = ${my_CFLAGS}
AM_LDFLAGS = -Wl,--as-needed

util_sources = \
	util/byte.c util/byte.h \
	util/cfgopt.c util/cfgopt.h \
	util/daemon.c util/daemon.h \
	util/file.c util/file.h \
	util/net.c util/net.h \
	util/pcapnet.c util/pcapnet.h \
	util/rate.c util/rate.h \
	util/ring.c util/ring.h \
	util/rng.c util/rng.h \
	util/scanfmt.c util/scanfmt.h \
	util/server.c util/server.h \
	util/socket.c util/socket.h \
	util/uint.c util/uint.h \
	util/util.c util/util.h

bin_PROGRAMS += src/pcapdump
src_pcapdump_SOURCES = \
	src/pcapdump.c \
	$(util_sources)

bin_PROGRAMS += src/pcapip
src_pcapip_SOURCES = \
	src/pcapip.c \
	$(util_sources)

bin_PROGRAMS += src/pcappick
src_pcappick_SOURCES = \
	src/pcappick.c \
	$(util_sources)

bin_PROGRAMS += src/pcapuc
src_pcapuc_SOURCES = \
	src/pcapuc.c \
	$(util_sources)

SUFFIXES = .1 .docbook

DOCBOOK_PROCESS = docbook2x-man --to-stdout --xinclude $< > $@

.docbook.1:
	$(DOCBOOK_PROCESS)

dist_man_MANS = \
	doc/pcapdump.1 \
	doc/pcapip.1 \
	doc/pcappick.1 \
	doc/pcapuc.1

EXTRA_DIST += \
	doc/pcapdump.docbook \
	doc/pcapip.docbook \
	doc/pcapnet.docbook \
	doc/pcappick.docbook \
	doc/pcapup.docbook
