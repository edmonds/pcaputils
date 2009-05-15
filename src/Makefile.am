AM_CFLAGS = @EXTRA_CFLAGS@

bin_PROGRAMS = pcapdump pcapip pcappick pcapuc

pcapdump_LDADD = ../util/libutil.a
pcapdump_LDFLAGS = -lpcap
pcapdump_SOURCES = pcapdump.c

pcapip_LDADD = ../util/libutil.a
pcapip_LDFLAGS = -lpcap -lJudy
pcapip_SOURCES = pcapip.c

pcappick_LDADD = ../util/libutil.a
pcappick_LDFLAGS = -lpcap
pcappick_SOURCES = pcappick.c

pcapuc_LDADD = ../util/libutil.a
pcapuc_LDFLAGS = -lpcap -lJudy
pcapuc_SOURCES = pcapuc.c
