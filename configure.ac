AC_PREREQ(2.60)
AC_INIT([pcaputils], [0.11], [edmonds@debian.org])
AC_CONFIG_SRCDIR([src/pcapdump.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_SILENT_RULES([yes])

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

AC_CHECK_FUNC([getline], [], [AC_MSG_ERROR([required system function not found])])

AC_CHECK_HEADER([pcap.h], [], [AC_MSG_ERROR([required header file not found])])
AC_SEARCH_LIBS([pcap_create], [pcap],
    AC_DEFINE([HAVE_PCAP_CREATE], [1], [Define to 1 if pcap_create() is available.])
)

AC_CHECK_HEADER([Judy.h], [], [AC_MSG_ERROR([required header file not found])])
AC_SEARCH_LIBS([JudyLNext], [Judy],
    AC_DEFINE([HAVE_JUDY], [1], [Define to 1 if libJudy is available.])
)

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
])
