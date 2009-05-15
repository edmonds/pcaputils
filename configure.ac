AC_PREREQ([2.63])
AC_INIT([pcaputils], [0.9], [edmonds@debian.org])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.9 foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# C compiler checks
if test "x$GCC" = xyes; then
    EXTRA_CFLAGS="-Wall -Wextra -Werror -std=gnu99"
fi
AC_SUBST([EXTRA_CFLAGS])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h], [], [AC_MSG_ERROR([required header not found])])
AC_CHECK_HEADERS([endian.h sys/endian.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm gettimeofday socket strcasecmp strdup strerror strtoul], [], [AC_MSG_ERROR([required function not found])])

AC_CONFIG_FILES([Makefile src/Makefile util/Makefile])
AC_OUTPUT
