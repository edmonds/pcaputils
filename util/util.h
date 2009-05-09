#ifndef RSEUTIL_UTIL_H
#define RSEUTIL_UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

extern bool util_flag_daemonized;
extern bool util_flag_verbose;

/* macros */

#define DEBUG(format, ...) do{ \
	if(util_flag_daemonized) syslog(LOG_DAEMON | LOG_DEBUG, "%s] " format, __func__, ## __VA_ARGS__); \
	else fprintf(stderr, "%s] " format "\n", __func__, ## __VA_ARGS__); \
}while(0)

#define ERROR(format, ...) do{ \
	DEBUG("Error: " format, ## __VA_ARGS__); \
	exit(EXIT_FAILURE); \
}while(0)

#define VERBOSE(format, ...) do{ \
	if(util_flag_verbose) DEBUG(format, ## __VA_ARGS__); \
}while(0)

#define MALLOC(target, size) do{ \
	target = malloc(size); \
	if(target == NULL){ \
		DEBUG("malloc() failed, aborting"); \
		abort(); \
	} \
}while(0)

#define CALLOC(target, size) do{ \
	target = calloc(1, size); \
	if(target == NULL){ \
		DEBUG("calloc() failed, aborting"); \
		abort(); \
	} \
}while(0)

#define REALLOC(target, size) do { \
	target = realloc(target, size); \
	if(target == NULL){ \
		DEBUG("realloc() failed, aborting"); \
		abort(); \
	} \
}while(0)

#define NEW(target) do{ \
	target = malloc(sizeof(*target)); \
	if(target == NULL){ \
		DEBUG("malloc() failed, aborting"); \
		abort(); \
	} \
}while(0)

#define NEW0(target) do{ \
	target = calloc(1, sizeof(*target)); \
	if(target == NULL){ \
		DEBUG("malloc() failed, aborting"); \
		abort(); \
	} \
}while(0)

#define FREE(target) do{ \
	if(target){ \
		free(target); \
		target = NULL; \
	} \
}while(0)

#define Chdir(dir) do{ \
	if(chdir(dir) != 0) ERROR("unable to chdir(%s): %s", dir, strerror(errno)); \
}while(0)

#define Chroot(dir) do{ \
	if(chroot(dir) != 0) ERROR("unable to chroot(%s): %s", dir, strerror(errno)); \
}while(0)

#define ZERO(target) memset(&target, 0, sizeof(target));

/* General-purpose swap macro from http://www.spinellis.gr/blog/20060130/index.html */
#define SWAP(a, b) do{\
	char c[sizeof(a)]; \
	memcpy((void *)&c, (void *)&a, sizeof(c)); \
	memcpy((void *)&a, (void *)&b, sizeof(a)); \
	memcpy((void *)&b, (void *)&c, sizeof(b)); \
}while(0)

#define likely(x)	__builtin_expect((x), 1)
#define unlikely(x)	__builtin_expect((x), 0)

#if __GNUC__ >= 3
# define __unused __attribute__((unused))
#else
# define __unused
#endif

#if __GNUC_GNU_INLINE__
# define __inline inline __attribute__((gnu_inline))
#else
# define __inline inline
#endif

void util_print_backtrace(int);

#endif
