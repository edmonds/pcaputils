#ifndef RSEUTIL_FILE_H
#define RSEUTIL_FILE_H

#include <sys/types.h>
#include <unistd.h>

#include <util/util.h>

#define Chdir(dir) do{ \
	if(chdir(dir) != 0) ERROR("unable to chdir(%s): %s", dir, strerror(errno)); \
}while(0)

extern int creat_mog(const char *pathname, mode_t mode, const char *owner, const char *group);
extern int Open(const char *pathname, int flags);

#endif
