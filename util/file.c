/*

file.c - abstractions for file manipulation

Copyright (C) 2008 Robert S. Edmonds 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <util/file.h>
#include <util/util.h>

int creat_mog(const char *pathname, mode_t mode, const char *owner, const char *group){
	uid_t uid;
	gid_t gid;
	int fd;
	struct group *gr;
	struct passwd *pw;

	pw = getpwnam(owner);
	gr = getgrnam(group);

	if(pw)
		uid = pw->pw_uid;
	else
		uid = geteuid();
	if(gr)
		gid = gr->gr_gid;
	else
		gid = getegid();

	if((fd = creat(pathname, mode)) == -1)
		ERROR("creat() failed: %s", strerror(errno));
	if(geteuid() == 0)
		if(fchown(fd, uid, gid) != 0)
			ERROR("fchown() failed: %s", strerror(errno));
	return fd;
}

int Open(const char *pathname, int flags){
	int fd = open(pathname, flags);
	if(fd == -1)
		ERROR("unable to open(%s, %d): %s", pathname, flags, strerror(errno));
	return fd;
}
