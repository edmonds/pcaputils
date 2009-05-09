/*

daemon.c - functions for daemonizing

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

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "daemon.h"
#include "scanfmt.h"
#include "util.h"

void pidfile_create(const char *pidfile){
	FILE *fp;
	pid_t pid;

	if(!pidfile) return;

	pid = getpid();
	if(!(fp = fopen(pidfile, "w")))
		ERROR("unable to open pidfile %s for writing: %s", pidfile, strerror(errno));
	fprintf(fp, "%d\n", pid);
	fclose(fp);
}

void util_daemonize(char *program_name, char *pidfile){
	if(daemon(0, 0) != 0)
		ERROR("%s", strerror(errno));
	pidfile_create(pidfile);
	openlog(program_name, LOG_PID, LOG_DAEMON);
	util_flag_daemonized = true;
}

void envuidgid(void){
	char *envuid;
	char *envgid;
	unsigned long uid;
	unsigned long gid;

	if((envgid = getenv("GID"))){
		scan_ulong(envgid, &gid);
		if(-1 == setgid((gid_t) gid))
			ERROR("unable to setgid(%s): %s", envgid, strerror(errno));
	}
	if((envuid = getenv("UID"))){
		scan_ulong(envuid, &uid);
		if(-1 == setuid((uid_t) uid))
			ERROR("unable to setuid(%s): %s", envuid, strerror(errno));
	}
}
