#include <execinfo.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <util/util.h>

bool util_flag_daemonized;
bool util_flag_verbose;

void util_print_backtrace(int x __unused){
#define NFRAMES 32
	int nptrs;
	void *buf[NFRAMES];

	fprintf(stderr, "what? alarms?! good lord, we're under electronic attack!\n");

	nptrs = backtrace(buf, NFRAMES);
	backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
	abort();
}
