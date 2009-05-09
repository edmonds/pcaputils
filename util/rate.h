#ifndef RATE_H
#define RATE_H

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

typedef struct rate {
	unsigned call_no;
	int call_no_last;
	int call_rate;
	int gtod_rate;
	int sleep_rate;
	int cur_rate;
	struct timeval tv[2];
	struct timespec ts;
} rate_t;

rate_t *rate_new(int call_rate);
void rate_free(rate_t **);
void rate_call(rate_t *, void (fn)(void *), void *data);

#endif
