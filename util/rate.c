#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include <util/rate.h>
#include <util/util.h>

rate_t *rate_new(int call_rate){
	rate_t *r;
	NEW0(r);
	r->call_rate = call_rate;
	r->gtod_rate = call_rate / 10;
	r->sleep_rate = call_rate / 100;
	r->ts.tv_sec = 0;
	r->ts.tv_nsec = 4E6;

	if(r->gtod_rate == 0)
		r->gtod_rate = 1;
	if(r->sleep_rate == 0)
		r->sleep_rate = 1;

	gettimeofday(&r->tv[0], NULL);
	return r;
}

void rate_free(rate_t **r){
	FREE(*r);
}

void rate_call(rate_t *r, void (fn)(void *), void *data){
	(r->call_no)++;
	(r->call_no_last)++;
	if(unlikely(r->call_no % r->sleep_rate == 0)){
		nanosleep(&r->ts, NULL);
	}
	if(unlikely(r->call_no % r->gtod_rate == 0)){
		gettimeofday(&r->tv[1], NULL);
		double d0 = r->tv[0].tv_sec + r->tv[0].tv_usec / 1E6;
		double d1 = r->tv[1].tv_sec + r->tv[1].tv_usec / 1E6;
		r->cur_rate = ((int) (r->call_no_last / (d1 - d0)));
		if(abs(r->cur_rate - r->call_rate) > 10){
			if(r->cur_rate - r->call_rate > 0){
				if(r->sleep_rate > 1){
					int d = r->sleep_rate / 10;
					r->sleep_rate -= (d > 1 ? d : 1);
					VERBOSE("sleep_rate=%d", r->sleep_rate);
				}
			}else if (r->sleep_rate < 1E6){
				int d = r->sleep_rate / 10;
				r->sleep_rate += (d > 1 ? d : 1);
				VERBOSE("sleep_rate=%d", r->sleep_rate);
			}
		}
		r->call_no_last = 0;
		r->tv[0] = r->tv[1];
	}
	if(fn) fn(data);
}
