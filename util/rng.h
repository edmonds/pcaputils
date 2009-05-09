#ifndef RSEUTIL_RNG_H
#define RSEUTIL_RNG_H

#include <stdbool.h>

extern void rng_seed(bool secure);
extern int rng_randint(int min, int max);

#endif
