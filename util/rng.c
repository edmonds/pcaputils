/*

rng.c - randomization functions

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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "rng.h"
#include "util.h"

void rng_seed(bool secure){
        char *dev;
        int fd;
        unsigned seed;

        if(secure)
                dev = "/dev/random";
        else
                dev = "/dev/urandom";
        if((fd = open(dev, O_RDONLY)) != -1){
                if(read(fd, &seed, sizeof(seed)) != sizeof(seed))
                        ERROR("unable to read %u bytes from %s", (unsigned) sizeof(seed), dev);
        }else{
                ERROR("unable to open %s for reading: %s", dev, strerror(errno));
        }
        srandom(seed);
        close(fd);
}

int rng_randint(int min, int max){
	return (int) (((double) (max - min + 1)) * (rand() / (RAND_MAX + ((double) min))));
}
