#ifndef PA_RINGBUFFER_H
#define PA_RINGBUFFER_H

/*
 * Portable Audio I/O Library
 * Ring Buffer utility.
 *
 * Author: Phil Burk, http://www.softsynth.com
 * modified for SMP safety on OS X by Bjorn Roche.
 * also allowed for const where possible.
 *
 * Note that this is safe only for a single-thread reader
 * and a single-thread writer.
 *
 * This program is distributed with the PortAudio Portable Audio Library.
 * For more information see: http://www.portaudio.com
 * Copyright (c) 1999-2000 Ross Bencina and Phil Burk
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* derived from http://www.portaudio.com/trac/browser/portaudio/branches/v19-devel/src/common/pa_ringbuffer.h */

#include <sys/types.h>

#if defined(__GNUC__)
#   if defined(__PPC__)
#      define ring_fmb() asm volatile("sync":::"memory")
#      define ring_rmb() asm volatile("sync":::"memory")
#      define ring_wmb() asm volatile("sync":::"memory")
#   elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(__x86_64__)
#      define ring_fmb() asm volatile("mfence":::"memory")
#      define ring_rmb() asm volatile("lfence":::"memory")
#      define ring_wmb() asm volatile("sfence":::"memory")
#   elif (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1)
#      define ring_fmb() __sync_synchronize()
#      define ring_rmb() __sync_synchronize()
#      define ring_wmb() __sync_synchronize()
#   else
#      define ring_fmb()
#      define ring_rmb()
#      define ring_wmb()
#   endif
#endif

typedef struct ring
{
    size_t buffer_size;
    size_t write_idx;
    size_t read_idx;
    size_t big_mask;
    size_t small_mask;
    char *buffer;
} ring_t;

ring_t *ring_new(size_t sz);
size_t ring_advance_read_idx(ring_t *rbuf, size_t sz);
size_t ring_advance_write_idx(ring_t *rbuf, size_t sz);
size_t ring_get_read_regions(ring_t *rbuf, size_t sz, void **dataPtr1, size_t *sizePtr1, void **dataPtr2, size_t *sizePtr2);
size_t ring_get_write_regions(ring_t *rbuf, size_t sz, void **dataPtr1, size_t *sizePtr1, void **dataPtr2, size_t *sizePtr2);
size_t ring_read(ring_t *rbuf, void *data, size_t sz);
size_t ring_read_bytes_avail(ring_t *rbuf);
size_t ring_write(ring_t *rbuf, const void *data, size_t sz);
size_t ring_write_bytes_avail(ring_t *rbuf);
void ring_flush(ring_t *rbuf);

#endif
