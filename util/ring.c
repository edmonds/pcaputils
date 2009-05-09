/*
 * Portable Audio I/O Library
 * Ring Buffer utility.
 *
 * Author: Phil Burk, http://www.softsynth.com
 * modified for SMP safety on Mac OS X by Bjorn Roche
 * modified for SMP safety on Linux by Leland Lucius
 * also, allowed for const where possible
 *
 * Note that this is safe only for a single-thread reader and a
 * single-thread writer.
 *
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

/* derived from http://www.portaudio.com/trac/browser/portaudio/branches/v19-devel/src/common/pa_ringbuffer.c */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ring.h"
#include "util.h"

ring_t *ring_new(size_t sz){
	ring_t *rbuf = NULL;

	if( ((sz - 1) & sz) == 0){
		NEW0(rbuf);
		MALLOC(rbuf->buffer, sz);
		rbuf->buffer_size = sz;
		ring_flush(rbuf);
		rbuf->big_mask = (2 * sz) - 1;
		rbuf->small_mask = sz - 1;
	}else{
		ERROR("sz=%zd is not a power of 2", sz);
	}
	return rbuf;
}

size_t ring_read_bytes_avail(ring_t *rbuf){
	ring_rmb();
	return ( (rbuf->write_idx - rbuf->read_idx) & rbuf->big_mask );
}

size_t ring_write_bytes_avail(ring_t *rbuf){
	return rbuf->buffer_size - ring_read_bytes_avail(rbuf);
}

void ring_flush(ring_t *rbuf){
	rbuf->write_idx = rbuf->read_idx = 0;
}

size_t ring_get_write_regions(ring_t *rbuf, size_t sz, void **dataPtr1, size_t *sizePtr1, void **dataPtr2, size_t *sizePtr2){
	size_t index;
	size_t available = ring_write_bytes_avail(rbuf);

	if(sz > available) sz = available;
	index = rbuf->write_idx & rbuf->small_mask;
	if((index + sz) > rbuf->buffer_size)
	{
		size_t first_half = rbuf->buffer_size - index;
		*dataPtr1 = &rbuf->buffer[index];
		*sizePtr1 = first_half;
		*dataPtr2 = &rbuf->buffer[0];
		*sizePtr2 = sz - first_half;
	}
	else
	{
		*dataPtr1 = &rbuf->buffer[index];
		*sizePtr1 = sz;
		*dataPtr2 = NULL;
		*sizePtr2 = 0;
	}
	return sz;
}

size_t ring_advance_write_idx(ring_t *rbuf, size_t sz){
	ring_wmb();
	return rbuf->write_idx = (rbuf->write_idx + sz) & rbuf->big_mask;
}

size_t ring_get_read_regions(ring_t *rbuf, size_t sz, void **dataPtr1, size_t *sizePtr1, void **dataPtr2, size_t *sizePtr2){
	size_t index;
	size_t available = ring_read_bytes_avail(rbuf);

	if(sz > available) sz = available;
	index = rbuf->read_idx & rbuf->small_mask;
	if((index + sz) > rbuf->buffer_size)
	{
		size_t first_half = rbuf->buffer_size - index;
		*dataPtr1 = &rbuf->buffer[index];
		*sizePtr1 = first_half;
		*dataPtr2 = &rbuf->buffer[0];
		*sizePtr2 = sz - first_half;
	}
	else
	{
		*dataPtr1 = &rbuf->buffer[index];
		*sizePtr1 = sz;
		*dataPtr2 = NULL;
		*sizePtr2 = 0;
	}
	return sz;
}

size_t ring_advance_read_idx(ring_t *rbuf, size_t sz){
	ring_wmb();
	return rbuf->read_idx = (rbuf->read_idx + sz) & rbuf->big_mask;
}

size_t ring_write(ring_t *rbuf, const void *data, size_t sz){
	size_t size1, size2, num_written;
	void *data1, *data2;
	num_written = ring_get_write_regions(rbuf, sz, &data1, &size1, &data2, &size2);
	if(size2 > 0)
	{
		memcpy(data1, data, size1);
		data = ((char *) data) + size1;
		memcpy(data2, data, size2);
	}
	else
	{
		memcpy(data1, data, size1);
	}
	ring_advance_write_idx(rbuf, num_written);
	return num_written;
}

size_t ring_read(ring_t *rbuf, void *data, size_t sz){
	size_t size1, size2, num_read;
	void *data1, *data2;
	num_read = ring_get_read_regions(rbuf, sz, &data1, &size1, &data2, &size2);
	if(size2 > 0)
	{
		memcpy(data, data1, size1);
		data = ((char *)data) + size1;
		memcpy(data, data2, size2);
	}
	else
	{
		memcpy(data, data1, size1);
	}
	ring_advance_read_idx(rbuf, num_read);
	return num_read;
}
