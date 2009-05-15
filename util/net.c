/*

net.c - functions useful for programs which interact with the network

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

#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "byte.h"
#include "net.h"
#include "scanfmt.h"
#include "uint.h"
#include "util.h"

/* functions */

u32 my_bswap32(u32 x){
	return  ((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}

u16 my_bswap16(u16 x){
	return (u16) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}

ipaddr_range_t sips_to_range(char *sip0, char *sip1){
	ipaddr_range_t ipr;
	scan_ip4(sip0, ipr.ip0);
	scan_ip4(sip1, ipr.ip1);
	return ipr;
}

char *human_readable_rate(u64 packets, u64 bytes, unsigned interval){
	char prefix_packets[] = "\0\0";
	char prefix_bytes[] = "\0\0";
	char *str;
	CALLOC(str, 64);

	double div_packets = ((double) packets) / interval;
	double div_bytes = ((double) bytes) / interval;

	if(div_packets >= 1E9){
		prefix_packets[0] = 'G';
		div_packets /= 1E9;
	}else if(div_packets >= 1E6){
		prefix_packets[0] = 'M';
		div_packets /= 1E6;
	}else if(div_packets >= 1E3){
		prefix_packets[0] = 'K';
		div_packets /= 1E3;
	}

	if(div_bytes >= 1E9){
		prefix_bytes[0] = 'G';
		div_bytes /= 1E9;
	}else if(div_bytes >= 1E6){
		prefix_bytes[0] = 'M';
		div_bytes /= 1E6;
	}else if(div_bytes >= 1E3){
		prefix_bytes[0] = 'K';
		div_bytes /= 1E3;
	}

	snprintf(str, 64, "%.2f %spps, %.2f %sBps",
		div_packets, prefix_packets, div_bytes, prefix_bytes);
	return str;
}

u16 random_unprivileged_port(void){
	long r = random();
	r &= 0xffff;
	r |= 0x400;
	return (u16) r;
}

bool gai4(const char *hostname, char ip[4]){
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = 0,
		.ai_protocol = 0
	};
	struct addrinfo *res;

	if(0 == getaddrinfo(hostname, NULL, &hints, &res)){
		byte_copy(ip, 4, (char *) &((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr);
		freeaddrinfo(res);
		return true;
	}else{
		DEBUG("getaddrinfo() returned: %s", strerror(errno));
	}
	return false;
}

bool gai6(const char *hostname, char ip[16]){
	struct addrinfo hints = {
		.ai_family = AF_INET6,
		.ai_socktype = 0,
		.ai_protocol = 0
	};
	struct addrinfo *res;

	if(0 == getaddrinfo(hostname, NULL, &hints, &res)){
		byte_copy(ip, 16, (char *) &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr);
		freeaddrinfo(res);
		return true;
	}else{
		DEBUG("getaddrinfo() returned: %s", strerror(errno));
	}
	return false;
}
