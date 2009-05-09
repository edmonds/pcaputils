#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "byte.h"
#include "socket.h"
#include "uint.h"

/* from libowfat */

/*
 Copyright (c) 2001 Felix von Leitner.
 All rights reserved.

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License Version 2 as published
 by the Free Software Foundation.
*/

const char V4any[4]={0,0,0,0};
const char V4loopback[4]={127,0,0,1};
const char V4mappedprefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
const char V6loopback[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const char V6any[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

int socket_tcp6(void){
	int s;

	s = socket(PF_INET6, SOCK_STREAM, 0);
	if(s == -1 && errno == EINVAL)
		s = socket(PF_INET, SOCK_STREAM, 0);
	return s;
}

int socket_tcp(void){
	int s;

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1) return -1;
	return s;
}

int socket_bind6(int s, const char ip[16], u16 port, u32 scope_id){
	struct sockaddr_in6 sa;
	
	byte_zero(&sa, sizeof sa);
	sa.sin6_family = AF_INET6;
	u16_pack_big((char *) &sa.sin6_port, port);
	/* implicit: sa.sin6_flowinfo = 0; */
	byte_copy((char *) &sa.sin6_addr, 16, ip);
	sa.sin6_scope_id = scope_id;

	return bind(s, (struct sockaddr *) &sa, sizeof sa);
}

int socket_bind6_reuse(int s, const char ip[16], u16 port, u32 scope_id){
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
	return socket_bind6(s, ip, port, scope_id);
}

int socket_listen(int s, unsigned backlog){
	return listen(s, backlog);
}

int socket_accept6(int s, char ip[16], u16 *port, u32 *scope_id){
	struct sockaddr_in6 sa;
	unsigned dummy = sizeof sa;
	int fd;

	fd = accept(s, (struct sockaddr *) &sa, &dummy);
	if(fd == -1) return -1;
	if(sa.sin6_family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *) &sa;
		byte_copy(ip, 12, V4mappedprefix);
		byte_copy(ip + 12, 4, (char *) &sa4->sin_addr);
		u16_unpack_big((char *) &sa4->sin_port, port);
		return fd;
	}
	byte_copy(ip, 16, (char *) &sa.sin6_addr);
	u16_unpack_big((char *) &sa.sin6_port, port);
	if(scope_id) *scope_id = sa.sin6_scope_id;
	return fd;
}

int socket_recv6(int s, char *buf, unsigned len, char ip[16], u16 *port, u32 *scope_id){
	struct sockaddr_in6 sa;
	unsigned int dummy = sizeof sa;
	int r;

	byte_zero(&sa, dummy);
	r = recvfrom(s, buf, len, 0, (struct sockaddr *) &sa, &dummy);
	if(r == -1) return -1;

	byte_copy(ip, 16, (char *) &sa.sin6_addr);
	u16_unpack_big((char *) &sa.sin6_port, port);
	if(scope_id) *scope_id = sa.sin6_scope_id;

	return r;
}

int socket_bind4(int s, const char ip[4], u16 port){
	struct sockaddr_in sa;

	byte_zero(&sa, sizeof sa);
	sa.sin_family = AF_INET;
	u16_pack_big((char *) &sa.sin_port,port);
	byte_copy((char *) &sa.sin_addr, 4, ip);

	return bind(s, (struct sockaddr *) &sa, sizeof sa);
}

int socket_bind4_reuse(int s, const char ip[4], u16 port){
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
	return socket_bind4(s, ip, port);
}

int socket_connect4(int s, const char ip[4], u16 port){
	struct sockaddr_in sa;

	byte_zero(&sa, sizeof sa);
	sa.sin_family = AF_INET;
	u16_pack_big((char *) &sa.sin_port, port);
	byte_copy((char *) &sa.sin_addr, 4, ip);

	return connect(s, (struct sockaddr *) &sa, sizeof sa);
}

int socket_connect6(int s, const char ip[16], u16 port, u32 scope_id){
	struct sockaddr_in6 sa;

	byte_zero(&sa, sizeof sa);
	sa.sin6_family = PF_INET6;
	u16_pack_big((char *) &sa.sin6_port, port);
	sa.sin6_flowinfo = 0;
	sa.sin6_scope_id = scope_id;
	byte_copy((char *) &sa.sin6_addr, 16, ip);

	return connect(s, (struct sockaddr *) &sa, sizeof sa);
}

int socket_udp6(void){
	int s;

	s = socket(PF_INET6, SOCK_DGRAM, 0);
	if(s == -1){
		if(errno == EINVAL)
			s = socket(PF_INET, SOCK_DGRAM, 0);
	}
	return s;
}

int socket_udp(void){
	return socket(PF_INET, SOCK_DGRAM, 0);
}

int socket_send4(int s, const char *buf, int len, const char ip[4], u16 port){
	struct sockaddr_in sa;

	byte_zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	u16_pack_big((char *) &sa.sin_port, port);
	byte_copy((char *) &sa.sin_addr, 4, ip);

	return sendto(s, buf, len, 0, (struct sockaddr *) &sa, sizeof(sa));
}

int socket_recv4(int s, char *buf, int len, char ip[4], u16 *port){
	struct sockaddr_in sa;
	socklen_t dummy = sizeof(sa);
	int r;

	r = recvfrom(s, buf, len, 0, (struct sockaddr *) &sa, &dummy);
	if(r == -1) return -1;
	byte_copy(ip, 4, (char *) &sa.sin_addr);
	u16_unpack_big((char *) &sa.sin_port, port);

	return r;
}
