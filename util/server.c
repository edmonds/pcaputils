/*

server.c - functions useful for programs which provide network services

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

#include "scanfmt.h"
#include "server.h"
#include "socket.h"
#include "uint.h"
#include "util.h"

int setup_tcp_server_socket(const char ip[4], const char ip6[16], u16 port, int backlog){
	char sip[FMT_IP6];
	int fd;

	fd = socket_tcp6();
	if(fd >= 0){
		if(socket_bind6_reuse(fd, ip6, port, 0) == -1){
			close(fd);
			fd = socket_tcp();
			if(fd >= 0){
				if(-1 == socket_bind4_reuse(fd, ip, port))
					ERROR("unable to create server socket: %s", strerror(errno));
				else{
					fmt_ip4(sip, ip);
					DEBUG("bound TCP socket on %s:%hu", sip, port);
				}
			}else{
				ERROR("unable to create TCP socket: %s", strerror(errno));
			}
		}else{
			fmt_ip6(sip, ip6);
			DEBUG("bound TCP socket on [%s]:%hu", sip, port);
		}
		if(socket_listen(fd, backlog) == -1)
			ERROR("listen() failed: %s", strerror(errno));
	}else{
		ERROR("unable to create TCP socket: %s", strerror(errno));
	}
	return fd;
}

int setup_udp_server_socket(const char ip[4], const char ip6[16], u16 port){
	char sip[FMT_IP6];
	int fd;

	fd = socket_udp6();
	if(fd >= 0){
		if(socket_bind6(fd, ip6, port, 0) == -1){
			close(fd);
			fd = socket_udp();
			if(socket_bind4(fd, ip, port) == -1){
				ERROR("unable to create server socket: %s", strerror(errno));
			}else{
				fmt_ip4(sip, ip);
				DEBUG("bound UDP socket on %s:%hu", sip, port);
			}
		}else{
			fmt_ip6(sip, ip6);
			DEBUG("bound UDP socket on [%s]:%hu", sip, port);
		}
	}else{
		ERROR("unable to create UDP socket: %s", strerror(errno));
	}
	return fd;
}
