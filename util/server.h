#ifndef RSEUTIL_SERVER_H
#define RSEUTIL_SERVER_H

#include "socket.h"
#include "uint.h"

extern int setup_tcp_server_socket(const char ip[4], const char ip6[16], u16 port, int backlog);
extern int setup_udp_server_socket(const char ip[4], const char ip6[16], u16 port);

#endif
