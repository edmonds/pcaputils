#ifndef RSEUTIL_SOCKET_H
#define RSEUTIL_SOCKET_H

#include <sys/socket.h>
#include <unistd.h>

#include "byte.h"
#include "uint.h"

extern const char V4any[4];
extern const char V4loopback[4];
extern const char V4mappedprefix[12];
extern const char V6loopback[16];
extern const char V6any[16];

#define ip6_isv4mapped(ip) (byte_equal(ip,12,V4mappedprefix))

extern int socket_accept6(int s, char *ip, u16 *port, u32 *scope_id);
extern int socket_bind4(int s, const char *ip, u16);
extern int socket_bind4_reuse(int s, const char *ip, u16);
extern int socket_bind6(int s, const char *ip, u16 port, u32 scope_id);
extern int socket_bind6_reuse(int s, const char *ip, u16 port, u32 scope_id);
extern int socket_connect4(int s, const char *ip, u16 port);
extern int socket_connect6(int s, const char *ip, u16 port, u32 scope_id);
extern int socket_listen(int s, unsigned backlog);
extern int socket_recv4(int s, char *buf, int len, char ip[4], u16 *port);
extern int socket_recv6(int s, char *buf, unsigned len, char *ip, u16 *port, u32 *scope_id);
extern int socket_send4(int s, const char *buf, int len, const char ip[4], u16 port);
extern int socket_send6(int s, const char *buf, unsigned len, const char *ip, u16 port, u32 scope_id);
extern int socket_tcp(void);
extern int socket_tcp6(void);
extern int socket_udp(void);
extern int socket_udp6(void);

#endif
