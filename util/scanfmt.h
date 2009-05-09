#ifndef RSEUTIL_SCANFMT_H
#define RSEUTIL_SCANFMT_H

#define FMT_IP4 20
#define FMT_IP6 40
#define FMT_MAC 20

extern unsigned fmt_ulong(char *s, unsigned long u);
extern unsigned scan_ulong(const char *s, unsigned long *u);

extern unsigned fmt_ip4(char *s, const char ip[4]);
extern unsigned scan_ip4(const char *s, char ip[4]);

extern unsigned fmt_ip6(char *s, const char ip[16]);
extern unsigned scan_ip6(const char *s, char ip[16]);

extern unsigned fmt_xlong(char *s, unsigned long u);
extern unsigned scan_xlong(const char *s, unsigned long *d);

extern int scan_fromhex(unsigned char c);

extern unsigned fmt_mac(char *s, const char mac[6]);
extern unsigned scan_mac(const char *s, char mac[6]);

#endif
