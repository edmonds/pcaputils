#ifndef RSEUTIL_NET_H
#define RSEUTIL_NET_H

#include "config.h"

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

#ifdef HAVE_SYS_ENDIAN_H
# include <sys/endian.h>
#endif

#include <stdint.h>

#include "uint.h"
#include "util.h"

/* macros */

#define INET_ADDRSTRLEN	16
#define IP_MIN_HLEN	20
#define UDP_HLEN	8
#define ICMP_HLEN	4
#define ETH_ALEN	6
#define ETH_HLEN	14
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_IPV6	0x86dd
#define ETHERTYPE_ARP	0x0806
#define ETHERTYPE_VLAN	0x8100

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000

#if !defined(IPPROTO_ICMP)
#define IPPROTO_ICMP	1
#endif

#if !defined(IPPROTO_IPIP)
#define IPPROTO_IPIP	4
#endif

#if !defined(IPPROTO_TCP)
#define IPPROTO_TCP	6
#endif

#if !defined(IPPROTO_UDP)
#define IPPROTO_UDP	17
#endif

#if !defined(IPPROTO_IPV6)
#define IPPROTO_IPV6	41
#endif

#if !defined(IPPROTO_ICMPV6)
#define IPPROTO_ICMPV6	58
#endif

#if !defined(INET6_ADDRSTRLEN)
#define INET6_ADDRSTRLEN 46
#endif

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCPFLAGS_STRLEN sizeof("FSRPAU")

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define my_ntohs(x) my_bswap16(x)
#define my_htons(x) my_bswap16(x)
#define my_ntohl(x) my_bswap32(x)
#define my_htonl(x) my_bswap32(x)
#else
#define my_ntohs(x) (x)
#define my_htons(x) (x)
#define my_ntohl(x) (x)
#define my_htonl(x) (x)
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

/* declarations */

struct ethhdr {
	char dst[ETH_ALEN];
	char src[ETH_ALEN];
	u16 type;
} __attribute__ ((__packed__));

struct arphdr {
	u16 fmt_hw;	/* hardware address format */
	u16 fmt_proto;	/* protocol address format */
	u8 len_hw;	/* length of hardware address */
	u8 len_proto;	/* length of protocol address */
	u16 opcode;
	char sender_hw[ETH_ALEN];
	char sender_ip[4];
	char target_hw[ETH_ALEN];
	char target_ip[4];
} __attribute__ ((__packed__));

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPHRD_ETHER 1

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#endif
	u8 tos;
	u16 tot_len;
	u16 id;
	u16 frag_off;
	u8 ttl;
	u8 protocol;
	u16 check;
	u32 saddr;
	u32 daddr;
} __attribute__ ((__packed__));

struct ip6hdr {
	union {
		struct ip6_hdrctl {
			u32 ip6_un1_flow; /* 20 bits of flow-ID */
			u16 ip6_un1_plen; /* payload length */
			u8  ip6_un1_nxt;  /* next header */
			u8  ip6_un1_hlim; /* hop limit */
		} ip6_un1;
		u8 ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	char src[16];
	char dst[16];
} __attribute__ ((__packed__));

#define ip6_vfc  ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt  ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim

struct icmphdr {
	u8 type;
	u8 code;
	u16 check;
	union {
		struct {
			u16 id;
			u16 seq;
		} echo;
		u32 gateway;
		struct {
			u16 unused;
			u16 mtu;
		} frag; /* pmtud */
	} un;
} __attribute__ ((__packed__));

#define ICMP_ECHOREPLY	0
#define ICMP_ECHO	8

struct tcphdr {
	u16 source;
	u16 dest;
	u32 seq;
	u32 ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u16 res1:4;
	u16 doff:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u16 doff:4;
	u16 res1:4;
#endif
	u8 flags;
	u16 window;
	u16 check;
	u16 urg_ptr;
} __attribute__ ((__packed__));

struct pseudo_tcphdr {
	u32 saddr;
	u32 daddr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u8 proto;
	u8 zero;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u8 zero;
	u8 proto;
#endif
	u16 tot_len;
} __attribute__ ((__packed__));

struct udphdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
} __attribute__ ((__packed__));

struct dnshdr {
	unsigned id :16;	 /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
		 /* fields in third byte */
	unsigned qr: 1;	  /* response flag */
	unsigned opcode: 4;      /* purpose of message */
	unsigned aa: 1;	  /* authoritive answer */
	unsigned tc: 1;	  /* truncated message */
	unsigned rd: 1;	  /* recursion desired */
		 /* fields in fourth byte */
	unsigned ra: 1;	  /* recursion available */
	unsigned unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
	unsigned ad: 1;	  /* authentic data from named */
	unsigned cd: 1;	  /* checking disabled by resolver */
	unsigned rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
			/* fields in third byte */
	unsigned rd :1;	  /* recursion desired */
	unsigned tc :1;	  /* truncated message */
	unsigned aa :1;	  /* authoritive answer */
	unsigned opcode :4;      /* purpose of message */
	unsigned qr :1;	  /* response flag */
		 /* fields in fourth byte */
	unsigned rcode :4;       /* response code */
	unsigned cd: 1;	  /* checking disabled by resolver */
	unsigned ad: 1;	  /* authentic data from named */
	unsigned unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
	unsigned ra :1;	  /* recursion available */
#endif
		 /* remaining bytes */
	unsigned qdcount :16;    /* number of question entries */
	unsigned ancount :16;    /* number of answer entries */
	unsigned nscount :16;    /* number of authority entries */
	unsigned arcount :16;    /* number of resource entries */
} __attribute__ ((__packed__));

typedef u32 ipaddr_t;
typedef u16 port_t;

typedef struct ipaddr_range {
	char ip0[4];
	char ip1[4];
} ipaddr_range_t;

bool gai4(const char *hostname, char ip[4]);
bool gai6(const char *hostname, char ip[16]);
char *human_readable_rate(u64 packets, u64 bytes, unsigned interval);
ipaddr_range_t sips_to_range(char *sip0, char *sip1);
u16 random_unprivileged_port(void);
u16 my_bswap16(u16 x);
u32 my_bswap32(u32 x);

#endif
