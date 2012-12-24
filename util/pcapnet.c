/*

pcapnet.c - libpcap abstraction layer

Copyright (C) 2007 Robert S. Edmonds 

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

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <pcap.h>

#include "cfgopt.h"
#include "net.h"
#include "pcapnet.h"
#include "util.h"

/* functions */

void pcapnet_load_cfg(pcap_args_t *pa, cfgopt_t *cfg){
	cfgopt_t *cur;
	char *str;

	if(!pa || !cfg)
		ERROR("pa or cfg null");

	if((str = cfgopt_get_str(cfg, "device")) && str && str[0] != '\0')
		pa->dev = strdup(str);
	if((str = cfgopt_get_str(cfg, "inject")) && str && str[0] != '\0')
		pa->dev_out = strdup(str);
	if((str = cfgopt_get_str(cfg, "readfile")) && str && str[0] != '\0')
		pa->fname = strdup(str);
	if((str = cfgopt_get_str(cfg, "writefile")) && str && str[0] != '\0')
		pa->fname_out = strdup(str);
	if((str = cfgopt_get_str(cfg, "bpf")) && str && str[0] != '\0')
		pa->bpf_string = strdup(str);
	if((str = cfgopt_get_str(cfg, "kickcmd")) && str && str[0] != '\0')
		pa->kickcmd = strdup(str);

	if((cur = cfgopt_get(cfg, "snaplen")) && cur->val.num)
		pa->snaplen = *cur->val.num;
	if((cur = cfgopt_get(cfg, "promisc")) && cur->val.boolean)
		pa->promisc = *cur->val.boolean;
}

bool pcapnet_are_packets_available(pcap_args_t *pa){
	if(!pa->fname && !pa->dev)
		return false;
	return true;
}

const u_char *pcapnet_start_network_header(
		int datalink,
		const u_char *orig_pkt,
		int *etype, /* modified */
		size_t *len /* modified */
		){
	const u_char *pkt = orig_pkt;
	switch(datalink){
		case DLT_NULL: {
			if(*len < 4)
				return NULL;
			*len -= 4;
			pkt += 4;
			uint32_t x = *(const uint32_t *) pkt;
			if     (x == PF_INET)  *etype = ETHERTYPE_IP;
			else if(x == PF_INET6) *etype = ETHERTYPE_IPV6;
			break;
		}
		case DLT_LOOP: {
			if(*len < 4)
				return NULL;
			*len -= 4;
			pkt += 4;
			uint32_t x = my_ntohl(*(const uint32_t *) pkt);
			if     (x == PF_INET)  *etype = ETHERTYPE_IP;
			else if(x == PF_INET6) *etype = ETHERTYPE_IPV6;
			break;
		}
		case DLT_EN10MB: {
			if(*len < ETH_HLEN)
				return NULL;
			const struct ethhdr *ether = (const struct ethhdr *) pkt;
			*etype = my_ntohs(ether->type);
			*len -= ETH_HLEN;
			pkt += ETH_HLEN;
			if(*etype == ETHERTYPE_VLAN){
				if(*len < 4)
					return NULL;
				*len -= 4;
				*etype = my_ntohs(*(const uint16_t *)(pkt + 2));
				pkt += 4;
			}
			break;
		}
		case DLT_RAW: {
			if(*len < sizeof(struct iphdr))
				return NULL;
			const struct iphdr *ip = (const struct iphdr *) pkt;
			if(ip->ihl == 4U){
				*etype = ETHERTYPE_IP;
			}else if(ip->ihl == 6U){
				*etype = ETHERTYPE_IPV6;
			}else{
				return NULL;
			}
			break;
		}
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL: {
			if(*len < 16)
				return NULL;
			*etype = my_ntohs(*(const uint16_t *)(pkt + 14));
			*len -= 16;
			pkt += 16;
			break;
		}
#endif
	}
	return pkt;
}

const u_char *pcapnet_start_transport_header(
		int datalink,
		const u_char *orig_pkt,
		size_t *len /* modified */,
		u8 *proto /* modified */
		){
	int etype = 0;
	size_t net_len = *len;
	const u_char *pkt = pcapnet_start_network_header(datalink, orig_pkt, &etype, &net_len);
	if(!pkt)
		return NULL;
	switch(etype){
		struct iphdr *ip;
		struct ip6hdr *ip6;

		case ETHERTYPE_IP:
			ip = (void *) pkt;
			if(*len < sizeof(struct iphdr) || *len < (4U * ip->ihl))
				return NULL;
			*len -= 4 * ip->ihl;
			pkt += 4 * ip->ihl;
			*proto = ip->protocol;
			break;

		case ETHERTYPE_IPV6:
			ip6 = (void *) pkt;
			if(*len < sizeof(struct ip6hdr))
				return NULL;
			*len -= sizeof(struct ip6hdr);
			pkt += sizeof(struct ip6hdr);
			*proto = ip6->ip6_nxt;
			break;

		default:
			return NULL;
	}
	switch(*proto){
		case IPPROTO_TCP:
			if(*len < sizeof(struct tcphdr))
				return NULL;
		case IPPROTO_UDP:
			if(*len < sizeof(struct udphdr))
				return NULL;
		case IPPROTO_ICMPV6:
		case IPPROTO_ICMP:
			if(*len < ICMP_HLEN)
				return NULL;
	}
	return pkt;
}

const u_char *pcapnet_start_app_layer(
		int datalink,
		const u_char *orig_pkt,
		size_t *len /* modified */
		){
	u8 proto;
	int etype = 0;
	size_t net_len = *len;
	const u_char *pkt = pcapnet_start_network_header(datalink, orig_pkt, &etype, &net_len);
	if(!pkt)
		return NULL;
	switch(etype){
		struct iphdr *ip;
		struct ip6hdr *ip6;

		ip_header:
		case ETHERTYPE_IP:
			ip = (void *) pkt;
			if(*len < (unsigned) IP_MIN_HLEN || *len < (4U * ip->ihl))
				return NULL;
			*len -= 4 * ip->ihl;
			pkt += 4 * ip->ihl;
			proto = ip->protocol;
			break;

		ipv6_header:
		case ETHERTYPE_IPV6:
			ip6 = (void *) pkt;
			if(*len < sizeof(struct ip6hdr))
				return NULL;
			*len -= sizeof(struct ip6hdr);
			pkt += sizeof(struct ip6hdr);
			proto = ip6->ip6_nxt;
			break;

		default:
			return NULL;
	}
	switch(proto){
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (void *) pkt;
			if(*len < sizeof(struct tcphdr))
				break;
			*len -= sizeof(struct tcphdr);
			pkt += sizeof(struct tcphdr);

			size_t option_octets = 4 * tcp->doff - sizeof(struct tcphdr);
			if(*len < option_octets)
				break;
			*len -= option_octets;
			pkt += option_octets;

			break;
		}
		case IPPROTO_UDP:
			if(*len < UDP_HLEN)
				break;
			*len -= UDP_HLEN;
			pkt += UDP_HLEN;
			break;
		case IPPROTO_ICMPV6:
		case IPPROTO_ICMP:
			if(*len < ICMP_HLEN)
				break;
			*len -= ICMP_HLEN;
			pkt += ICMP_HLEN;
			break;
		case IPPROTO_IPV6:
			goto ipv6_header;
		case IPPROTO_IPIP:
			goto ip_header;
	}
	return pkt;
}

void pcapnet_check_datalink_type(int dlt){
	switch(dlt) {
		case DLT_NULL:
		case DLT_LOOP:
		case DLT_EN10MB:
		case DLT_RAW:
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL:
#endif
			break;
		default:
			ERROR("datalink type %s not supported",
				pcap_datalink_val_to_name(dlt));
	}
}

void pcapnet_init(pcap_args_t *pa){
	if(pa->dev && pa->fname)
		ERROR("cannot read packets from device and file simultaneously");
	if(!(pa->dev || pa->fname))
		ERROR("need a packet capture source");
	if(pa->snaplen < 0 || pa->snaplen > 65536){
		pa->snaplen = 1522;
	}
	if(pa->dev){
		DEBUG("opening capture interface %s%s%s%s",
			pa->dev,
			pa->bpf_string ? " with filter '" : "",
			pa->bpf_string ? pa->bpf_string : "",
			pa->bpf_string ? "'" : ""
		);
		pcapnet_init_device(&pa->handle, pa->dev, pa->snaplen, pa->to_ms, pa->promisc);
		pcapnet_init_bpf(pa);
	}
	if(pa->dev_out){
		DEBUG("opening injection interface %s", pa->dev_out);
		if(pa->dev && strcmp(pa->dev, pa->dev_out) == 0){
			pa->handle_out = pa->handle;
		}else{
			pcapnet_init_device(&pa->handle_out, pa->dev_out, 1, 0, true);
		}
	}
	if(pa->fname){
		pcapnet_init_file(&pa->handle, pa->fname);
		pcapnet_init_bpf(pa);
		DEBUG("reading from pcap file %s link-type %s%s%s%s",
			pa->fname,
			pcap_datalink_val_to_name(pcap_datalink(pa->handle)),
			pa->bpf_string ? " with filter '" : "",
			pa->bpf_string ? pa->bpf_string : "",
			pa->bpf_string ? "'" : ""
		);
	}
	if(pa->fname_out){
		pcapnet_init_dump(pa, pa->fname_out);
	}
	if(pa->handle){
		pa->datalink = pcap_datalink(pa->handle);
		pcapnet_check_datalink_type(pa->datalink);
	}
	if(pa->handle_out){
		pa->datalink_out = pcap_datalink(pa->handle_out);
	}
}

void pcapnet_reinit_device(pcap_args_t *pa){
	if(pa->handle)
		pcap_close(pa->handle);
	pcapnet_init_device(&pa->handle, pa->dev, pa->snaplen, pa->to_ms, pa->promisc);
	pcapnet_init_bpf(pa);
}

void pcapnet_init_bpf(pcap_args_t *pa){
	struct bpf_program pcap_filter;
	if(pa->bpf_string != NULL){
		HENDEL_PCAPERR(pa->handle, pcap_compile(pa->handle, &pcap_filter, pa->bpf_string, 1, 0));
		HENDEL_PCAPERR(pa->handle, pcap_setfilter(pa->handle, &pcap_filter));
		pcap_freecode(&pcap_filter);
	}
}

void pcapnet_init_device(pcap_t **pcap, char *dev, int snaplen, int to_ms, bool promisc){
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	if(NULL == (*pcap = pcap_open_live(dev, snaplen, promisc, to_ms, pcap_errbuf)))
		ERROR("pcap_open_live failed: %s", pcap_errbuf);
}

void pcapnet_init_dump(pcap_args_t *pa, char *fname){
	if(!fname)
		ERROR("filename is nil");
	if(!pa->dumper){
		if(!(pa->dumper = pcap_dump_open(pa->handle, fname))){
			ERROR("pcap_dump_open: %s", pcap_geterr(pa->handle));
		}
	}else{
		ERROR("pcap dumper already initialized");
	}
}

void pcapnet_init_dumpfd(pcap_args_t *pa, int fd){
	if(!pa->dumper){
		FILE *fp = fdopen(fd, "w");
		if(!fp) ERROR("fdopen: %s", strerror(errno));
		if(!(pa->dumper = pcap_dump_fopen(pa->handle, fp))){
			ERROR("pcap_dump_fopen: %s", pcap_geterr(pa->handle));
		}
	}else{
		ERROR("pcap dumper already initialized");
	}
}

void pcapnet_init_file(pcap_t **pcap, char *fname){
	FILE *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(strcmp(fname, "-") == 0)
		fp = fdopen(0, "r");
	else
		fp = fopen(fname, "r");
	if(fp == NULL)
		ERROR("f(d)open failed: %s", strerror(errno));
	if(NULL == (*pcap = pcap_fopen_offline(fp, errbuf)))
		ERROR("pcap_fopen_offline failed: %s", errbuf);
}

void pcapnet_close(pcap_args_t *pa){
	pcapnet_close_dump(pa);
	if(pa->handle_out){
		DEBUG("closing handle_out");
		pcap_close(pa->handle_out);
		pa->handle_out = NULL;
	}
	if(pa->handle){
		DEBUG("closing handle");
		pcap_close(pa->handle);
		pa->handle = NULL;
	}
	FREE(pa->dev);
	FREE(pa->dev_out);
	FREE(pa->fname);
	FREE(pa->fname_out);
	FREE(pa->kickcmd);
}

/* see sf-pcap.c (pcap_dump_flush and pcap_dump_close) */
void pcapnet_close_dump(pcap_args_t *pa){
	if(pa->dumper){
		if(pa->fname_out)
			DEBUG("closing pcap file %s", pa->fname_out);

		sigset_t new_mask;
		sigset_t old_mask;

		if (sigfillset(&new_mask) == -1)
			ERROR("initializing full signal set failed: %s", strerror(errno));
		if (sigemptyset(&old_mask) == -1)
			ERROR("initializing empty signal set failed: %s", strerror(errno));

		if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1)
			ERROR("blocking signals failed: %s", strerror(errno));

		if (fflush((FILE *)pa->dumper) != 0)
			ERROR("fflush failed: %s", strerror(errno));

		if (ferror((FILE *)pa->dumper) != 0)
			ERROR("ferror failed: %s", strerror(errno));

		if (fclose((FILE *)pa->dumper) != 0)
			ERROR("fclose failed: %s", strerror(errno));

		if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
			ERROR("unblocking signals failed: %s", strerror(errno));

		pa->dumper = NULL;

		if(pa->kickcmd != NULL && pa->fname_out != NULL){
			char *cmd = NULL;
			if(asprintf(&cmd, "%s \"%s\" &", pa->kickcmd, pa->fname_out) < 0)
				ERROR("cannot initialize kick command string");
			DEBUG("running '%s'", cmd);
			system(cmd);
			free(cmd);
		}
	}
}

void pcapnet_packet_loop(pcap_args_t *pa, pcap_handler cb){
	if(!pa || !(pa->handle))
		ERROR("pcap handle not initialized");
	int res = pcap_loop(pa->handle, -1, cb, (void *)pa);
	DEBUG("pcap_loop returned %i", res);
	if (res == -1)
		ERROR("pcap_loop failed: %s", pcap_geterr(pa->handle));
}

void pcapnet_break_loop(pcap_args_t *pa){
	if(!pa || !(pa->handle))
		ERROR("pcap handle not initialized");
	pcap_breakloop(pa->handle);
}

void pcapnet_setup_signals(void (*sighandler)(int)){
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	siginterrupt(SIGINT, 1);
	siginterrupt(SIGTERM, 1);
}

void pcapnet_print_pkt(const struct pcap_pkthdr *hdr, const u_char *pkt){
	int c = 0;
	for(unsigned i = 0 ; i < hdr->caplen ; ++i, ++c){
		if(c == 25){
			c = 0;
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "%2.x ", pkt[i]);
	}
}

/* copied from pcap-int.h */
struct pcap_timeval {
	bpf_int32 tv_sec;       /* seconds */
	bpf_int32 tv_usec;      /* microseconds */
};

/* copied from pcap-int.h */
struct pcap_sf_pkthdr {
	struct pcap_timeval ts; /* time stamp */
	bpf_u_int32 caplen;     /* length of portion present */
	bpf_u_int32 len;        /* length this packet (off wire) */
};

/* copied from sf-pcap.c - adapted to be safely used with signals */
void pcapnet_dump_pkt(u_char *dumper, const struct pcap_pkthdr *h, const u_char *pkt){
	FILE *f;
	struct pcap_sf_pkthdr sf_hdr;
	sigset_t new_mask;
	sigset_t old_mask;

	f = (FILE *)dumper;

	sf_hdr.ts.tv_sec  = h->ts.tv_sec;
	sf_hdr.ts.tv_usec = h->ts.tv_usec;
	sf_hdr.caplen     = h->caplen;
	sf_hdr.len        = h->len;

	if (sigfillset(&new_mask) == -1)
		ERROR("initializing full signal set failed: %s", strerror(errno));
	if (sigemptyset(&old_mask) == -1)
		ERROR("initializing empty signal set failed: %s", strerror(errno));

	if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1)
		ERROR("blocking signals failed: %s", strerror(errno));

	if (fwrite(&sf_hdr, sizeof(sf_hdr), 1, f) != 1)
		ERROR("writing packet header failed: %s", strerror(errno));
	if (fwrite(pkt, h->caplen, 1, f) != 1)
		ERROR("writing packet body failed: %s", strerror(errno));

	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
		ERROR("unblocking signals failed: %s", strerror(errno));
}
