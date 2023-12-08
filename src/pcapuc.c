/*

pcapuc.c - pcap IP address unique count

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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <Judy.h>
#include <pcap.h>

#include <util/net.h>
#include <util/pcapnet.h>
#include <util/scanfmt.h>
#include <util/util.h>

/* globals */

static char *program_name = "pcapuc";

static bool count_src_only = false;
static bool count_dst_only = false;
static bool count_pairs_only = false;
static bool count_summary_only = false;

static cfgopt_t cfg[] = {
	pcapcfg_device,
	pcapcfg_readfile,
	pcapcfg_bpf,
	pcapcfg_promisc,
	{ 'S', "countsrc",	CONFIG_BOOL, { .boolean = &count_src_only },	"0", "count src addresses only" },
	{ 'D', "countdst",	CONFIG_BOOL, { .boolean = &count_dst_only },	"0", "count dst addresses only" },
	{ 'P', "countpairs",	CONFIG_BOOL, { .boolean = &count_pairs_only },	"0", "count (src, dst) sets only" },
	{ 'C', "countsum",	CONFIG_BOOL, { .boolean = &count_summary_only },"0", "only output the summary count" },
	cfgopt_end
};

static pcap_args_t pa;
static void *pool = NULL;

/* forward declarations */

static void parse_args(int argc, char **argv);
static void print_uniq(void);
static void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void sighandler(int x __unused);
static void usage(const char *msg);

int main(int argc, char **argv){
	parse_args(argc, argv);
	pcapnet_init(&pa);
	pcapnet_setup_signals(sighandler);
	pcapnet_packet_loop(&pa, process_packet);
	pcapnet_close(&pa);
	print_uniq();
	return EXIT_SUCCESS;
}

static void process_packet(u_char *user __unused, const struct pcap_pkthdr *hdr, const u_char *pkt){
	int etype;
	size_t len = hdr->caplen;
	struct iphdr *ip_hdr = (struct iphdr *) pcapnet_start_network_header(pa.datalink, pkt, &etype, &len);
	if(ip_hdr == NULL)
		return;
	if(etype == ETHERTYPE_IP){
		if(count_src_only){
			ipaddr_t addr = my_ntohl(ip_hdr->saddr);
			Word_t *val = (Word_t *) JudyLGet(pool, addr, PJE0);
			if(val == NULL){
				val = (Word_t *) JudyLIns(&pool, addr, PJE0);
				*val = 1;
			}else{
				*val += 1;
			}
		}else if(count_dst_only){
			ipaddr_t addr = my_ntohl(ip_hdr->daddr);
			Word_t *val = (Word_t *) JudyLGet(pool, addr, PJE0);
			if(val == NULL){
				val = (Word_t *) JudyLIns(&pool, addr, PJE0);
				*val = 1;
			}else{
				*val += 1;
			}
		}else if(count_pairs_only){
			ipaddr_t ip[2] = { my_ntohl(ip_hdr->saddr), my_ntohl(ip_hdr->daddr) };
			if(ip[0] > ip[1])
				SWAP(ip[0], ip[1]);

			void **val_ip0 = (void **) JudyLGet(pool, ip[0], PJE0);
			if(val_ip0 == NULL){
				val_ip0 = (void **) JudyLIns(&pool, ip[0], PJE0);
				*val_ip0 = NULL;
			}

			Word_t *val_ip1 = (Word_t *) JudyLGet(*val_ip0, ip[1], PJE0);
			if(val_ip1 == NULL){
				val_ip1 = (Word_t *) JudyLIns(val_ip0, ip[1], PJE0);
				*val_ip1 = 1;
			}else{
				*val_ip1 += 1;
			}
		}
	}
}

static void print_uniq(void){
	if(count_src_only || count_dst_only){
		Word_t ip = 0;
		Word_t *val;
		if(count_summary_only){
			uint64_t count = JudyLCount(pool, 0, -1, PJE0);
			printf("%" PRIu64 "\n", count);
		}else{
			while((val = (Word_t *) JudyLNext(pool, &ip, PJE0)) != NULL){
				char sip[INET_ADDRSTRLEN];
				ipaddr_t ip_copy = my_htonl(ip);
				fmt_ip4(sip, (char *) &ip_copy);
				printf("%s\t%ld\n", sip, (long) *val);
			}
		}
	}else if(count_pairs_only){
		Word_t ip[2] = { 0, 0 };
		Word_t **val_ip0;
		Word_t *val_ip1;
		if(count_summary_only){
			uint64_t count = 0;
			while((val_ip0 = (Word_t **) JudyLNext(pool, &ip[0], PJE0)) != NULL){
				count += JudyLCount(*val_ip0, 0, -1, PJE0);
			}
			printf("%" PRIu64 "\n", count);
		}else{
			uint64_t count = 0;
			while((val_ip0 = (Word_t **) JudyLNext(pool, &ip[0], PJE0)) != NULL){
				while((val_ip1 = (Word_t *) JudyLNext(*val_ip0, &ip[1], PJE0)) != NULL){
					++count;
					char sip0[INET_ADDRSTRLEN];
					char sip1[INET_ADDRSTRLEN];
					ipaddr_t ip0 = my_htonl(ip[0]);
					ipaddr_t ip1 = my_htonl(ip[1]);
					fmt_ip4(sip0, (char *) &ip0);
					fmt_ip4(sip1, (char *) &ip1);
					printf("%s\t%s\t%ld\n", sip0, sip1, (long) *val_ip1);
				}
				ip[1] = 0;
			}
		}
	}
}

static void sighandler(int x __unused){
	pcapnet_break_loop(&pa);
}

static void parse_args(int argc, char **argv){
	cfgopt_parse_args(cfg, argc, argv);
	pcapnet_load_cfg(&pa, cfg);

	if(!pcapnet_are_packets_available(&pa))
		usage("need to specify a packet capture source");
	int c = count_src_only + count_dst_only + count_pairs_only;
	if(c > 1)
		usage("mutually exclusive options selected");
	else if(c == 0)
		usage("select a counting mode");
}

static void usage(const char *msg){
	fprintf(stderr, "Error: %s\n\n", msg);
	fprintf(stderr, "Usage: %s <options>\n", program_name);
	cfgopt_usage(cfg);
	exit(EXIT_FAILURE);
}
