/*

pcapip.c - pcap IP filter

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

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <pcap.h>

#include <util/cfgopt.h>
#include <util/getline.h>
#include <util/net.h>
#include <util/pcapnet.h>
#include <util/scanfmt.h>
#include <util/util.h>

/* globals */

static char *program_name = "pcapip";

static cfgopt_t cfg[] = {
	pcapcfg_device,
	pcapcfg_bpf,
	pcapcfg_readfile,
	pcapcfg_writefile,
	pcapcfg_snaplen,
	pcapcfg_promisc,
	{ 'l', "list", CONFIG_STR, {}, NULL, "file containing list of IP addresses" },
	cfgopt_end
};

static pcap_args_t pa;
static void *pool = NULL;

/* forward declarations */

static void parse_args(int argc, char **argv);
static void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void read_ipfile(char *fname);
static void sighandler(int x __unused);
static void usage(const char *msg);

/* functions */

int main(int argc, char **argv){
	parse_args(argc, argv);
	read_ipfile(cfgopt_get_str(cfg, "list"));
	pcapnet_init(&pa);
	pcapnet_setup_signals(sighandler);
	pcapnet_packet_loop(&pa, process_packet);
	pcapnet_close(&pa);
	return EXIT_SUCCESS;
}

static void sighandler(int x __unused){
	pcapnet_break_loop(&pa);
}

static void process_packet(u_char *user __unused, const struct pcap_pkthdr *hdr, const u_char *pkt){
	int etype;
	size_t len = hdr->caplen;
	struct iphdr *ip_hdr = (struct iphdr *) pcapnet_start_network_header(pa.datalink, pkt, &etype, &len);
	if(ip_hdr == NULL)
		return;
	if(etype == ETHERTYPE_IP){
		if(JudyLGet(pool, my_ntohl(ip_hdr->saddr), PJE0)){
			pcap_dump((u_char *) pa.dumper, hdr, pkt);
		}else
		if(JudyLGet(pool, my_ntohl(ip_hdr->daddr), PJE0)){
			pcap_dump((u_char *) pa.dumper, hdr, pkt);
		}
	}
}

static void read_ipfile(char *fname){
	char *line = NULL;
	size_t len = 0;
	FILE *fp = fopen(fname, "r");
	if(fp == NULL){
		ERROR("unable to open file '%s'", fname);
	}
	while(getline(&line, &len, fp) != -1){
		ipaddr_t addr;
		scan_ip4(line, (char *) &addr);
		addr = my_ntohl(addr);
		Word_t *val = (Word_t *)JudyLGet(pool, addr, PJE0);
		if(val == NULL){
			val = (Word_t *)JudyLIns(&pool, addr, PJE0);
		}
	}
	FREE(line);
}

static void parse_args(int argc, char **argv){
	cfgopt_parse_args(cfg, argc, argv);
	pcapnet_load_cfg(&pa, cfg);

	if(!pcapnet_are_packets_available(&pa))
		usage("need to specify a packet capture source");
	if(!cfgopt_is_present(cfg, "writefile"))
		usage("need to specify output file");
	if(!cfgopt_is_present(cfg, "list"))
		usage("need to specify an IP list file");
}

static void usage(const char *msg){
	fprintf(stderr, "Error: %s\n\n", msg);
	fprintf(stderr, "Usage: %s <options>\n", program_name);
	cfgopt_usage(cfg);
	exit(EXIT_FAILURE);
}
