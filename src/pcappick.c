/*

pcappick.c - pick a pcap frame

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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <util/cfgopt.h>
#include <util/pcapnet.h>
#include <util/util.h>

/* globals */

static char *program_name = "pcappick";

static cfgopt_t cfg[] = {
	pcapcfg_device,
	pcapcfg_readfile,
	pcapcfg_writefile,
	pcapcfg_bpf,
	pcapcfg_snaplen,
	pcapcfg_promisc,
	{ 'c', "count", CONFIG_DEC, {}, NULL, "frame number to pick" },
	cfgopt_end
};

static pcap_args_t pa;
static uint64_t count_packet = 0;
static uint64_t count_target = 0;

/* forward declarations */

static void parse_args(int argc, char **argv);
static void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void usage(const char *msg);

/* functions */

int main(int argc, char **argv){
	parse_args(argc, argv);
	pcapnet_init(&pa);
	pcapnet_packet_loop(&pa, process_packet);
	pcapnet_close(&pa);
	return EXIT_FAILURE;
}

static void process_packet(u_char *user __unused, const struct pcap_pkthdr *hdr, const u_char *pkt){
	++count_packet;
	if(count_packet == count_target){
		pcap_dump((u_char *) pa.dumper, hdr, pkt);
		pcapnet_close(&pa);
		exit(EXIT_SUCCESS);
	}
}

static void parse_args(int argc, char **argv){
	cfgopt_parse_args(cfg, argc, argv);
	pcapnet_load_cfg(&pa, cfg);

	if(!pcapnet_are_packets_available(&pa))
		usage("need to specify a packet capture source");
	if(!cfgopt_is_present(cfg, "count"))
		usage("need a frame number");
	count_target = cfgopt_get_num(cfg, "count");
}

static void usage(const char *msg){
	fprintf(stderr, "Error: %s\n\n", msg);
	fprintf(stderr, "Usage: %s <options>\n", program_name);
	cfgopt_usage(cfg);
	exit(EXIT_FAILURE);
}
