/*

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

#ifndef PCAPNET_H
#define PCAPNET_H

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <pcap.h>

#include "cfgopt.h"
#include "uint.h"
#include "util.h"

/* macros */

#define HENDEL_PCAPERR(pcaphandle, pcapexprn) do{ \
	int rc = pcapexprn; \
	if(rc == -1){ \
		DEBUG("pcap error [" #pcapexprn "]: %s", pcap_geterr(pcaphandle)); \
		exit(EXIT_FAILURE); \
	} \
}while(0)

/* declarations */

#define pcapcfg_device		{ 'i', "device",	CONFIG_STR,	{}, NULL,	"input interface" }
#define pcapcfg_inject		{ 'o', "inject",	CONFIG_STR,	{}, NULL,	"output interface" }
#define pcapcfg_readfile	{ 'r', "readfile",	CONFIG_STR,	{}, NULL,	"input file" }
#define pcapcfg_writefile	{ 'w', "writefile",	CONFIG_STR,	{}, NULL,	"output file" }
#define pcapcfg_bpf		{ 'f', "bpf",		CONFIG_STR,	{}, NULL,	"bpf filter" }
#define pcapcfg_snaplen		{ 's', "snaplen",	CONFIG_DEC,	{}, "1518",	"capture length" }
#define pcapcfg_promisc		{ 'p', "promisc",	CONFIG_BOOL,	{}, "1",	"disable promiscuous mode" }

typedef struct pcap_args {
	bool promisc;
	char *bpf_string;
	char *dev;
	char *dev_out;
	char *fname;
	char *fname_out;
	int datalink;
	int datalink_out;
	int dumpfd;
	int snaplen;
	int to_ms;
	pcap_dumper_t *dumper;
	pcap_t *handle;
	pcap_t *handle_out;
} pcap_args_t;

const u_char *pcapnet_start_network_header(int datalink, const u_char *pkt, int *etype, size_t *len);
const u_char *pcapnet_start_transport_header(int datalink, const u_char *pkt, size_t *len, u8 *proto);
const u_char *pcapnet_start_app_layer(int datalink, const u_char *pkt, size_t *len);
bool pcapnet_are_packets_available(pcap_args_t *);
void pcapnet_break_loop(pcap_args_t *);
void pcapnet_check_datalink_type(int dlt);
void pcapnet_close(pcap_args_t *);
void pcapnet_close_dump(pcap_args_t *);
void pcapnet_init(pcap_args_t *);
void pcapnet_init_bpf(pcap_args_t *);
void pcapnet_init_device(pcap_t **, char *dev, int snaplen, int to_ms, bool promisc);
void pcapnet_init_dump(pcap_args_t *, char *fname);
void pcapnet_init_dumpfd(pcap_args_t *, int fd);
void pcapnet_init_file(pcap_t **, char *fname);
void pcapnet_load_cfg(pcap_args_t *, cfgopt_t *);
void pcapnet_packet_loop(pcap_args_t *, pcap_handler cb);
void pcapnet_print_pkt(const struct pcap_pkthdr *, const u_char *);
void pcapnet_reinit_device(pcap_args_t *);
void pcapnet_setup_signals(void (*sighandler)(int));

#endif
