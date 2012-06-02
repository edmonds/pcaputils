/*

pcapdump.c - dump and filter pcaps

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

#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <pcap.h>

#include <util/daemon.h>
#include <util/file.h>
#include <util/net.h>
#include <util/pcapnet.h>
#include <util/util.h>
#include <util/rng.h>

#define FNAME_MAXLEN 512

/* globals */

static char *program_name = "pcapdump";

static cfgopt_t cfg[] = {
	pcapcfg_device,
	pcapcfg_readfile,
	pcapcfg_bpf,
	pcapcfg_snaplen,
	pcapcfg_promisc,
	{ 'u', "owner",         CONFIG_STR, {}, "root",  "output file owning user" },
	{ 'g', "group",         CONFIG_STR, {}, "root",  "output file owning group" },
	{ 'm', "mode",          CONFIG_OCT, {}, "0600",  "output file mode" },
	{ 't', "interval",      CONFIG_DEC, {}, "86400", "output file rotation interval" },
	{ 'T', "duration",	CONFIG_DEC, {}, NULL,    "capture duration in seconds" },
	{ 'c', "count",         CONFIG_DEC, {}, NULL,    "packet count limit" },
	{ 'H', "headersonly",   CONFIG_BOOL,{}, "0",     "dump headers only" },
	{ 'S', "sample",        CONFIG_DEC, {}, "0",     "sample value" },
	{ 'R', "random",	CONFIG_BOOL,{}, "0",     "random sampling of packets" },
	{ 'w', "filefmt",       CONFIG_STR, {}, NULL,    "output file format" },
	{ 'P', "pidfile",       CONFIG_STR, {}, NULL,    "pid file" },
	cfgopt_cfgfile,
	cfgopt_end
};

static pcap_args_t pa;

static bool check_interval = false;
static bool headers_only = false;
static bool reload_config = false;
static bool stop_running = false;
static char *pcapdump_filefmt;
static int pcapdump_interval;
static int last_ifdrop;
static int64_t count_bytes;
static int64_t count_packets;
static int64_t pcapdump_packetlimit = -1;
static int64_t pcapdump_duration = -1;
static int64_t total_count_bytes;
static int64_t total_count_dropped;
static int64_t total_count_packets;
static time_t time_lastdump;
static time_t time_start;

static bool pcapdump_sample_random = false;
static int pcapdump_sample;
static int pcapdump_sample_value;

/* forward declarations */

static bool has_config_changed(void);
static bool should_sample(void);
static inline bool is_new_interval(time_t t);
static void check_interval_and_reset(void);
static void close_and_exit(void);
static void daemonize(void);
static void load_config(void);
static void parse_args(int argc, char **argv);
static void print_end_stats(void);
static void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void reset_config(void);
static void reset_dump(void);
static void setup_signals(void);
static void sigalarm_handler(int x __unused);
static void sighup_handler(int x __unused);
static void sigterm_handler(int x __unused);
static void update_and_print_stats(void);
static void usage(const char *msg);

/* functions */

int main(int argc, char **argv){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	time_start = tv.tv_sec;

	setlinebuf(stderr);
	parse_args(argc, argv);
	daemonize();
	reset_config();
	setup_signals();
	reset_dump();
	for(;;){
		pcapnet_packet_loop(&pa, process_packet);
		if(stop_running){
			close_and_exit();
		}else if(check_interval){
			check_interval_and_reset();
		}else if(reload_config){
			reset_config();
			reload_config = false;
		}
		else
			break;
	}
	return EXIT_SUCCESS;
}

static void daemonize(void){
	cfgopt_t *cur = cfgopt_get(cfg, "pidfile");
	if(cur && cur->val.str)
		util_daemonize(program_name, cur->val.str);
}

static void reset_config(void){
	if(!pa.handle){
		/* initial call to reset_config */
		load_config();
		pcapnet_init(&pa);
		cfgopt_print(cfg);
	}else{
		/* called from signal handler */
		if(has_config_changed()){
			load_config();
			pcapnet_reinit_device(&pa);
		}
		reset_dump();
	}
}

static void load_config(void){
	FREE(pa.dev);
	FREE(pa.bpf_string);
	FREE(pcapdump_filefmt);

	pa.dev = cfgopt_get_str_dup(cfg, "device");
	pa.bpf_string = cfgopt_get_str_dup(cfg, "bpf");
	pcapdump_filefmt = cfgopt_get_str_dup(cfg, "filefmt");

	pa.promisc = cfgopt_get_bool(cfg, "promisc");
	pa.snaplen = cfgopt_get_num(cfg, "snaplen");
	pcapdump_interval = cfgopt_get_num(cfg, "interval");
	pcapdump_packetlimit = cfgopt_get_num(cfg, "count");
	pcapdump_duration = cfgopt_get_num(cfg, "duration");
}

static bool has_config_changed(void){
	char *configfile = cfgopt_get_str(cfg, "configfile");
	if(configfile){
		if(!cfgopt_load(cfg, configfile))
			ERROR("configuration error, exiting");
	}

	if(
		cfgopt_get_num(cfg, "interval") != pcapdump_interval ||
		cfgopt_get_num(cfg, "duration") != pcapdump_duration ||
		cfgopt_get_bool(cfg, "promisc")  != pa.promisc ||
		cfgopt_get_num(cfg, "snaplen")  != pa.snaplen ||
		strcmp(pa.bpf_string,   cfgopt_get_str(cfg, "bpf")) != 0 ||
		strcmp(pa.dev,		cfgopt_get_str(cfg, "device")) != 0 ||
		strcmp(pcapdump_filefmt,cfgopt_get_str(cfg, "filefmt")) != 0
	){
		return true;
	}else{
		return false;
	}
}

static void close_and_exit(void){
	print_end_stats();
	pcapnet_close(&pa);
	exit(EXIT_SUCCESS);
}

static void process_packet(u_char *user __unused, const struct pcap_pkthdr *hdr, const u_char *pkt){
	if(
		pcapdump_packetlimit > 0 &&
		total_count_packets + count_packets >= pcapdump_packetlimit
	){
		DEBUG("packet limit reached");
		close_and_exit();
	}
	if(
		pcapdump_duration > 0 &&
		hdr->ts.tv_sec > (time_start + pcapdump_duration)
	){
		DEBUG("duration exceeded");
		close_and_exit();
	}
	if(is_new_interval(hdr->ts.tv_sec))
		reset_dump();
	if(pcapdump_sample > 0 && !should_sample())
		return;
	if(unlikely(!headers_only)){
		pcap_dump((u_char *) pa.dumper, hdr, pkt);
		++count_packets;
		count_bytes += hdr->len;
	}else{
		size_t len = hdr->caplen;
		const u_char *app = pcapnet_start_app_layer(pa.datalink, pkt, &len);
		u32 applen = app - pkt;
		if(app && applen <= (u32) pa.snaplen){
			struct pcap_pkthdr newhdr = {
				.ts = hdr->ts,
				.caplen = applen,
				.len = hdr->len,
			};
			pcap_dump((u_char *) pa.dumper, &newhdr, pkt);
			++count_packets;
			count_bytes += applen;
		}
	}
	return;
}

static bool should_sample(void){
	/* See RFC 5475 for a description of sampling techniques. Comments
	 * in this function use the RFC terminology. */
	if(!pcapdump_sample_random) {
		/* Systematic count-based sampling, section 5.1 */
		if(--pcapdump_sample_value == 0){
			pcapdump_sample_value = pcapdump_sample;
			return true;
		}else{
			return false;
		}
	}else{
		/* Uniform probabilistic sampling, section 5.2.2.1 */
		if(rng_randint(0, pcapdump_sample - 1) == 0){
			return true;
		}else{
			return false;
		}
	}
}

static inline bool is_new_interval(time_t t){
	if(
		(pcapdump_interval > 0) &&
		(((t % pcapdump_interval == 0) && (t != time_lastdump)) ||
			(t - time_lastdump > pcapdump_interval))
	)
		return true;
	else
		return false;
}

static void check_interval_and_reset(void){
	check_interval = false;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if(is_new_interval(tv.tv_sec) && !reload_config)
		reset_dump();
	if(pa.dev)
		alarm(1);
}

static void reset_dump(void){
	if(pa.dumper)
		pcapnet_close_dump(&pa);
	char *fname;
	CALLOC(fname, FNAME_MAXLEN);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm *the_time = gmtime(&tv.tv_sec);
	strftime(fname, FNAME_MAXLEN, pcapdump_filefmt, the_time);

	update_and_print_stats();

	if(pcapdump_interval > 0)
		time_lastdump = tv.tv_sec - (tv.tv_sec % pcapdump_interval);

	int fd = creat_mog(
		fname,
		cfgopt_get_num(cfg, "mode"),
		cfgopt_get_str(cfg, "owner"),
		cfgopt_get_str(cfg, "group")
	);
	pcapnet_init_dumpfd(&pa, fd);
	DEBUG("opened %s", fname);
	FREE(fname);
}

static void update_and_print_stats(void){
	char *rate;
	struct pcap_stat stat;
	unsigned count_dropped;

	rate = human_readable_rate(count_packets, count_bytes, pcapdump_interval);
	if(pcap_stats(pa.handle, &stat) == 0){
		count_dropped = stat.ps_drop - last_ifdrop;
		total_count_dropped = stat.ps_drop;
		last_ifdrop = stat.ps_drop;
		if(time_lastdump > 0 && pcapdump_interval > 0)
			DEBUG("%" PRIi64 " packets dumped (%u dropped) at %s",
				count_packets, count_dropped, rate
			);
	}
	FREE(rate);
	total_count_packets += count_packets;
	total_count_bytes += count_bytes;
	count_packets = 0;
	count_bytes = 0;
}

static void print_end_stats(void){
	char *rate;
	struct pcap_stat stat;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	total_count_packets += count_packets;
	total_count_bytes += count_bytes;
	count_packets = 0;
	count_bytes = 0;
	rate = human_readable_rate(total_count_packets, total_count_bytes, tv.tv_sec - time_start);

	if(pcap_stats(pa.handle, &stat) == 0){
		total_count_dropped += stat.ps_drop;
		if(time_lastdump > 0 && pcapdump_interval > 0)
			DEBUG("%" PRIi64 " total packets dumped (%" PRIi64 " dropped) at %s",
				total_count_packets, total_count_dropped, rate
			);
	}
	FREE(rate);
}

static void setup_signals(void){
	signal(SIGHUP, sighup_handler);
	siginterrupt(SIGHUP, 1);
	pcapnet_setup_signals(sigterm_handler);
	if(pa.dev && pcapdump_interval > 0){
		signal(SIGALRM, sigalarm_handler);
		siginterrupt(SIGALRM, 1);
		alarm(1);
	}
}

static void sigalarm_handler(int x __unused){
	check_interval = true;
	pcapnet_break_loop(&pa);
}

static void sighup_handler(int x __unused){
	reload_config = true;
	pcapnet_break_loop(&pa);
}

static void sigterm_handler(int x __unused){
	stop_running = true;
	pcapnet_break_loop(&pa);
}

static void parse_args(int argc, char **argv){
	cfgopt_t *cur;

	cfgopt_parse_args(cfg, argc, argv);
	pcapnet_load_cfg(&pa, cfg);

	if(!pcapnet_are_packets_available(&pa))
		usage("need to specify a packet capture source");
	if(!cfgopt_is_present(cfg, "filefmt"))
		usage("need to specify output file format");
	if((cur = cfgopt_get(cfg, "configfile")) && cur->val.str && cur->val.str[0] != '/')
		usage("use fully qualified config file path");
	headers_only = cfgopt_get_bool(cfg, "headersonly");
	pcapdump_sample = pcapdump_sample_value = cfgopt_get_num(cfg, "sample");
	pcapdump_sample_random = cfgopt_get_bool(cfg, "random");
	if(pcapdump_sample_random && (pcapdump_sample <= 0))
		usage("random sampling requires a random value");
	if(pcapdump_sample_random)
		rng_seed(false);
	cfgopt_free(cur);
}

static void usage(const char *msg){
	fprintf(stderr, "Error: %s\n\n", msg);
	fprintf(stderr, "Usage: %s <options>\n", program_name);
	cfgopt_usage(cfg);
	exit(EXIT_FAILURE);
}
