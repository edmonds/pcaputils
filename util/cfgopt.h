#ifndef CFGOPT_H
#define CFGOPT_H

#include <stdbool.h>

#include "util.h"

/* declarations */

enum CFGOPT_TYPE {
	CONFIG_STR,
	CONFIG_DEC,
	CONFIG_OCT,
	CONFIG_BOOL,
	CONFIG_IP,
	CONFIG_IP6,
	CONFIG_MAC,
	CONFIG_NONOPT,
	CONFIG_END
};

typedef struct cfgopt {
	char cmd;
	char *key;
	enum CFGOPT_TYPE type;
	union {
		char *str;
		long *num;
		bool *boolean;
		char *ip;
		char *ip6;
		char *mac;
		char *nonopt;
	} val;
	char *default_value;
	char *help;
} cfgopt_t;

#define cfgopt_cfgfile  { 'C', "configfile", CONFIG_STR, {}, NULL, "config file" }
#define cfgopt_help     { 'h', "help", CONFIG_BOOL, {}, "0", "show help" }
#define cfgopt_verbose  { 'V', "verbose", CONFIG_BOOL, { .boolean = &util_flag_verbose }, "0", "verbose output" }
#define cfgopt_nonopt	{ '\0', "", CONFIG_NONOPT, {}, "", "" }
#define cfgopt_end      { '\0', "", CONFIG_END, {}, "", "" }

/* functions */

extern bool cfgopt_load(cfgopt_t *, char *fname);
extern size_t cfgopt_len(cfgopt_t *);
extern void cfgopt_free(cfgopt_t *);
extern void cfgopt_parse_args(cfgopt_t *, int argc, char **argv);
extern void cfgopt_print(cfgopt_t *);
extern void cfgopt_usage(cfgopt_t *);

extern bool cfgopt_get_bool(cfgopt_t *, char *key);
extern bool cfgopt_is_present(cfgopt_t *, char *key);
extern cfgopt_t *cfgopt_get(cfgopt_t *, char *key);
extern char *cfgopt_get_ip(cfgopt_t *, char *key);
extern char *cfgopt_get_ip6(cfgopt_t *, char *key);
extern char *cfgopt_get_mac(cfgopt_t *, char *key);
extern char *cfgopt_get_nonopt(cfgopt_t *);
extern char *cfgopt_get_str(cfgopt_t *, char *key);
extern char *cfgopt_get_str_dup(cfgopt_t *, char *key);
extern long cfgopt_get_num(cfgopt_t *, char *key);

#endif
