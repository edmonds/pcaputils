/*

cfgopt.c - unified config file / command line option parsing

Copyright (C) 2008 Robert S. Edmonds 

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

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "cfgopt.h"
#include "scanfmt.h"
#include "util.h"

/* declarations */

static void cfgopt_load_value(cfgopt_t *cfg, char *value);

/* functions */

bool cfgopt_load(cfgopt_t *cfg, char *fname){
	FILE *fp;
	size_t len;
	char *line = NULL;
	bool success = true;

	if(!cfg || !fname)
		return false;
	if(!(fp = fopen(fname, "r")))
		ERROR("fopen() failed: %s", strerror(errno));
	while(getline(&line, &len, fp) != -1){
		char *tok_key;
		char *tok_val;
		tok_key = strtok(line, "=\"\t\n");
		if(!tok_key) continue;
		tok_val = strtok(NULL, "\"\t\n");
		if(!tok_val){
			DEBUG("null value for key='%s'", tok_key);
			continue;
		}

		cfgopt_t *cur = cfgopt_get(cfg, tok_key);
		if(!cur){
			DEBUG("unknown configuration key '%s'", tok_key);
			success = false;
			continue;
		}else{
			cfgopt_load_value(cur, tok_val);
		}

		FREE(line);
	}
	for(; cfg->type != CONFIG_END ; ++cfg)
		if(!cfg->val.str)
			cfgopt_load_value(cfg, cfg->default_value);
	FREE(line);
	fclose(fp);
	return success;
}

static void cfgopt_load_value(cfgopt_t *cfg, char *value){
	if(!value) return;
	switch(cfg->type){
	case CONFIG_STR: {
		cfg->val.str = strdup(value);
		break;
	}
	case CONFIG_DEC:
	case CONFIG_OCT: {
		int base = cfg->type == CONFIG_DEC ? 0 : 8;
		if(!cfg->val.num) NEW0(cfg->val.num);
		*cfg->val.num = strtoul(value, NULL, base);
		break;
	}
	case CONFIG_BOOL: {
		if(!cfg->val.boolean) NEW0(cfg->val.boolean);
		*cfg->val.boolean = (bool) strtoul(value, NULL, 0);
		break;
	}
	case CONFIG_IP: {
		char *ip;
		MALLOC(ip, 4);
		if(scan_ip4(value, ip) == 0)
			ERROR("invalid IPv4 literal: %s", value);
		cfg->val.ip = ip;
		break;
	}
	case CONFIG_IP6: {
		char *ip6;
		MALLOC(ip6, 16);
		if(scan_ip6(value, ip6) == 0)
			ERROR("invalid IPv6 literal: %s", value);
		cfg->val.ip6 = ip6;
		break;
	}
	case CONFIG_MAC: {
		char *mac;
		MALLOC(mac, 6);
		if(scan_mac(value, mac) != 6)
			ERROR("invalid MAC literal: %s", value);
		cfg->val.mac = mac;
		break;
	}
	case CONFIG_NONOPT: {
		if(!cfg->val.nonopt){
			cfg->val.nonopt = strdup(value);
		}else{
			size_t new_size = 2 + strlen(cfg->val.nonopt) + strlen(value);
			REALLOC(cfg->val.nonopt, new_size);
			strcat(cfg->val.nonopt, " ");
			strcat(cfg->val.nonopt, value);
		}
		break;
	}
	default:
		ERROR("invalid configuration type %d", (int) cfg->type);
	}
}

cfgopt_t *cfgopt_get(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0)
			return cfg;
	}
	return NULL;
}

char *cfgopt_get_str(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_STR)
				ERROR("key='%s' is not a CONFIG_STR", key);
			return cfg->val.str;
		}
	}
	return NULL;
}

char *cfgopt_get_str_dup(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_STR)
				ERROR("key='%s' is not a CONFIG_STR", key);
			if(cfg->val.str)
				return strdup(cfg->val.str);
		}
	}
	return NULL;
}

long cfgopt_get_num(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_DEC && cfg->type != CONFIG_OCT)
				ERROR("key='%s' is not a CONFIG_DEC or CONFIG_OCT", key);
			if(cfg->val.num)
				return *cfg->val.num;
		}
	}
	return 0;
}

bool cfgopt_get_bool(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_BOOL)
				ERROR("key='%s' is not a CONFIG_BOOL", key);
			if(cfg->val.boolean)
				return *cfg->val.boolean;
		}
	}
	return false;
}

char *cfgopt_get_ip(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_IP)
				ERROR("key='%s' is not a CONFIG_IP", key);
			if(cfg->val.ip)
				return cfg->val.ip;
		}
	}
	return NULL;
}

char *cfgopt_get_ip6(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_IP6)
				ERROR("key='%s' is not a CONFIG_IP6", key);
			return cfg->val.ip;
		}
	}
	return NULL;
}

char *cfgopt_get_mac(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(strcasecmp(cfg->key, key) == 0){
			if(cfg->type != CONFIG_MAC)
				ERROR("key='%s' is not a CONFIG_MAC", key);
			return cfg->val.mac;
		}
	}
	return NULL;
}

char *cfgopt_get_nonopt(cfgopt_t *cfg){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if(cfg->type == CONFIG_NONOPT)
			return cfg->val.nonopt;
	}
	return NULL;
}

void cfgopt_free(cfgopt_t *cfg){
	for(; cfg->type != CONFIG_END ; ++cfg){
		FREE(cfg->val.str);
	}
}

bool cfgopt_is_present(cfgopt_t *cfg, char *key){
	for(; cfg->type != CONFIG_END ; ++cfg){
		if((strcasecmp(cfg->key, key) == 0) && cfg->val.str)
			return true;
	}
	return false;
}

void cfgopt_print(cfgopt_t *cfg){
	for(; cfg->type != CONFIG_END ; ++cfg){
		switch(cfg->type){
		case CONFIG_STR:
			if(cfg->val.str)
				DEBUG("key='%s', val='%s'", cfg->key, cfg->val.str);
			break;
		case CONFIG_BOOL:
			if(cfg->val.boolean)
				DEBUG("key='%s', val=%s", cfg->key, *cfg->val.boolean ? "true" : "false");
			break;
		case CONFIG_DEC:
			if(cfg->val.num)
				DEBUG("key='%s', val=%ld", cfg->key, *cfg->val.num);
			break;
		case CONFIG_OCT:
			if(cfg->val.num)
				DEBUG("key='%s', val=%lo", cfg->key, *cfg->val.num);
			break;
		case CONFIG_IP: {
			char sip[FMT_IP4];
			fmt_ip4(sip, cfg->val.ip);
			DEBUG("key='%s', val=%s", cfg->key, sip);
			break;
		}
		case CONFIG_IP6: {
			char sip[FMT_IP6];
			fmt_ip6(sip, cfg->val.ip);
			DEBUG("key='%s', val=%s", cfg->key, sip);
			break;
		}
		case CONFIG_MAC: {
			char smac[FMT_MAC];
			fmt_mac(smac, cfg->val.mac);
			DEBUG("key='%s', val=%s", cfg->key, smac);
			break;
		}
		case CONFIG_NONOPT:
			if(cfg->val.nonopt)
				DEBUG("nonopt='%s'", cfg->val.nonopt);
			break;
		default:
			break;
		}
	}
}

void cfgopt_usage(cfgopt_t *cfg){
	for(; cfg->type != CONFIG_END ; ++cfg){
		switch(cfg->type){
		case CONFIG_STR:
		case CONFIG_DEC:
		case CONFIG_OCT:
		case CONFIG_IP:
		case CONFIG_IP6:
		case CONFIG_MAC:
			fprintf(stderr, "\t[ -%c <%s> %s %s%s%s]\n",
				cfg->cmd, cfg->key, cfg->help,
				cfg->default_value == NULL ? "" : "(default: ",
				cfg->default_value == NULL ? "" : cfg->default_value,
				cfg->default_value == NULL ? "" : ") "
			);
			break;
		case CONFIG_BOOL:
			fprintf(stderr, "\t[ -%c %s %s%s%s]\n",
				cfg->cmd, cfg->help,
				cfg->default_value == NULL ? "" : "(default: ",
				cfg->default_value == NULL ? "" : cfg->default_value,
				cfg->default_value == NULL ? "" : ") "
			);
			break;
		default:
			break;
		}
	}
}

void cfgopt_parse_args(cfgopt_t *cfg, int argc, char **argv){
	int c;
	char *options;
	cfgopt_t *cur;

	CALLOC(options, 2 * cfgopt_len(cfg));

	for(cur = cfg ; cur->type != CONFIG_END ; ++cur){
		switch(cur->type){
		case CONFIG_STR:
		case CONFIG_DEC:
		case CONFIG_OCT:
		case CONFIG_IP:
		case CONFIG_IP6:
		case CONFIG_MAC:
			strcat(options, &cur->cmd);
			strcat(options, ":");
			break;
		case CONFIG_BOOL:
			strcat(options, &cur->cmd);
			break;
		default:
			break;
		}
	}

	for(cur = cfg ; cur->type != CONFIG_END ; ++cur)
		if(cur->type != CONFIG_NONOPT)
			cfgopt_load_value(cur, cur->default_value);

	while((c = getopt(argc, argv, options)) != EOF){
		for(cur = cfg ; cur->type != CONFIG_END ; ++cur){
			if(c == cur->cmd){
				if(cur->type == CONFIG_BOOL){
					if(cur->default_value && cur->default_value[0] == '0')
						cfgopt_load_value(cur, "1");
					else if(cur->default_value && cur->default_value[0] == '1')
						cfgopt_load_value(cur, "0");
					else
						cfgopt_load_value(cur, "1");
				}else{
					cfgopt_load_value(cur, optarg);
				}
			}
		}
	}
	for(cur = cfg ; cur->type != CONFIG_END; ++cur)
		if(cur->type == CONFIG_NONOPT)
			while(argv[optind] != '\0')
				cfgopt_load_value(cur, argv[optind++]);

	if((cur = cfgopt_get(cfg, "configfile")) && cur->val.str && !cfgopt_load(cfg, cur->val.str))
		ERROR("configuration error, exiting");

	FREE(options);
}

size_t cfgopt_len(cfgopt_t *cfg){
	size_t len = 0;
	for(; cfg->type != CONFIG_END ; ++cfg) ++len;
	return len;
}
