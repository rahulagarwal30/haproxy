/*
 * HTTP/2 protocol variables and settings and protocol elements
 *
 * Copyright 2000-2017 Willy Tarreau <w@1wt.eu>
 * Copyright 2017 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/standard.h>
#include <types/h2common.h>

/* some protocol constants */
const char h2_conn_preface[24] = // PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	"\x50\x52\x49\x20\x2a\x20\x48\x54"
	"\x54\x50\x2f\x32\x2e\x30\x0d\x0a"
	"\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a";


/* strings representing various entities' states, for debugging and dumps */
const char *h2_ft_strings[H2_FT_ENTRIES] = {
	[H2_FT_DATA]          = "DATA",
	[H2_FT_HEADERS]       = "HEADERS",
	[H2_FT_PRIORITY]      = "PRIORITY",
	[H2_FT_RST_STREAM]    = "RST_STREAM",
	[H2_FT_SETTINGS]      = "SETTINGS",
	[H2_FT_PUSH_PROMISE]  = "PUSH_PROMISE",
	[H2_FT_PING]          = "PING",
	[H2_FT_GOAWAY]        = "GOAWAY",
	[H2_FT_WINDOW_UPDATE] =	"WINDOW_UPDATE",
};

/* a few global settings */
int h2_settings_header_table_size      =  4096; /* initial value */
int h2_settings_initial_window_size    = 65535; /* initial value */
int h2_settings_max_concurrent_streams =   100;


/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_header_table_size = atoi(args[1]);
	if (h2_settings_header_table_size < 4096 || h2_settings_header_table_size > 65536) {
		memprintf(err, "'%s' expects a numeric value between 4096 and 65536.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.initial-window-size" */
static int h2_parse_initial_window_size(char **args, int section_type, struct proxy *curpx,
                                        struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_initial_window_size = atoi(args[1]);
	if (h2_settings_initial_window_size < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-concurrent-streams" */
static int h2_parse_max_concurrent_streams(char **args, int section_type, struct proxy *curpx,
                                           struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_concurrent_streams = atoi(args[1]);
	if (h2_settings_max_concurrent_streams < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ 0, NULL, NULL }
}};

__attribute__((constructor))
static void __h2_init(void)
{
	cfg_register_keywords(&cfg_kws);
}
