/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

//#include <stdbool.h>
#include <stdlib.h>

//#include <isc/buffer.h>
#include <isc/commandline.h>
//#include <isc/hash.h>
#include <isc/mem.h>
//#include <isc/print.h>
//#include <isc/string.h>
#include <isc/util.h>

#include <isccfg/namedconf.h>

//#include <dns/callbacks.h>
//#include <dns/db.h>
//#include <dns/dbiterator.h>
//#include <dns/ds.h>
//#include <dns/fixedname.h>
//#include <dns/keyvalues.h>
#include <dns/log.h>
//#include <dns/master.h>
//#include <dns/name.h>
//#include <dns/rdata.h>
//#include <dns/rdataclass.h>
//#include <dns/rdataset.h>
//#include <dns/rdatasetiter.h>
//#include <dns/rdatatype.h>
#include <dns/result.h>

#include "dnssectool.h"

const char *program = "kasp-dbsetup";
int verbose;

ISC_PLATFORM_NORETURN_PRE static void
usage(void) ISC_PLATFORM_NORETURN_POST;

static void
usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,	"    %s [options]\n", program);
	fprintf(stderr, "Version: %s\n", VERSION);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -c <file>: named configuration with dnssecpolicy\n");
	fprintf(stderr, "    -h: print usage and exit\n");
	fprintf(stderr, "    -V: print version and exit\n");
	fprintf(stderr, "    -v <verbose level>\n");
	fprintf(stderr, "    -y: yes to all questions\n");
	exit (-1);
}

static void
output(void *closure, const char *text, int textlen) {
	UNUSED(closure);
	if (fwrite(text, 1, textlen, stdout) != (size_t)textlen) {
		perror("fwrite");
		exit(1);
	}
}

static void
print_dnssec_policies(const cfg_obj_t *config)
{
	const cfg_listelt_t *element = NULL;
	const cfg_obj_t *policies = NULL;
	const cfg_obj_t *dpconfig = NULL;

	(void)cfg_map_get(config, "dnssecpolicy", &policies);
	for (element = cfg_list_first(policies); element != NULL;
	     element = cfg_list_next(element))
        {
		dpconfig = cfg_listelt_value(element);
		if (dpconfig == NULL) {
			continue;
		}
		cfg_printx(dpconfig, 0, output, NULL);
	}
}

int
main(int argc, char **argv) {
	isc_mem_t *mctx = NULL;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *config = NULL;
	isc_log_t *log = NULL;
	isc_result_t result;

	const char *configfile = NULL;
	bool yes = false;

	char *endp;
	int ch;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	if (result != ISC_R_SUCCESS) {
		fatal("out of memory");
	}

	isc_commandline_errprint = false;
#define CMDLINE_FLAGS "c:h:vy"
	while ((ch = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (ch) {
		case 'c':
			configfile = isc_commandline_argument;
			if (strlen(configfile) == 0U) {
				fatal("config file must be non-empty string");
			}
			break;
		case 'y':
			yes = true;
			break;
                case 'v':
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0') {
				fatal("-v must be followed by a number");
			}
			break;
		case 'V':
			/* Does not return. */
			version(program);
		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					program, isc_commandline_option);
			}
			/* FALLTHROUGH */
		case 'h':
			/* Does not return. */
			usage();
		default:
			fprintf(stderr, "%s: unhandled option -%c\n",
				program, isc_commandline_option);
			exit(1);
		}
	}

	if (argc > isc_commandline_index + 1) {
		fatal("extraneous arguments");
	}

	setup_logging(mctx, &log);
        dns_result_register();
	RUNTIME_CHECK(cfg_parser_create(mctx, log, &parser) == ISC_R_SUCCESS);

	if (configfile == NULL) {
		configfile = NAMED_CONFFILE;
	}

	if (cfg_parse_file(parser, configfile, &cfg_type_namedconf,
			   &config) != ISC_R_SUCCESS)
	{
                exit(1);
	}

	print_dnssec_policies(config);

	cleanup_logging(&log);
//	if (verbose > 10) {
//		isc_mem_stats(mctx, stdout);
//	}
//	isc_mem_destroy(&mctx);

	fflush(stdout);
	if (ferror(stdout)) {
		fprintf(stderr, "write error\n");
		return (1);
	} else {
		return (0);
	}
}
