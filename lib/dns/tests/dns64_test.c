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

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/netaddr.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/dns64.h>

static void
dns64_findprefix(void **state) {
	unsigned int i, j, o;
	isc_result_t result;
	struct {
		unsigned char	prefix[12];
		unsigned int	prefixlen;
		isc_result_t	result;
	} tests[] = {
		/* The WKP with various lengths. */
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			32, ISC_R_SUCCESS
		},
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			40, ISC_R_SUCCESS
		},
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			48, ISC_R_SUCCESS
		},
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			56, ISC_R_SUCCESS
		},
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			64, ISC_R_SUCCESS
		},
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 },
			96, ISC_R_SUCCESS
		},
		/*
		 * Prefix with the mapped addresses also appearing in the
		 * prefix.
		 */
		{
			{ 0, 0, 0, 0, 192, 0, 0, 170, 0, 0, 0, 0 },
			96, ISC_R_SUCCESS
		},
		{
			{ 0, 0, 0, 0, 192, 0, 0, 171, 0, 0, 0, 0 },
			96, ISC_R_SUCCESS
		},
		/* Bad prefix, MBZ != 0. */
		{
			{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 1, 0, 0, 0 },
			96, ISC_R_NOTFOUND
		},
	};

	UNUSED(state);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		size_t count = 2;
		dns_rdataset_t rdataset;
		dns_rdatalist_t rdatalist;
		dns_rdata_t rdata[2] = { DNS_RDATA_INIT, DNS_RDATA_INIT };
		struct in6_addr ina6[2];
		isc_netprefix_t prefix[2];
		unsigned char aa[] = { 192, 0, 0, 170 };
		unsigned char ab[] = { 192, 0, 0, 171 };
		isc_region_t region;

		/*
		 * Construct rdata.
		 */
		memset(ina6[0].s6_addr, 0, sizeof(ina6[0].s6_addr));
		memset(ina6[1].s6_addr, 0, sizeof(ina6[1].s6_addr));
		memmove(ina6[0].s6_addr, tests[i].prefix, 12);
		memmove(ina6[1].s6_addr, tests[i].prefix, 12);
		o = tests[i].prefixlen/8;
		for (j = 0; j < 4; j++) {
			if ((o + j) == 8U) {
				 o++; /* skip mbz */
			}
			ina6[0].s6_addr[j + o] = aa[j];
			ina6[1].s6_addr[j + o] = ab[j];
		}
		region.base = ina6[0].s6_addr;
		region.length = sizeof(ina6[0].s6_addr);
		dns_rdata_fromregion(&rdata[0], dns_rdataclass_in,
				     dns_rdatatype_aaaa, &region);
		region.base = ina6[1].s6_addr;
		region.length = sizeof(ina6[1].s6_addr);
		dns_rdata_fromregion(&rdata[1], dns_rdataclass_in,
				     dns_rdatatype_aaaa, &region);

		dns_rdatalist_init(&rdatalist);
		rdatalist.type = rdata[0].type;
		rdatalist.rdclass = rdata[0].rdclass;
		rdatalist.ttl = 0;
		ISC_LIST_APPEND(rdatalist.rdata, &rdata[0], link);
		ISC_LIST_APPEND(rdatalist.rdata, &rdata[1], link);
		dns_rdataset_init(&rdataset);
		result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_dns64_findprefix(&rdataset, prefix, &count);
		assert_int_equal(result, tests[i].result);
		if (tests[i].result == ISC_R_SUCCESS) {
			assert_int_equal(count, 1);
			assert_int_equal(prefix[0].prefixlen,
					 tests[i].prefixlen);
		}
	}
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(dns64_findprefix, NULL, NULL)
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
