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

#ifndef IN_1_HTTPSSVC_65479_H
#define IN_1_HTTPSSVC_65479_H 1

/*!
 *  \brief Per draft-nygren-httpbis-httpssvc-01 */

typedef struct dns_rdata_in_httpssvc {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	uint8_t			type;
	uint16_t		priority;
	uint8_t			svcdomainlen;
	dns_name_t		svcdomain;
	uint16_t		svclen;
	unsigned char *		svc;
} dns_rdata_in_httpssvc_t;

#endif /* IN_1_HTTPSSVC_65479_H */
