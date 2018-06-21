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

#pragma once

/*! \file dns/zoneverify.h */

#include <dns/types.h>

#include <isc/attribute.h>
#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/*%
 * Verify that certain things are sane:
 *
 *   The apex has a DNSKEY record with at least one KSK, and at least
 *   one ZSK if the -x flag was not used.
 *
 *   The DNSKEY record was signed with at least one of the KSKs in this
 *   set.
 *
 *   The rest of the zone was signed with at least one of the ZSKs
 *   present in the DNSKEY RRSET.
 */
isc_result_t
dns_zoneverify_dnssec(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *ver,
		      dns_name_t *origin, isc_mem_t *mctx,
		      isc_boolean_t ignore_kskflag,
		      isc_boolean_t keyset_kskonly)
	ISC_ATTRIBUTE_WARN_UNUSED_RESULT;

ISC_LANG_ENDDECLS
