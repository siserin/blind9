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

#ifndef DNS_KASP_H
#define DNS_KASP_H 1

/*****
 ***** Module Info
 *****/

/*! \file dns/kasp.h
 * \brief
 * DNSSEC Key and Signing Policy (KASP)
 *
 * A "kasp" is a DNSSEC policy, that determines how a zone should be
 * signed and maintained.
 */

#include <time.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/mutex.h>
#include <isc/refcount.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

struct dns_kasp {
	unsigned int			magic;
	isc_mem_t*			mctx;
	char*				name;
	char* 				dbfile;

	/* Internals. */
	isc_mutex_t			lock;
	bool				frozen;

	/* Locked by themselves. */
	isc_refcount_t			references;

	/* Under owner's locking control. */
	ISC_LINK(struct dns_kasp)	link;
	dns_kasplist_t*			kasplist;

	/* Configuration */
	time_t				signatures_resign;
	time_t				signatures_refresh;
	time_t				signatures_validity;
	time_t				signatures_validity_dnskey;
	time_t				signatures_validity_denial;
	time_t				signatures_jitter;
	time_t				signatures_inception_offset;

	// [WMM]: TODO: The rest of the KASP configuration
};

#define DNS_KASP_MAGIC			ISC_MAGIC('K','A','S','P')
#define DNS_KASP_VALID(kasp)		ISC_MAGIC_VALID(kasp, DNS_KASP_MAGIC)

/* Defaults */
#define DNS_KASP_SIGNATURES_RESIGN		(7200)
#define DNS_KASP_SIGNATURES_REFRESH		(86400*3)
#define DNS_KASP_SIGNATURES_VALIDITY		(86400*14)
#define DNS_KASP_SIGNATURES_VALIDITY_DNSKEY	(86400*14)
#define DNS_KASP_SIGNATURES_VALIDITY_DENIAL	(86400*7)
#define DNS_KASP_SIGNATURES_JITTER		(3600*12)
#define DNS_KASP_SIGNATURES_INCEPTION_OFFSET	(300)


isc_result_t
dns_kasp_create(isc_mem_t *mctx, const char* name, dns_kasp_t **kaspp);
/*%<
 * Create a KASP.
 *
 * Requires:
 *
 *\li	'mctx' is a valid memory context.
 *
 *\li	'name' is a valid C string.
 *
 *\li	kaspp != NULL && *kaspp == NULL
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *
 *\li	Other errors are possible.
 */

void
dns_kasp_attach(dns_kasp_t *source, dns_kasp_t **targetp);
/*%<
 * Attach '*targetp' to 'source'.
 *
 * Requires:
 *
 *\li   'source' is a valid, frozen kasp.
 *
 *\li   'targetp' points to a NULL dns_kasp_t *.
 *
 * Ensures:
 *
 *\li   *targetp is attached to source.
 *
 *\li   While *targetp is attached, the kasp will not shut down.
 */

void
dns_kasp_detach(dns_kasp_t **kaspp);
/*%<
 * Detach KASP.
 *
 * Requires:
 *
 *\li   'kaspp' points to a valid dns_kasp_t *
 *
 * Ensures:
 *
 *\li   *kaspp is NULL.
 */

void
dns_kasp_freeze(dns_kasp_t *kasp);
/*%<
 * Freeze kasp.  No changes can be made to kasp configuration while frozen.
 *
 * Requires:
 *
 *\li   'kasp' is a valid, unfrozen kasp.
 *
 * Ensures:
 *
 *\li   'kasp' is frozen.
 */

void
dns_kasp_thaw(dns_kasp_t *kasp);
/*%<
 * Thaw kasp.
 *
 * Requires:
 *
 *\li   'kasp' is a valid, frozen kasp.
 *
 * Ensures:
 *
 *\li   'kasp' is no longer frozen.
 */

isc_result_t
dns_kasplist_find(dns_kasplist_t *list, const char *name, dns_kasp_t **kaspp);
/*%<
 * Search for a kasp with name 'name' in 'list'.
 * If found, '*kaspp' is (strongly) attached to it.
 *
 * Requires:
 *
 *\li   'kaspp' points to a NULL dns_kasp_t *.
 *
 * Returns:
 *
 *\li   #ISC_R_SUCCESS          A matching kasp was found.
 *\li   #ISC_R_NOTFOUND         No matching kasp was found.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_KASP_H */
