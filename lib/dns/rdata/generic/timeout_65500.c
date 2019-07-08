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

/* draft-pusateri-dnsop-update-timeout-03 */

#include <isc/time.h>

#ifndef RDATA_GENERIC_TIMEOUT_C
#define RDATA_GENERIC_TIMEOUT_C

#define RRTYPE_TIMEOUT_ATTRIBUTES (0)

static inline isc_result_t
fromtext_timeout(ARGS_FROMTEXT) {
	isc_result_t result;
	isc_token_t token;
	int64_t timeout;
	unsigned int count;
	unsigned int method;
	dns_rdatatype_t covers;
	unsigned int i;
	unsigned int rdlen;

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	/*
	 * Type covered.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	result = dns_rdatatype_fromtext(&covers, &token.value.as_textregion);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTIMPLEMENTED) {
		char *e;
		i = strtoul(DNS_AS_STR(token), &e, 10);
		if (i > 0xffffU)
			RETTOK(ISC_R_RANGE);
		if (*e != 0)
			RETTOK(result);
		covers = (dns_rdatatype_t)i;
	}
	RETERR(uint16_tobuffer(covers, target));

	/*
	 * Count
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU)
		RETTOK(ISC_R_RANGE);
	count = token.value.as_ulong;
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * Method
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU)
		RETTOK(ISC_R_RANGE);
	method = token.value.as_ulong;
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * Timeout
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	RETTOK(dns_time64_fromtext(DNS_AS_STR(token), &timeout));
	RETERR(uint64_tobuffer(timeout, target));

	for (i = 0; i < count; i++ ) {
		isc_buffer_t b = *target;
		switch (method) {
		case 0:
			return (DNS_R_FORMERR);
		case 1:
			/*
			 * Data Length
			 */
			RETERR(isc_lex_getmastertoken(lexer, &token,
						      isc_tokentype_number,
						      false));
			if (token.value.as_ulong > 0xffffU) {
				RETTOK(ISC_R_RANGE);
			}
			rdlen = token.value.as_ulong;
			RETERR(uint16_tobuffer(token.value.as_ulong, target));
			RETERR(dns_rdata_fromtext(NULL, rdclass, covers,
						  lexer, origin,
						  options|DNS_RDATA_NOCHECKEOL,
						  mctx, target, callbacks));
			/*
			 * Sanity.
			 */
			if ((target->used - b.used - 2) != rdlen) {
				RETERR(DNS_R_SYNTAX);
			}
			break;
		default:
			return (ISC_R_NOTIMPLEMENTED);
		}
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_timeout(ARGS_TOTEXT) {
	isc_region_t sr;
	dns_rdatatype_t covers;
	unsigned int count;
	unsigned int method;
	char buf[sizeof("yyyy-mm-ddTHH:MM:SSZ")];
	int64_t expire;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &sr);

	/*
	 * Type covered.
	 */
	covers = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	/*
	 * XXXAG We should have something like dns_rdatatype_isknown()
	 * that does the right thing with type 0.
	 */
	if (dns_rdatatype_isknown(covers) && covers != 0) {
		RETERR(dns_rdatatype_totext(covers, target));
	} else {
		snprintf(buf, sizeof(buf), "TYPE%u", covers);
		RETERR(str_totext(buf, target));
	}
	RETERR(str_totext(" ", target));

	/*
	 * Count
	 */
	count = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	snprintf(buf, sizeof(buf), "%u ", count);
	RETERR(str_totext(buf, target));

	/*
	 * Method
	 */
	method = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	snprintf(buf, sizeof(buf), "%u ", method);
	RETERR(str_totext(buf, target));

	if (method != 0 && method != 1)
		return (ISC_R_NOTIMPLEMENTED);

	/*
	 * Expire
	 */
	expire = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	expire <<= 32;
	expire |= uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	RETERR(dns_time64_totext(expire, target));

	while (sr.length != 0) {
		unsigned int rdlen, length;

		INSIST(sr.length >= 2);
		rdlen = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);
		snprintf(buf, sizeof(buf), " %u ", rdlen);
		RETERR(str_totext(buf, target));

		INSIST(sr.length >= rdlen);
		length = sr.length;
		sr.length = rdlen;

		switch (method) {
		case 1: {
			dns_rdata_t this = DNS_RDATA_INIT;
			dns_rdata_fromregion(&this, rdata->rdclass, covers,
					     &sr);
			RETERR(dns_rdata_tofmttext(&this, tctx->origin,
						   tctx->flags, tctx->width,
						   0xffffffff,
						   tctx->linebreak,
						   target));
			break;
			}
		default:
			INSIST(0);
		}
		sr.length = length;
		isc_region_consume(&sr, rdlen);
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_timeout(ARGS_FROMWIRE) {
	isc_region_t sr;
	unsigned int covers, count, method, i;

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(options);

	isc_buffer_activeregion(source, &sr);
	if (sr.length < 12)
		return (ISC_R_UNEXPECTEDEND);

	isc_buffer_forward(source, 12);
	RETERR(mem_tobuffer(target, sr.base, 12));

	covers = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	count = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	method = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	/* expire */
	isc_region_consume(&sr, 8);

	for (i = 0; i < count; i++) {
		unsigned int rdlen;
		if (sr.length < 2)
			return (ISC_R_UNEXPECTEDEND);
		RETERR(mem_tobuffer(target, sr.base, 2));
		isc_buffer_forward(source, 2);
		rdlen = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);
		if (sr.length < rdlen)
			return (ISC_R_UNEXPECTEDEND);
		switch (method) {
		case 1: {
			isc_buffer_t b;
			isc_buffer_init(&b, sr.base, rdlen);
			isc_buffer_add(&b, rdlen);
			isc_buffer_setactive(&b, rdlen);
			RETERR(dns_rdata_fromwire(NULL, rdclass, covers,
						  &b, dctx, options, target));
			break;
			}
		default:
			RETERR(mem_tobuffer(target, sr.base, rdlen));
			break;
		}
		isc_buffer_forward(source, rdlen);
		isc_region_consume(&sr, rdlen);
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_timeout(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_timeout(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_timeout);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_timeout(ARGS_FROMSTRUCT) {
	dns_rdata_timeout_t *timeout = source;

	REQUIRE(timeout != NULL);
	REQUIRE(type == dns_rdatatype_timeout);
	REQUIRE(timeout->common.rdtype == type);
	REQUIRE(timeout->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint16_tobuffer(timeout->covers, target));
	RETERR(uint8_tobuffer(timeout->count, target));
	RETERR(uint8_tobuffer(timeout->type, target));
	RETERR(uint64_tobuffer(timeout->when, target));

	return (mem_tobuffer(target, timeout->data, timeout->length));
}

static inline isc_result_t
tostruct_timeout(ARGS_TOSTRUCT) {
	dns_rdata_timeout_t *timeout = target;
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	REQUIRE(timeout != NULL);
	timeout->common.rdclass = rdata->rdclass;
	timeout->common.rdtype = rdata->type;
	ISC_LINK_INIT(&timeout->common, link);

	dns_rdata_toregion(rdata, &sr);
	timeout->covers = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	timeout->count = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	timeout->type = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	timeout->when = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	timeout->when <<= 32;
	timeout->when |= uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	timeout->length = sr.length;
	timeout->data = mem_maybedup(mctx, sr.base, sr.length);
	if (timeout->data == NULL)
		return (ISC_R_NOMEMORY);

	timeout->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_timeout(ARGS_FREESTRUCT) {
	dns_rdata_timeout_t *timeout = (dns_rdata_timeout_t *) source;

	REQUIRE(timeout != NULL);
	REQUIRE(timeout->common.rdtype == dns_rdatatype_timeout);

	if (timeout->mctx == NULL)
		return;

	if (timeout->data != NULL)
		isc_mem_free(timeout->mctx, timeout->data);
	timeout->mctx = NULL;
}

static inline isc_result_t
additionaldata_timeout(ARGS_ADDLDATA) {

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_timeout(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

static inline bool
checkowner_timeout(ARGS_CHECKOWNER) {

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
checknames_timeout(ARGS_CHECKNAMES) {

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (true);
}

static inline int
casecompare_timeout(ARGS_COMPARE) {
	return (compare_timeout(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_TIMEOUT_C */
