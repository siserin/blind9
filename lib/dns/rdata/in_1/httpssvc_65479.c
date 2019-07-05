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

/* draft-nygren-httpbis-httpssvc-01 */

#ifndef RDATA_IN_1_HTTPSSVC_65479_C
#define RDATA_IN_1_HTTPSSVC_65479_C

#define RRTYPE_HTTPSSVC_ATTRIBUTES (0)

#define SVCDOMAINLEN 1	/* XXXMPA hopefully gone in -02 */
#define SVCLEN 1	/* XXXMPA hopefully gone in -02 */

static inline isc_result_t
fromtext_in_httpssvc(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer, sb;
#if 0
	bool ok;
#endif

	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/*
	 * Type.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU)
		RETTOK(ISC_R_RANGE);
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * Priority.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU)
		RETTOK(ISC_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/*
	 * Domain.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
				      false));
#ifdef SVCDOMAINLEN
	if (token.value.as_region.length == 0U) {
		RETERR(uint8_tobuffer(0, target));
	} else {
		sb = *target;
		RETERR(uint8_tobuffer(0, target));	/* dummy */
#endif
		dns_name_init(&name, NULL);
		buffer_fromregion(&buffer, &token.value.as_region);
		if (origin == NULL)
			origin = dns_rootname;
		RETTOK(dns_name_fromtext(&name, &buffer, origin, options,
					 target));
#ifdef SVCDOMAINLEN
		/* backfill length */
		RETERR(uint8_tobuffer(name.length, &sb));
	}
#endif
#if 0
	ok = true;
	if ((options & DNS_RDATA_CHECKNAMES) != 0)
		ok = dns_name_ishostname(&name, false);
	if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0)
		RETTOK(DNS_R_BADNAME);
	if (!ok && callbacks != NULL)
		warn_badname(&name, lexer, callbacks);
#endif

	/*
	 * SVC
	 */
#ifdef SVCLEN
	sb = *target;
	RETERR(uint16_tobuffer(0, target));		/* dummy */
#endif
        RETERR(isc_lex_getmastertoken(lexer, &token,
                                      isc_tokentype_qstring, false));
        if (token.type != isc_tokentype_qstring &&
            token.type != isc_tokentype_string)
                RETERR(DNS_R_SYNTAX);
        RETERR(multitxt_fromtext(&token.value.as_textregion, target));
#ifdef SVCLEN
	/* backfill length */
	RETERR (uint16_tobuffer(target->used - sb.used - 2, &sb));
#endif
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_in_httpssvc(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	bool sub;
	char buf[sizeof("64000")];
	unsigned short num;

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	/*
	 * Type.
	 */
	dns_rdata_toregion(rdata, &region);
	num = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/*
	 * Priority.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

#ifdef SVCDOMAINLEN
	num = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (num == 0) {
		RETERR(str_totext("\"\"", target));
	} else {
#endif
		/*
		 * Target.
		 */
		dns_name_fromregion(&name, &region);
		isc_region_consume(&region, name_length(&name));
		sub = name_prefix(&name, tctx->origin, &prefix);
		RETERR(dns_name_totext(&prefix, sub, target));
#ifdef SVCDOMAINLEN
	}
#endif
	RETERR(str_totext(" ", target));
#ifdef SVCLEN
	isc_region_consume(&region, 2);
#endif
	return (multitxt_totext(&region, target));
}

static inline isc_result_t
fromwire_in_httpssvc(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	dns_name_init(&name, NULL);

	/*
	 * Type, Priority, domain length.
	 */
	isc_buffer_activeregion(source, &sr);
#ifdef SVCDOMAINLEN
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_buffer_forward(source, 4);
#else
	if (sr.length < 3)
		return (ISC_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 3));
	isc_buffer_forward(source, 3);
#endif

#ifdef SVCDOMAINLEN
	if (sr.base[3] != 0) {
#endif
		/*
		 * Target.
		 */
		RETERR(dns_name_fromwire(&name, source, dctx, options, target));
		if (name.length != sr.base[3]) {
			return (DNS_R_FORMERR);
		}
#ifdef SVCDOMAINLEN
	}
#endif

	/*
	 * SVC
	 */
	isc_buffer_activeregion(source, &sr);
#ifdef SVCLEN
	if (sr.length < 2) {
		return (ISC_R_UNEXPECTEDEND);
	}
	if (uint16_fromregion(&sr) != (sr.length - 2)) {
		return (DNS_R_FORMERR);
	}
#endif
	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_in_httpssvc(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);
	/*
	 * Type, Priority.
	 */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 3));
	isc_region_consume(&sr, 3);

#ifdef SVCDOMAINLEN
	/*
	 * SRV DOMAIN LENGTH
	 */
	RETERR(mem_tobuffer(target, sr.base, 1));
	isc_region_consume(&sr, 1);
	if (sr.base[-1] != 0) {
#endif
		/*
		 * Target.
		 */
		dns_name_init(&name, offsets);
		dns_name_fromregion(&name, &sr);
		RETERR(dns_name_towire(&name, cctx, target));
		isc_region_consume(&sr, name_length(&name));
#ifdef SVCDOMAINLEN
	}
#endif
	return(mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_in_httpssvc(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
        dns_rdata_toregion(rdata2, &region2);
        return (isc_region_compare(&region1, &region2));
}

static inline isc_result_t
fromstruct_in_httpssvc(ARGS_FROMSTRUCT) {
	dns_rdata_in_httpssvc_t *httpssvc = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(source != NULL);
	REQUIRE(httpssvc->common.rdtype == type);
	REQUIRE(httpssvc->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(httpssvc->type, target));
	RETERR(uint16_tobuffer(httpssvc->priority, target));
#ifdef SVCDOMAINLEN
	RETERR(uint8_tobuffer(httpssvc->svcdomainlen, target));
	if (httpssvc->svcdomainlen != 0) {
#endif
		dns_name_toregion(&httpssvc->svcdomain, &region);
		RETERR(isc_buffer_copyregion(target, &region));
#ifdef SVCDOMAINLEN
	}
#endif
#ifdef SVCLEN
	RETERR(uint16_tobuffer(httpssvc->svclen, target));
#endif
	return (mem_tobuffer(target, httpssvc->svc, httpssvc->svclen));
}

static inline isc_result_t
tostruct_in_httpssvc(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_in_httpssvc_t *httpssvc = target;
	dns_name_t name;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	httpssvc->common.rdclass = rdata->rdclass;
	httpssvc->common.rdtype = rdata->type;
	ISC_LINK_INIT(&httpssvc->common, link);

	dns_rdata_toregion(rdata, &region);
	httpssvc->type = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	httpssvc->priority = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	dns_name_init(&httpssvc->svcdomain, NULL);
#ifdef SVCDOMAINLEN
	httpssvc->svcdomainlen = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (httpssvc->svcdomainlen != 0) {
#endif
		dns_name_init(&name, NULL);
		dns_name_fromregion(&name, &region);
		isc_region_consume(&region, name_length(&name));
		RETERR(name_duporclone(&name, mctx, &httpssvc->svcdomain));
#ifdef SVCDOMAINLEN
	}
#endif
#ifdef SVCLEN
	httpssvc->svclen = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
#else
	httpssvc->svclen = region.length;
#endif
	httpssvc->svc = mem_maybedup(mctx, region.base, region.length);
        if (httpssvc->svc == NULL)
                return (ISC_R_NOMEMORY);

	httpssvc->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_in_httpssvc(ARGS_FREESTRUCT) {
	dns_rdata_in_httpssvc_t *httpssvc = source;

	REQUIRE(source != NULL);
	REQUIRE(httpssvc->common.rdclass == dns_rdataclass_in);
	REQUIRE(httpssvc->common.rdtype == dns_rdatatype_httpssvc);

	if (httpssvc->mctx == NULL)
		return;

#ifdef SVCDOMAINLEN
	if (httpssvc->svcdomainlen != 0) {
#endif
		dns_name_free(&httpssvc->svcdomain, httpssvc->mctx);
#ifdef SVCDOMAINLEN
	}
#endif
	if (httpssvc->svc != NULL) {
		isc_mem_free(httpssvc->mctx, httpssvc->svc);
	}
	httpssvc->mctx = NULL;
}

static inline isc_result_t
additionaldata_in_httpssvc(ARGS_ADDLDATA) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;
#ifdef SVCDOMAINLEN
	uint8_t svcdomainlen;
#endif

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &region);
#ifdef SVCDOMAINLEN
	svcdomainlen = region.base[3];
	if (svcdomainlen == 0)
		return (ISC_R_SUCCESS);
#endif
	isc_region_consume(&region, 4);
	dns_name_fromregion(&name, &region);
	if (dns_name_equal(&name, dns_rootname))
		return (ISC_R_SUCCESS);

	return ((add)(arg, &name, dns_rdatatype_a));
}

static inline isc_result_t
digest_in_httpssvc(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return ((digest)(arg, &region1));
}

static inline bool
checkowner_in_httpssvc(ARGS_CHECKOWNER) {

	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
checknames_in_httpssvc(ARGS_CHECKNAMES) {
#if 0
	isc_region_t region;
	dns_name_t name;
#endif

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(bad);
	UNUSED(owner);

#if 0
	dns_rdata_toregion(rdata, &region);
#ifdef SVCDOMAINLEN
	isc_region_consume(&region, 4);
#else
	isc_region_consume(&region, 3);
#endif
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL)
			dns_name_clone(&name, bad);
		return (false);
	}
#endif
	return (true);
}

static inline int
casecompare_in_httpssvc(ARGS_COMPARE) {
	return (compare_in_httpssvc(rdata1, rdata2));
}

#endif	/* RDATA_IN_1_HTTPSSVC_65479_C */