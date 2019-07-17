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

#ifndef RDATA_GENERIC_CNAME_5_C
#define RDATA_GENERIC_CNAME_5_C

#define RRTYPE_CNAME_ATTRIBUTES \
	(DNS_RDATATYPEATTR_EXCLUSIVE | DNS_RDATATYPEATTR_SINGLETON)

static inline isc_result_t fromtext_cname(ARGS_FROMTEXT)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == dns_rdatatype_cname);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_fromtext(&name, &buffer, origin, options, target));
	return (ISC_R_SUCCESS);
}

static inline isc_result_t totext_cname(ARGS_TOTEXT)
{
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	bool sub;

	REQUIRE(rdata->type == dns_rdatatype_cname);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	sub = name_prefix(&name, tctx->origin, &prefix);

	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t fromwire_cname(ARGS_FROMWIRE)
{
	dns_name_t name;

	REQUIRE(type == dns_rdatatype_cname);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, NULL);
	return (dns_name_fromwire(&name, source, dctx, options, target));
}

static inline isc_result_t towire_cname(ARGS_TOWIRE)
{
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_cname);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return (dns_name_towire(&name, cctx, target));
}

static inline int compare_cname(ARGS_COMPARE)
{
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_cname);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_rdatacompare(&name1, &name2));
}

static inline isc_result_t fromstruct_cname(ARGS_FROMSTRUCT)
{
	dns_rdata_cname_t *cname = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_cname);
	REQUIRE(source != NULL);
	REQUIRE(cname->common.rdtype == type);
	REQUIRE(cname->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&cname->cname, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t tostruct_cname(ARGS_TOSTRUCT)
{
	isc_region_t region;
	dns_rdata_cname_t *cname = target;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_cname);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	cname->common.rdclass = rdata->rdclass;
	cname->common.rdtype = rdata->type;
	ISC_LINK_INIT(&cname->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);
	dns_name_init(&cname->cname, NULL);
	RETERR(name_duporclone(&name, mctx, &cname->cname));
	cname->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void freestruct_cname(ARGS_FREESTRUCT)
{
	dns_rdata_cname_t *cname = source;

	REQUIRE(source != NULL);

	if (cname->mctx == NULL) {
		return;
	}

	dns_name_free(&cname->cname, cname->mctx);
	cname->mctx = NULL;
}

static inline isc_result_t additionaldata_cname(ARGS_ADDLDATA)
{
	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == dns_rdatatype_cname);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t digest_cname(ARGS_DIGEST)
{
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_cname);

	dns_rdata_toregion(rdata, &r);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);

	return (dns_name_digest(&name, digest, arg));
}

static inline bool checkowner_cname(ARGS_CHECKOWNER)
{
	REQUIRE(type == dns_rdatatype_cname);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool checknames_cname(ARGS_CHECKNAMES)
{
	REQUIRE(rdata->type == dns_rdatatype_cname);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (true);
}

static inline int casecompare_cname(ARGS_COMPARE)
{
	return (compare_cname(rdata1, rdata2));
}

#endif /* RDATA_GENERIC_CNAME_5_C */
