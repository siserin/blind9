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

#include "config.h"

#include <unistd.h>
#include <uv.h>
#include <ck_fifo.h>
#include <ck_stack.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"


static void
dnslisten_readcb(void *arg, isc_nmhandle_t*handle, isc_region_t *region);


/*
 * Accept callback for TCP-DNS connection
 */
static void
dnslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	INSIST(result == ISC_R_SUCCESS); /* XXXWPK TODO */
	isc_nmsocket_t *dnslistensocket = (isc_nmsocket_t*) cbarg;
	INSIST(VALID_NMSOCK(dnslistensocket));
	INSIST(dnslistensocket->type == isc_nm_tcpdnslistener);

	/* We need to create a 'wrapper' dnssocket for this connection */
	isc_nmsocket_t *dnssocket = isc_mem_get(handle->socket->mgr->mctx,
						sizeof(*dnssocket));
	isc__nmsocket_init(dnssocket, handle->socket->mgr,
			   isc_nm_tcpdnssocket);
	/* We need to copy read callbacks from parent socket */
	dnssocket->rcb.recv = dnslistensocket->rcb.recv;
	dnssocket->rcbarg = dnslistensocket->rcbarg;
	dnssocket->extrahandlesize = dnslistensocket->extrahandlesize;
	isc_nmsocket_attach(handle->socket, &dnssocket->parent);
	isc_nm_read(handle, dnslisten_readcb, dnssocket);
}

/*
 * We've got a read on our underlying socket, need to check if we have
 * a complete DNS packet and, if so - call the callback
 */
static void
dnslisten_readcb(void *arg, isc_nmhandle_t*handle, isc_region_t *region) {
	/* A 'wrapper' handle */
	(void)handle;
	isc_nmsocket_t *dnssocket = (isc_nmsocket_t*) arg;
	/* XXXWPK for the love of all that is holy fix it, that's so wrong */
	INSIST(((region->base[0] << 8) + (region->base[1]) ==
		(int) region->length - 2));
	isc_nmhandle_t *dnshandle =
		isc__nmhandle_get(dnssocket, &handle->peer);
	isc_region_t r2 =
	{.base = region->base + 2, .length = region->length - 2};
	dnssocket->rcb.recv(dnssocket->rcbarg, dnshandle, &r2);
}

/*
 * isc_nm_tcp_dnslistens listens for connections and accepts
 * them immediately, then calls the cb for each incoming DNS packet
 * (with 2-byte length stripped) - just like for UDP packet.
 */
isc_result_t
isc_nm_tcp_dnslisten(isc_nm_t *mgr,
		     isc_nmiface_t *iface,
		     isc_nm_recv_cb_t cb,
		     size_t extrahandlesize,
		     void *cbarg,
		     isc_nmsocket_t **rv)
{
	return (ISC_R_SUCCESS);
	isc_result_t result;

	/* A 'wrapper' socket object with parent set to true TCP socket */
	isc_nmsocket_t *dnslistensocket =
		isc_mem_get(mgr->mctx, sizeof(*dnslistensocket));
	isc__nmsocket_init(dnslistensocket, mgr, isc_nm_tcpdnslistener);
	dnslistensocket->iface = iface;
	dnslistensocket->rcb.recv = cb;
	dnslistensocket->rcbarg = cbarg;
	dnslistensocket->extrahandlesize = extrahandlesize;

	/* We set dnslistensocket->parent to a true listening socket */
	result = isc_nm_tcp_listen(mgr,
				   iface,
				   dnslisten_acceptcb,
				   extrahandlesize,
				   dnslistensocket,
				   &dnslistensocket->parent);
	*rv = dnslistensocket;
	return (result);
}

isc_result_t
isc_nm_tcpdns_stoplistening(isc_nmsocket_t **rv);


typedef struct tcpsend {
	isc_nmhandle_t *	handle;
	isc_region_t		region;
	isc_nmhandle_t *	orighandle;
	isc_nm_send_cb_t	cb;
	void*			cbarg;
} tcpsend_t;

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t*ts = (tcpsend_t*) cbarg;
	(void) handle;
	ts->cb(ts->orighandle, result, ts->cbarg);
}
/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle,
		    isc_region_t *region,
		    isc_nm_send_cb_t cb,
		    void *cbarg)
{
	isc_nmsocket_t *socket = handle->socket;

	INSIST(socket->type == isc_nm_tcpdnssocket);
	tcpsend_t *t = malloc(sizeof(*t));
	*t = (tcpsend_t) {};
	t->handle = &handle->socket->parent->tcphandle;
	t->cb = cb;
	t->cbarg = cbarg;
	t->region =
		(isc_region_t) { .base = malloc(region->length + 2),
				 .length = region->length + 2 };
	memmove(t->region.base + 2, region->base, region->length);
	t->region.base[0] = (uint8_t) (region->length >> 8);
	t->region.base[1] = (uint8_t) (region->length & 0xff);
	isc_nmhandle_attach(handle, &t->orighandle);
	return (isc__nm_tcp_send(t->handle, &t->region, tcpdnssend_cb, t));
}
