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

/*
 *  U   U  DDD   PPP
 *  U   U  D  D  P  P
 *  U   U  D  D  PPP
 *  U   U  D  D  P
 *   UUU   DDD   P
 */

static isc_result_t
udp_send_direct(isc_nmsocket_t *socket,
		isc__nm_uvreq_t *req,
		isc_sockaddr_t *peer);

static void
udp_recv_cb(uv_udp_t *handle,
	    ssize_t nrecv,
	    const uv_buf_t *buf,
	    const struct sockaddr *addr,
	    unsigned flags);

static void
udp_send_cb(uv_udp_send_t *req, int status);


isc_result_t
isc_nm_udp_listen(isc_nm_t *mgr,
		  isc_nmiface_t *iface,
		  isc_nm_recv_cb_t cb,
		  size_t extrahandlesize,
		  void *arg,
		  isc_nmsocket_t **rv) {
	isc_nmsocket_t *nsocket;
	int res;

	/*
	 * We are creating nworkers duplicated sockets, one for each worker
	 * thread
	 */

	nsocket = malloc(sizeof(*nsocket)); /* TODO for debugging
	                                     * isc_mem_get(mgr->mctx,
	                                     * sizeof(*nsocket)); */
	isc__nmsocket_init(nsocket, mgr, isc_nm_udplistener);
	nsocket->iface = iface;
	nsocket->nchildren = mgr->nworkers;
	nsocket->rchildren = mgr->nworkers;
	nsocket->children = malloc(mgr->nworkers * sizeof(*nsocket));
/* TODO for debugging		isc_mem_get(mgr->mctx, mgr->nworkers *
 * sizeof(*nsocket)); */
	nsocket->rcb.recv = cb;
	nsocket->rcbarg = arg;
	nsocket->extrahandlesize = extrahandlesize;

	for (int i = 0; i < mgr->nworkers; i++) {
		isc__netievent_udplisten_t *ievent;
		isc_nmsocket_t *csocket = &nsocket->children[i];
		isc__nmsocket_init(csocket, mgr, isc_nm_udpsocket);
		csocket->parent = nsocket;
		csocket->iface = iface;
		csocket->tid = i;
		csocket->extrahandlesize = extrahandlesize;
		csocket->rcb.recv = cb;
		csocket->rcbarg = arg;
		csocket->fd = socket(AF_INET, SOCK_DGRAM, 0);
		INSIST(csocket->fd >= 0);
		res = setsockopt(csocket->fd,
				 SOL_SOCKET,
				 SO_REUSEPORT,
				 &(int){1},
				 sizeof(int));
		INSIST(res == 0);
		ievent = isc__nm_get_ievent(mgr, netievent_udplisten);
		ievent->socket = csocket;
		isc__nm_enqueue_ievent(&mgr->workers[i],
				       (isc__netievent_t*) ievent);
	}
	*rv = nsocket;
	return (ISC_R_SUCCESS);
}

void
isc_nm_udp_stoplistening(isc_nmsocket_t *socket) {
	int i;

	INSIST(VALID_NMSOCK(socket));
	/* We can't be launched from network thread */
	INSIST(isc__nm_tid() == ISC_NETMGR_TID_UNKNOWN);
	INSIST(socket->type == isc_nm_udplistener);

	for (i = 0; i < socket->nchildren; i++) {
		isc__netievent_udpstoplisten_t *ievent;
		ievent = isc__nm_get_ievent(socket->mgr,
					    netievent_udpstoplisten);
		ievent->socket = &socket->children[i];
		isc__nm_enqueue_ievent(&socket->mgr->workers[i],
				       (isc__netievent_t*) ievent);
	}
}

/*
 * handle 'udplisten' async call - start listening on a socket.
 */
void
isc__nm_handle_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_udplisten_t *ievent =
		(isc__netievent_udplisten_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;

	REQUIRE(socket->type == isc_nm_udpsocket);
	REQUIRE(socket->iface != NULL);
	REQUIRE(socket->parent != NULL);

	uv_udp_init(&worker->loop, &socket->uv_handle.udp);
	socket->uv_handle.udp.data = NULL;
	isc_nmsocket_attach(socket,
			    (isc_nmsocket_t**)&socket->uv_handle.udp.data);
	uv_udp_open(&socket->uv_handle.udp, socket->fd);
	uv_udp_bind(&socket->uv_handle.udp,
		    &socket->parent->iface->addr.type.sa,
		    0);
	uv_udp_recv_start(&socket->uv_handle.udp, isc__nm_alloc_cb,
			  udp_recv_cb);
}

static void
udp_close_cb(uv_handle_t *handle) {
	isc_nmsocket_t *socket = handle->data;
	isc_nmsocket_detach((isc_nmsocket_t**)&socket->uv_handle.udp.data);
}
/*
 * handle 'udpstoplisten' async call - stop listening on a socket.
 */
void
isc__nm_handle_udpstoplisten(isc__networker_t *worker,
			     isc__netievent_t *ievent0) {
	(void) worker;
	ck_stack_entry_t *sentry;
	isc__netievent_udplisten_t *ievent =
		(isc__netievent_udplisten_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;

	REQUIRE(socket->type == isc_nm_udpsocket);
	REQUIRE(socket->iface != NULL);
	REQUIRE(socket->parent != NULL);

	/* XXXWPK TODO do it properly! */
	if (uv_is_closing((uv_handle_t*) &socket->uv_handle.udp)) {
		return;
	}
	uv_udp_recv_stop(&socket->uv_handle.udp);
	uv_close((uv_handle_t*) &socket->uv_handle.udp, udp_close_cb);
	while ((sentry = ck_stack_pop_mpmc(&socket->inactivehandles)) !=
	       NULL)
	{
		isc_nmhandle_t *handle = nm_handle_is_get(sentry);
		isc__nmhandle_free(socket, handle);
	}
	while ((sentry = ck_stack_pop_mpmc(&socket->inactivereqs)) != NULL) {
		isc__nm_uvreq_t *uvreq = uvreq_is_get(sentry);
		isc_mem_put(socket->mgr->mctx, uvreq, sizeof(*uvreq));
	}
}


/*
 * udp_recv_cb handles incoming UDP packet from uv.
 * The buffer here is reused for a series of packets,
 * so we need to allocate a new one. This new one can
 * be reused to send the response then.
 */

static void
udp_recv_cb(uv_udp_t *handle,
	    ssize_t nrecv,
	    const uv_buf_t *buf,
	    const struct sockaddr *addr,
	    unsigned flags)
{
	isc_result_t result;
	isc_nmhandle_t *nmhandle;
	isc_sockaddr_t sockaddr;
	isc_region_t region;
	/* XXXWPK TODO handle it! */
	(void) flags;
	isc_nmsocket_t *socket = (isc_nmsocket_t *) handle->data;
	REQUIRE(VALID_NMSOCK(socket));
	INSIST(socket->rcb.recv != NULL);

	/*
	 * If addr == NULL that's the end of stream - we can
	 * free the buffer and bail.
	 */
	if (addr == NULL) {
		isc__nm_free_uvbuf(socket, buf);
		return;
	}

	result = isc_sockaddr_fromsockaddr(&sockaddr, addr);
	REQUIRE(result == ISC_R_SUCCESS);

	nmhandle = isc__nmhandle_get(socket, &sockaddr);
	region.base = (unsigned char *) buf->base;
	/* not buf->len, that'd be the whole buffer! */
	region.length = nrecv;

	socket->rcb.recv(socket->rcbarg, nmhandle, &region);
	isc__nm_free_uvbuf(socket, buf);

	/* If recv callback wants it it should attach to it */
	isc_nmhandle_detach(&nmhandle);
}

/*
 * isc__nm_udp_send sends buf to a peer on a socket.
 * It tries to find a proper sibling/child socket so that we won't have
 * to jump to other thread.
 */
isc_result_t
isc__nm_udp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg) {
	isc_nmsocket_t *psocket, *rsocket;
	isc_nmsocket_t *socket = handle->socket;
	isc_sockaddr_t *peer = &handle->peer;
	isc__netievent_udpsend_t *ievent;
	isc__nm_uvreq_t *uvreq;
	int ntid = socket->tid;

	if (socket->type == isc_nm_udpsocket) {
		INSIST(socket->parent != NULL);
		psocket = socket->parent;
	} else if (socket->type == isc_nm_udplistener) {
		psocket = socket;
	} else {
		return (ISC_R_UNEXPECTED);
	}

	ntid = isc__nm_tid() >= 0 ?
	       isc__nm_tid() : (int) isc_random_uniform(socket->nchildren);

	rsocket = &psocket->children[ntid];

	uvreq = isc__nm_uvreq_get(socket->mgr, socket);
	uvreq->uvbuf.base = (char *) region->base;
	uvreq->uvbuf.len = region->length;
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (isc__nm_tid() == rsocket->tid) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (udp_send_direct(rsocket, uvreq, peer));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(socket->mgr, netievent_udpsend);
		ievent->handle.socket = rsocket;
		ievent->handle.peer = *peer;
		ievent->req = uvreq;
		isc__nm_enqueue_ievent(&socket->mgr->workers[rsocket->tid],
				       (isc__netievent_t*) ievent);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_UNEXPECTED);
}


/*
 * handle 'udpsend' async event - send a packet on the socket
 */
void
isc__nm_handle_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_udpsend_t *ievent =
		(isc__netievent_udpsend_t *) ievent0;
	INSIST(worker->id == ievent->handle.socket->tid);
	udp_send_direct(ievent->handle.socket,
			ievent->req,
			&ievent->handle.peer);
}

/*
 * udp_send_cb - callback
 */
static void
udp_send_cb(uv_udp_send_t *req, int status) {
	isc_result_t result;
	isc__nm_uvreq_t *uvreq = (isc__nm_uvreq_t*)req->data;
	INSIST(VALID_UVREQ(uvreq));
	if (status == 0) {
		result = ISC_R_SUCCESS;
	} else {
		result = ISC_R_FAILURE;
	}
	INSIST(VALID_NMHANDLE(uvreq->handle));
	uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
	isc__nm_uvreq_put(&uvreq, uvreq->handle->socket);
}

/*
 * udp_send_direct sends buf to a peer on a socket. Sock has to be in
 * the same thread as the callee.
 */
static isc_result_t
udp_send_direct(isc_nmsocket_t *socket,
		isc__nm_uvreq_t *req,
		isc_sockaddr_t *peer)
{
	int rv;
	INSIST(socket->tid == isc__nm_tid());
	INSIST(socket->type == isc_nm_udpsocket);

	rv = uv_udp_send(&req->uv_req.udp_send,
			 &socket->uv_handle.udp,
			 &req->uvbuf,
			 1,
			 &peer->type.sa,
			 udp_send_cb);
	if (rv == 0) {
		return (ISC_R_SUCCESS);
	} else {
		/* TODO call cb! */
		return (ISC_R_FAILURE);
	}
}

