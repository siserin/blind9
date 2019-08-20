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
 * TTTTT   CCC   PPP
 *   T    C   C  P  P
 *   T    C      PPP
 *   T    C   C  P
 *   T     CCC   P
 */

static int
tcp_connect_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req);

static isc_result_t
tcp_send_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req);
static void
tcp_connect_cb(uv_connect_t *uvreq, int status);

static void
tcp_connection_cb(uv_stream_t *server, int status);

static void
read_cb(uv_stream_t*stream, ssize_t nread, const uv_buf_t*buf);


/*
 * isc_nm_tcp_connect connects to 'peer' using (optional) 'iface' as the
 * source IP.
 * If the result is ISC_R_SUCCESS then the cb is always called.
 */
isc_result_t
isc_nm_tcp_connect(isc_nm_t*mgr,
		   isc_nmiface_t *iface,
		   isc_sockaddr_t *peer,
		   isc_nm_connect_cb_t cb,
		   void *cbarg)
{
	isc_nmsocket_t *sock;
	isc__nm_uvreq_t *req;
	isc_result_t result;

	sock = isc_mem_get(mgr->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(sock, mgr, isc_nm_tcpsocket);

	sock->uv_handle.tcp.data = sock;

	req = isc__nm_uvreq_get(sock->mgr, sock);
	memcpy(&req->peer, peer, peer->length);
	if (iface != NULL) {
		memcpy(&req->local, iface, iface->addr.length);
	} else {
		req->local.length = 0;
	}
	req->cb.connect = cb;
	req->cbarg = cbarg;

	result = tcp_connect_direct(sock, req);
	if (result != ISC_R_SUCCESS) {
		isc__nm_uvreq_put(&req, NULL);
		isc_mem_put(mgr->mctx, sock, sizeof(isc_nmsocket_t));
	}
	return (result);
}

static int
tcp_connect_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req)
{
	isc__networker_t *worker;
	int r;

	REQUIRE(isc_nm_tid() >= 0);

	worker = &req->mgr->workers[isc_nm_tid()];

	r = uv_tcp_init(&worker->loop, &socket->uv_handle.tcp);
	if (r != 0) {
		return (r);
	}
	if (req->local.length != 0) {
		r = uv_tcp_bind(&socket->uv_handle.tcp,
				&req->local.type.sa,
				0);
		if (r != 0) {
			/* TODO uv_close() */
			return (r);
		}
	}
	r = uv_tcp_connect(&req->uv_req.connect,
			   &socket->uv_handle.tcp,
			   &req->peer.type.sa,
			   tcp_connect_cb);
	return (r);
}

void
isc__nm_handle_tcpconnect(isc__networker_t *worker,
			  isc__netievent_t *ievent0) {
	int r;
	isc__netievent_tcpconnect_t *ievent =
		(isc__netievent_tcpconnect_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;
	isc__nm_uvreq_t *req = ievent->req;

	REQUIRE(socket->type == isc_nm_tcpsocket);
	REQUIRE(worker->id == ievent->req->mgr->workers[isc_nm_tid()].id);

	r = tcp_connect_direct(socket, req);
	if (r != 0) {
		/* We need to issue callbacks ourselves */
		tcp_connect_cb(&req->uv_req.connect, r);
	}
}

static void
tcp_connect_cb(uv_connect_t *uvreq, int status) {
	isc__nm_uvreq_t *req = (isc__nm_uvreq_t*) uvreq->data;
	isc_nmsocket_t *socket = uvreq->handle->data;
	INSIST(VALID_UVREQ(req));

	if (status == 0) {
		isc_sockaddr_t peer;
		struct sockaddr_storage ss;
		int l = sizeof(ss);
		uv_tcp_getpeername(&socket->uv_handle.tcp,
				   (struct sockaddr*) &ss,
				   &l);
		isc_result_t result =
			isc_sockaddr_fromsockaddr(&peer,
						  (struct sockaddr*) &ss);
		INSIST(result == ISC_R_SUCCESS);

		isc_nmhandle_t *handle = isc__nmhandle_get(socket, &peer);
		/* handle->peer = NULL; */
		req->cb.connect(handle, ISC_R_SUCCESS, req->cbarg);
	} else {
		/* TODO handle it properly, free socket, translate code */
		req->cb.connect(NULL, ISC_R_FAILURE, req->cbarg);
	}
	isc__nm_uvreq_put(&req, socket);
}

isc_result_t
isc_nm_tcp_listen(isc_nm_t *mgr,
		  isc_nmiface_t *iface,
		  isc_nm_accept_cb_t cb,
		  size_t extrahandlesize,
		  void *cbarg,
		  isc_nmsocket_t **rv)
{
	isc__netievent_tcplisten_t *ievent;
	INSIST(VALID_NM(mgr));
	isc_nmsocket_t *nsocket;

	nsocket = isc_mem_get(mgr->mctx, sizeof(*nsocket));
	isc__nmsocket_init(nsocket, mgr, isc_nm_tcplistener);
	nsocket->iface = iface;
	nsocket->rcb.accept = cb;
	nsocket->rcbarg = cbarg;
	nsocket->extrahandlesize = extrahandlesize;
	nsocket->tid = isc_random_uniform(mgr->nworkers);
	/*
	 * Listening to TCP is rare enough not to care about the
	 * added overhead from passing this to another thread.
	 */
	ievent = isc__nm_get_ievent(mgr, netievent_tcplisten);
	ievent->socket = nsocket;
	isc__nm_enqueue_ievent(&mgr->workers[nsocket->tid],
			       (isc__netievent_t*) ievent);
	*rv = nsocket;
	return (ISC_R_SUCCESS);
}

void
isc__nm_handle_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
	int r;
	isc__netievent_tcplisten_t *ievent =
		(isc__netievent_tcplisten_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;

	REQUIRE(isc_nm_tid() >= 0);
	REQUIRE(socket->type == isc_nm_tcplistener);

	r = uv_tcp_init(&worker->loop, &socket->uv_handle.tcp);
	if (r != 0) {
		return;
	}

	uv_tcp_bind(&socket->uv_handle.tcp, &socket->iface->addr.type.sa, 0);
	r = uv_listen((uv_stream_t*) &socket->uv_handle.tcp,
		      10,
		      tcp_connection_cb);
	socket->listening = true;
	return;
	/* issue callback? */
}


void
isc_nm_tcp_stoplistening(isc_nmsocket_t *socket) {
	isc__netievent_tcpstoplisten_t *ievent;
	INSIST(VALID_NMSOCK(socket));
	REQUIRE(!isc__nm_in_netthread());

	ievent = isc__nm_get_ievent(socket->mgr, netievent_tcpstoplisten);
	isc_nmsocket_attach(socket, &ievent->socket);
	isc__nm_enqueue_ievent(&socket->mgr->workers[socket->tid],
			       (isc__netievent_t*) ievent);
	isc_mutex_lock(&socket->lock);
	while (atomic_load(&socket->listening) == true) {
		isc_condition_wait(&socket->cond, &socket->lock);
	}
	isc_mutex_unlock(&socket->lock);
	isc_nmsocket_detach(&socket);
}

static void
stoplistening_cb(uv_handle_t *handle) {
	isc_nmsocket_t *socket = handle->data;
	isc_mutex_lock(&socket->lock);
	atomic_store(&socket->listening, false);
	isc_condition_signal(&socket->cond);
	isc_mutex_unlock(&socket->lock);
}

void
isc__nm_handle_tcpstoplistening(isc__networker_t *worker,
				isc__netievent_t *ievent0) {
	(void)worker;
	isc__netievent_tcpstoplisten_t *ievent =
		(isc__netievent_tcpstoplisten_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;

	REQUIRE(isc_nm_tid() >= 0);
	REQUIRE(VALID_NMSOCK(socket));
	REQUIRE(socket->type == isc_nm_tcplistener);

	uv_close(&socket->uv_handle.handle, stoplistening_cb);
}


isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	INSIST(VALID_NMHANDLE(handle));
	isc_nmsocket_t *socket = handle->socket;
	INSIST(VALID_NMSOCK(socket));
	socket->rcb.recv = cb;
	socket->rcbarg = cbarg; /* That's obviously broken... */
	if (socket->tid == isc_nm_tid()) {
		uv_read_start(&socket->uv_handle.stream,
			      isc__nm_alloc_cb,
			      read_cb);
	} else {
		isc__netievent_startread_t *ievent =
			isc__nm_get_ievent(socket->mgr,
					   netievent_tcpstartread);
		ievent->socket = socket;
		isc__nm_enqueue_ievent(&socket->mgr->workers[socket->tid],
				       (isc__netievent_t*) ievent);
	}
	return (ISC_R_SUCCESS);
}

void
isc__nm_handle_startread(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_startread_t *ievent =
		(isc__netievent_startread_t *) ievent0;
	REQUIRE(worker->id == isc_nm_tid());

	isc_nmsocket_t *socket = ievent->socket;

	uv_read_start(&socket->uv_handle.stream, isc__nm_alloc_cb, read_cb);
}

static void
read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t*buf) {
	isc_nmsocket_t *socket = uv_handle_get_data((uv_handle_t*) stream);
	INSIST(buf != NULL);
	if (nread < 0) {
		isc__nm_free_uvbuf(socket, buf);
		/* XXXWPK TODO clean up handles! */
		return;
	}
	isc_region_t region = { .base = (unsigned char *) buf->base,
				.length = nread };

	INSIST(VALID_NMSOCK(socket));
	INSIST(socket->rcb.recv != NULL);

	socket->rcb.recv(socket->rcbarg, &socket->tcphandle, &region);
	isc__nm_free_uvbuf(socket, buf);
}

static void
tcp_connection_cb(uv_stream_t *server, int status) {
	(void) status; /* TODO */
	isc_nmsocket_t *csocket, *ssocket;
	isc__networker_t *worker;

	ssocket = uv_handle_get_data((uv_handle_t*) server);
	REQUIRE(VALID_NMSOCK(ssocket));
	REQUIRE(ssocket->tid == isc_nm_tid());
	if (!atomic_load_relaxed(&ssocket->active)) {
		/* We're closing, bail */
		return;
	}
	INSIST(ssocket->rcb.accept != NULL);

	worker = &ssocket->mgr->workers[isc_nm_tid()];

	csocket = isc_mem_get(ssocket->mgr->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(csocket, ssocket->mgr, isc_nm_tcpsocket);
	csocket->tid = isc_nm_tid();
	csocket->extrahandlesize = ssocket->extrahandlesize;

	uv_tcp_init(&worker->loop, &csocket->uv_handle.tcp);
	int r = uv_accept(server, &csocket->uv_handle.stream);
	if (r != 0) {
		return; /* XXXWPK TODO LOG */
	}
	isc_sockaddr_t peer;
	struct sockaddr_storage ss;
	int l = sizeof(ss);
	uv_tcp_getpeername(&csocket->uv_handle.tcp, (struct sockaddr*) &ss,
			   &l);
	isc_result_t result =
		isc_sockaddr_fromsockaddr(&peer, (struct sockaddr*) &ss);
	INSIST(result == ISC_R_SUCCESS);
	isc_nmhandle_t *handle = isc__nmhandle_get(csocket, &peer);
	ssocket->rcb.accept(handle, ISC_R_SUCCESS, ssocket->rcbarg);
}

/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg)
{
	isc_nmsocket_t *socket = handle->socket;
	isc__netievent_udpsend_t *ievent;
	isc__nm_uvreq_t *uvreq;

	INSIST(socket->type == isc_nm_tcpsocket);

	uvreq = isc__nm_uvreq_get(socket->mgr, socket);
	uvreq->uvbuf.base = (char *) region->base;
	uvreq->uvbuf.len = region->length;
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (socket->tid == isc_nm_tid()) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (tcp_send_direct(socket, uvreq));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(socket->mgr, netievent_tcpsend);
		ievent->handle.socket = socket;
		ievent->req = uvreq;
		isc__nm_enqueue_ievent(&socket->mgr->workers[socket->tid],
				       (isc__netievent_t*) ievent);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_UNEXPECTED);
}

static void
tcp_send_cb(uv_write_t *req, int status) {
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
 * handle 'tcpsend' async event - send a packet on the socket
 */
void
isc__nm_handle_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_udpsend_t *ievent =
		(isc__netievent_udpsend_t *) ievent0;
	INSIST(worker->id == ievent->handle.socket->tid);
	isc_result_t result = tcp_send_direct(ievent->handle.socket,
					      ievent->req);
	if (result != ISC_R_SUCCESS) {
		ievent->req->cb.send(NULL, result, ievent->req->cbarg);
		isc__nm_uvreq_put(&ievent->req, ievent->req->handle->socket);
	}
}

static isc_result_t
tcp_send_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req)
{
	int rv;
	INSIST(socket->tid == isc_nm_tid());
	INSIST(socket->type == isc_nm_tcpsocket);

	rv = uv_write(&req->uv_req.write,
		      &socket->uv_handle.stream,
		      &req->uvbuf,
		      1,
		      tcp_send_cb);
	if (rv == 0) {
		return (ISC_R_SUCCESS);
	} else {
		/* TODO call cb! */
		return (ISC_R_FAILURE);
	}
}
