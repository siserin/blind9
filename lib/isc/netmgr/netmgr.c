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
 * libuv is not thread safe but has mechanisms to pass messages
 * between threads. Each socket is owned by a thread. For UDP
 * sockets we have a set of sockets for each interface and we can
 * choose a sibling and send the message directly. For TCP or if
 * we're calling from a not networking thread we need to pass the
 * request using async_cb
 */

#if defined(HAVE_TLS)
#if defined(HAVE_THREAD_LOCAL)
#include <threads.h>
static thread_local int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___THREAD)
static __thread int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___DECLSPEC_THREAD)
static __declspec( thread ) int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#else  /* if defined(HAVE_THREAD_LOCAL) */
#error "Unknown method for defining a TLS variable!"
#endif /* if defined(HAVE_THREAD_LOCAL) */
#else  /* if defined(HAVE_TLS) */
static int isc__nm_tid_v = ISC_NETMGR_TID_NOTLS;
#endif /* if defined(HAVE_TLS) */

static void *
nm_thread(void *worker0);

static void
async_cb(uv_async_t *handle);



int
isc__nm_tid() {
	return (isc__nm_tid_v);
}

/*
 * isc_nm_start creates and starts a network manager, with `workers` workers.
 */
isc_nm_t*
isc_nm_start(isc_mem_t *mctx, int workers) {
	int i;
	isc_result_t result;
	isc_nm_t*mgr;
	int r;
	char name[32];

	mgr = isc_mem_get(mctx, sizeof(*mgr));
	*mgr = (isc_nm_t) { .nworkers = workers};
	isc_mem_attach(mctx, &mgr->mctx);
	isc_mutex_init(&mgr->lock);
	isc_condition_init(&mgr->wkstatecond);
	isc_refcount_init(&mgr->refs, 1);
	mgr->workers = isc_mem_get(mctx, workers * sizeof(isc__networker_t));
	for (i = 0; i < workers; i++) {
		isc__networker_t *worker = &mgr->workers[i];
		mgr->workers[i] = (isc__networker_t) {
			.mgr = mgr,
			.id = i,
			.loop.data = &mgr->workers[i]
		};

		r = uv_loop_init(&worker->loop);
		RUNTIME_CHECK(r == 0);

		r = uv_async_init(&worker->loop,
				  &worker->async, async_cb);
		RUNTIME_CHECK(r == 0);

		isc_mutex_init(&worker->lock);
		isc_condition_init(&worker->cond);

		isc_mempool_create(mgr->mctx, 65536, &worker->mpool_bufs);
		struct ck_fifo_mpmc_entry *stub =
			isc_mem_get(mgr->mctx, sizeof(*stub));
		ck_fifo_mpmc_init(&worker->ievents, stub);

		result = isc_thread_create(nm_thread, &mgr->workers[i],
					   &worker->thread);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		snprintf(name, sizeof(name), "isc-net-%04u", i);
		isc_thread_setname(worker->thread, name);
	}
	mgr->magic = NM_MAGIC;
	return (mgr);
}

/*
 * isc_nm_shutdown shuts down the network manager.
 * TODO we need to clean up properly - launch all missing callbacks,
 * destroy all listeners, etc.
 */
void
isc_nm_shutdown(isc_nm_t **mgr0) {
	isc_nm_t *mgr = *mgr0;
	int i;

	LOCK(&mgr->lock);
	for (i = 0; i < mgr->nworkers; i++) {
		LOCK(&mgr->workers[i].lock);
		mgr->workers[i].finished = true;
		UNLOCK(&mgr->workers[i].lock);
		isc__netievent_t *ievent = isc__nm_get_ievent(mgr,
							      netievent_stop);
		isc__nm_enqueue_ievent(&mgr->workers[i], ievent);
	}
	while (mgr->workers_running > 0) {
		isc_condition_wait(&mgr->wkstatecond, &mgr->lock);
	}
	for (i = 0; i < mgr->nworkers; i++) {
		struct ck_fifo_mpmc_entry *garbage;
		ck_fifo_mpmc_deinit(&mgr->workers[i].ievents, &garbage);
		isc_mem_put(mgr->mctx, garbage, sizeof(*garbage));
		isc_mempool_destroy(&mgr->workers[i].mpool_bufs);
	}
	UNLOCK(&mgr->lock);
	isc_condition_destroy(&mgr->wkstatecond);
	isc_mutex_destroy(&mgr->lock);
	isc_mem_put(mgr->mctx, mgr->workers,
		    mgr->nworkers * sizeof(isc__networker_t));
	isc_mem_putanddetach(&mgr->mctx, mgr, sizeof(*mgr));
	*mgr0 = NULL;
}

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst) {
	INSIST(mgr != NULL);
	INSIST(dst != NULL && *dst == NULL);
	INSIST(isc_refcount_increment(&mgr->refs) > 0);
	*dst = mgr;
}

void
isc_nm_detach(isc_nm_t **mgr0) {
	isc_nm_t *mgr;
	int refs;

	INSIST(mgr0 != NULL);
	mgr = *mgr0;
	INSIST(VALID_NM(mgr));

	refs = isc_refcount_decrement(&mgr->refs);
	INSIST(refs > 0);
	if (refs == 1) {
		/* XXXWPK TODO */
	}
	mgr0 = NULL;
}


/*
 * nm_thread is a single worker thread, that runs uv_run event loop
 * until asked to stop.
 */
static void *
nm_thread(void *worker0) {
	isc__networker_t *worker = (isc__networker_t*) worker0;
	atomic_fetch_add_explicit(&worker->mgr->workers_running, 1,
				  memory_order_relaxed);
	isc__nm_tid_v = worker->id;
	while (true) {
		int r = uv_run(&worker->loop, UV_RUN_DEFAULT);
		/*
		 * or there's nothing to do. In the first case - wait
		 * for condition. In the latter - timedwait
		 */
		LOCK(&worker->lock);
		while (worker->paused) {
			atomic_fetch_sub_explicit(&worker->mgr->workers_paused,
						  1, memory_order_acquire);
			isc_condition_signal(&worker->mgr->wkstatecond);
			isc_condition_wait(&worker->cond, &worker->lock);
		}
		atomic_fetch_add_explicit(&worker->mgr->workers_paused, 1,
					  memory_order_release);
		UNLOCK(&worker->lock);
		if (worker->finished) {
			/* TODO walk the handles and free them! */
			break;
		}

		if (r == 0) {
			/* TODO */
			usleep(100000);
		}
	}
	atomic_fetch_sub_explicit(&worker->mgr->workers_running, 1,
				  memory_order_relaxed);
	isc_condition_signal(&worker->mgr->wkstatecond);
	return (NULL);
}


/*
 * async_cb is an universal callback for 'async' events sent to event loop.
 * It's the only way to safely pass data to libuv event loop. We use a single
 * async event and a lockless queue of 'isc__netievent_t' structures passed
 * from other threads.
 */
static void
async_cb(uv_async_t *handle) {
	isc__networker_t *worker = (isc__networker_t *) handle->loop->data;
	isc__netievent_t *ievent;
	struct ck_fifo_mpmc_entry *garbage;
	/*
	 * We only try dequeue to not waste time, libuv guarantees
	 * that if someone calls uv_async_send -after- async_cb was called
	 * then async_cb will be called again, we won't loose any signals.
	 */
	while (ck_fifo_mpmc_trydequeue(&worker->ievents, &ievent, &garbage)) {
		switch (ievent->type) {
		case netievent_stop:
			uv_stop(handle->loop);
			break;
		case netievent_udplisten:
			isc__nm_handle_udplisten(worker, ievent);
			break;
		case netievent_udpstoplisten:
			isc__nm_handle_udpstoplisten(worker, ievent);
			break;
		case netievent_udpsend:
			isc__nm_handle_udpsend(worker, ievent);
			break;
		case netievent_tcpconnect:
			isc__nm_handle_tcpconnect(worker, ievent);
			break;
		case netievent_tcplisten:
			isc__nm_handle_tcplisten(worker, ievent);
			break;
		case netievent_tcpstartread:
			isc__nm_handle_startread(worker, ievent);
			break;
/*              case netievent_tcpstopread:
 *                      handle_stopread(worker, ievent);
 *                      break; */
		case netievent_tcpsend:
			isc__nm_handle_tcpsend(worker, ievent);
			break;


/*              case netievent_tcpstoplisten:
 *                      handle_tcpstoplisten(worker, ievent);
 *                      break; */
		default:
			INSIST(0);
		}
		isc_mem_put(worker->mgr->mctx, ievent,
			    sizeof(isc__netievent_storage_t));
		isc_mem_put(worker->mgr->mctx, garbage, sizeof(*garbage));
	}
}
/*
 * isc__nm_get_ievent allocates an ievent and sets the type
 * xxxwpk: use pool?
 */
void *
isc__nm_get_ievent(isc_nm_t *mgr, isc__netievent_type type) {
	isc__netievent_t *event =
		isc_mem_get(mgr->mctx, sizeof(isc__netievent_storage_t));
	*event = (isc__netievent_t) { .type = type };
	return (event);
}

/*
 * enqueue ievent on a specific worker queue. This the only safe
 * way to use isc__networker_t from another thread.
 */
void
isc__nm_enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event) {
	struct ck_fifo_mpmc_entry *entry = isc_mem_get(worker->mgr->mctx,
						       sizeof(*entry));
	ck_fifo_mpmc_enqueue(&worker->ievents, entry, event);
	uv_async_send(&worker->async);
}



void
isc_nmsocket_attach(isc_nmsocket_t *socket, isc_nmsocket_t **target) {
	REQUIRE(VALID_NMSOCK(socket));
	REQUIRE(target != NULL && *target == NULL);
	isc_refcount_increment(&socket->refs);
	*target = socket;
}

void
isc_nmsocket_detach(isc_nmsocket_t **socketp) {
	isc_nmsocket_t *socket;
	int refs;
	REQUIRE(socketp != NULL && *socketp != NULL);
	socket = *socketp;
	REQUIRE(VALID_NMSOCK(socket));

	refs = isc_refcount_decrement(&socket->refs);
	INSIST(refs > 0);
	if (refs == 1) {
		switch (socket->type) {
		case isc_nm_udplistener:
			isc_nm_udp_stoplistening(socket);
			break;
		case isc_nm_udpsocket:
		default:
			break;
		}
		/* TODO - wait for callback, only then free everything */
	}
	/* TODO free it! */
	*socketp = NULL;
}

void
isc__nmsocket_init(isc_nmsocket_t *socket,
		   isc_nm_t *mgr,
		   isc_nmsocket_type type) {
	*socket = (isc_nmsocket_t) {
		.type = type,
		.fd = -1
	};

	isc_nm_attach(mgr, &socket->mgr);
	uv_handle_set_data(&socket->uv_handle.handle, socket);

	ck_stack_init(&socket->inactivehandles);
	ck_stack_init(&socket->inactivereqs);
	socket->magic = NMSOCK_MAGIC;
	isc_refcount_init(&socket->refs, 1);
	if (type == isc_nm_tcpsocket) {
		socket->tcphandle = (isc_nmhandle_t) { .socket = socket};
	}
}
/*
 * alloc_cb for recv operations. XXXWPK TODO use a pool
 */
void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *socket = (isc_nmsocket_t *) handle->data;
	REQUIRE(VALID_NMSOCK(socket));
	REQUIRE(socket->tid >= 0);
	INSIST(size <= 65536);
	/* TODO that's for UDP only! */
	isc__networker_t *worker = &socket->mgr->workers[socket->tid];
	REQUIRE(!worker->udprecvbuf_inuse);
	buf->base = worker->udprecvbuf;
/*	buf->base = isc_mempool_get(worker->mpool_bufs); */
	worker->udprecvbuf_inuse = true;
	buf->len = size;
}

void
isc__nm_free_uvbuf(isc_nmsocket_t *socket, const uv_buf_t *buf) {
	REQUIRE(VALID_NMSOCK(socket));
	(void) buf;
	isc__networker_t *worker = &socket->mgr->workers[socket->tid];
	REQUIRE(worker->udprecvbuf_inuse);
	REQUIRE(buf->base == worker->udprecvbuf);
	worker->udprecvbuf_inuse = false;
/*	void *b = buf->base;
 *      if (b != NULL) {
 *              isc_mempool_put(worker->mpool_bufs, b);
 *      } */
}

/*
 * alloc_handle allocates a handle. XXXWPK TODO use a pool
 */

static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *socket);

static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *socket) {
	isc_nmhandle_t *handle;
	handle = isc_mem_get(socket->mgr->mctx,
			     sizeof(isc_nmhandle_t) +
			     socket->extrahandlesize);
	*handle = (isc_nmhandle_t) {};
	isc_refcount_init(&handle->refs, 1);
	handle->magic = NMHANDLE_MAGIC;
	return (handle);
}

isc_nmhandle_t *
isc__nmhandle_get(isc_nmsocket_t *socket, isc_sockaddr_t *peer) {
	isc_nmhandle_t *handle = NULL;
	ck_stack_entry_t *sentry;
	REQUIRE(VALID_NMSOCK(socket));
	INSIST(peer != NULL);
	if (socket->type == isc_nm_tcpsocket) {
		handle = &socket->tcphandle;
		/* XXXWPK this should be more elegant */
		INSIST(!VALID_NMHANDLE(handle));
		*handle = (isc_nmhandle_t) {};
		isc_refcount_init(&handle->refs, 1);
		handle->magic = NMHANDLE_MAGIC;
	} else {
		sentry = ck_stack_pop_mpmc(&socket->inactivehandles);
		if (sentry != NULL) {
			handle = nm_handle_is_get(sentry);
		}
		if (handle == NULL) {
			handle = alloc_handle(socket);
		} else {
			INSIST(VALID_NMHANDLE(handle));
			isc_refcount_increment(&handle->refs);
		}
	}
	isc_nmsocket_attach(socket, &handle->socket);
	memcpy(&handle->peer, peer, sizeof(isc_sockaddr_t));
	return(handle);
}

void
isc_nmhandle_attach(isc_nmhandle_t *handle, isc_nmhandle_t **handlep) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(handlep != NULL && *handlep == NULL);
	INSIST(isc_refcount_increment(&handle->refs) > 0);
	*handlep = handle;
}

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle) {
	return(handle->socket->type == isc_nm_tcpsocket ||
	       handle->socket->type == isc_nm_tcpdnssocket);
}

void
isc__nmhandle_free(isc_nmsocket_t *socket, isc_nmhandle_t *handle) {
	size_t extra = socket->extrahandlesize;
	if (handle->dofree) {
		handle->dofree(handle->opaque);
	}
	handle->magic = 0;
	handle->refs = 0;
	isc_mem_put(socket->mgr->mctx,
		    handle,
		    sizeof(isc_nmhandle_t) + extra);
}

void
isc_nmhandle_detach(isc_nmhandle_t **handlep) {
	isc_nmhandle_t *handle = *handlep;
	REQUIRE(VALID_NMHANDLE(handle));
	if (isc_refcount_decrement(&handle->refs) == 1) {
		/* Move reference */
		isc_nmsocket_t *socket = handle->socket;
		handle->socket = NULL;
		if (handle->doreset != NULL) {
			handle->doreset(handle->opaque);
		}
		bool reuse = ck_stack_trypush_mpmc(&socket->inactivehandles,
						   &handle->ilink);
		if (!reuse) {
			isc__nmhandle_free(socket, handle);
		}
		isc_nmsocket_detach(&socket);
	}
	*handlep = NULL;
}


void *
isc_nmhandle_getdata(isc_nmhandle_t *handle) {
	INSIST(VALID_NMHANDLE(handle));
	return (handle->opaque);
}

void
isc_nmhandle_setdata(isc_nmhandle_t *handle,
		     void *arg,
		     isc_nm_opaquecb doreset,
		     isc_nm_opaquecb dofree) {
	INSIST(VALID_NMHANDLE(handle));
	handle->opaque = arg;
	handle->doreset = doreset;
	handle->dofree = dofree;
}

void*
isc_nmhandle_getextra(isc_nmhandle_t *handle) {
	INSIST(VALID_NMHANDLE(handle));
	return (handle->extra);
}

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle) {
	INSIST(VALID_NMHANDLE(handle));
	return (handle->peer);
}

/*
 * isc__nm_uvreq_get returns an uv_req_t of specified type
 * with data field set up.
 */

isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *socket) {
	isc__nm_uvreq_t *req = NULL;
	if (socket != NULL) {
		/* Try to reuse one */
		ck_stack_entry_t *sentry =
			ck_stack_pop_mpmc(&socket->inactivereqs);
		if (sentry != NULL) {
			req = uvreq_is_get(sentry);
		}
	}
	if (req == NULL) {
		req = isc_mem_get(mgr->mctx, sizeof(isc__nm_uvreq_t));
	}
	uv_req_set_data(&req->uv_req.req, req);
	req->mgr = NULL;
	isc_nm_attach(mgr, &req->mgr);
	req->magic = UVREQ_MAGIC;
	req->handle = NULL;
	return (req);
}

/*
 * isc__nm_uvreq_put frees uv_req_t of specified type
 */
void
isc__nm_uvreq_put(isc__nm_uvreq_t **req0, isc_nmsocket_t *socket) {
	isc__nm_uvreq_t *req;
	isc_nm_t *mgr;

	INSIST(req0 != NULL);
	req = *req0;
	INSIST(VALID_UVREQ(req));
	req0 = NULL;
	req->magic = 0;
	if (req->handle != NULL) {
		isc_nmhandle_detach(&req->handle);
	}
	/*
	 * We need to do it this way to make sure that mgr won't disappear
	 * in the meantime, taking mctx with it.
	 */
	mgr = req->mgr;
	req->mgr = NULL;
	if (!(socket != NULL &&
	      ck_stack_trypush_mpmc(&socket->inactivereqs, &req->ilink))) {
		isc_mem_put(mgr->mctx, req, sizeof(isc__nm_uvreq_t));
	}
	isc_nm_detach(&mgr);
}

/*
 * isc_nm_send sends data in 'region' to endpoint specified by 'handle'
 * handle can be of any type.
 */
isc_result_t
isc_nm_send(isc_nmhandle_t *handle,
	    isc_region_t *region,
	    isc_nm_send_cb_t cb,
	    void *cbarg)
{
	switch (handle->socket->type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		return (isc__nm_udp_send(handle, region, cb, cbarg));
	case isc_nm_tcpsocket:
		return (isc__nm_tcp_send(handle, region, cb, cbarg));
	case isc_nm_tcpdnssocket:
		return (isc__nm_tcpdns_send(handle, region, cb, cbarg));
	default:
		INSIST(0);
	}
	return (ISC_R_FAILURE);
}
