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

/*
 * libuv is not thread safe but has mechanisms to pass messages
 * between threads. Each socket is owned by a thread. For UDP
 * sockets we have a set of sockets for each interface and we can
 * choose a sibling and send the message directly. For TCP or if
 * we're calling from a not networking thread we need to pass the
 * request using async_cb
 */

#define ISC_NETMGR_TID_UNKNOWN -1
#define ISC_NETMGR_TID_NOTLS -2
#if defined(HAVE_TLS)
#if defined(HAVE_THREAD_LOCAL)
#include <threads.h>
static thread_local int isc_netmgr_tid = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___THREAD)
static __thread int isc_netmgr_tid = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___DECLSPEC_THREAD)
static __declspec( thread ) int isc_netmgr_tid = ISC_NETMGR_TID_UNKNOWN;
#else  /* if defined(HAVE_THREAD_LOCAL) */
#error "Unknown method for defining a TLS variable!"
#endif /* if defined(HAVE_THREAD_LOCAL) */
#else  /* if defined(HAVE_TLS) */
static int isc_netmgr_tid = ISC_NETMGR_TID_NOTLS;
#endif /* if defined(HAVE_TLS) */


/*
 * Single network event loop worker.
 */
typedef struct isc__networker {
	isc_nm_t *		   mgr;
	int			   id;          /* thread id */
	uv_loop_t		   loop;        /* libuv loop structure */
	uv_async_t		   async;       /* async channel to send
	                                         * data to this networker */
	isc_mutex_t		   lock;
	isc_mempool_t *		   mpool_bufs;
	isc_condition_t		   cond;
	bool			   paused;
	bool			   finished;
	isc_thread_t		   thread;
	struct ck_fifo_mpmc	   ievents;     /* incoming async events */
	isc_refcount_t		   references;
	atomic_int_fast64_t	   pktcount;
	char			   udprecvbuf[65536];
	bool			   udprecvbuf_inuse;
} isc__networker_t;

/*
 * A general handle for a connection bound to a networker.
 * For UDP connections we have peer address here,
 * so both TCP and UDP can be handled with a simple send-like
 * function
 */
#define NMHANDLE_MAGIC                        ISC_MAGIC('N', 'M', 'H', 'D')
#define VALID_NMHANDLE(t)                     ISC_MAGIC_VALID(t, \
							      NMHANDLE_MAGIC)

struct isc_nmhandle {
	int			magic;
	isc_refcount_t		refs;
	isc_nmsocket_t *	socket;
	isc_sockaddr_t		peer;
	void *			opaque;
	ck_stack_entry_t	ilink;
	isc_nm_opaquecb		doreset;
	isc_nm_opaquecb		dofree;
	char			extra[];
};

CK_STACK_CONTAINER(struct isc_nmhandle, ilink, nm_handle_is_get)

/*
 * An interface - an address we can listen on.
 */
struct isc_nmiface {
	isc_sockaddr_t        addr;
};

typedef enum isc__netievent_type {
	netievent_stop,
	netievent_udplisten,
	netievent_udpstoplisten,
	netievent_udpsend,
	netievent_udprecv,
	netievent_tcpconnect,
	netievent_tcpsend,
	netievent_tcprecv,
	netievent_tcpstartread,
	netievent_tcpstopread,
	netievent_tcplisten,
	netievent_tcpstoplisten,
} isc__netievent_type;

typedef struct isc__netievent_stop {
	isc__netievent_type        type;
} isc__netievent_stop_t;

/* We have to split it because we can read and write on a socket simultaneously */
typedef union {
	isc_nm_recv_cb_t	   recv;
	isc_nm_accept_cb_t	   accept;
} isc__nm_readcb_t;

typedef union {
	isc_nm_send_cb_t	   send;
	isc_nm_connect_cb_t	   connect;
} isc__nm_writecb_t;

typedef union {
	isc_nm_recv_cb_t	   recv;
	isc_nm_accept_cb_t	   accept;
	isc_nm_send_cb_t	   send;
	isc_nm_connect_cb_t	   connect;
} isc__nm_cb_t;

/*
 * Wrapper around uv_req_t with 'our' fields in it.
 * req->data should always point to it's parent.
 * Note that we always allocate more than sizeof(struct)
 * because we make room for different req types;
 */
#define UVREQ_MAGIC                        ISC_MAGIC('N', 'M', 'U', 'R')
#define VALID_UVREQ(t)                     ISC_MAGIC_VALID(t, UVREQ_MAGIC)

typedef struct isc__nm_uvreq {
	int		      magic;
	isc_nm_t *	      mgr;
	uv_buf_t	      uvbuf; /* translated isc_region_t, to be sent or
	                              * received */
	isc_sockaddr_t	      local; /* local address */
	isc_sockaddr_t	      peer;  /* peer address */
	isc__nm_cb_t 	      cb;    /* callback */
	void *		      cbarg;
	isc_nmhandle_t *      handle;
	ck_stack_entry_t      ilink;
	union {
		uv_req_t		req;
		uv_getaddrinfo_t	getaddrinfo;
		uv_getnameinfo_t	getnameinfo;
		uv_shutdown_t		shutdown;
		uv_write_t		write;
		uv_connect_t		connect;
		uv_udp_send_t		udp_send;
		uv_fs_t			fs;
		uv_work_t		work;
	} uv_req;
} isc__nm_uvreq_t;

CK_STACK_CONTAINER(struct isc__nm_uvreq, ilink, uvreq_is_get);

/*
 * Make the worker listen for UDP requests on a specified socket.
 * socket must have FD and iface filled.
 */

typedef struct isc__netievent_udplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
} isc__netievent_udplisten_t;

typedef struct isc__netievent_udpstoplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
} isc__netievent_udpstoplisten_t;

typedef struct isc__netievent_udpsend {
	isc__netievent_type	   type;
	isc_nmhandle_t		   handle;
	isc__nm_uvreq_t *	   req;
} isc__netievent_udpsend_t;

typedef struct isc__netievent_tcpconnect {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcpconnect_t;

typedef struct isc__netievent_tcplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcplisten_t;

typedef struct isc__netievent_tcpsend {
	isc__netievent_type	   type;
	isc_nmhandle_t		   handle;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcpsend_t;

typedef struct isc__netievent_startread {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_startread_t;

typedef struct isc__netievent {
	isc__netievent_type        type;
} isc__netievent_t;

typedef struct isc__netievent_storage {
	union {
		isc__netievent_t		  ni;
		isc__netievent_stop_t		  nis;
		isc__netievent_udplisten_t	  niul;
		isc__netievent_udpsend_t	  nius;
	};
} isc__netievent_storage_t;

/*
 * Network manager
 */
#define NM_MAGIC                        ISC_MAGIC('N', 'E', 'T', 'M')
#define VALID_NM(t)                     ISC_MAGIC_VALID(t, NM_MAGIC)

struct isc_nm {
	int			    magic;
	isc_refcount_t		    refs;
	isc_mem_t *		    mctx;
	int			    nworkers;
	isc_mutex_t		    lock;
	isc_condition_t		    wkstatecond;
	isc__networker_t *	    workers;
	atomic_uint_fast32_t	    workers_running;
	atomic_uint_fast32_t	    workers_paused;
};


typedef enum isc_nmsocket_type {
	isc_nm_udpsocket,
	isc_nm_udplistener, /* Aggregate of nm_udpsocks */
	isc_nm_tcpsocket,
	isc_nm_tcplistener,
	isc_nm_tcpdnslistener,
	isc_nm_tcpdnssocket
} isc_nmsocket_type;


/*
 * An universal structure for either a single socket or
 * a group of dup'd/SO_REUSE_PORT-using sockets listening
 * on the same interface.
 */
#define NMSOCK_MAGIC                    ISC_MAGIC('N', 'M', 'S', 'K')
#define VALID_NMSOCK(t)                 ISC_MAGIC_VALID(t, NMSOCK_MAGIC)
struct isc_nmsocket {
	int				  magic;
	isc_nmsocket_type		  type;
	isc_refcount_t			  refs;
	isc_nm_t *			  mgr;
	isc_nmsocket_t *		  parent;
	isc_nmsocket_t *		  children;
	int				  nchildren;
	atomic_int_fast32_t		  rchildren;
	int				  tid;
	isc_nmiface_t *			  iface;
	isc_nmhandle_t			  tcphandle;
	/*
	 * 'spare' handles for that can be reused to avoid allocations,
	 * for UDP.
	 */
	ck_stack_t inactivehandles	  CK_CC_CACHELINE;
	ck_stack_t inactivereqs		  CK_CC_CACHELINE;
	/* extra data allocated at the end of each isc_nmhandle_t */
	size_t				  extrahandlesize;

	uv_os_sock_t			  fd;
	union {
		uv_handle_t	   handle;
		uv_stream_t	   stream;
		uv_udp_t	   udp;
		uv_tcp_t	   tcp;
	} uv_handle;

	isc__nm_readcb_t	    rcb;
	void *		 	    rcbarg;
	isc__nm_writecb_t	    wcb;
	void *			    wcbarg;
};

static void *
isc__net_thread(void *worker0);
static void
async_cb(uv_async_t *handle);
static void *
get_ievent(isc_nm_t *mgr, isc__netievent_type type);
static void
enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event);
static void
alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void
free_uvbuf(isc_nmsocket_t *socket, const uv_buf_t *buf);
static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *socket);
static isc_nmhandle_t *
get_handle(isc_nmsocket_t *socket, isc_sockaddr_t *peer);
static isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *socket);
static void
isc__nm_uvreq_put(isc__nm_uvreq_t **req, isc_nmsocket_t *socket);

static isc_result_t
isc__nm_udp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req,
			isc_sockaddr_t *peer);
static isc_result_t
isc__nm_udp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);
static void
udp_recv_cb(uv_udp_t *handle,
	    ssize_t nrecv,
	    const uv_buf_t *buf,
	    const struct sockaddr *addr,
	    unsigned flags);
static void
handle_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
handle_udpstoplisten(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
handle_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
udp_send_cb(uv_udp_send_t *req, int status);

static int
isc__nm_tcp_connect_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req);

static isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);

static isc_result_t
isc__nm_tcp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req);



static void
handle_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
tcp_connect_cb(uv_connect_t *uvreq, int status);

static void
handle_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
handle_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
tcp_connection_cb(uv_stream_t *server, int status);

static void
handle_startread(isc__networker_t *worker, isc__netievent_t *ievent0);
/* static void
handle_stopread(isc__networker_t *worker, isc__netievent_t *ievent0);
*/
static void
read_cb(uv_stream_t* stream,
        ssize_t nread,
        const uv_buf_t* buf);


static void
dnslisten_readcb(void *arg, isc_nmhandle_t* handle, isc_region_t *region);

static isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle,
		    isc_region_t *region,
		    isc_nm_send_cb_t cb,
		    void *cbarg);

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
	mgr->mctx = NULL;
	isc_mem_attach(mctx, &mgr->mctx);
	isc_mutex_init(&mgr->lock);
	isc_condition_init(&mgr->wkstatecond);
	isc_refcount_init(&mgr->refs, 1);
	mgr->nworkers = workers;
	mgr->workers_running = 0;
	mgr->workers_paused = 0;


	mgr->workers = isc_mem_get(mctx, workers * sizeof(isc__networker_t));
	for (i = 0; i < workers; i++) {
		isc__networker_t *worker = &mgr->workers[i];
		worker->mgr = mgr;
		worker->id = i;

		r = uv_loop_init(&worker->loop);
		RUNTIME_CHECK(r == 0);

		r = uv_async_init(&worker->loop,
				  &worker->async, async_cb);
		RUNTIME_CHECK(r == 0);

		isc_mutex_init(&worker->lock);
		isc_condition_init(&worker->cond);

		worker->paused = false;
		worker->finished = false;
		worker->loop.data = &mgr->workers[i];
		worker->mpool_bufs = NULL;
		isc_mempool_create(mgr->mctx, 65536, &worker->mpool_bufs);
		struct ck_fifo_mpmc_entry *stub =
			isc_mem_get(mgr->mctx, sizeof(*stub));
		ck_fifo_mpmc_init(&worker->ievents, stub);
		worker->pktcount = 0;
		worker->udprecvbuf_inuse = false;

		result = isc_thread_create(isc__net_thread, &mgr->workers[i],
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
		isc__netievent_t *ievent = get_ievent(mgr, netievent_stop);
		enqueue_ievent(&mgr->workers[i], ievent);
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
 * isc__net_thread is a single worker thread, that runs uv_run event loop
 * until asked to stop.
 */
static void *
isc__net_thread(void *worker0) {
	isc__networker_t *worker = (isc__networker_t*) worker0;
	atomic_fetch_add_explicit(&worker->mgr->workers_running, 1,
				  memory_order_relaxed);
	isc_netmgr_tid = worker->id;
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
			handle_udplisten(worker, ievent);
			break;
		case netievent_udpstoplisten:
			handle_udpstoplisten(worker, ievent);
			break;
		case netievent_udpsend:
			handle_udpsend(worker, ievent);
			break;
		case netievent_tcpconnect:
			handle_tcpconnect(worker, ievent);
			break;
		case netievent_tcplisten:
			handle_tcplisten(worker, ievent);
			break;
        	case netievent_tcpstartread:
                	handle_startread(worker, ievent);
                	break;
/*        	case netievent_tcpstopread:
                	handle_stopread(worker, ievent);
                	break; */
		case netievent_tcpsend:
                       handle_tcpsend(worker, ievent);
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
 * get_ievent allocates an ievent and sets the type
 * xxxwpk: use pool?
 */
static void *
get_ievent(isc_nm_t *mgr, isc__netievent_type type) {
	isc__netievent_t *event =
		isc_mem_get(mgr->mctx, sizeof(isc__netievent_storage_t));
	*event = (isc__netievent_t) { .type = type };
	return (event);
}

/*
 * enqueue ievent on a specific worker queue. This the only safe
 * way to use isc__networker_t from another thread.
 */
static void
enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event) {
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

		case isc_nm_udpsocket:
		default:
			break;
		}
	}
	/* TODO free it! */
	*socketp = NULL;
}

static void
nmsocket_init(isc_nmsocket_t *socket, isc_nm_t *mgr, isc_nmsocket_type type) {
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
static void
alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
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

static void
free_uvbuf(isc_nmsocket_t *socket, const uv_buf_t *buf) {
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
alloc_handle(isc_nmsocket_t *socket) {
	isc_nmhandle_t *handle;
	handle = isc_mem_get(socket->mgr->mctx,
			     sizeof(isc_nmhandle_t) +
			     socket->extrahandlesize);
	*handle = (isc_nmhandle_t) {};
	isc_nmsocket_attach(socket, &handle->socket);
	isc_refcount_init(&handle->refs, 1);
	handle->magic = NMHANDLE_MAGIC;
	return (handle);
}

static isc_nmhandle_t *
get_handle(isc_nmsocket_t *socket, isc_sockaddr_t *peer) {
	isc_nmhandle_t *handle = NULL;
	ck_stack_entry_t *sentry;
	REQUIRE(VALID_NMSOCK(socket));
	if (socket->type == isc_nm_tcpsocket) {
		handle = &socket->tcphandle;
		/* XXXWPK this should be more elegant */
		INSIST(!VALID_NMHANDLE(handle));
		*handle = (isc_nmhandle_t) {};
		isc_nmsocket_attach(socket, &handle->socket);
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
	if (peer != NULL) {
		memcpy(&handle->peer, peer, sizeof(isc_sockaddr_t));
	}
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
	return handle->socket->type == isc_nm_tcpsocket || handle->socket->type == isc_nm_tcpdnssocket;
}

static void
nmhandle_free(isc_nmhandle_t *handle) {
	isc_nm_t *mgr = NULL;
	size_t extra = handle->socket->extrahandlesize;
	if (handle->dofree) {
		handle->dofree(handle->opaque);
	}
	isc_nm_attach(handle->socket->mgr, &mgr);
	isc_nmsocket_detach(&handle->socket);
	handle->magic = 0;
	handle->refs = 0;
	isc_mem_put(mgr->mctx,
		    handle,
		    sizeof(isc_nmhandle_t) + extra);
	isc_nm_detach(&mgr);
}

void
isc_nmhandle_detach(isc_nmhandle_t **handlep) {
	isc_nmhandle_t *handle = *handlep;
	REQUIRE(VALID_NMHANDLE(handle));
	if (isc_refcount_decrement(&handle->refs) == 1) {
		bool reuse;
		if (handle->doreset) {
			handle->doreset(handle->opaque);
		}
		reuse = ck_stack_trypush_mpmc(&handle->socket->inactivehandles,
					      &handle->ilink);
		if (!reuse) {
			nmhandle_free(handle);
		}
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

static isc__nm_uvreq_t *
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
static void
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
	if (! (socket != NULL && ck_stack_trypush_mpmc(&socket->inactivereqs, &req->ilink))) {
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
	    void *cbarg) {
	switch (handle->socket->type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		return (isc__nm_udp_send(handle, region, cb, cbarg));
		break;
	case isc_nm_tcpsocket:
		return (isc__nm_tcp_send(handle, region, cb, cbarg));
	case isc_nm_tcpdnssocket:
		return (isc__nm_tcpdns_send(handle, region, cb, cbarg));
	default:
		INSIST(0);
	}
	return (ISC_R_FAILURE);
}


/*
 *  U   U  DDD   PPP
 *  U   U  D  D  P  P
 *  U   U  D  D  PPP
 *  U   U  D  D  P
 *   UUU   DDD   P
 */
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
	nmsocket_init(nsocket, mgr, isc_nm_udplistener);
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
		nmsocket_init(csocket, mgr, isc_nm_udpsocket);
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
		ievent = get_ievent(mgr, netievent_udplisten);
		ievent->socket = csocket;
		enqueue_ievent(&mgr->workers[i], (isc__netievent_t*) ievent);
	}
	*rv = nsocket;
	return (ISC_R_SUCCESS);
}

void
isc_nm_udp_stoplistening(isc_nmsocket_t *socket) {
	int i;

	INSIST(VALID_NMSOCK(socket));
	/* We can't be launched from network thread */
	INSIST(isc_netmgr_tid == ISC_NETMGR_TID_UNKNOWN);
	INSIST(socket->type == isc_nm_udplistener);

	for (i = 0; i < socket->nchildren; i++) {
		isc__netievent_udpstoplisten_t *ievent;
		ievent = get_ievent(socket->mgr, netievent_udpstoplisten);
		ievent->socket = &socket->children[i];
		enqueue_ievent(&socket->mgr->workers[i],
			       (isc__netievent_t*) ievent);
	}
}

/*
 * handle 'udplisten' async call - start listening on a socket.
 */
static void
handle_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
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
	uv_udp_recv_start(&socket->uv_handle.udp, alloc_cb, udp_recv_cb);
}

static void
udp_close_cb(uv_handle_t *handle) {
	isc_nmsocket_t *socket = handle->data;
	isc_nmsocket_detach((isc_nmsocket_t**)&socket->uv_handle.udp.data);
}
/*
 * handle 'udpstoplisten' async call - stop listening on a socket.
 */
static void
handle_udpstoplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
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
		nmhandle_free(handle);
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
		free_uvbuf(socket, buf);
		return;
	}

	result = isc_sockaddr_fromsockaddr(&sockaddr, addr);
	REQUIRE(result == ISC_R_SUCCESS);

	nmhandle = get_handle(socket, &sockaddr);
	region.base = (unsigned char *) buf->base;
	/* not buf->len, that'd be the whole buffer! */
	region.length = nrecv;

	socket->rcb.recv(socket->rcbarg, nmhandle, &region);
	free_uvbuf(socket, buf);

	/* If recv callback wants it it should attach to it */
	isc_nmhandle_detach(&nmhandle);
}

/*
 * isc__nm_udp_send sends buf to a peer on a socket.
 * It tries to find a proper sibling/child socket so that we won't have
 * to jump to other thread.
 */
static isc_result_t
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

	ntid = isc_netmgr_tid >= 0 ?
	       isc_netmgr_tid : (int) isc_random_uniform(socket->nchildren);

	rsocket = &psocket->children[ntid];

	uvreq = isc__nm_uvreq_get(socket->mgr, socket);
	uvreq->uvbuf.base = (char *) region->base;
	uvreq->uvbuf.len = region->length;
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (isc_netmgr_tid == rsocket->tid) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (isc__nm_udp_send_direct(rsocket, uvreq, peer));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = get_ievent(socket->mgr, netievent_udpsend);
		ievent->handle.socket = rsocket;
		ievent->handle.peer = *peer;
		ievent->req = uvreq;
		enqueue_ievent(&socket->mgr->workers[rsocket->tid],
			       (isc__netievent_t*) ievent);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_UNEXPECTED);
}


/*
 * handle 'udpsend' async event - send a packet on the socket
 */
static void
handle_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_udpsend_t *ievent =
		(isc__netievent_udpsend_t *) ievent0;
	INSIST(worker->id == ievent->handle.socket->tid);
	isc__nm_udp_send_direct(ievent->handle.socket,
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
 * isc__nm_udp_send_direct sends buf to a peer on a socket. Sock has to be in
 * the same thread as the callee.
 */
static isc_result_t
isc__nm_udp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req,
			isc_sockaddr_t *peer)
{
	int rv;
	INSIST(socket->tid == isc_netmgr_tid);
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


/*
 * TTTTT   CCC   PPP
 *   T    C   C  P  P
 *   T    C      PPP
 *   T    C   C  P
 *   T     CCC   P
 */

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
	sock->type = isc_nm_tcpsocket;
	isc_refcount_init(&sock->refs, 1);
	sock->mgr = mgr;
	sock->parent = NULL;
	sock->children = NULL;
	sock->nchildren = 0;

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

	result = isc__nm_tcp_connect_direct(sock, req);
	if (result != ISC_R_SUCCESS) {
		isc__nm_uvreq_put(&req, NULL);
		isc_mem_put(mgr->mctx, sock, sizeof(isc_nmsocket_t));
	}
	return (result);
}

static int
isc__nm_tcp_connect_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req)
{
	isc__networker_t *worker;
	int r;

	REQUIRE(isc_netmgr_tid >= 0);

	worker = &req->mgr->workers[isc_netmgr_tid];

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

static void
handle_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0) {
	int r;
	isc__netievent_tcpconnect_t *ievent =
		(isc__netievent_tcpconnect_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;
	isc__nm_uvreq_t *req = ievent->req;

	REQUIRE(socket->type == isc_nm_tcpsocket);
	REQUIRE(worker->id == ievent->req->mgr->workers[isc_netmgr_tid].id);

	r = isc__nm_tcp_connect_direct(socket, req);
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
		isc_nmhandle_t *handle = isc_mem_get(socket->mgr->mctx,
						     sizeof(isc_nmhandle_t));
		handle->socket = socket;
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
		  isc_nmsocket_t ** rv)
{
	isc__netievent_tcplisten_t *ievent;
	INSIST(VALID_NM(mgr));
	isc_nmsocket_t *nsocket;

	nsocket = isc_mem_get(mgr->mctx, sizeof(*nsocket));
	nmsocket_init(nsocket, mgr, isc_nm_tcplistener);
	nsocket->iface = iface;
	nsocket->rcb.accept = cb;
	nsocket->rcbarg = cbarg;
	nsocket->extrahandlesize = extrahandlesize;
	nsocket->tid = isc_random_uniform(mgr->nworkers);
	/*
	 * Listening to TCP is rare enough not to care about the
	 * added overhead from passing this to another thread.
	 */
	ievent = get_ievent(mgr, netievent_tcplisten);
	ievent->socket = nsocket;
	enqueue_ievent(&mgr->workers[nsocket->tid],
		       (isc__netievent_t*) ievent);
	*rv = nsocket;
	return (ISC_R_SUCCESS);
}

static void
handle_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
	int r;
	isc__netievent_tcpconnect_t *ievent =
		(isc__netievent_tcpconnect_t *) ievent0;
	isc_nmsocket_t *socket = ievent->socket;

	REQUIRE(isc_netmgr_tid >= 0);
	REQUIRE(socket->type == isc_nm_tcplistener);
//	REQUIRE(worker->id == ievent->req->mgr->workers[isc_netmgr_tid].id);

	r = uv_tcp_init(&worker->loop, &socket->uv_handle.tcp);
	if (r != 0) {
		return;
	}

	uv_tcp_bind(&socket->uv_handle.tcp, &socket->iface->addr.type.sa, 0);
	r = uv_listen((uv_stream_t*) &socket->uv_handle.tcp,
		      10,
		      tcp_connection_cb);
	return;
	/* issue callback? */
}


isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void* cbarg) {
	INSIST(VALID_NMHANDLE(handle));
	isc_nmsocket_t *socket = handle->socket;
	INSIST(VALID_NMSOCK(socket));
	socket->rcb.recv = cb;
	socket->rcbarg = cbarg; /* THat's obviously broken... */
	if (socket->tid == isc_netmgr_tid) {
		uv_read_start(&socket->uv_handle.stream, alloc_cb, read_cb);
	} else {
		isc__netievent_startread_t *ievent =
			get_ievent(socket->mgr, netievent_tcpstartread);
		ievent->socket = socket;
		enqueue_ievent(&socket->mgr->workers[socket->tid],
			       (isc__netievent_t*) ievent);

	}
	return (ISC_R_SUCCESS);
}

static void
handle_startread(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_startread_t *ievent =
		(isc__netievent_startread_t *) ievent0;
	REQUIRE(worker->id == isc_netmgr_tid);
	
	isc_nmsocket_t *socket = ievent->socket;

	uv_read_start(&socket->uv_handle.stream, alloc_cb, read_cb);
}

static void
read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	isc_nmsocket_t *socket = uv_handle_get_data((uv_handle_t*) stream);
	INSIST(buf != NULL);
	if (nread < 0) {
		free_uvbuf(socket, buf);
		/* XXXWPK TODO clean up handles! */
		return;
	}
	isc_region_t region = { .base = (unsigned char *) buf->base, 
				.length = nread };

	INSIST(VALID_NMSOCK(socket));
	INSIST(socket->rcb.recv != NULL);

	socket->rcb.recv(socket->rcbarg, &socket->tcphandle, &region);
	free_uvbuf(socket, buf);
}

static void
tcp_connection_cb(uv_stream_t *server, int status) {
	(void) status; /* TODO */
	isc_nmsocket_t *csocket, *ssocket;
	isc__networker_t *worker;

	ssocket = uv_handle_get_data((uv_handle_t*) server);
	REQUIRE(VALID_NMSOCK(ssocket));
	REQUIRE(ssocket->tid == isc_netmgr_tid);
	INSIST(ssocket->rcb.accept != NULL);

	worker = &ssocket->mgr->workers[isc_netmgr_tid];

	csocket = isc_mem_get(ssocket->mgr->mctx, sizeof(isc_nmsocket_t));
	nmsocket_init(csocket, ssocket->mgr, isc_nm_tcpsocket);
	csocket->tid = isc_netmgr_tid;
	csocket->extrahandlesize = ssocket->extrahandlesize;

	uv_tcp_init(&worker->loop, &csocket->uv_handle.tcp);
	int r = uv_accept(server, &csocket->uv_handle.stream);
	if (r != 0) {
		return; /* XXXWPK TODO LOG */
	}
	isc_sockaddr_t peer;
	struct sockaddr_storage ss;
	int l = sizeof(ss);
	uv_tcp_getpeername(&csocket->uv_handle.tcp, (struct sockaddr*) &ss, &l);
	isc_result_t result = isc_sockaddr_fromsockaddr(&peer, (struct sockaddr*) &ss);
	INSIST(result == ISC_R_SUCCESS);
	isc_nmhandle_t *handle = get_handle(csocket, &peer);
	ssocket->rcb.accept(handle, ISC_R_SUCCESS, ssocket->rcbarg);
}

/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
static isc_result_t
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

	if (socket->tid == isc_netmgr_tid) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (isc__nm_tcp_send_direct(socket, uvreq));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = get_ievent(socket->mgr, netievent_tcpsend);
		ievent->handle.socket = socket;
		ievent->req = uvreq;
		enqueue_ievent(&socket->mgr->workers[socket->tid],
			       (isc__netievent_t*) ievent);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_UNEXPECTED);
}


/*
 * handle 'tcpsend' async event - send a packet on the socket
 */
static void
handle_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_udpsend_t *ievent =
		(isc__netievent_udpsend_t *) ievent0;
	INSIST(worker->id == ievent->handle.socket->tid);
	isc__nm_tcp_send_direct(ievent->handle.socket,
				ievent->req);
}

/*
 * udp_send_cb - callback
 */
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
 * isc__nm_udp_send_direct sends buf to a peer on a socket. Sock has to be in
 * the same thread as the callee.
 */
static isc_result_t
isc__nm_tcp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req)
{
	int rv;
	INSIST(socket->tid == isc_netmgr_tid);
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
	isc_nmsocket_t *dnssocket = isc_mem_get(handle->socket->mgr->mctx, sizeof(*dnssocket));
	nmsocket_init(dnssocket, handle->socket->mgr, isc_nm_tcpdnssocket);
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
dnslisten_readcb(void *arg, isc_nmhandle_t* handle, isc_region_t *region) {
	/* A 'wrapper' handle */
	(void)handle;
	isc_nmsocket_t *dnssocket = (isc_nmsocket_t*) arg;
	/* XXXWPK for the love of all that is holy fix it, that's so wrong */
	INSIST(((region->base[0] << 8) + (region->base[1]) == (int) region->length - 2));
	isc_nmhandle_t *dnshandle = get_handle(dnssocket, &handle->peer);
	isc_region_t r2 = {.base = region->base+2, .length = region->length-2};
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
	isc_result_t result;

	/* A 'wrapper' socket object with parent set to true TCP socket */
	isc_nmsocket_t *dnslistensocket = isc_mem_get(mgr->mctx, sizeof(*dnslistensocket));
	nmsocket_init(dnslistensocket, mgr, isc_nm_tcpdnslistener);
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

typedef struct tcpsend {
	isc_nmhandle_t *handle;
	isc_region_t region;
	isc_nmhandle_t *orighandle;
	isc_nm_send_cb_t cb;
	void* cbarg;
} tcpsend_t;

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t* ts = (tcpsend_t*) cbarg;
	(void) handle;
	ts->cb(ts->orighandle, result, ts->cbarg);
}
/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
static isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle,
		    isc_region_t *region,
		    isc_nm_send_cb_t cb,
		    void *cbarg)
{
	isc_nmsocket_t *socket = handle->socket;

	INSIST(socket->type == isc_nm_tcpdnssocket);
	tcpsend_t * t = malloc(sizeof(*t));
	*t = (tcpsend_t) {};
	t->handle = &handle->socket->parent->tcphandle;
	t->cb = cb;
	t->cbarg = cbarg;
	t->region = (isc_region_t) { .base = malloc(region->length+2), .length=region->length+2 };
	memmove(t->region.base+2, region->base, region->length);
	t->region.base[0] = region->length<<8;
	t->region.base[1] = region->length&0xff;
	isc_nmhandle_attach(handle, &t->orighandle);

	return (isc__nm_tcp_send(t->handle, &t->region, tcpdnssend_cb, t));
}

