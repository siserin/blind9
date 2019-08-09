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

#define ISC_NETMGR_TID_UNKNOWN -1
#define ISC_NETMGR_TID_NOTLS -2

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

typedef void (*isc__nm_closecb)(isc_nmhandle_t*);

struct isc_nmhandle {
	int		      magic;
	isc_refcount_t	      references;
	/* The socket is not 'attached' in the traditional reference-counting
	 * sense. Instead, we keep all handles in an array in the socket object.
	 * This way, we don't have circular dependencies and we can close all
	 * handles when we're destroying the socket. */
	isc_nmsocket_t *	socket;
	size_t			ah_pos;  /* Position in socket active handles
	                                  * array */
	/* The handle is 'inflight' if netmgr is not currently processing it in
	 * any way - it might mean that e.g. a recursive resolution is
	 * happening. For an inflight handle we must wait for the calling
	 * code to finish before we can free it. */
	atomic_bool		inflight;
	isc_sockaddr_t		peer;
	ck_stack_entry_t	ilink;
	isc_nm_opaquecb		doreset; /* reset extra callback, external */
	isc_nm_opaquecb		dofree;  /* free extra callback, external */
	void *			opaque;
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

/* We have to split it because we can read and write on a socket simultaneously
 * */
typedef union {
	isc_nm_recv_cb_t	  recv;
	isc_nm_accept_cb_t	  accept;
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
	int			magic;
	isc_nm_t *		mgr;
	uv_buf_t		uvbuf; /* translated isc_region_t, to be sent or
	                                * received */
	isc_sockaddr_t		local; /* local address */
	isc_sockaddr_t		peer; /* peer address */
	isc__nm_cb_t		cb;  /* callback */
	void *			cbarg;
	isc_nmhandle_t *	handle;
	ck_stack_entry_t	ilink;
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
	isc_refcount_t		    references;
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
	/* Unlocked, RO */
	int			 magic;
	int			 tid;
	isc_nmsocket_type	 type;
	isc_nm_t *		 mgr;
	isc_nmsocket_t *	 parent;
	isc_nmsocket_t *	 children;
	int			 nchildren;
	isc_nmiface_t *		 iface;
	isc_nmhandle_t		 tcphandle;

	/* extra data allocated at the end of each isc_nmhandle_t */
	size_t			 extrahandlesize;

	/* libuv data */
	uv_os_sock_t		 fd;
	union {
		uv_handle_t	   handle;
		uv_stream_t	   stream;
		uv_udp_t	   udp;
		uv_tcp_t	   tcp;
	} uv_handle;

	/* Atomic */
	/* Number of running (e.g. listening) children sockets */
	atomic_int_fast32_t        rchildren;
	/*
	 * Socket if active if it's listening, working, etc., if we're
	 * closing a socket it doesn't make any sense to e.g. still
	 * push handles or reqs for reuse
	 */
	atomic_bool        active;
	/*
	 * Socket is closed if it's not active and all the possible callbacks
	 * were fired, there are no active handles, etc.
	 * active==false, closed == false means the socket is closing.
	 */
	atomic_bool	      closed;
	isc_refcount_t	      references;
	/*
	 * 'spare' handles for that can be reused to avoid allocations,
	 * for UDP.
	 */
	ck_stack_t inactivehandles	  CK_CC_CACHELINE;
	ck_stack_t inactivereqs		  CK_CC_CACHELINE;

	/* Used for active/rchildren during shutdown */
	isc_mutex_t			  lock;
	isc_condition_t			  cond;

	/*
	 * List of active handles.
	 * ah_size - size of ah_frees and ah_handles
	 * ah_cpos - current position in ah_frees;
	 * ah_handles - array of *handles.
	 * Adding a handle
	 *  - if ah_cpos == ah_size, realloc
	 *  - x = ah_frees[ah_cpos]
	 *  - ah_frees[ah_cpos++] = 0;
	 *  - ah_handles[x] = handle
	 *  - x must be stored with the handle!
	 * Removing a handle:
	 *  - ah_frees[--ah_cpos] = x
	 *  - ah_handles[x] = NULL;
	 *
	 * XXXWPK for now this is locked with socket->lock, but we might want
	 * to change it to something lockless
	 */
	size_t			ah_size;
	size_t			ah_cpos;
	size_t *		ah_frees;
	isc_nmhandle_t **	ah_handles;

	/* XXXWPK can it be not locked? */
	isc__nm_readcb_t	rcb;
	void *			rcbarg;
};

/* Are we in network thread? */
bool
isc__nm_in_netthread(void);

void
isc__nmhandle_free(isc_nmsocket_t *socket, isc_nmhandle_t *handle);

void *
isc__nm_get_ievent(isc_nm_t *mgr, isc__netievent_type type);

void
isc__nm_enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event);

void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);

void
isc__nm_free_uvbuf(isc_nmsocket_t *socket, const uv_buf_t *buf);

isc_nmhandle_t *
isc__nmhandle_get(isc_nmsocket_t *socket, isc_sockaddr_t *peer);

isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *socket);

void
isc__nm_uvreq_put(isc__nm_uvreq_t **req, isc_nmsocket_t *socket);

void
isc__nmsocket_init(isc_nmsocket_t *socket,
		   isc_nm_t *mgr,
		   isc_nmsocket_type type);

/*
 * Send for UDP handle
 */
isc_result_t
isc__nm_udp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);
/*
 * Async callbacks for UDP
 */
void
isc__nm_handle_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_handle_udpstoplisten(isc__networker_t *worker,
			     isc__netievent_t *ievent0);
void
isc__nm_handle_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0);


/*
 * Send for TCP handle
 */
isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);


/*
 * Async callbacks for TCP
 */

void
isc__nm_handle_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_handle_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_handle_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_handle_startread(isc__networker_t *worker, isc__netievent_t *ievent0);

/* static void
 * handle_stopread(isc__networker_t *worker, isc__netievent_t *ievent0);
 */


isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle,
		    isc_region_t *region,
		    isc_nm_send_cb_t cb,
		    void *cbarg);
