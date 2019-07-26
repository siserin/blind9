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
#pragma once

#include <config.h>

#include <isc/mem.h>
#include <isc/result.h>

typedef struct isc_nm isc_nm_t;
typedef struct isc_nmsocket isc_nmsocket_t;
typedef struct isc_nmiface isc_nmiface_t;
typedef struct isc_nmhandle isc_nmhandle_t;

typedef enum {
	NMEV_READ,
	NMEV_WRITE,
	NMEV_ACCEPT,
	NMEV_CONNECTED,
	NMEV_CANCELLED,
	NMEV_SHUTDOWN
} isc_nmev_type;

/*
 * isc_nm_start creates and starts a netmgr
 */
isc_nm_t*
isc_nm_start(isc_mem_t *mctx, int workers);

/*
 * isc_nm_shutdown shutdowns netmgr, freeing all the resources
 */
void
isc_nm_shutdown(isc_nm_t**mgr);

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst);

void
isc_nm_detach(isc_nm_t **mgr0);


/*
 * isc_nm_freehandle frees a handle, releasing resources
 */
void
isc_nm_freehandle(isc_nmhandle_t *handle);

/*
 * isc_nmsocket_attach attaches to a socket, increasing refcount
 */
void
isc_nmsocket_attach(isc_nmsocket_t *socket, isc_nmsocket_t **target);

/*
 * isc_nmsocket_detach detaches from socket, decreasing refcount
 * and possibly destroying the socket if it's no longer referenced.
 */
void
isc_nmsocket_detach(isc_nmsocket_t **socketp);

void
isc_nmhandle_attach(isc_nmhandle_t *handle, isc_nmhandle_t **handlep);

void
isc_nmhandle_detach(isc_nmhandle_t **handlep);

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle);

void*
isc_nmhandle_getextra(isc_nmhandle_t *handle);

typedef void (*isc_nm_opaquecb)(void *arg);

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle);

/* 
 * isc_nmhandle_t has a void* opaque field (usually - ns_client_t).
 * We reuse handle and `opaque` can also be reused between calls.
 * This function sets this field and two callbacks:
 * - doreset resets the `opaque` to initial state
 * - dofree frees everything associated with `opaque`
 */
void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg, isc_nm_opaquecb doreset, isc_nm_opaquecb dofree);

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle);

/*
 * Callback for receiving a packet.
 * arg is the argument passed to isc_nm_listen_udp
 * handle - handle that can be used to send back the answer
 * region - contains the received data. It will be freed after
 *          return by caller
 */
typedef void (*isc_nm_recv_cb_t)(void *arg, isc_nmhandle_t* handle,
				 isc_region_t *region);

/*
 * isc_nm_udp_listen starts listening for UDP packets on iface using mgr.
 * When a packet is received cb is called with cbarg as its first argument
 */
isc_result_t
isc_nm_udp_listen(isc_nm_t *mgr,
		  isc_nmiface_t *iface,
		  isc_nm_recv_cb_t cb,
		  size_t extrasize,
		  void *cbarg,
		  isc_nmsocket_t **rv);

void
isc_nm_udp_stoplistening(isc_nmsocket_t *socket);


/* XXXWPK TODOs */
typedef void (*isc_nm_send_cb_t)(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);
typedef void (*isc_nm_connect_cb_t)(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);
typedef void (*isc_nm_accept_cb_t)(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);

isc_result_t
isc_nm_listen_tcp(isc_nm_t*mgr, isc_nm_accept_cb_t*cb);

isc_result_t
isc_nm_pause(isc_nm_t*mgr);

isc_result_t
isc_nm_resume(isc_nm_t*mgr);

isc_result_t
isc_nm_tcp_connect(isc_nm_t* mgr,
		   isc_nmiface_t *iface,
		   isc_sockaddr_t *peer,
		   isc_nm_connect_cb_t cb,
		   void *cbarg);

isc_nmsocket_t*
isc_nm_udp_socket();

isc_result_t
isc_nm_dnsread(isc_nmsocket_t *socket, isc_buffer_t*buf);


isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void* cbarg);

/*
 * isc_nm_send sends region to handle, after finishing cb is called. 
 * region is not copied, it has to be allocated beforehand and freed in cb.
 * Callback can be invoked directly from the calling thread, or called later.
 */
isc_result_t
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_send_cb_t cb, void *cbarg);

isc_result_t
isc_nm_tcp_listen(isc_nm_t *mgr,
		  isc_nmiface_t *iface,
		  isc_nm_accept_cb_t cb,
		  size_t extrahandlesize,
		  void *cbarg,
		  isc_nmsocket_t **rv);


isc_result_t
isc_nm_tcp_dnslisten(isc_nm_t *mgr,
		     isc_nmiface_t *iface,
		     isc_nm_recv_cb_t cb,
		     size_t extrahandlesize,
		     void *arg,
		     isc_nmsocket_t **rv);
