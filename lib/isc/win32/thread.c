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

#include <process.h>

#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/util.h>

void
isc_thread_create(isc_threadfunc_t start, isc_threadarg_t arg,
		  isc_thread_t *threadp)
{
	isc_thread_t thread;
	unsigned int id;

	thread = (isc_thread_t)_beginthreadex(NULL, 0, start, arg, 0, &id);
	if (thread == NULL) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(errno, strbuf, sizeof(strbuf));
		isc_error_fatal(__FILE__, __LINE__, "_beginthreadex failed: %s",
				strbuf);
	}

	*threadp = thread;

	return;
}

void
isc_thread_join(isc_thread_t thread, isc_threadresult_t *rp) {
	DWORD result;

	result = WaitForSingleObject(thread, INFINITE);
	if (result != WAIT_OBJECT_0) {
		isc_error_fatal(__FILE__, __LINE__,
				"WaitForSingleObject() != WAIT_OBJECT_0");
	}
	if (rp != NULL && !GetExitCodeThread(thread, rp)) {
		isc_error_fatal(__FILE__, __LINE__,
				"GetExitCodeThread() failed: %d", GetLastError());

	}
	(void)CloseHandle(thread);

	return (ISC_R_SUCCESS);
}

void
isc_thread_setconcurrency(unsigned int level) {
	/*
	 * This is unnecessary on Win32 systems, but is here so that the
	 * call exists
	 */
}

void
isc_thread_setname(isc_thread_t thread, const char *name) {
	UNUSED(thread);
	UNUSED(name);
}

isc_result_t
isc_thread_setaffinity(int cpu) {
	/* no-op on Windows for now */
	return (ISC_R_SUCCESS);
}

void *
isc_thread_key_getspecific(isc_thread_key_t key) {
	return(TlsGetValue(key));
}

int
isc_thread_key_setspecific(isc_thread_key_t key, void *value) {
	return (TlsSetValue(key, value) ? 0 : GetLastError());
}

int
isc_thread_key_create(isc_thread_key_t *key, void (*func)(void *)) {
	*key = TlsAlloc();

	return ((*key != -1) ? 0 : GetLastError());
}

int
isc_thread_key_delete(isc_thread_key_t key) {
	return (TlsFree(key) ? 0 : GetLastError());
}
