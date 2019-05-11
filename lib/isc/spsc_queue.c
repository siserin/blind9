/** Lock-free Single-Producer Single-consumer (MPMC) queue.
 *
 * Based on Dmitry Vyukov#s Bounded MPMC queue:
 *   http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
 *
 * @author Steffen Vogel <post@steffenvogel.de>
 * @copyright 2016 Steffen Vogel
 * @license BSD 2-Clause License
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modiffication, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <isc/mem.h>
#include <isc/result.h>

#include "spsc_queue.h"

/** Initialize SPSC queue */
static inline isc_result_t
spsc_queue_init(struct spsc_queue *q, size_t size, isc_mem_t *mctx)
{
	/* Queue size must be 2 exponent */
	if ((size < 2) || ((size & (size - 1)) != 0)) {
		return (ISC_R_RANGE);
	}

	q->mctx = mctx;
	q->buffer_mask = size - 1;
	q->buffer = isc_mem_get(q->mctx, sizeof(q->buffer[0]) * size);

	q->tail = 0;
	q->head = 0;

	return (ISC_R_SUCCESS);
}

static inline void
spsc_queue_destroy(struct spsc_queue *q)
{
	isc_mem_put(q->mctx, q->buffer,
		    (q->buffer_mask + 1) * sizeof(q->buffer[0]));
}

/** Return estimation of current queue usage.
 *
 * Note: This is only an estimation and not accurate as long other
 *       threads are performing operations.
 */
static inline size_t
spsc_queue_size(struct spsc_queue *q)
{
	return (&q->tail - &q->head);
}

static inline isc_result_t
spsc_queue_put(struct spsc_queue *q, void *ptr)
{
	if (((q->head - (q->tail + 1)) & q->buffer_mask) == 0) {
		return (ISC_R_NOSPACE);
	}

	q->buffer[q->tail & q->buffer_mask] = ptr;
	q->tail++;
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
spsc_queue_get(struct spsc_queue *q, void **ptr) {
	if (((q->tail - q->head) & q->buffer_mask) == 0) {
		return (ISC_R_NOMEMORY);
	}

	*ptr = q->buffer[q->head & q->buffer_mask];
	q->head++;
	return (ISC_R_SUCCESS);
}
