/** Lock-free Multiple-Producer Multiple-consumer (MPMC) queue.
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

#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/result.h>

#include "mpmc_queue.h"

/** Initialize MPMC queue */
static inline isc_result_t
mpmc_queue_init(struct mpmc_queue *q, size_t size, isc_mem_t *mctx)
{
	/* Queue size must be 2 exponent */
	if ((size < 2) || ((size & (size - 1)) != 0)) {
		return (ISC_R_RANGE);
	}

	q->mctx = mctx;
	q->buffer_mask = size - 1;
	q->buffer = isc_mem_get(q->mctx, sizeof(q->buffer[0]) * size);

	for (size_t i = 0; i != size; i += 1) {
		atomic_store_relaxed(&q->buffer[i].sequence, i);
	}

	atomic_store_relaxed(&q->tail, 0);
	atomic_store_relaxed(&q->head, 0);

	return (ISC_R_SUCCESS);
}

static inline void
mpmc_queue_destroy(struct mpmc_queue *q)
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
mpmc_queue_size(struct mpmc_queue *q)
{
	return (atomic_load_relaxed(&q->tail) - atomic_load_relaxed(&q->head));
}

static inline isc_result_t
mpmc_queue_put(struct mpmc_queue *q, void *ptr)
{
	struct mpmc_queue_cell *cell;
	uint64_t pos = atomic_load_relaxed(&q->tail);

	for (;;) {
		uint64_t seq;
		intptr_t diff;
		cell = &q->buffer[pos & q->buffer_mask];
		seq = atomic_load_acquire(&cell->sequence);
		diff = (intptr_t) seq - (intptr_t) pos;

		if (diff == 0) {
			if (atomic_compare_exchange_weak_acq_rel(
				    &q->tail, &pos, pos + 1))
			{
				break;
			}
		} else if (diff < 0) {
			return (ISC_R_NOSPACE);
		} else {
			pos = atomic_load_relaxed(&q->tail);
		}
	}

	cell->data = ptr;
	atomic_store_release(&cell->sequence, pos + 1);

	return (ISC_R_SUCCESS);;
}

static inline isc_result_t
mpmc_queue_get(struct mpmc_queue *q, void **ptr)
{
	struct mpmc_queue_cell *cell;
	uint64_t pos = atomic_load_relaxed(&q->head);
	for (;;) {
		uint64_t seq;
		intptr_t diff;
		cell = &q->buffer[pos & q->buffer_mask];

		seq = atomic_load_acquire(&cell->sequence);
		diff = (intptr_t) seq - (intptr_t) (pos + 1);

		if (diff == 0) {
			if (atomic_compare_exchange_weak_acq_rel(
				    &q->head, &pos, pos + 1))
			{
				break;
			}
		} else if (diff < 0) {
			return (ISC_R_NOMEMORY);
		} else {
			pos = atomic_load_relaxed(&q->head);
		}
	}

	*ptr = cell->data;
	atomic_store_release(&cell->sequence, pos + q->buffer_mask + 1);

	return (ISC_R_SUCCESS);
}
