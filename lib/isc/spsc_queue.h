#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>

#define CACHELINE_SIZE 64

typedef char cacheline_pad_t[CACHELINE_SIZE];

struct spsc_queue {
	/**< Shared area: all threads read */
	isc_mem_t *mctx;
	size_t buffer_mask;
	void **buffer;
	char _pad0[CACHELINE_SIZE
		   - sizeof(isc_mem_t *)
		   - sizeof(size_t)
		   - sizeof(void *)];

	/**> Producer area: only producers read & write */
	uint_fast64_t	tail;	/**> Queue tail pointer */
	char _pad1[CACHELINE_SIZE - sizeof(uint_fast64_t)];

	/**> Consumer area: only consumers read & write */
	uint_fast64_t	head;	/**> Queue head pointer */
	char _pad2[CACHELINE_SIZE - sizeof(uint_fast64_t)];
};

/** Initialize MPMC queue */
static inline isc_result_t
spsc_queue_init(struct spsc_queue *q, size_t size, isc_mem_t *mctx);

/** Destroy MPMC queue and release memory */
static inline void
spsc_queue_destroy(struct spsc_queue *q);

/** Return estimation of current queue usage.
 *
 * Note: This is only an estimation and not accurate as long other
 *       threads are performing operations.
 */
static inline size_t
spsc_queue_size(struct spsc_queue *q);

static inline isc_result_t
spsc_queue_put(struct spsc_queue *q, void *ptr);

static inline isc_result_t
spsc_queue_get(struct spsc_queue *q, void **ptr);
