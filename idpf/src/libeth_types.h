/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024-2025 Intel Corporation */

#ifndef _LIBETH_TYPES_H_
#define _LIBETH_TYPES_H_

#include <linux/workqueue.h>

/* Stats */

/**
 * struct libeth_rq_napi_stats - "hot" counters to update in Rx polling loop
 * @packets: received frames counter
 * @bytes: sum of bytes of received frames above
 * @fragments: sum of fragments of received S/G frames
 * @hsplit: number of frames the device performed the header split for
 * @raw: alias to access all the fields as an array
 */
struct libeth_rq_napi_stats {
	union {
		struct {
							u32 packets;
							u32 bytes;
							u32 fragments;
							u32 hsplit;
		};
		DECLARE_FLEX_ARRAY(u32, raw);
	};
};

/**
 * struct libeth_sq_napi_stats - "hot" counters to update in Tx completion loop
 * @packets: completed frames counter
 * @bytes: sum of bytes of completed frames above
 * @raw: alias to access all the fields as an array
 */
struct libeth_sq_napi_stats {
	union {
		struct {
							u32 packets;
							u32 bytes;
		};
		DECLARE_FLEX_ARRAY(u32, raw);
	};
};

/**
 * struct libeth_xdpsq_napi_stats - "hot" counters to update in XDP Tx
 *				    completion loop
 * @packets: completed frames counter
 * @bytes: sum of bytes of completed frames above
 * @fragments: sum of fragments of completed S/G frames
 * @raw: alias to access all the fields as an array
 */
struct libeth_xdpsq_napi_stats {
	union {
		struct {
							u32 packets;
							u32 bytes;
							u32 fragments;
		};
		DECLARE_FLEX_ARRAY(u32, raw);
	};
};

/* XDP */

/*
 * The following structures should be embedded into driver's queue structure
 * and passed to the libeth_xdp helpers, never used directly.
 */

/* XDPSQ sharing */

/**
 * struct libeth_xdpsq_lock - locking primitive for sharing XDPSQs
 * @lock: spinlock for locking the queue
 * @share: whether this particular queue is shared
 */
struct libeth_xdpsq_lock {
	spinlock_t			lock;
	bool				share;
};

/* XDPSQ clean-up timers */

/**
 * struct libeth_xdpsq_timer - timer for cleaning up XDPSQs w/o interrupts
 * @xdpsq: queue this timer belongs to
 * @lock: lock for the queue
 * @dwork: work performing cleanups
 *
 * XDPSQs not using interrupts but lazy cleaning, i.e. only when there's no
 * space for sending the current queued frame/bulk, must fire up timers to
 * make sure there are no stale buffers to free.
 */
struct libeth_xdpsq_timer {
	void				*xdpsq;
	struct libeth_xdpsq_lock	*lock;

	struct delayed_work		dwork;
};

#endif /* _LIBETH_TYPES_H_ */
