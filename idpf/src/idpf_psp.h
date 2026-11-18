/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_H_
#define _IDPF_PSP_H_

#include "idpf.h"

#if IS_ENABLED(CONFIG_INET_PSP)

void idpf_psp_init(struct idpf_adapter *adapter);
void idpf_psp_free(struct idpf_adapter *adapter);
void idpf_psp_register(struct idpf_adapter *adapter);
void idpf_psp_unregister(struct idpf_adapter *adapter);
void idpf_psp_recv_reply(struct idpf_adapter *adapter,
			 const struct idpf_ctlq_msg *ctlq_msg);
void idpf_psp_recv_late_reply(struct idpf_adapter *adapter,
			      const struct idpf_ctlq_msg *ctlq_msg);
void idpf_psp_rotation_event(struct idpf_adapter *adapter,
			     const struct idpf_ctlq_msg *ctlq_msg);

struct idpf_psp_tx_key *idpf_psp_tx_key_alloc(void);
void idpf_psp_tx_key_get(struct idpf_psp_tx_key *key);
void idpf_psp_tx_key_put(struct idpf_psp_tx_key *key);
void idpf_psp_queue_delete(struct idpf_adapter *adapter,
			   struct idpf_psp_tx_key *key);
void idpf_queue_psp_work(struct idpf_adapter *adapter);
void idpf_retry_psp_work(struct idpf_adapter *adapter);
void idpf_cancel_psp_work(struct idpf_adapter *adapter);
void idpf_psp_quiesce(struct idpf_adapter *adapter);
void idpf_psp_insert_timer_arm(struct idpf_adapter *adapter,
			       unsigned long expires);
void idpf_psp_tx_key_inserted(struct idpf_adapter *adapter,
			      struct idpf_psp_tx_key *key, u32 saidx);
void idpf_psp_tx_key_failed(struct idpf_adapter *adapter,
			    struct idpf_psp_tx_key *key);

/**
 * idpf_psp_saidx_ok - Check an SA index returned by the CP
 * @adapter: private data struct
 * @saidx: the SA index
 *
 * Return: true if @saidx fits in the SA index width negotiated for the
 * adapter, false otherwise.
 */
static inline bool idpf_psp_saidx_ok(const struct idpf_adapter *adapter,
				     u32 saidx)
{
	return saidx < BIT(adapter->psp.saidx_width);
}

/**
 * idpf_psp_idx_valid - Check if the SA index of a TX key is usable
 * @idx: SA index or state of a TX key, see struct idpf_psp_tx_key
 *
 * Only SA indexes checked with idpf_psp_saidx_ok() are stored in a TX key.
 *
 * Return: true if @idx is an SA index, false if it is a state.
 */
static inline bool idpf_psp_idx_valid(u32 idx)
{
	return idx <= IDPF_PSP_IDX_MAX;
}

#else /* !CONFIG_INET_PSP */

static inline void idpf_psp_init(struct idpf_adapter *adapter) { }
static inline void idpf_psp_free(struct idpf_adapter *adapter) { }
static inline void idpf_psp_register(struct idpf_adapter *adapter) { }
static inline void idpf_psp_unregister(struct idpf_adapter *adapter) { }

static inline void
idpf_psp_recv_reply(struct idpf_adapter *adapter,
		    const struct idpf_ctlq_msg *ctlq_msg) { }

static inline void
idpf_psp_recv_late_reply(struct idpf_adapter *adapter,
			 const struct idpf_ctlq_msg *ctlq_msg) { }

static inline void idpf_queue_psp_work(struct idpf_adapter *adapter) { }
static inline void idpf_cancel_psp_work(struct idpf_adapter *adapter) { }
static inline void idpf_psp_quiesce(struct idpf_adapter *adapter) { }

static inline void
idpf_psp_rotation_event(struct idpf_adapter *adapter,
			const struct idpf_ctlq_msg *ctlq_msg) { }

#endif /* CONFIG_INET_PSP */

#endif /* !_IDPF_PSP_H_ */
