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
int idpf_psp_queue_insert(struct idpf_adapter *adapter,
			  struct idpf_psp_tx_key *key);

enum idpf_psp_tx_verdict
__idpf_psp_tx_prep(const struct idpf_vport *vport, struct idpf_queue *tx_q,
		   struct sk_buff *skb, struct psp_assoc *pas,
		   struct idpf_psp_tx *psp);

/**
 * idpf_psp_tx_prep - Get the PSP parameters of a TX packet
 * @vport: vport the packet is transmitted on
 * @tx_q: TX queue of the packet
 * @skb: the packet
 * @psp: filled with the PSP parameters of the packet
 *
 * Return: IDPF_PSP_TX_PLAIN if @skb is not a PSP packet, IDPF_PSP_TX_SEND if
 * it can be transmitted with @psp, IDPF_PSP_TX_CONSUMED if it was queued until
 * the SA index of its TX key is known, or dropped.
 */
static inline enum idpf_psp_tx_verdict
idpf_psp_tx_prep(const struct idpf_vport *vport, struct idpf_queue *tx_q,
		 struct sk_buff *skb, struct idpf_psp_tx *psp)
{
	enum idpf_psp_tx_verdict ret = IDPF_PSP_TX_PLAIN;
	struct psp_assoc *pas;

	/* The stack only holds rcu_read_lock_bh() */
	rcu_read_lock();
	pas = psp_skb_get_assoc_rcu(skb);
	if (unlikely(pas))
		ret = __idpf_psp_tx_prep(vport, tx_q, skb, pas, psp);
	rcu_read_unlock();

	return ret;
}

void idpf_psp_tx_ctx_desc(union idpf_flex_tx_ctx_desc *desc,
			  const struct idpf_tx_offload_params *off, bool tso,
			  u32 saidx);
bool idpf_psp_tx_encap(struct idpf_queue *tx_q, struct sk_buff *skb,
		       const struct idpf_psp_tx *psp);
int idpf_psp_rx_process_skb(struct idpf_queue *rxq, struct sk_buff *skb,
			    u16 rx_ptype);
bool idpf_psp_is_rx_ptype(const struct virtchnl2_ptype *ptype);
void idpf_psp_set_rx_ptype(struct idpf_adapter *adapter, u16 ptype);

/**
 * idpf_psp_is_offload_rx - Check if a received packet was decrypted
 * @skb: the packet
 *
 * Return: true if the packet was decrypted and decapsulated, see
 * idpf_psp_rx_process_skb()
 */
static inline bool idpf_psp_is_offload_rx(const struct sk_buff *skb)
{
	return skb_ext_find(skb, SKB_EXT_PSP);
}

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

static inline enum idpf_psp_tx_verdict
idpf_psp_tx_prep(const struct idpf_vport *vport, struct idpf_queue *tx_q,
		 struct sk_buff *skb, struct idpf_psp_tx *psp)
{
	return IDPF_PSP_TX_PLAIN;
}

static inline void
idpf_psp_tx_ctx_desc(union idpf_flex_tx_ctx_desc *desc,
		     const struct idpf_tx_offload_params *off, bool tso,
		     u32 saidx) { }

static inline bool idpf_psp_tx_encap(struct idpf_queue *tx_q,
				     struct sk_buff *skb,
				     const struct idpf_psp_tx *psp)
{
	return false;
}

static inline int idpf_psp_rx_process_skb(struct idpf_queue *rxq,
					  struct sk_buff *skb, u16 rx_ptype)
{
	return 0;
}

static inline bool idpf_psp_is_rx_ptype(const struct virtchnl2_ptype *ptype)
{
	return false;
}

static inline void idpf_psp_set_rx_ptype(struct idpf_adapter *adapter,
					 u16 ptype) { }

static inline bool idpf_psp_is_offload_rx(const struct sk_buff *skb)
{
	return false;
}

static inline void
idpf_psp_rotation_event(struct idpf_adapter *adapter,
			const struct idpf_ctlq_msg *ctlq_msg) { }

#endif /* CONFIG_INET_PSP */

#endif /* !_IDPF_PSP_H_ */
