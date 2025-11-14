/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"
#ifdef HAVE_NETDEV_BPF_XSK_POOL

/**
 * idpf_get_xsk_pool - get xsk_pool pointer from netdev
 * @q: queue to use
 * @xdp_txq: true if queue pointed by q parameter represents XDP Tx queue,
 *	     false otherwise
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
void idpf_get_xsk_pool(struct idpf_queue *q, bool xdp_txq)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct idpf_vport *vport = q->vport;
	int qid;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;

	if (!idpf_xdp_is_prog_ena(q->vport)) {
		q->xsk_pool = NULL;
		return;
	}

	qid = xdp_txq ? q->idx - q->vport->xdp_txq_offset : q->idx;

	if (!test_bit(qid, cfg_data->af_xdp_zc_qps)) {
		q->xsk_pool = NULL;
		return;
	}

	q->xsk_pool = xsk_get_pool_from_qid(q->vport->netdev, qid);
}

/**
 * idpf_xsk_is_zc_bufq - checks if rx bufq is used for zero-copy
 * @rxbufq: rx buffer queue to be tested
 *
 * Returns true if the buffer queue is used for zero-copy.
 */
bool idpf_xsk_is_zc_bufq(struct idpf_queue *rxbufq)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct idpf_vport *vport = rxbufq->vport;
	u16 idx = rxbufq->vport->idx;
	bool ret;

	cfg_data = &vport->adapter->vport_config[idx]->user_config;

	ret = idpf_xdp_is_prog_ena(vport) &&
	      test_bit(rxbufq->rx.rxq_idx, cfg_data->af_xdp_zc_qps);

	return ret;
}

/**
 * idpf_xsk_pool_disable - disables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_disable(struct idpf_vport *vport, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct xsk_buff_pool *pool;

	pool = xsk_get_pool_from_qid(vport->netdev, qid);
	if (!pool)
		return -EINVAL;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;

	vport->req_xsk_pool = pool;
	vport->xsk_enable_req = false;

	clear_bit(qid, cfg_data->af_xdp_zc_qps);

	return 0;
}

/**
 * idpf_xsk_pool_enable - enables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_enable(struct idpf_vport *vport,
				struct xsk_buff_pool *pool, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;

	if (qid >= vport->netdev->real_num_rx_queues ||
	    qid >= vport->netdev->real_num_tx_queues)
		return -EINVAL;

	vport->req_xsk_pool = pool;
	vport->xsk_enable_req = true;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;
	set_bit(qid, cfg_data->af_xdp_zc_qps);

	return 0;
}

/**
 * idpf_xsk_pool_unmap - unmap the xsk_pool while the HW is down
 * @netdev: current netdev of interest
 * @qid: queue id
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_xsk_pool_unmap(struct net_device *netdev, u16 qid)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport_user_config_data *cfg_data;
	struct xsk_buff_pool *pool;

	cfg_data = &np->adapter->vport_config[np->vport_idx]->user_config;
	clear_bit(qid, cfg_data->af_xdp_zc_qps);

	pool = xsk_get_pool_from_qid(netdev, qid);
	if (!pool)
		return -EINVAL;

	xsk_pool_dma_unmap(pool, IDPF_RX_DMA_ATTR);

	return 0;
}

/**
 * idpf_xsk_pool_setup - enable/disable a BUFF POOL region
 * @netdev: current netdev of interest
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on failure
 */
int idpf_xsk_pool_setup(struct net_device *netdev, struct xsk_buff_pool *pool,
			u16 qid)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport = np->vport;
	bool pool_present = !!pool;
	int err;

	/* Do not allow for adding new pools while reseting */
	if (pool_present && test_bit(IDPF_HR_RESET_IN_PROG, np->adapter->flags))
		return -EBUSY;

	if (!vport)
		return pool_present ? -EINVAL :
				      idpf_xsk_pool_unmap(netdev, qid);

	err = pool_present ? idpf_xsk_pool_enable(vport, pool, qid) :
			     idpf_xsk_pool_disable(vport, qid);

	if (err) {
		netdev_err(vport->netdev, "Could not %sable BUFF POOL, error = %d\n",
			   pool_present ? "en" : "dis", err);
		return err;
	}

	if (!idpf_xdp_is_prog_ena(vport))
		netdev_warn(vport->netdev, "RSS may schedule pkts to q occupied by AF XDP\n");

	return idpf_initiate_soft_reset(vport, IDPF_SR_XDP_CHANGE);
}

/**
 * idpf_xsk_handle_pool_change - perform XSK DMA mapping/unmapping
 * @vport: current vport of interest
 *
 * Returns 0 on success, negative on failure
 */
int idpf_xsk_handle_pool_change(struct idpf_vport *vport)
{
	int err = 0;

	/* Do nothing if no change of xsk_pool was requested. */
	if (!vport->req_xsk_pool)
		return 0;

	if (vport->xsk_enable_req) {
		err = xsk_pool_dma_map(vport->req_xsk_pool,
				       idpf_adapter_to_dev(vport->adapter),
				       IDPF_RX_DMA_ATTR);
		if (err)
			goto xsk_change_exit;
	} else {
		xsk_pool_dma_unmap(vport->req_xsk_pool, IDPF_RX_DMA_ATTR);
	}

xsk_change_exit:
	vport->req_xsk_pool = NULL;
	return err;
}

/**
 * idpf_xmit_splitq_zc - Sends AF_XDP entries, and cleans XDP entries
 * @xdpq: XDP Tx queue
 * @budget: max number of frames to xmit
 *
 * Returns true if the given budget is not fully exhausted, so there are
 * no more frames to be sent, false otherwise, what means that napi_schedule
 * shall be requested because some frames have not been transmitted yet.
 */
static bool
idpf_xmit_splitq_zc(struct idpf_queue *xdpq, int budget)
{
	struct idpf_tx_splitq_params tx_parms = {
		(enum idpf_tx_desc_dtype_value)0, 0, { }, { }
	};
	union idpf_tx_flex_desc *tx_desc = NULL;
	u16 ntu = xdpq->next_to_use;
	struct xdp_desc desc;
	dma_addr_t dma;

	while (likely(budget-- > 0)) {
		struct idpf_tx_buf *tx_buf;

		tx_buf = &xdpq->tx.bufs[ntu];

		if (!xsk_tx_peek_desc(xdpq->xsk_pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma,
						 desc.len);
		tx_buf->bytecount = desc.len;

		tx_parms.compl_tag =
			(xdpq->compl_tag_cur_gen << xdpq->compl_tag_gen_s) | ntu;

		tx_desc = IDPF_FLEX_TX_DESC(xdpq, ntu);
		tx_desc->q.buf_addr = cpu_to_le64(dma);

		tx_parms.dtype = IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_parms.eop_cmd = IDPF_TXD_FLEX_FLOW_CMD_EOP;

		idpf_tx_splitq_build_desc(tx_desc, &tx_parms, tx_parms.eop_cmd |
					  tx_parms.offload.td_cmd, desc.len);

		ntu++;
		if (ntu == xdpq->desc_count) {
			ntu = 0;
			xdpq->compl_tag_cur_gen = IDPF_TX_ADJ_COMPL_TAG_GEN(xdpq);
		}

		tx_buf->compl_tag = tx_parms.compl_tag;
	}

	if (likely(tx_desc)) {
		xdpq->next_to_use = ntu;

		idpf_xdpq_update_tail(xdpq);
		xsk_tx_release(xdpq->xsk_pool);
	}

	return budget > 0;
}

/**
 * idpf_xmit_singleq_zc - Sends AF_XDP entries, and cleans XDP entries
 * @xdpq: XDP Tx queue
 * @budget: max number of frames to xmit
 *
 * Returns true if the given budget is not fully exhausted, so there are
 * no more frames to be sent, false otherwise, what means that napi_schedule
 * shall be requested because some frames have not been transmitted yet.
 */
static bool
idpf_xmit_singleq_zc(struct idpf_queue *xdpq, int budget)
{
	struct idpf_base_tx_desc *tx_desc = NULL;
	u16 ntu = xdpq->next_to_use;
	struct xdp_desc desc;
	dma_addr_t dma;
	u64 td_cmd;

	while (likely(budget-- > 0)) {
		struct idpf_tx_buf *tx_buf;

		tx_buf = &xdpq->tx.bufs[ntu];

		if (!xsk_tx_peek_desc(xdpq->xsk_pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma,
						 desc.len);
		tx_buf->bytecount = desc.len;

		tx_desc = IDPF_BASE_TX_DESC(xdpq, ntu);
		tx_desc->buf_addr = cpu_to_le64(dma);

		td_cmd = IDPF_TX_DESC_CMD_EOP;
		tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd, 0x0, desc.len, 0);

		xdpq->xdp_next_rs_idx = ntu;
		ntu++;
		if (ntu == xdpq->desc_count)
			ntu = 0;
	}

	if (likely(tx_desc)) {
		xdpq->next_to_use = ntu;

		/* Set RS bit for the last frame and bump tail ptr */
		td_cmd |= IDPF_TX_DESC_CMD_RS;
		tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd, 0x0, desc.len, 0);

		idpf_xdpq_update_tail(xdpq);
		xsk_tx_release(xdpq->xsk_pool);
	}

	return budget > 0;
}

/**
 * idpf_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdpq: XDP Tx queue
 * @tx_buf: Tx buffer to clean
 */
static void
idpf_clean_xdp_tx_buf(struct idpf_queue *xdpq, struct idpf_tx_buf *tx_buf)
{
#ifdef HAVE_XDP_FRAME_STRUCT
	xdp_return_frame(tx_buf->xdpf);
#else
	xdp_return_frame((struct xdp_frame *)tx_buf->raw_buf);
#endif
	xdpq->xdp_tx_active--;
	dma_unmap_single(xdpq->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * idpf_tx_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *		      (implementation of common part for singleq and splitq
 *		      modes).
 * @xdpq: AF XDP Tx queue to clean
 * @ntc: Index of the next Tx buffer that shall be cleaned.
 * @clean_count: number of ready Tx frames that should be cleaned.
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 *
 * Returns the structure containing the number of bytes and packets cleaned.
 */
static void
idpf_tx_clean_zc(struct idpf_queue *xdpq, u16 ntc, u16 clean_count,
		 struct idpf_cleaned_stats *cleaned)
{
	struct idpf_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	u16 i;

	if (!clean_count)
		return;

	if (likely(!xdpq->xdp_tx_active)) {
		xsk_frames = clean_count;
		goto skip;
	}

	for (i = 0; i < clean_count; i++) {
		tx_buf = &xdpq->tx.bufs[ntc];

#ifdef HAVE_XDP_FRAME_STRUCT
		if (tx_buf->xdpf) {
#else
		if (tx_buf->raw_buf) {
#endif
			idpf_clean_xdp_tx_buf(xdpq, tx_buf);
#ifdef HAVE_XDP_FRAME_STRUCT
			tx_buf->xdpf = NULL;
#else
			tx_buf->raw_buf = NULL;
#endif
			cleaned->bytes += tx_buf->bytecount;
		} else {
			xsk_frames++;
		}

		++ntc;
		if (unlikely(ntc >= xdpq->desc_count))
			ntc = 0;
	}
skip:
	xdpq->next_to_clean += clean_count;
	if (unlikely(xdpq->next_to_clean >= xdpq->desc_count))
		xdpq->next_to_clean -= xdpq->desc_count;

	if (xsk_frames) {
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
		cleaned->bytes += (xsk_frames * xdpq->xsk_pool->frame_len);
	}

	if (xsk_uses_need_wakeup(xdpq->xsk_pool))
		xsk_set_tx_need_wakeup(xdpq->xsk_pool);

	cleaned->packets += clean_count;
}

/**
 * idpf_prepare_for_xmit_zc - Prepare XSK pool to perform AF_XDP Tx action
 *			      including computing the Tx budget.
 * @xdpq: AF XDP Tx queue used to xmit
 *
 * Returns the AF_XDP Tx budget.
 */
static u16
idpf_prepare_for_xmit_zc(struct idpf_queue *xdpq)
{
	u16 send_budget;

#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(xdpq->xsk_pool))
		xsk_set_tx_need_wakeup(xdpq->xsk_pool);
#endif /* HAVE_NDO_XSK_WAKEUP */

	send_budget = min_t(u16, IDPF_DESC_UNUSED(xdpq), xdpq->desc_count / 4);

	return send_budget;
}

/**
 * idpf_tx_splitq_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *			     in split queue mode
 * @xdpq: AF XDP Tx queue to clean
 * @compl_tag: completion tag of the packet that should be cleaned
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 *
 * Returns the structure containing the number of bytes and packets cleaned.
 */
void
idpf_tx_splitq_clean_zc(struct idpf_queue *xdpq, u16 compl_tag,
			struct idpf_cleaned_stats *cleaned)
{
	u16 end = (compl_tag & xdpq->compl_tag_bufid_m) + 1;
	u16 ntc = xdpq->next_to_clean;
	u16 frames_ready = 0;

	if (end >= ntc)
		frames_ready = end - ntc;
	else
		frames_ready = end + xdpq->desc_count - ntc;

	return idpf_tx_clean_zc(xdpq, ntc, frames_ready, cleaned);
}

/**
 * idpf_tx_singleq_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *			      in single queue mode
 * @xdpq: AF XDP Tx queue to clean
 * @cleaned: returns number of packets cleaned
 *
 * Returns true if all AF_XDP frames have been successfully sent, false
 * otherwise.
 */
bool
idpf_tx_singleq_clean_zc(struct idpf_queue *xdpq, int *cleaned)
{
	struct idpf_cleaned_stats cleaned_stats = { };
	u16 next_rs_idx = xdpq->xdp_next_rs_idx;
	struct idpf_base_tx_desc *next_rs_desc;
	u16 send_budget, frames_ready = 0;
	s16 ntc = xdpq->next_to_clean;

	next_rs_desc = IDPF_BASE_TX_DESC(xdpq, next_rs_idx);
	if (next_rs_desc->qw1 &
	    cpu_to_le64(IDPF_TX_DESC_DTYPE_DESC_DONE)) {
		if (next_rs_idx >= ntc)
			frames_ready = next_rs_idx - ntc;
		else
			frames_ready = next_rs_idx + xdpq->desc_count - ntc;
	}

	idpf_tx_clean_zc(xdpq, ntc, frames_ready, &cleaned_stats);
	*cleaned = cleaned_stats.packets;

	send_budget = idpf_prepare_for_xmit_zc(xdpq);
	return idpf_xmit_singleq_zc(xdpq, send_budget);
}

/**
 * idpf_tx_splitq_xmit_zc - Sends all unsent data in XDP ZC queue
 * @xdpq: AF XDP Tx queue to clean
 *
 * Returns true if transmission is done.
 */
bool
idpf_tx_splitq_xmit_zc(struct idpf_queue *xdpq)
{
	u16 send_budget = idpf_prepare_for_xmit_zc(xdpq);

	return idpf_xmit_splitq_zc(xdpq, send_budget);
}

/**
 * idpf_trigger_sw_intr - trigger a software interrupt
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
idpf_trigger_sw_intr(struct idpf_hw *hw, struct idpf_q_vector *q_vector)
{
	struct idpf_intr_reg *intr = &q_vector->intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m |
	      intr->dyn_ctl_itridx_m |    /* set no itr*/
	      intr->dyn_ctl_swint_trig_m |
	      intr->dyn_ctl_sw_itridx_ena_m;

	writel(val, intr->dyn_ctl);
}

/**
 * idpf_xsk_check_xmit_params - Implements ndo_xsk_wakeup for split queue
 * @vport: current vport of interest
 * @xdpq_idx: index of XDP Tx queue
 *
 * Returns negative error code on error, zero otherwise.
 */
static int
idpf_xsk_check_xmit_params(struct idpf_vport *vport, u32 xdpq_idx)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct idpf_vport_user_config_data *cfg_data;

	if (unlikely(!np->active))
		return -ENETDOWN;

	if (unlikely(!idpf_xdp_is_prog_ena(vport)))
		return -ENXIO;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;
	if (unlikely(!test_bit(xdpq_idx - vport->xdp_txq_offset,
			       cfg_data->af_xdp_zc_qps)))
		return -ENXIO;

	if (unlikely(xdpq_idx >= vport->num_txq))
		return -ENXIO;

	if (unlikely(!vport->txqs[xdpq_idx]->xsk_pool))
		return -ENXIO;

	return 0;
}

/**
 * idpf_xsk_schedule_napi_for_xmit - Schedule SW interrupt for AF_XDP xmit
 * @vport: vport of intrest
 * @q_vector: interrupt vector to trigger the software interrupt for
 *
 */
static void idpf_xsk_schedule_napi_for_xmit(struct idpf_vport *vport,
					    struct idpf_q_vector *q_vector)
{
	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		idpf_trigger_sw_intr(&vport->adapter->hw, q_vector);
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * idpf_xsk_splitq_wakeup - Implements ndo_xsk_wakeup for split queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative value on error, zero otherwise.
 */
int idpf_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id,
			   u32 __always_unused flags)
{
#else
/**
 * idpf_xsk_splitq_async_xmit - Implements ndo_xsk_async_xmit for split queue
 *				mode
 * @netdev: net_device
 * @q_id: queue to wake up
 *
 * Returns negative value on error, zero otherwise.
 */
int idpf_xsk_splitq_async_xmit(struct net_device *netdev, u32 q_id)
{
#endif /* HAVE_NDO_XSK_WAKEUP */
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport = np->vport;
	struct idpf_q_vector *q_vector;
	u32 idx;
	int ret;

	rcu_read_lock();
	if (unlikely(test_bit(IDPF_HR_RESET_IN_PROG, np->adapter->flags) ||
		     mutex_is_locked(&np->adapter->vport_cfg_lock))) {
		ret = -EBUSY;
		goto exit;
	}

	idx = q_id + vport->xdp_txq_offset;

	ret = idpf_xsk_check_xmit_params(vport, idx);
	if (unlikely(ret))
		goto exit;

	q_vector = vport->txqs[idx]->txq_grp->complq->q_vector;

	idpf_xsk_schedule_napi_for_xmit(vport, q_vector);
exit:
	rcu_read_unlock();

	return ret;
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * idpf_xsk_singleq_wakeup - Implements ndo_xsk_wakeup for single queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative value on error, zero otherwise.
 */
int idpf_xsk_singleq_wakeup(struct net_device *netdev, u32 q_id,
			    u32 __always_unused flags)
{
#else
/**
 * idpf_xsk_singleq_async_xmit - Implements ndo_xsk_async_xmit for single queue
 *				 mode
 * @netdev: net_device
 * @q_id: queue to wake up
 *
 * Returns negative value on error, zero otherwise.
 */
int idpf_xsk_singleq_async_xmit(struct net_device *netdev, u32 q_id)
{
#endif /* HAVE_NDO_XSK_WAKEUP */
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport = np->vport;
	struct idpf_q_vector *q_vector;
	u32 idx;
	int ret;

	rcu_read_lock();
	if (unlikely(mutex_is_locked(&np->adapter->vport_cfg_lock))) {
		ret = -EBUSY;
		goto exit;
	}

	idx = q_id + vport->xdp_txq_offset;

	ret = idpf_xsk_check_xmit_params(vport, idx);
	if (unlikely(ret))
		goto exit;

	q_vector = vport->txqs[idx]->q_vector;

	idpf_xsk_schedule_napi_for_xmit(vport, q_vector);
exit:
	rcu_read_unlock();
	return ret;
}

/**
 * idpf_xsk_cleanup_xdpq - remove Tx and Completion descriptors related to the
 *			   XDP queue
 * @xdpq: pointer to XDP Tx queue
 */
void idpf_xsk_cleanup_xdpq(struct idpf_queue *xdpq)
{
	u16 ntc = xdpq->next_to_clean, ntu = xdpq->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct idpf_tx_buf *tx_buf = &xdpq->tx.bufs[ntc];

#ifdef HAVE_XDP_FRAME_STRUCT
		if (tx_buf->xdpf)
#else
		if (tx_buf->raw_buf)
#endif
			idpf_clean_xdp_tx_buf(xdpq, tx_buf);
		else
			xsk_frames++;

#ifdef HAVE_XDP_FRAME_STRUCT
		tx_buf->xdpf = NULL;
#else
		tx_buf->raw_buf = NULL;
#endif

		ntc++;
		if (ntc >= xdpq->desc_count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
}

/**
 * idpf_xsk_any_rxq_ena - Checks if Rx queues have AF_XDP buff pool attached
 * @vport: vport to be checked
 *
 * Returns true if any of the Rx queues has an AF_XDP buff pool attached
 */
bool idpf_xsk_any_rxq_ena(struct idpf_vport *vport)
{
	int i;

	for (i = 0; i < vport->dflt_grp.q_grp.num_rxq; i++) {
		if (xsk_get_pool_from_qid(vport->netdev, i))
			return true;
	}

	return false;
}

/**
 * idpf_rx_buf_hw_alloc_zc - allocate a single Rx buffer
 * @buf: receive buffer to allocate
 * @xsk_pool: pointer to AF_XDP pool
 *
 * Returns false if the allocation was successful, true if it failed.
 */
static bool idpf_rx_buf_hw_alloc_zc(struct idpf_rx_buf *buf,
				    struct xsk_buff_pool *xsk_pool)
{
	buf->xdp = xsk_buff_alloc(xsk_pool);
	if (!buf->xdp)
		return true;

	buf->page_info[buf->page_indx].page_offset = 0;
	buf->page_info[buf->page_indx].dma = xsk_buff_xdp_get_dma(buf->xdp);

	return false;
}

/**
 * idpf_rx_update_bufq_desc_zc - update buffer queue descriptor for zero-copy
 * @buf: Buffer to be updated
 * @bufq: Pointer to the buffer queue
 * @page_info: Page info structure
 * @buf_desc: Buffer queue descriptor
 * @buf_id: Buffer ID
 *
 * Return 0 on success and negative on failure.
 */
int idpf_rx_update_bufq_desc_zc(struct idpf_rx_buf *buf,
				struct idpf_queue *bufq,
				struct idpf_page_info *page_info,
				struct virtchnl2_splitq_rx_buf_desc *buf_desc,
				u16 buf_id)
{
	if (idpf_rx_buf_hw_alloc_zc(buf, bufq->xsk_pool))
		return -ENOMEM;

	buf_desc->pkt_addr = cpu_to_le64(page_info->dma);
	buf_desc->qword0.buf_id = cpu_to_le16(buf_id);

	return 0;
}

/**
 * idpf_rx_splitq_buf_hw_alloc_zc_all - allocate a number of Rx buffers
 * @rx_bufq: receive buffer queue
 * @rxq: Rx queue
 * @count: The number of buffers to allocate
 *
 * Returns false if all allocations were successful, true if any fail.
 */
static bool idpf_rx_splitq_buf_hw_alloc_zc_all(struct idpf_queue *rx_bufq,
					       struct idpf_queue *rxq,
					       u16 count)
{
	struct xsk_buff_pool *xsk_pool = rx_bufq->xsk_pool;
	struct virtchnl2_splitq_rx_buf_desc *buf_desc;
	struct idpf_page_info *page_info;
	struct idpf_rx_buf *buf;
	bool ret = false;
	u16 nta = 0;

	buf = &rx_bufq->rx.bufs[nta];

	do {
		ret = idpf_rx_buf_hw_alloc_zc(buf, xsk_pool);
		if (ret)
			break;

		buf_desc = IDPF_SPLITQ_RX_BUF_DESC(rx_bufq, nta);
		page_info = &buf->page_info[buf->page_indx];
		buf_desc->pkt_addr = cpu_to_le64(page_info->dma);

		buf++;
		nta++;

		if (unlikely(nta == rx_bufq->desc_count)) {
			buf = rx_bufq->rx.bufs;
			nta = 0;
		}

		count--;

	} while (count);

	if (nta != rx_bufq->desc_count - 1) {
		while (nta < rx_bufq->desc_count - 1) {
			/* Pass all uninitialized buffers to the refillq,
			 * but without buf->xdp. On dequeue from refillq in
			 * idpf_rx_clean_refillq, will have to retry: same as
			 * non-xsk path.
			 */
			idpf_rx_post_buf_refill(&rxq->rx.refillqs[0], nta);
			nta++;
		}
	}

	rx_bufq->next_to_alloc = nta;
	idpf_rx_buf_hw_update(rx_bufq, rx_bufq->next_to_alloc & ~(rx_bufq->rx_buf_stride - 1));

	return ret;
}

/**
 * idpf_rx_singleq_buf_hw_alloc_zc_all - allocate a number of Rx buffers
 * @rxq: receive queue
 * @count: The number of buffers to allocate
 *
 * Returns false if all allocations were successful, true if any fail.
 */
static bool idpf_rx_singleq_buf_hw_alloc_zc_all(struct idpf_queue *rxq,
						u16 count)
{
	struct virtchnl2_singleq_rx_buf_desc *singleq_rx_desc = NULL;
	struct xsk_buff_pool *xsk_pool = rxq->xsk_pool;
	u16 nta = rxq->next_to_alloc;
	struct idpf_rx_buf *buf;

	/* do nothing if no valid netdev defined */
	if (!rxq->vport->netdev || !count)
		return false;

	singleq_rx_desc = IDPF_SINGLEQ_RX_BUF_DESC(rxq, nta);
	buf = &rxq->rx.bufs[nta];

	do {
		if (idpf_rx_buf_hw_alloc_zc(buf, xsk_pool))
			break;

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		singleq_rx_desc->pkt_addr = cpu_to_le64(buf->page_info[buf->page_indx].dma);
		singleq_rx_desc->hdr_addr = 0;
		singleq_rx_desc++;

		buf++;
		nta++;
		if (unlikely(nta == rxq->desc_count)) {
			singleq_rx_desc = IDPF_SINGLEQ_RX_BUF_DESC(rxq, 0);
			buf = rxq->rx.bufs;
			nta = 0;
		}

		count--;
	} while (count);

	if (rxq->next_to_alloc != nta) {
		idpf_rx_buf_hw_update(rxq, nta);
		rxq->next_to_alloc = nta;
	}

	return !!count;
}

/**
 * idpf_rx_buf_hw_alloc_zc_all - allocate a number of Rx buffers
 * @vport: current vport
 * @q_grp: Queue resources
 * @rxq: Rx queue
 */
void idpf_rx_buf_hw_alloc_zc_all(struct idpf_vport *vport,
				 struct idpf_q_grp *q_grp,
				 struct idpf_queue *rxq)
{
	int i, desc_cnt;
	bool err;

	if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
		err = idpf_rx_singleq_buf_hw_alloc_zc_all(rxq,
							  rxq->desc_count - 1);
		if (err)
			dev_info(rxq->dev, "Failed to allocate some buffers on UMEM enabled qp id %d\n",
				 rxq->idx);
		return;
	}

	for (i = 0; i < q_grp->bufq_per_rxq; i++) {
		int offset = rxq->idx * q_grp->bufq_per_rxq + i;
		struct idpf_queue *rxbufq;

		rxbufq = &q_grp->bufqs[offset];
		rxbufq->xsk_pool = rxq->xsk_pool;
		desc_cnt = rxbufq->desc_count - 1;
		err = idpf_rx_splitq_buf_hw_alloc_zc_all(rxbufq, rxq,
							 desc_cnt);
		if (err)
			dev_info(rxbufq->dev, "Failed to allocate some buffers on UMEM enabled qp id %d, rxbufq %d\n",
				 rxq->idx, i);
	}
}

/**
 * idpf_rx_buf_rel_zc - Free AF_XDP Rx buffer
 * @buf: receive buffer to be released
 */
void idpf_rx_buf_rel_zc(struct idpf_rx_buf *buf)
{
	if (!buf->xdp)
		return;

	xsk_buff_free(buf->xdp);
	buf->xdp = NULL;
}

/**
 * idpf_run_xdp_zc - Executes an XDP program on initialized xdp_buff
 * @rxq: Rx queue
 * @xdpq: XDP Tx queue
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns IDPF_XDP_PASS for packets to be sent up the stack, IDPF_XDP_CONSUMED
 * otherwise.
 */
static int idpf_run_xdp_zc(struct idpf_queue *rxq, struct idpf_queue *xdpq,
			   struct xdp_buff *xdp)
{
	int err, result = IDPF_XDP_PASS;
	struct bpf_prog *xdp_prog;
	u32 act;

	/* ZC path is enabled only when XDP program is set, no need to check
	 * for NULL
	 */
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rxq->vport->netdev, xdp, xdp_prog);
		if (err)
			goto out_failure;
		return IDPF_XDP_REDIR;
	}

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		result = idpf_xmit_xdpq(xdp_convert_buff_to_frame(xdp), xdpq);
		if (result == IDPF_XDP_CONSUMED)
			goto out_failure;
		break;
	default:
		bpf_warn_invalid_xdp_action(rxq->vport->netdev, xdp_prog, act);
		fallthrough; /* not supported action */
	case XDP_ABORTED:
out_failure:
		trace_xdp_exception(rxq->vport->netdev, xdp_prog, act);
		fallthrough; /* handle aborts by dropping frame */
	case XDP_DROP:
		return IDPF_XDP_CONSUMED;
	}

	return result;
}

/**
 * idpf_rx_construct_skb_zc - Create an skb from zero-copy buffer
 * @rxq: Rx descriptor queue
 * @rx_buf: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb on success, NULL on failure.
 */
static struct sk_buff *idpf_rx_construct_skb_zc(struct idpf_queue *rxq,
						struct idpf_rx_buf *rx_buf,
						unsigned int size)
{
	unsigned int datasize = (u8 *)rx_buf->xdp->data_end - (u8 *)rx_buf->xdp->data_meta;
	unsigned int metasize = (u8 *)rx_buf->xdp->data - (u8 *)rx_buf->xdp->data_meta;
	unsigned int datasize_hard = (u8 *)rx_buf->xdp->data_end -
				     (u8 *)rx_buf->xdp->data_hard_start;
	struct sk_buff *skb;

	skb = napi_alloc_skb(&rxq->q_vector->napi, datasize_hard);

	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, (u8 *)rx_buf->xdp->data_meta - (u8 *)rx_buf->xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), (u8 *)rx_buf->xdp->data_meta, datasize);

	if (metasize) {
		__skb_pull(skb, metasize);
		skb_metadata_set(skb, metasize);
	}

	xsk_buff_free(rx_buf->xdp);
	rx_buf->xdp = NULL;
	return skb;
}

/**
 * idpf_rx_splitq_clean_zc - consumes packets from the hardware queue
 * @rxq: AF_XDP receive queue
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int idpf_rx_splitq_clean_zc(struct idpf_queue *rxq, int budget)
{
	struct idpf_queue *xdpq = idpf_get_related_xdp_queue(rxq);
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	struct sk_buff *skb = rxq->rx.skb;
	u16 ntc = rxq->next_to_clean;
	unsigned int xdp_xmit = 0;
	bool failure = false;

	rcu_read_lock();
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct virtchnl2_rx_flex_desc_adv_nic_3 *splitq_flex_rx_desc;
		struct idpf_sw_queue *refillq = NULL;
		unsigned int xdp_res = IDPF_XDP_PASS;
		struct idpf_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *rx_desc;
		unsigned int pkt_len = 0;
		u16 gen_id, buf_id;
		int bufq_id;

		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		rx_desc = IDPF_RX_DESC(rxq, ntc);
		splitq_flex_rx_desc = (struct virtchnl2_rx_flex_desc_adv_nic_3 *)rx_desc;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc
		 */
		dma_rmb();

		/* if the descriptor isn't done, no work yet to do */
		gen_id = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id);
		gen_id = (gen_id & VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M) >>
			 VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_S;
		if (test_bit(__IDPF_Q_GEN_CHK, rxq->flags) != gen_id)
			break;

		pkt_len = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id) &
				      VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M;
		if (!pkt_len)
			break;

		bufq_id = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id);
		bufq_id = (bufq_id & VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M) >>
			  VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_S;

		refillq = &rxq->rx.refillqs[bufq_id];

		buf_id = le16_to_cpu(splitq_flex_rx_desc->buf_id);
		rx_buf = &rxq->rx.bufq_bufs[bufq_id][buf_id];

		if (!rx_buf->xdp)
			break;

		rx_buf->xdp->data_end = (u8 *)rx_buf->xdp->data + pkt_len;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp);

		xdp_res = idpf_run_xdp_zc(rxq, xdpq, rx_buf->xdp);

		if (xdp_res) {
			if (xdp_res & (IDPF_XDP_TX | IDPF_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(rx_buf->xdp);

			rx_buf->xdp = NULL;
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			failure |= idpf_rx_buf_hw_alloc_zc(rx_buf, rxq->xsk_pool);
			idpf_rx_post_buf_refill(refillq, buf_id);
			ntc = idpf_rx_bump_ntc(rxq, ntc);
			continue;
		}

		/* XDP_PASS path */
		skb = idpf_rx_construct_skb_zc(rxq, rx_buf, pkt_len);
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf) {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			break;
		}
		failure |= idpf_rx_buf_hw_alloc_zc(rx_buf, rxq->xsk_pool);
		idpf_rx_post_buf_refill(refillq, buf_id);
		ntc = idpf_rx_bump_ntc(rxq, ntc);

		/* pad skb if needed (to make valid ethernet frame) */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* protocol */
		if (unlikely(idpf_rx_process_skb_fields(rxq, skb,
							splitq_flex_rx_desc))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* send completed skb up the stack */
		skb->protocol = eth_type_trans(skb, rxq->vport->netdev);
		napi_gro_receive(&rxq->q_vector->napi, skb);
		skb = NULL;

		/* Update budget accounting */
		total_rx_pkts++;
	}

	rxq->next_to_clean = ntc;

	idpf_finalize_xdp_rx(xdpq, xdp_xmit);
	rcu_read_unlock();

	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_add(&rxq->q_stats.rx.packets, total_rx_pkts);
	u64_stats_add(&rxq->q_stats.rx.bytes, total_rx_bytes);
	u64_stats_update_end(&rxq->stats_sync);

	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return (int)total_rx_pkts;
	}

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}

/**
 * idpf_rx_singleq_clean_zc - consumes packets from the hardware queue
 * @rxq: AF_XDP receive queue
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int idpf_rx_singleq_clean_zc(struct idpf_queue *rxq, int budget)
{
	struct idpf_queue *xdpq = idpf_get_related_xdp_queue(rxq);
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	struct sk_buff *skb = rxq->rx.skb;
	u16 ntc = rxq->next_to_clean;
	unsigned int xdp_xmit = 0;
	u16 cleaned_count = 0;
	bool failure = false;

	rcu_read_lock();
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct idpf_rx_extracted fields = { };
		unsigned int xdp_res = IDPF_XDP_PASS;
		struct idpf_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *rx_desc;
		unsigned int pkt_len = 0;

		rx_desc = IDPF_RX_DESC(rxq, ntc);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc
		 */
		dma_rmb();

		/* status_error_ptype_len will always be zero for unused
		 * descriptors because it's cleared in cleanup, and overlaps
		 * with hdr_addr which is always zero because packet split
		 * isn't used, if the hardware wrote DD then the length will be
		 * non-zero
		 */
#define IDPF_RXD_DD VIRTCHNL2_RX_BASE_DESC_STATUS_DD_M
		if (!idpf_rx_singleq_test_staterr(rx_desc, IDPF_RXD_DD))
			break;
		idpf_rx_singleq_extract_fields(rxq, rx_desc, &fields);
		pkt_len = fields.size;

		if (!pkt_len)
			break;

		rx_buf = &rxq->rx.bufs[rxq->next_to_clean];
		if (!rx_buf->xdp)
			break;

		rx_buf->xdp->data_end = (u8 *)rx_buf->xdp->data + pkt_len;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp);

		xdp_res = idpf_run_xdp_zc(rxq, xdpq, rx_buf->xdp);
		if (xdp_res) {
			if (xdp_res & (IDPF_XDP_TX | IDPF_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(rx_buf->xdp);

			rx_buf->xdp = NULL;
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			cleaned_count++;

			ntc = idpf_singleq_bump_desc_idx(rxq, ntc);
			continue;
		}

		/* XDP_PASS path */
		skb = idpf_rx_construct_skb_zc(rxq, rx_buf, pkt_len);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf) {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			break;
		}

		ntc = idpf_singleq_bump_desc_idx(rxq, ntc);

		cleaned_count++;

		/* skip if it is non EOP desc */
		if (idpf_rx_singleq_is_non_eop(rxq, rx_desc, skb))
			continue;

#define IDPF_RXD_ERR_S BIT(VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S)
		if (unlikely(idpf_rx_singleq_test_staterr(rx_desc, IDPF_RXD_ERR_S))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* pad skb if needed (to make valid ethernet frame) */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* protocol */
		idpf_rx_singleq_process_skb_fields(rxq, skb, rx_desc, fields.rx_ptype);

		/* send completed skb up the stack */
		napi_gro_receive(&rxq->q_vector->napi, skb);

		/* update budget accounting */
		total_rx_pkts++;
	}

	rxq->next_to_clean = ntc;

	if (cleaned_count)
		failure = idpf_rx_singleq_buf_hw_alloc_zc_all(rxq, cleaned_count);

	idpf_finalize_xdp_rx(xdpq, xdp_xmit);
	rcu_read_unlock();

	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_add(&rxq->q_stats.rx.packets, total_rx_pkts);
	u64_stats_add(&rxq->q_stats.rx.bytes, total_rx_bytes);
	u64_stats_update_end(&rxq->stats_sync);

	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return (int)total_rx_pkts;
	}

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
