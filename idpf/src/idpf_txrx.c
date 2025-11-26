/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "kcompat.h"
#include <linux/timer.h>
#ifdef HAVE_GRO_HEADER
#include <net/gro.h>
#endif /* HAVE_GRO_HEADER */
#include "idpf.h"
#include "idpf_virtchnl.h"
#include "idpf_lan_txrx.h"
#include "idpf_ptp.h"

#ifdef CONFIG_TX_TIMEOUT_VERBOSE
static void idpf_dump_tx_data_flow_desc(struct idpf_queue *txq, u16 i)
{
	union idpf_tx_flex_desc *data_desc = NULL;
	struct idpf_flex_tx_sched_desc *fdesc;
	u8 cmd_dtype;

	data_desc = IDPF_FLEX_TX_DESC(txq, i);
	fdesc = (struct idpf_flex_tx_sched_desc *)data_desc;

	cmd_dtype = fdesc->qw1.cmd_dtype;

	netdev_info(txq->vport->netdev,
		    "data_desc[%03i]: buf_addr = 0x%016llx, dtype = %u, cmd bits %i:%i:%i (eop:cs_en:re), compl_tag = %u, rxr_bufsize = %u\n",
		    i, le64_to_cpu(fdesc->buf_addr),
		    FIELD_GET(IDPF_TXD_FLEX_FLOW_DTYPE_M, cmd_dtype),
		    FIELD_GET(IDPF_TXD_FLEX_FLOW_CMD_EOP, cmd_dtype),
		    FIELD_GET(IDPF_TXD_FLEX_FLOW_CMD_CS_EN, cmd_dtype),
		    FIELD_GET(IDPF_TXD_FLEX_FLOW_CMD_RE, cmd_dtype),
		    le16_to_cpu(fdesc->qw1.compl_tag),
		    le16_to_cpu(fdesc->qw1.rxr_bufsize));
}

/**
 * idpf_dump_tx_state - dump TXQ and TXCOMPQ (if applicable) state
 * @vport: virtual port private structure
 * @txq: pointer to txq struct
 */
static void idpf_dump_tx_state(struct idpf_vport *vport, struct idpf_queue *txq)
{
	struct idpf_tx_queue_stats *txq_stats = &txq->q_stats.tx;
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct idpf_queue *complq = txq->txq_grp->complq;
	struct idpf_adapter *adapter = vport->adapter;
	struct net_device *netdev = vport->netdev;
	struct netdev_queue *nq;
	unsigned int start;
	int i;

	nq = netdev_get_tx_queue(netdev, txq->idx);

	netdev_err(netdev,
		   "Detected tx timeout: %d vport: %d, txq: %d, ntc: %d, ntu: %d, hw_tail: %d\n",
		   adapter->tx_timeout_count, vport->idx, txq->q_id,
		   txq->next_to_clean,
		   txq->next_to_use, readl(txq->tail));

	do {
		start = u64_stats_fetch_begin(&txq->stats_sync);
		netdev_info(netdev,
			    "\t\t Busy events: total: %llu (restarts: %llu), low_txq_desc_avail: %llu, too_many_pending_compls: %llu\n",
			    u64_stats_read(&txq_stats->q_busy),
			    u64_stats_read(&txq_stats->busy_q_restarts),
			    u64_stats_read(&txq_stats->busy_low_txq_descs),
			    u64_stats_read(&txq_stats->busy_too_many_pend_compl));
		netdev_info(netdev,
			    "\t\t Complq clean incomplete: %llu, Rxq clean incomplete: %llu\n",
			    u64_stats_read(&txq_stats->complq_clean_incomplete),
			    u64_stats_read(&txq_stats->sharedrxq_clean_incomplete));
		netdev_info(netdev,
			    "\t\t Bql: num_queued: %u, adj_limit: %u, last_obj_cnt: %u, limit: %u, num_completed: %u\n",
			    nq->dql.num_queued, nq->dql.adj_limit, nq->dql.last_obj_cnt, nq->dql.limit, nq->dql.num_completed);
		netdev_info(netdev,
			    "\t\t Bql: prev_ovlimit: %u, prev_num_queued: %u, prev_last_obj_cnt: %u\n",
			    nq->dql.prev_ovlimit, nq->dql.prev_num_queued, nq->dql.prev_last_obj_cnt);
		netdev_info(netdev,
			    "\t\t Bql: lowest_slack: %u, slack_start_time: %lu, slack_hold_time: %u\n",
			    nq->dql.lowest_slack, nq->dql.slack_start_time, nq->dql.slack_hold_time);
		netdev_info(netdev,
			    "\t\t Bql: max_limit: %u, min_limit: %u\n",
			    nq->dql.max_limit, nq->dql.min_limit);
	} while (u64_stats_fetch_retry(&txq->stats_sync, start));

	for (i = 0; i < txq->desc_count; i++) {
		union idpf_flex_tx_ctx_desc *ctx_desc;
		u16 cmd_dtype, dtype;

		ctx_desc = IDPF_FLEX_TX_CTX_DESC(txq, i);

		cmd_dtype = le16_to_cpu(ctx_desc->tso.qw1.cmd_dtype);
		dtype = FIELD_GET(IDPF_FLEX_TXD_QW1_DTYPE_M, cmd_dtype);
		if (dtype == IDPF_TX_DESC_DTYPE_FLEX_TSO_CTX) {
			netdev_info(netdev,
				    "tso_ctx_desc[%03i]: dtype = %u, tso = %lu, tso_len = %u, mss_rt = %u, hdr_len = %u\n",
				    i, dtype,
				    FIELD_GET(IDPF_FLEX_TXD_QW1_DTYPE_M, cmd_dtype),
				    le32_to_cpu(ctx_desc->tso.qw0.flex_tlen),
				    le16_to_cpu(ctx_desc->tso.qw0.mss_rt),
				    ctx_desc->tso.qw0.hdr_len);
		} else if (dtype == IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE) {
			idpf_dump_tx_data_flow_desc(txq, i);
		} else {
			netdev_info(netdev, "desc[%03i]: unsupported desc type\n", i);
		}

	}

	if (!idpf_is_queue_model_split(q_grp->txq_model))
		return;

	for (i = 0; i < complq->desc_count; i++) {
		struct idpf_splitq_tx_compl_desc *complq_desc;
		u16 qid_comptype_gen, q_head_compl_tag;

		complq_desc = IDPF_SPLITQ_TX_COMPLQ_DESC(complq, i);
		qid_comptype_gen = le16_to_cpu(complq_desc->qid_comptype_gen);
		q_head_compl_tag = le16_to_cpu(complq_desc->q_head_compl_tag.compl_tag);

		netdev_info(netdev,
			    "cq_desc[%03i]: gen = %llu, ctype = %llu, qid = %llu, q_head_compl_tag = %u\n",
			    i, (qid_comptype_gen & IDPF_TXD_COMPLQ_GEN_M) >> IDPF_TXD_COMPLQ_GEN_S,
			    (qid_comptype_gen & IDPF_TXD_COMPLQ_COMPL_TYPE_M) >> IDPF_TXD_COMPLQ_COMPL_TYPE_S,
			    (qid_comptype_gen & IDPF_TXD_COMPLQ_QID_M) >> IDPF_TXD_COMPLQ_QID_S,
			    q_head_compl_tag);
	}

	netdev_err(netdev,
		   "txcomplq[%d]: ntc: %d, pending_compls: %u\n",
		   complq->q_id, complq->next_to_clean,
		   IDPF_TX_COMPLQ_PENDING(txq->txq_grp));
}

#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
/**
 * idpf_chk_linearize - Check if skb exceeds max descriptors per packet
 * @skb: send buffer
 * @max_bufs: maximum scatter gather buffers for single packet
 * @count: number of buffers this packet needs
 *
 * Make sure we don't exceed maximum scatter gather buffers for a single
 * packet.
 * TSO case has been handled earlier from idpf_features_check().
 */
static bool idpf_chk_linearize(const struct sk_buff *skb,
			       unsigned int max_bufs,
			       unsigned int count)
{
	if (likely(count <= max_bufs))
		return false;

	if (skb_is_gso(skb))
		return false;

	return true;
}

/**
 * idpf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: TX queue
 */
#ifdef HAVE_TX_TIMEOUT_TXQUEUE
void idpf_tx_timeout(struct net_device *netdev, unsigned int txqueue)
#else
void idpf_tx_timeout(struct net_device *netdev)
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
#ifndef HAVE_TX_TIMEOUT_TXQUEUE
	int i;
#endif /* !HAVE_TX_TIMEOUT_TXQUEUE */
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */

	adapter->tx_timeout_count++;

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
	netdev_err(netdev, "Detected Tx timeout: Count %d, Queue: %d\n",
		   adapter->tx_timeout_count, txqueue);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	idpf_dump_tx_state(vport, vport->txqs[txqueue]);
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
#else
	netdev_err(netdev, "Detected Tx timeout: Count %d\n",
		   adapter->tx_timeout_count);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	for (i = 0; i < vport->dflt_grp.q_grp.num_txq; i++)
		idpf_dump_tx_state(vport, vport->txqs[i]);
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
	if (!idpf_is_reset_in_prog(adapter)) {
		set_bit(IDPF_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}
}

/**
 * idpf_tx_buf_rel_all - Free any empty Tx buffers
 * @txq: queue to be cleaned
 */
static void idpf_tx_buf_rel_all(struct idpf_queue *txq)
{
	struct libeth_sq_napi_stats ss = { };
	struct libeth_cq_pp cp = {
		.dev	= txq->dev,
		.ss	= &ss,
	};
	u32 i;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (idpf_queue_has(XDP, txq) && txq->xsk_pool) {
		idpf_xsk_cleanup_xdpq(txq);
		return;
	}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	/* Buffers already cleared, nothing to do */
	if (!txq->tx.bufs)
		return;

	/* Free all the Tx buffer sk_buffs */
	for (i = 0; i < txq->buf_pool_size; i++)
		libeth_tx_complete(&txq->tx.bufs[i], &cp);

	kfree(txq->tx.bufs);
	txq->tx.bufs = NULL;
}

/**
 * idpf_tx_desc_rel - Free Tx resources per queue
 * @txq: Tx descriptor ring for a specific queue
 * @bufq: buffer q or completion q
 *
 * Free all transmit software resources
 */
static void idpf_tx_desc_rel(struct idpf_queue *txq, bool bufq)
{
	if (!txq)
		return;

	if (bufq) {
		idpf_tx_buf_rel_all(txq);
#ifdef HAVE_XDP_SUPPORT

		if (!idpf_queue_has(XDP, txq))
			netdev_tx_reset_queue(netdev_get_tx_queue(txq->vport->netdev,
								  txq->idx));
#elif
		netdev_tx_reset_queue(netdev_get_tx_queue(txq->vport->netdev,
							  txq->idx));
#endif /* HAVE_XDP_SUPPORT */
	}

	if (!txq->desc_ring)
		return;

	if (txq->tx.refillq)
		kfree(txq->tx.refillq->ring);

	dmam_free_coherent(txq->dev, txq->size, txq->desc_ring, txq->dma);
	txq->desc_ring = NULL;
	txq->next_to_alloc = 0;
	txq->next_to_use = 0;
	txq->next_to_clean = 0;
}

/**
 * idpf_tx_desc_rel_all - Free Tx Resources for All Queues
 * @q_grp: Queue resources
 *
 * Free all transmit software resources
 */
static void idpf_tx_desc_rel_all(struct idpf_q_grp *q_grp)
{
	int i, j;

	if (!q_grp->txq_grps)
		return;

	for (i = 0; i < q_grp->num_txq_grp; i++) {
		struct idpf_txq_group *txq_grp = &q_grp->txq_grps[i];

		for (j = 0; j < txq_grp->num_txq; j++)
			idpf_tx_desc_rel(txq_grp->txqs[j], true);

		if (idpf_is_queue_model_split(q_grp->txq_model))
			idpf_tx_desc_rel(txq_grp->complq, false);
	}
}

/**
 * idpf_tx_buf_alloc_all - Allocate memory for all buffer resources
 * @tx_q: queue for which the buffers are allocated
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_tx_buf_alloc_all(struct idpf_queue *tx_q)
{
	/* Allocate book keeping buffers only. Buffers to be supplied to HW
	 * are allocated by kernel network stack and received as part of skb
	 */
	if (idpf_queue_has(FLOW_SCH_EN, tx_q)) {
		if (idpf_is_cap_ena(tx_q->vport->adapter, IDPF_OTHER_CAPS,
				    VIRTCHNL2_CAP_MISS_COMPL_TAG))
			/* We lose the upper bit of the completion tag when
			 * MISS bit is enabled, thus reducing our pool size.
			 */
			tx_q->buf_pool_size = U16_MAX >> 1;
		else
			tx_q->buf_pool_size = U16_MAX;
	} else {
		tx_q->buf_pool_size = tx_q->desc_count;
	}
	tx_q->tx.bufs = kcalloc(tx_q->buf_pool_size, sizeof(*tx_q->tx.bufs),
				GFP_KERNEL);
	if (!tx_q->tx.bufs)
		return -ENOMEM;

	return 0;
}

/**
 * idpf_tx_desc_alloc - Allocate the Tx descriptors
 * @tx_q: the tx ring to set up
 * @bufq: buffer or completion queue
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_tx_desc_alloc(struct idpf_queue *tx_q, bool bufq)
{
	struct device *dev = tx_q->dev;
	struct idpf_sw_queue *refillq;
	u32 desc_sz, i;
	int err;

	if (bufq) {
		err = idpf_tx_buf_alloc_all(tx_q);
		if (err)
			goto err_alloc;

		desc_sz = sizeof(struct idpf_base_tx_desc);
	} else {
		desc_sz = sizeof(struct idpf_splitq_tx_compl_desc);
	}

	tx_q->size = tx_q->desc_count * desc_sz;

	/* Allocate descriptors also round up to nearest 4K */
	tx_q->size = ALIGN(tx_q->size, 4096);
	tx_q->desc_ring = dmam_alloc_coherent(dev, tx_q->size, &tx_q->dma,
					      GFP_KERNEL);
	if (!tx_q->desc_ring) {
		dev_err(dev, "Unable to allocate memory for the Tx descriptor ring, size=%d\n",
			tx_q->size);
		err = -ENOMEM;
		goto err_alloc;
	}

	tx_q->next_to_alloc = 0;
	tx_q->next_to_use = 0;
	tx_q->next_to_clean = 0;
	idpf_queue_set(GEN_CHK, tx_q);

	if (!idpf_queue_has(FLOW_SCH_EN, tx_q) || !bufq)
		return 0;

	refillq = tx_q->tx.refillq;
	refillq->desc_count = tx_q->buf_pool_size;
	refillq->ring = kcalloc(refillq->desc_count, sizeof(u32), GFP_KERNEL);
	if (!refillq->ring) {
		err = -ENOMEM;
		goto err_alloc;
	}

	for (i = 0; i < refillq->desc_count; i++)
		refillq->ring[i] =
			FIELD_PREP(IDPF_RFL_BI_BUFID_M, i) |
			FIELD_PREP(IDPF_RFL_BI_GEN_M,
				   idpf_queue_has(GEN_CHK, refillq));

	/* Go ahead and flip the GEN bit since this counts as filling
	 * up the ring, i.e. we already ring wrapped.
	 */
	idpf_queue_change(GEN_CHK, refillq);

	tx_q->tx.last_re = tx_q->desc_count - IDPF_TX_SPLITQ_RE_MIN_GAP;

	return 0;

err_alloc:
	idpf_tx_desc_rel(tx_q, bufq);

	return err;
}

/**
 * idpf_tx_desc_alloc_all - allocate all queues TX resources
 * @vport: virtual port private structure
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_tx_desc_alloc_all(struct idpf_vport *vport,
				  struct idpf_q_grp *q_grp)
{
	bool is_splitq = idpf_is_queue_model_split(q_grp->txq_model);
	int err = 0;
	int i, j;

	/* Setup buffer queues. In single queue model buffer queues and
	 * completion queues will be same.
	 */
	for (i = 0; i < q_grp->num_txq_grp; i++) {
		for (j = 0; j < q_grp->txq_grps[i].num_txq; j++) {
			struct idpf_queue *txq = q_grp->txq_grps[i].txqs[j];

			err = idpf_tx_desc_alloc(txq, true);
			if (err)
				return err;
		}

		if (!is_splitq)
			continue;

		err = idpf_tx_desc_alloc(q_grp->txq_grps[i].complq, false);
		if (err)
			return err;
	}

	return 0;
}

/**
 * idpf_rx_page_rel - Release an rx buffer page
 * @rxq: the queue that owns the buffer
 * @pinfo: pointer to page metadata of page to be freed
 */
static void idpf_rx_page_rel(struct idpf_queue *rxq,
			     struct idpf_page_info *pinfo)
{
	if (unlikely(!pinfo->page))
		return;

#ifndef HAVE_STRUCT_DMA_ATTRS
	dma_unmap_page_attrs(rxq->dev, pinfo->dma, PAGE_SIZE,
			     DMA_FROM_DEVICE, IDPF_RX_DMA_ATTR);
#else
	dma_unmap_page(rxq->dev, pinfo->dma, PAGE_SIZE,
		       DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */
	__page_frag_cache_drain(pinfo->page, pinfo->pagecnt_bias);

	pinfo->page = NULL;
	pinfo->page_offset = 0;
}

/**
 * idpf_rx_buf_rel - Release a rx buffer
 * @q: Queue that owns the buffer
 * @rx_buf: Buffer to free
 */
static void idpf_rx_buf_rel(struct idpf_queue *q,
			    struct idpf_rx_buf *rx_buf)
{
	idpf_rx_page_rel(q, &rx_buf->page_info[0]);
	if (PAGE_SIZE < 8192 && rx_buf->buf_size > IDPF_RX_BUF_2048)
		idpf_rx_page_rel(q, &rx_buf->page_info[1]);

	if (rx_buf->skb) {
		dev_kfree_skb(rx_buf->skb);
		rx_buf->skb = NULL;
	}
}

/**
 * idpf_rx_hdr_buf_rel - Release header buffer memory
 * @rxq: Queue to use
 */
static void idpf_rx_hdr_buf_rel(struct idpf_queue *rxq)
{
	struct idpf_adapter *adapter;

	adapter = rxq->vport->adapter;
	dma_free_coherent(idpf_adapter_to_dev(adapter),
			  rxq->desc_count * IDPF_HDR_BUF_SIZE,
			  rxq->rx.hdr_buf_va,
			  rxq->rx.hdr_buf_pa);
	rxq->rx.hdr_buf_va = NULL;
}

/**
 * idpf_rx_buf_rel_all - Free all Rx buffer resources for a queue
 * @q: Queue to be cleaned
 */
static void idpf_rx_buf_rel_all(struct idpf_queue *q)
{
	u16 i;

	/* queue already cleared, nothing to do */
	if (!q->rx.bufs)
		return;

	/* Free all the bufs allocated and given to hw on Rx queue */
	for (i = 0; i < q->desc_count; i++)
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (q->xsk_pool)
			idpf_rx_buf_rel_zc(&q->rx.bufs[i]);
		else
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
			idpf_rx_buf_rel(q, &q->rx.bufs[i]);

	if (q->rx.hdr_buf_va)
		idpf_rx_hdr_buf_rel(q);

	kfree(q->rx.bufs);
	q->rx.bufs = NULL;
}

/**
 * idpf_rx_buf_hw_update - Store the new tail and head values
 * @rxq: queue to bump
 * @val: new head index
 */
void idpf_rx_buf_hw_update(struct idpf_queue *rxq, u32 val)
{
	rxq->next_to_use = val;

	if (unlikely(!rxq->tail))
		return;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	writel(val, rxq->tail);
}

/**
 * idpf_alloc_page - Allocate page to back RX buffer
 * @dev: Device handle for alloc ownership
 * @pinfo: Pointer to page metadata struct
 */
int idpf_alloc_page(struct device *dev, struct idpf_page_info *pinfo)
{
	pinfo->page = alloc_page(GFP_ATOMIC);
	if (unlikely(!pinfo->page))
		return -ENOMEM;

#ifndef HAVE_STRUCT_DMA_ATTRS
	pinfo->dma = dma_map_page_attrs(dev, pinfo->page,
					0, PAGE_SIZE, DMA_FROM_DEVICE,
					IDPF_RX_DMA_ATTR);
#else
	pinfo->dma = dma_map_page(dev, pinfo->page, 0, PAGE_SIZE,
				  DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */
	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(dev, pinfo->dma)) {
		__free_pages(pinfo->page, 0);

		return -ENOMEM;
	}

	pinfo->page_offset = pinfo->default_offset;

	/* initialize pagecnt_bias to claim we fully own page */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	page_ref_add(pinfo->page, USHRT_MAX - 1);
	pinfo->pagecnt_bias = USHRT_MAX;
#else
	pinfo->pagecnt_bias = 1;
#endif /* HAVE_PAGE_COUNT_BULK_UPDATE */

	return 0;
}

/**
 * idpf_rx_hdr_buf_alloc - Allocate memory for header buffers
 * @rxq: Ring to use
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_rx_hdr_buf_alloc(struct idpf_queue *rxq)
{
	struct idpf_adapter *adapter = rxq->vport->adapter;

	rxq->rx.hdr_buf_va =
		dma_alloc_coherent(idpf_adapter_to_dev(adapter),
				   IDPF_HDR_BUF_SIZE * rxq->desc_count,
				   &rxq->rx.hdr_buf_pa,
				   GFP_KERNEL);
	if (!rxq->rx.hdr_buf_va)
		return -ENOMEM;

	return 0;
}

/**
 * idpf_post_buf_refill - Post buffer id to refill queue
 * @refillq: refill queue to post to
 * @buf_id: buffer id to post
 */
void idpf_post_buf_refill(struct idpf_sw_queue *refillq, u16 buf_id)
{
	u32 nta = refillq->next_to_use;

	/* store the buffer ID and the SW maintained GEN bit to the refillq */
	refillq->ring[nta] =
		FIELD_PREP(IDPF_RFL_BI_BUFID_M, buf_id) |
		FIELD_PREP(IDPF_RFL_BI_GEN_M,
			   idpf_queue_has(GEN_CHK, refillq));

	if (unlikely(++nta == refillq->desc_count)) {
		nta = 0;
		idpf_queue_change(GEN_CHK, refillq);
	}
	refillq->next_to_use = nta;
}

/**
 * idpf_rx_post_buf_desc - Post buffer to bufq descriptor ring
 * @bufq: buffer queue to post to
 * @buf_id: buffer id to post
 */
static void idpf_rx_post_buf_desc(struct idpf_queue *bufq, u16 buf_id)
{
	struct virtchnl2_splitq_rx_buf_desc *splitq_rx_desc = NULL;
	u16 nta = bufq->next_to_alloc;
	struct idpf_page_info *pinfo;
	struct idpf_rx_buf *buf;
	dma_addr_t addr;
	u32 offset;

	splitq_rx_desc = IDPF_SPLITQ_RX_BUF_DESC(bufq, nta);

	if (bufq->rx_hsplit_en) {
		splitq_rx_desc->hdr_addr =
			cpu_to_le64(bufq->rx.hdr_buf_pa +
				    (u32)buf_id * IDPF_HDR_BUF_SIZE);
	}

	buf = &bufq->rx.bufs[buf_id];
	pinfo = &buf->page_info[buf->page_indx];
	offset = pinfo->page_offset - pinfo->default_offset;
	dma_sync_single_range_for_device(bufq->dev, pinfo->dma, offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);

	addr = pinfo->dma + pinfo->page_offset;

	splitq_rx_desc->pkt_addr = cpu_to_le64(addr);
	splitq_rx_desc->qword0.buf_id = cpu_to_le16(buf_id);

	nta++;
	if (unlikely(nta == bufq->desc_count))
		nta = 0;
	bufq->next_to_alloc = nta;
}

/**
 * idpf_rx_post_init_bufs - Post initial buffers to bufq
 * @bufq: buffer queue to post working set to
 * @working_set: number of buffers to put in working set
 */
static void idpf_rx_post_init_bufs(struct idpf_queue *bufq,
				   u16 working_set)
{
	int i;

	for (i = 0; i < working_set; i++)
		idpf_rx_post_buf_desc(bufq, i);

	idpf_rx_buf_hw_update(bufq, ALIGN_DOWN(bufq->next_to_alloc,
					       bufq->rx_buf_stride));
}

/**
 * idpf_rx_buf_hw_alloc - Allocate buffers to be given to HW
 * @q: Queue to allocate buffers for, could be RX queue or buffer queue
 *     depending on queueing model
 * @is_splitq: True if RX queue model split
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_rx_buf_hw_alloc(struct idpf_queue *q, bool is_splitq)
{
	int num_bufs = q->desc_count - 1;
	int i, err;

	if (!is_splitq)
		return idpf_rx_singleq_buf_hw_alloc_all(q, num_bufs);

	for (i = 0; i < num_bufs; i++) {
		struct idpf_rx_buf *buf = &q->rx.bufs[i];

		if (idpf_xdp_is_prog_ena(q->vport))
			buf->page_info[0].default_offset = XDP_PACKET_HEADROOM;

		err = idpf_alloc_page(q->dev, &buf->page_info[0]);
		if (err)
			return err;

		buf->page_indx = 0;
		buf->buf_size = q->rx_buf_size;

		if (PAGE_SIZE >= 8192)
			continue;

		if (q->rx_buf_size > IDPF_RX_BUF_2048) {
			if (idpf_xdp_is_prog_ena(q->vport))
				buf->page_info[1].default_offset =
					XDP_PACKET_HEADROOM;
			/* For 4K buffers, we can reuse the page if there are
			 * no other owners, i.e. reuse_bias = 0. Since the
			 * memory is initialized to 0, both page_info's
			 * reuse_bias is already set appropriately.
			 */
			err = idpf_alloc_page(q->dev, &buf->page_info[1]);
			if (err)
				return err;
		} else {
			/* For 2K buffers, we can reuse the page if we are the
			 * only owner, i.e. reuse_bias = 1.
			 */
			buf->page_info[0].reuse_bias = 1;
		}
	}

	idpf_rx_post_init_bufs(q, IDPF_RX_BUFQ_WORKING_SET(q));

	return 0;
}

/**
 * idpf_rx_buf_alloc - Allocate buffers for a queue
 * @q: Queue to allocate for
 * @is_splitq: True if RX queue model split
 */
static int idpf_rx_buf_alloc(struct idpf_queue *q, bool is_splitq)
{
	int err;

	/* bookkeeping ring to contain the actual buffers */
	q->rx.bufs = kcalloc(q->desc_count, sizeof(struct idpf_rx_buf),
			     GFP_KERNEL);
	if (!q->rx.bufs)
		return -ENOMEM;

	if (q->rx_hsplit_en) {
		err = idpf_rx_hdr_buf_alloc(q);
		if (err)
			return err;
	}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	/* This function can be called before the vport is actually stopped,
	 * so do not perform AF_XDP allocation to avoid breaking consistency
	 * of AF_XDP data structures in bpf.
	 * The initialization of AF_XDP is contained in 'idpf_vport_xdp_init()'.
	 */
	if (idpf_xsk_is_zc_bufq(q)) {
		idpf_rx_post_init_bufs(q, IDPF_RX_BUFQ_WORKING_SET(q));
		return 0;
	}

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	err = idpf_rx_buf_hw_alloc(q, is_splitq);
	if (err)
		return err;

	return 0;
}

/**
 * idpf_fast_path_txq_init - Initialize TX queue array for the fast path access
 * @vport: Vport structure
 * @q_grp: Queue resources
 *
 * Instead of multiple indirections to dereference the TX queues from the
 * queue resource group, maintain a copy of the queue pointers in the vport
 * structure to dereference the queue quickly in the fast path.
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_fast_path_txq_init(struct idpf_vport *vport,
				   struct idpf_q_grp *q_grp)
{
	struct idpf_ptp_vport_tx_tstamp_caps *caps = vport->tx_tstamp_caps;
	struct work_struct *tstamp_task = &vport->tstamp_task;
	int i, j, k = 0;

	vport->txqs = kcalloc(q_grp->num_txq, sizeof(struct idpf_queue *),
			      GFP_KERNEL);
	if (!vport->txqs)
		return -ENOMEM;

	vport->num_txq = q_grp->num_txq;
	for (i = 0; i < q_grp->num_txq_grp; i++) {
		struct idpf_txq_group *tx_grp = &q_grp->txq_grps[i];

		for (j = 0; j < tx_grp->num_txq; j++, k++) {
			vport->txqs[k] = tx_grp->txqs[j];
			vport->txqs[k]->idx = k;

			if (!caps)
				continue;

			vport->txqs[i]->cached_tstamp_caps = caps;
			vport->txqs[i]->tstamp_task = tstamp_task;
		}
	}

	return 0;
}

/**
 * idpf_init_cached_phc_time - Initialize cached PHC time used to extend Tx/Rx
 *			       timestamp value
 * @vport: Vport structure
 * @q_grp: Queue resources
 *
 * Initialize cached PHC time, updated periodically in ptp structure, in Tx and
 * Rx queue to provide a quick and efficient access to these values when the
 * Tx/Rx timestamp are extended to 64 bit.
 */
static void idpf_init_cached_phc_time(struct idpf_vport *vport,
				      struct idpf_q_grp *q_grp)
{
	bool is_splitq = idpf_is_queue_model_split(q_grp->rxq_model);
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_ptp *ptp = adapter->ptp;
	u16 i, j;

	if (!ptp)
		return;

	if (ptp->get_dev_clk_time_access == IDPF_PTP_NONE)
		return;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		struct idpf_rxq_group *rxq_grp = &q_grp->rxq_grps[i];
		u16 num_rxq;

		num_rxq = is_splitq ? rxq_grp->splitq.num_rxq_sets :
				      rxq_grp->singleq.num_rxq;
		for (j = 0; j < num_rxq; j++) {
			struct idpf_queue *q;

			q = is_splitq ? &rxq_grp->splitq.rxq_sets[j]->rxq :
					rxq_grp->singleq.rxqs[j];
			q->cached_phc_time = &ptp->cached_phc_time;
		}
	}

	for (i = 0; i < q_grp->num_txq_grp; i++) {
		struct idpf_txq_group *txq_grp = &q_grp->txq_grps[i];

		for (j = 0; j < txq_grp->num_txq; j++)
			txq_grp->txqs[j]->cached_phc_time = &ptp->cached_phc_time;
	}
}

/**
 * idpf_rx_map_buffer_rings - Link RX buffer ring pointers to buffer rings
 * @q_grp: Queue resources
 *
 * In split queue model, the buffer queues own and manage the actual buffers
 * but RX queues still need a way to get buffers to make an skb on receive.
 * This links the buffer rings in buffer queues to RX queues.
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_rx_map_buffer_rings(struct idpf_q_grp *q_grp)
{
	int i, j, m;

	for (m = 0; m < q_grp->num_rxq_grp; m++) {
		struct idpf_rxq_group *rx_qgrp = &q_grp->rxq_grps[m];

		for (i = 0; i < rx_qgrp->splitq.num_rxq_sets; i++) {
			struct idpf_queue *rxq = &rx_qgrp->splitq.rxq_sets[i]->rxq;

			rxq->rx.bufq_bufs = kcalloc(q_grp->num_bufqs_per_qgrp,
						    sizeof(struct idpf_rx_buf *),
						    GFP_KERNEL);
			if (!rxq->rx.bufq_bufs)
				return -ENOMEM;

			if (rxq->rx_hsplit_en) {
				rxq->rx.bufq_hdr_bufs = kcalloc(q_grp->num_bufqs_per_qgrp,
								sizeof(void *),
								GFP_KERNEL);
				if (!rxq->rx.bufq_hdr_bufs)
					return -ENOMEM;
			}

			for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
				struct idpf_queue *bufq = &rx_qgrp->splitq.bufq_sets[j].bufq;
				u32 k;

				rxq->rx.bufq_bufs[j] = bufq->rx.bufs;

				if (!rxq->rx_hsplit_en)
					continue;

				rxq->rx.bufq_hdr_bufs[j] = kcalloc(bufq->desc_count,
								   sizeof(*rxq->rx.bufq_hdr_bufs[j]),
								   GFP_KERNEL);
				if (!rxq->rx.bufq_hdr_bufs[j])
					return -ENOMEM;

				for (k = 0; k < bufq->desc_count; k++)
					rxq->rx.bufq_hdr_bufs[j][k] =
						(u64)bufq->rx.hdr_buf_va + k * IDPF_HDR_BUF_SIZE;
			}
		}
	}

	return 0;
}

/**
 * idpf_rx_bufs_init_all - Initialize all RX bufs
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_rx_bufs_init_all(struct idpf_q_grp *q_grp)
{
	bool split = idpf_is_queue_model_split(q_grp->rxq_model);
	int i, j, err;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &q_grp->rxq_grps[i];

		/* Allocate bufs for the rxq itself in singleq */
		if (!split) {
			int num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq; j++) {
				struct idpf_queue *q;

				q = rx_qgrp->singleq.rxqs[j];
				err = idpf_rx_buf_alloc(q, false);
				if (err)
					return err;
			}

			continue;
		}

		/* Otherwise, allocate bufs for the buffer queues */
		for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
			struct idpf_queue *q;

			q = &rx_qgrp->splitq.bufq_sets[j].bufq;

			err = idpf_rx_buf_alloc(q, true);
			if (err)
				return err;
		}
	}

	if (idpf_is_queue_model_split(q_grp->rxq_model)) {
		err = idpf_rx_map_buffer_rings(q_grp);
		if (err)
			return err;
	}

	return 0;
}

/**
 * idpf_rx_desc_alloc - Allocate descriptors for an RX queue/buffer queue
 * @q: Queue to allocate for
 * @is_bufq: True if this is a buffer queue
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rx_desc_alloc(struct idpf_queue *q, bool is_bufq)
{
	q->size = q->desc_count * (is_bufq ?
		  sizeof(struct virtchnl2_splitq_rx_buf_desc) :
		  sizeof(union virtchnl2_rx_desc));

	/* Needs to be aligned to 4K for HW */
	q->size = ALIGN(q->size, SZ_4K);
	q->desc_ring = dma_alloc_coherent(q->dev, q->size, &q->dma,
					  GFP_KERNEL);
	if (!q->desc_ring)
		return -ENOMEM;

	return 0;
}

/**
 * idpf_txq_group_rel - Release all resources for txq groups
 * @q_grp: Queue resources
 */
static void idpf_txq_group_rel(struct idpf_q_grp *q_grp)
{
	bool split;
	int i, j;

	if (!q_grp->txq_grps)
		return;

	split = idpf_is_queue_model_split(q_grp->txq_model);

	for (i = 0; i < q_grp->num_txq_grp; i++) {
		struct idpf_txq_group *txq_grp = &q_grp->txq_grps[i];

		for (j = 0; j < txq_grp->num_txq; j++) {
			if (!txq_grp->txqs[j])
				continue;

			if (txq_grp->txqs[j]->tx.refillq) {
				kfree(txq_grp->txqs[j]->tx.refillq);
				txq_grp->txqs[j]->tx.refillq = NULL;
			}

			xa_destroy(&txq_grp->txqs[j]->reinject_timers);

			kfree(txq_grp->txqs[j]);
			txq_grp->txqs[j] = NULL;
		}

		kfree(txq_grp->txqs);
		txq_grp->txqs = NULL;

		if (!split)
			continue;

		kfree(txq_grp->complq);
		txq_grp->complq = NULL;
	}
	kfree(q_grp->txq_grps);
	q_grp->txq_grps = NULL;
}

/**
 * idpf_rxq_rel - Release resources for RX queue
 * @q_grp: Queue resources
 * @rxq: RX queue to release resources on
 */
static void idpf_rxq_rel(struct idpf_q_grp *q_grp, struct idpf_queue *rxq)
{
	int i;

	if (rxq->desc_ring) {
		dma_free_coherent(rxq->dev, rxq->size, rxq->desc_ring,
				  rxq->dma);
		rxq->desc_ring = NULL;
	}

	if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
		idpf_rx_buf_rel_all(rxq);

		return;
	}

	for (i = 0; i < q_grp->num_bufqs_per_qgrp; i++) {
		if (!rxq->rx.bufq_hdr_bufs)
			break;

		kfree(rxq->rx.bufq_hdr_bufs[i]);
		rxq->rx.bufq_hdr_bufs[i] = NULL;
	}
	kfree(rxq->rx.bufq_hdr_bufs);
	rxq->rx.bufq_hdr_bufs = NULL;
	kfree(rxq->rx.bufq_bufs);
	rxq->rx.bufq_bufs = NULL;
}

/**
 * idpf_bufq_rel - Release resources for buffer queue
 * @bufq: Buffer queue to release resources on
 */
static void idpf_bufq_rel(struct idpf_queue *bufq)
{
	if (!bufq)
		return;

	idpf_rx_buf_rel_all(bufq);

	if (!bufq->desc_ring)
		return;
	dma_free_coherent(bufq->dev, bufq->size, bufq->desc_ring,
			  bufq->dma);
	bufq->desc_ring = NULL;
}

/**
 * idpf_rx_desc_rel_all - Free Rx Resources for All Queues
 * @q_grp: Queue resources
 *
 * Free all rx queues resources
 */
static void idpf_rx_desc_rel_all(struct idpf_q_grp *q_grp)
{
	struct idpf_rxq_group *rx_qgrp;
	u16 num_rxq;
	int i, j;

	if (!q_grp->rxq_grps)
		return;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		rx_qgrp = &q_grp->rxq_grps[i];

		if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
			for (j = 0; j < rx_qgrp->singleq.num_rxq; j++)
				idpf_rxq_rel(q_grp, rx_qgrp->singleq.rxqs[j]);

			continue;
		}

		num_rxq = rx_qgrp->splitq.num_rxq_sets;
		for (j = 0; j < num_rxq; j++) {
			idpf_rxq_rel(q_grp, &rx_qgrp->splitq.rxq_sets[j]->rxq);
#ifdef HAVE_XDP_BUFF_RXQ

			if (xdp_rxq_info_is_reg(&rx_qgrp->splitq.rxq_sets[j]->rxq.xdp_rxq))
				xdp_rxq_info_unreg(&rx_qgrp->splitq.rxq_sets[j]->rxq.xdp_rxq);
#endif /* HAVE_XDP_BUFF_RXQ */
		}

		if (!rx_qgrp->splitq.bufq_sets)
			continue;

		for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
			struct idpf_bufq_set *bufq_set =
				&rx_qgrp->splitq.bufq_sets[j];

			idpf_bufq_rel(&bufq_set->bufq);
		}
	}
}

/**
 * idpf_rx_desc_alloc_all - allocate all RX queues resources
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rx_desc_alloc_all(struct idpf_q_grp *q_grp)
{
	struct idpf_rxq_group *rx_qgrp;
	int i, j, err;
	u16 num_rxq;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		rx_qgrp = &q_grp->rxq_grps[i];
		if (idpf_is_queue_model_split(q_grp->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			struct idpf_queue *q;

			if (idpf_is_queue_model_split(q_grp->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];

			err = idpf_rx_desc_alloc(q, false);
			if (err) {
				pci_err(rx_qgrp->vport->adapter->pdev,
					"Memory allocation for Rx queue %u from queue group %u failed\n",
					j, i);
				goto err_out;
			}
		}

		if (!idpf_is_queue_model_split(q_grp->rxq_model))
			continue;

		for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
			struct idpf_queue *q;

			q = &rx_qgrp->splitq.bufq_sets[j].bufq;

			err = idpf_rx_desc_alloc(q, true);
			if (err) {
				pci_err(rx_qgrp->vport->adapter->pdev,
					"Memory allocation for Rx Buffer Queue %u from queue group %u failed\n",
					j, i);
				goto err_out;
			}
		}
	}

	return 0;

err_out:
	idpf_rx_desc_rel_all(q_grp);

	return err;
}

/**
 * idpf_rxq_sw_queue_rel - Release software queue resources
 * @q_grp: Queue resources
 * @rx_qgrp: rx queue group with software queues
 */
static void idpf_rxq_sw_queue_rel(struct idpf_q_grp *q_grp, struct idpf_rxq_group *rx_qgrp)
{
	int i, j;

	for (i = 0; i < q_grp->num_bufqs_per_qgrp; i++) {
		struct idpf_bufq_set *bufq_set = &rx_qgrp->splitq.bufq_sets[i];

		for (j = 0; j < bufq_set->num_refillqs; j++) {
			kfree(bufq_set->refillqs[j].ring);
			bufq_set->refillqs[j].ring = NULL;
		}
		kfree(bufq_set->refillqs);
		bufq_set->refillqs = NULL;
	}
}

/**
 * idpf_rxq_group_rel - Release all resources for rxq groups
 * @q_grp: Queue resources
 */
static void idpf_rxq_group_rel(struct idpf_q_grp *q_grp)
{
	int i;

	if (!q_grp->rxq_grps)
		return;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &q_grp->rxq_grps[i];
		u16 num_rxq;
		int j;

		if (idpf_is_queue_model_split(q_grp->rxq_model)) {
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
			for (j = 0; j < num_rxq; j++) {
				kfree(rx_qgrp->splitq.rxq_sets[j]);
				rx_qgrp->splitq.rxq_sets[j] = NULL;
			}

			idpf_rxq_sw_queue_rel(q_grp, rx_qgrp);
			kfree(rx_qgrp->splitq.bufq_sets);
			rx_qgrp->splitq.bufq_sets = NULL;
		} else {
			num_rxq = rx_qgrp->singleq.num_rxq;
			for (j = 0; j < num_rxq; j++) {
				kfree(rx_qgrp->singleq.rxqs[j]);
				rx_qgrp->singleq.rxqs[j] = NULL;
			}
		}
	}
	kfree(q_grp->rxq_grps);
	q_grp->rxq_grps = NULL;
}

/**
 * idpf_vport_queue_grp_rel_all - Release all queue groups
 * @q_grp: Queue resources
 */
static void idpf_vport_queue_grp_rel_all(struct idpf_q_grp *q_grp)
{
	idpf_txq_group_rel(q_grp);
	idpf_rxq_group_rel(q_grp);
}

/**
 * idpf_vport_queues_rel - Free memory for all queues
 * @vport: virtual port
 * @q_grp: Queue resources
 *
 * Free the memory allocated for queues associated to a vport
 */
void idpf_vport_queues_rel(struct idpf_vport *vport,
			   struct idpf_q_grp *q_grp)
{
	idpf_tx_desc_rel_all(q_grp);
	idpf_rx_desc_rel_all(q_grp);

	idpf_vport_queue_grp_rel_all(q_grp);

	kfree(vport->txqs);
	vport->txqs = NULL;
}

/**
 * idpf_vport_init_num_qs - Initialize number of queues
 * @vport: vport to initialize queues
 * @vport_msg: data to be filled into vport
 * @q_grp: Queue resources
 */
void idpf_vport_init_num_qs(struct idpf_vport *vport,
			    struct virtchnl2_create_vport *vport_msg,
			    struct idpf_q_grp *q_grp)
{
	struct idpf_vport_user_config_data *config_data;
	u16 idx = vport->idx;

	config_data = &vport->adapter->vport_config[idx]->user_config;
	q_grp->num_txq = le16_to_cpu(vport_msg->num_tx_q);
	q_grp->num_rxq = le16_to_cpu(vport_msg->num_rx_q);
	/* number of txqs and rxqs in config data will be zeros only in the
	 * driver load path and we dont update them there after
	 */
	if (!config_data->num_req_tx_qs && !config_data->num_req_rx_qs) {
		config_data->num_req_tx_qs = le16_to_cpu(vport_msg->num_tx_q);
		config_data->num_req_rx_qs = le16_to_cpu(vport_msg->num_rx_q);
	}

	if (idpf_is_queue_model_split(q_grp->txq_model))
		q_grp->num_complq = le16_to_cpu(vport_msg->num_tx_complq);
	if (idpf_is_queue_model_split(q_grp->rxq_model))
		q_grp->num_bufq = le16_to_cpu(vport_msg->num_rx_bufq);
#ifdef HAVE_XDP_SUPPORT

	vport->num_xdp_rxq = 0;
	vport->xdp_rxq_offset = 0;
	if (!idpf_xdp_is_prog_ena(vport)) {
		vport->num_xdp_txq = 0;
		vport->xdp_txq_offset = 0;
		goto adjust_bufqs;
	}
	/* Do not create dummy Rx queues by default */
	vport->num_xdp_txq = le16_to_cpu(vport_msg->num_rx_q);
	vport->xdp_txq_offset = le16_to_cpu(vport_msg->num_tx_q) -
				le16_to_cpu(vport_msg->num_rx_q);

adjust_bufqs:
#endif /* HAVE_XDP_SUPPORT */
	/* Adjust number of buffer queues per Rx queue */
	if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
		q_grp->num_bufqs_per_qgrp = 0;
		q_grp->num_bufq = 0;
		q_grp->bufq_size[0] = IDPF_RX_BUF_2048;
		return;
	}

#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(vport)) {
		/* After loading the XDP program we will have only one buffer
		 * queue per group with buffer size 4kB.
		 */
		q_grp->num_bufqs_per_qgrp = IDPF_SINGLE_BUFQ_PER_RXQ_GRP;
		q_grp->bufq_size[0] = IDPF_RX_BUF_4096;
		q_grp->num_bufq = q_grp->num_rxq * q_grp->num_bufqs_per_qgrp;
		return;
	}
#endif /* HAVE_XDP_SUPPORT */

	q_grp->num_bufqs_per_qgrp = IDPF_MAX_BUFQS_PER_RXQ_GRP;
	/* Bufq[0] default buffer size is 4K
	 * Bufq[1] default buffer size is 2K
	 */
	q_grp->bufq_size[0] = IDPF_RX_BUF_4096;
	q_grp->bufq_size[1] = IDPF_RX_BUF_2048;
}

/**
 * idpf_vport_calc_num_q_desc - Calculate number of queue groups
 * @vport: vport to calculate q groups for
 * @q_grp: Queue resources
 */
void idpf_vport_calc_num_q_desc(struct idpf_vport *vport,
				struct idpf_q_grp *q_grp)
{
	struct idpf_vport_user_config_data *config_data;
	u8 num_bufqs = q_grp->num_bufqs_per_qgrp;
	u32 num_req_txq_desc, num_req_rxq_desc;
	u16 idx = vport->idx;
	int i;

	config_data =  &vport->adapter->vport_config[idx]->user_config;
	num_req_txq_desc = config_data->num_req_txq_desc;
	num_req_rxq_desc = config_data->num_req_rxq_desc;

	q_grp->complq_desc_count = 0;
	if (num_req_txq_desc) {
		q_grp->txq_desc_count = num_req_txq_desc;
		if (idpf_is_queue_model_split(q_grp->txq_model)) {
			q_grp->complq_desc_count = num_req_txq_desc;
			if (q_grp->complq_desc_count < IDPF_MIN_TXQ_COMPLQ_DESC)
				q_grp->complq_desc_count =
					IDPF_MIN_TXQ_COMPLQ_DESC;
		}
	} else {
		q_grp->txq_desc_count =	IDPF_DFLT_TX_Q_DESC_COUNT;
		if (idpf_is_queue_model_split(q_grp->txq_model)) {
			q_grp->complq_desc_count =
				IDPF_DFLT_TX_COMPLQ_DESC_COUNT;
		}
	}

	if (num_req_rxq_desc)
		q_grp->rxq_desc_count = num_req_rxq_desc;
	else
		q_grp->rxq_desc_count = IDPF_DFLT_RX_Q_DESC_COUNT;

	for (i = 0; i < num_bufqs; i++) {
		if (!q_grp->bufq_desc_count[i])
			q_grp->bufq_desc_count[i] =
				IDPF_RX_BUFQ_DESC_COUNT(q_grp->rxq_desc_count,
							num_bufqs);
	}
}

/**
 * idpf_vport_calc_total_qs - Calculate total number of queues
 * @adapter: private data struct
 * @vport_idx: vport idx to retrieve vport pointer
 * @vport_msg: message to fill with data
 * @max_q: vport max queue info
 */
void idpf_vport_calc_total_qs(struct idpf_adapter *adapter, u16 vport_idx,
			      struct virtchnl2_create_vport *vport_msg,
			      struct idpf_vport_max_q *max_q)
{
	u16 num_txq, num_complq = 0, num_rxq, num_bufq = 0;
	int num_bufq_per_rxq_grp = IDPF_MAX_BUFQS_PER_RXQ_GRP;
	struct idpf_vport_config *vport_config;

	vport_config = adapter->vport_config[vport_idx];
	if (vport_config) {
		num_txq = vport_config->user_config.num_req_tx_qs;
		num_rxq = vport_config->user_config.num_req_rx_qs;
#ifdef HAVE_XDP_SUPPORT

		/* If XDP on, we need an additional TX queue for every RX
		 * queue.
		 */
		if (vport_config->user_config.xdp_prog) {
			num_bufq_per_rxq_grp = IDPF_SINGLE_BUFQ_PER_RXQ_GRP;
			num_txq += num_rxq;
		}
#endif /* HAVE_XDP_SUPPORT */
	} else {
		int num_dflt_rx = IDPF_DFLT_NUM_Q;
		int num_dflt_tx = IDPF_DFLT_NUM_Q;
		int num_cpus = num_online_cpus();

		if (max_q->max_txq < IDPF_DFLT_NUM_Q)
			num_dflt_tx = max_q->max_txq;
		if (max_q->max_rxq < IDPF_DFLT_NUM_Q)
			num_dflt_rx = max_q->max_rxq;

		num_txq = min_t(int, num_dflt_tx, num_cpus);
		num_rxq = min_t(int, num_dflt_rx, num_cpus);
	}

	if (idpf_is_queue_model_split(le16_to_cpu(vport_msg->txq_model)))
		num_complq = num_txq * IDPF_COMPLQ_PER_GROUP;

	if (idpf_is_queue_model_split(le16_to_cpu(vport_msg->rxq_model))) {
		num_bufq = num_rxq * num_bufq_per_rxq_grp;
	}

	vport_msg->num_tx_q = cpu_to_le16(num_txq);
	vport_msg->num_tx_complq = cpu_to_le16(num_complq);
	vport_msg->num_rx_q = cpu_to_le16(num_rxq);
	vport_msg->num_rx_bufq = cpu_to_le16(num_bufq);
}

/**
 * idpf_vport_calc_num_q_groups - Calculate number of queue groups
 * @q_grp: Queue resources
 */
void idpf_vport_calc_num_q_groups(struct idpf_q_grp *q_grp)
{
	if (idpf_is_queue_model_split(q_grp->txq_model))
		q_grp->num_txq_grp = q_grp->num_complq;
	else
		q_grp->num_txq_grp = IDPF_DFLT_SINGLEQ_TX_Q_GROUPS;

	if (idpf_is_queue_model_split(q_grp->rxq_model))
		q_grp->num_rxq_grp = q_grp->num_rxq;
	else
		q_grp->num_rxq_grp = IDPF_DFLT_SINGLEQ_RX_Q_GROUPS;
}

/**
 * idpf_vport_calc_numq_per_grp - Calculate number of queues per group
 * @q_grp: Queue resources
 * @num_txq: return parameter for number of TX queues
 * @num_rxq: return parameter for number of RX queues
 */
static void idpf_vport_calc_numq_per_grp(struct idpf_q_grp *q_grp,
					 u16 *num_txq, u16 *num_rxq)
{
	if (idpf_is_queue_model_split(q_grp->txq_model))
		*num_txq = IDPF_DFLT_SPLITQ_TXQ_PER_GROUP;
	else
		*num_txq = q_grp->num_txq;

	if (idpf_is_queue_model_split(q_grp->rxq_model))
		*num_rxq = IDPF_DFLT_SPLITQ_RXQ_PER_GROUP;
	else
		*num_rxq = q_grp->num_rxq;
}

/**
 * idpf_rxq_set_descids - set the descids supported by this queue
 * @q_grp: Queue resources
 * @q: rx queue for which descids are set
 *
 */
static void idpf_rxq_set_descids(struct idpf_q_grp *q_grp, struct idpf_queue *q)
{
	if (q_grp->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		q->rxdids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
	} else {
		if (q_grp->base_rxd)
			q->rxdids = VIRTCHNL2_RXDID_1_32B_BASE_M;
		else
			q->rxdids = VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M;
	}
}

/**
 * idpf_txq_group_alloc - Allocate all txq group resources
 * @vport: vport to allocate txq groups for
 * @q_grp: Queue resources
 * @num_txq_per_grp: number of txqs to allocate for each group
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_txq_group_alloc(struct idpf_vport *vport, struct idpf_q_grp *q_grp,
				u16 num_txq_per_grp)
{
	struct idpf_adapter *adapter = vport->adapter;
	bool flow_sch_en, split;
	int i;

	q_grp->txq_grps = kcalloc(q_grp->num_txq_grp,
				  sizeof(*q_grp->txq_grps), GFP_KERNEL);
	if (!q_grp->txq_grps)
		return -ENOMEM;

	split = idpf_is_queue_model_split(q_grp->txq_model);
	flow_sch_en = !idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
				       VIRTCHNL2_CAP_SPLITQ_QSCHED);

	for (i = 0; i < q_grp->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &q_grp->txq_grps[i];
		int j;

		tx_qgrp->vport = vport;
		tx_qgrp->num_txq = num_txq_per_grp;

		tx_qgrp->txqs = kcalloc(tx_qgrp->num_txq,
					sizeof(*tx_qgrp->txqs), GFP_KERNEL);
		if (!tx_qgrp->txqs)
			goto err_alloc;

		for (j = 0; j < tx_qgrp->num_txq; j++) {
			tx_qgrp->txqs[j] = kzalloc(sizeof(*tx_qgrp->txqs[j]),
						   GFP_KERNEL);
			if (!tx_qgrp->txqs[j])
				goto err_alloc;
		}

		for (j = 0; j < tx_qgrp->num_txq; j++) {
			struct idpf_queue *q = tx_qgrp->txqs[j];

			u64_stats_init(&q->stats_sync);
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
			if (adapter->iommu_byp.ddev)
				q->dev = adapter->iommu_byp.ddev;
			else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
			q->dev = idpf_adapter_to_dev(adapter);
			q->netdev = vport->netdev;
			q->vport = vport;
			q->desc_count = q_grp->txq_desc_count;
			q->tx_max_bufs = idpf_get_max_tx_bufs(adapter);
			q->tx_min_pkt_len = idpf_get_min_tx_pkt_len(adapter);
			q->txq_grp = tx_qgrp;
			q->crc_enable = vport->crc_enable;
			if (split)
				q->tx.rel_qid = j;

			if (adapter->tx_compl_tstamp_gran_s) {
				q->tx.cmpl_tstamp_ns_s = adapter->tx_compl_tstamp_gran_s;
				q->tstmp_en = true;
			}

			if (flow_sch_en) {
				idpf_queue_set(FLOW_SCH_EN, q);
				q->tx.refillq = kzalloc(sizeof(*q->tx.refillq),
							GFP_KERNEL);
				if (!q->tx.refillq)
					goto err_alloc;

				idpf_queue_set(GEN_CHK, q->tx.refillq);
				idpf_queue_set(RFL_GEN_CHK, q->tx.refillq);

				xa_init(&q->reinject_timers);
			}
		}

		if (!idpf_is_queue_model_split(q_grp->txq_model))
			continue;

		tx_qgrp->complq = kcalloc(IDPF_COMPLQ_PER_GROUP,
					  sizeof(*tx_qgrp->complq),
					  GFP_KERNEL);
		if (!tx_qgrp->complq)
			goto err_alloc;

		u64_stats_init(&tx_qgrp->complq->stats_sync);
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
		if (adapter->iommu_byp.ddev)
			tx_qgrp->complq->dev = adapter->iommu_byp.ddev;
		else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
		tx_qgrp->complq->dev = idpf_adapter_to_dev(adapter);
		tx_qgrp->complq->netdev = vport->netdev;
		tx_qgrp->complq->desc_count = q_grp->complq_desc_count;
		tx_qgrp->complq->txq_grp = tx_qgrp;
		tx_qgrp->complq->vport = vport;

		if (flow_sch_en)
			idpf_queue_set(FLOW_SCH_EN, tx_qgrp->complq);
	}

	return 0;

err_alloc:
	idpf_txq_group_rel(q_grp);

	return -ENOMEM;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_xdp_rxq_init - Prepare and configure XDP structures on Rx queue
 * @q: rx queue where XDP should be initialized
 *
 * Returns 0 on success or error code in case of any failure
 */
int idpf_xdp_rxq_init(struct idpf_queue *q)
{
	int err = 0;
#ifdef HAVE_XDP_BUFF_RXQ
	if (!xdp_rxq_info_is_reg(&q->xdp_rxq))
		xdp_rxq_info_reg(&q->xdp_rxq, q->vport->netdev,
				 q->idx, q->q_vector->napi.napi_id);

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	/* For AF_XDP we are assuming that the queue id received from
	 * the user space is mapped to the pair of queues:
	 *  - Rx queue where queue id is mapped to the queue index (q->idx)
	 *  - XDP Tx queue where queue id is mapped to the queue index,
	 *    considering the XDP offset (q->idx + vport->xdp_txq_offset).
	 */
	idpf_get_xsk_pool(q, false);

	if (q->xsk_pool) {
		xdp_rxq_info_unreg_mem_model(&q->xdp_rxq);

		q->rx_buf_size = xsk_pool_get_rx_frame_size(q->xsk_pool);
		err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
						 MEM_TYPE_XSK_BUFF_POOL, NULL);

		if (err)
			goto err_alloc;
		xsk_pool_set_rxq_info(q->xsk_pool, &q->xdp_rxq);
	} else {
		err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
						 MEM_TYPE_PAGE_SHARED, NULL);
		if (err)
			goto err_alloc;
	}
#else
	err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
					 MEM_TYPE_PAGE_SHARED, NULL);
	if (err)
		goto err_alloc;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
err_alloc:
#endif /* HAVE_XDP_BUFF_RXQ */
	return err;
}

#endif /* HAVE_XDP_SUPPORT */
/**
 * __idpf_rxq_init - Helper to do common parts of queue init
 * @vport: Associated vport
 * @q: queue to init
 */
static void __idpf_rxq_init(struct idpf_vport *vport, struct idpf_queue *q)
{
	struct idpf_adapter *adapter = vport->adapter;

	u64_stats_init(&q->stats_sync);
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
	if (adapter->iommu_byp.ddev)
		q->dev = adapter->iommu_byp.ddev;
	else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
	q->dev = idpf_adapter_to_dev(adapter);
	q->vport = vport;
	q->rx_buffer_low_watermark = IDPF_LOW_WATERMARK;
	idpf_queue_set(GEN_CHK, q);
}

/**
 * idpf_rxq_init - Initialize all RX queue fields
 * @vport: Associated vport
 * @q_grp: Queue resources
 * @rxq: RX queue to initialize
 * @idx: RX queue index
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rxq_init(struct idpf_vport *vport, struct idpf_q_grp *q_grp,
			 struct idpf_queue *rxq, int idx)
{
	__idpf_rxq_init(vport, rxq);
	rxq->idx = idx;
	rxq->rx.rxq_idx = idx;
	rxq->desc_count = q_grp->rxq_desc_count;
	/* In splitq mode, RXQ buffer size should be set to that of the
	 * first buffer queue associated with this RXQ
	 */
	rxq->rx_buf_size = q_grp->bufq_size[0];
	rxq->rx_max_pkt_size = vport->netdev->mtu + IDPF_PACKET_HDR_PAD;

	idpf_rxq_set_descids(q_grp, rxq);
	if (IS_SIMICS_DEVICE(vport->adapter->hw.subsystem_device_id))
		rxq->gen_rxcsum_status = CHECKSUM_UNNECESSARY;
	else
		rxq->gen_rxcsum_status = CHECKSUM_COMPLETE;

	return 0;
}

/**
 * idpf_rxq_group_alloc - Allocate all rxq group resources
 * @vport: vport to allocate rxq groups for
 * @q_grp: Queue resources
 * @num_rxq: number of rxqs to allocate for each group
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rxq_group_alloc(struct idpf_vport *vport, struct idpf_q_grp *q_grp,
				u16 num_rxq)
{
	int i, k, err = 0;
	struct idpf_vport_user_config_data *config_data =
		&vport->adapter->vport_config[vport->idx]->user_config;

	q_grp->rxq_grps = kcalloc(q_grp->num_rxq_grp,
				  sizeof(struct idpf_rxq_group), GFP_KERNEL);
	if (!q_grp->rxq_grps)
		return -ENOMEM;

	for (i = 0; i < q_grp->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &q_grp->rxq_grps[i];
		int j;

		rx_qgrp->vport = vport;
		if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
			rx_qgrp->singleq.num_rxq = num_rxq;
			for (j = 0; j < num_rxq; j++) {
				rx_qgrp->singleq.rxqs[j] = kzalloc(sizeof(*rx_qgrp->singleq.rxqs[j]),
								   GFP_KERNEL);
				if (!rx_qgrp->singleq.rxqs[j]) {
					err = -ENOMEM;
					goto err_alloc;
				}
			}
			goto skip_splitq_rx_init;
		}
		rx_qgrp->splitq.num_rxq_sets = num_rxq;

		for (j = 0; j < num_rxq; j++) {
			rx_qgrp->splitq.rxq_sets[j] = kzalloc(sizeof(struct idpf_rxq_set),
							      GFP_KERNEL);
			if (!rx_qgrp->splitq.rxq_sets[j]) {
				err = -ENOMEM;
				goto err_alloc;
			}
		}

		rx_qgrp->splitq.bufq_sets = kcalloc(q_grp->num_bufqs_per_qgrp,
						    sizeof(struct idpf_bufq_set),
						    GFP_KERNEL);
		if (!rx_qgrp->splitq.bufq_sets) {
			err = -ENOMEM;
			goto err_alloc;
		}

		for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
			struct idpf_bufq_set *bufq_set =
				&rx_qgrp->splitq.bufq_sets[j];
			int swq_size = sizeof(struct idpf_sw_queue);
			struct idpf_queue *q;

			q = &rx_qgrp->splitq.bufq_sets[j].bufq;
			q->desc_count = q_grp->bufq_desc_count[j];
			q->rx_buffer_low_watermark = IDPF_LOW_WATERMARK;

			if (test_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags)) {
				q->rx_hsplit_en = true;
				q->rx_hbuf_size = IDPF_HDR_BUF_SIZE;
			}

			__idpf_rxq_init(vport, q);
			q->dev = &vport->adapter->pdev->dev;
			q->vport = vport;
			q->rxq_grp = rx_qgrp;
			q->idx = j;
			q->rx_buf_size = q_grp->bufq_size[j];
			q->rx_buf_stride = IDPF_RX_BUF_STRIDE;
			q->rx.rxq_idx = i / q_grp->num_bufqs_per_qgrp;

			bufq_set->num_refillqs = num_rxq;
			bufq_set->refillqs = kcalloc(num_rxq, swq_size,
						     GFP_KERNEL);
			if (!bufq_set->refillqs) {
				err = -ENOMEM;
				goto err_alloc;
			}
			for (k = 0; k < bufq_set->num_refillqs; k++) {
				struct idpf_sw_queue *refillq =
					&bufq_set->refillqs[k];

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
				if (vport->adapter->iommu_byp.ddev)
					refillq->dev = vport->adapter->iommu_byp.ddev;
				else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
				refillq->desc_count =
					q_grp->bufq_desc_count[j];
				idpf_queue_set(GEN_CHK, refillq);
				idpf_queue_set(RFL_GEN_CHK, refillq);
				refillq->ring = kcalloc(refillq->desc_count,
							sizeof(u32),
							GFP_KERNEL);
				if (!refillq->ring) {
					err = -ENOMEM;
					goto err_alloc;
				}
			}
		}

skip_splitq_rx_init:
		for (j = 0; j < num_rxq; j++) {
			struct idpf_queue *q;

			if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
				q = rx_qgrp->singleq.rxqs[j];
				goto setup_rxq;
			}

			q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			for (k = 0; k < q_grp->num_bufqs_per_qgrp; k++) {
				rx_qgrp->splitq.rxq_sets[j]->refillq[k] =
				      &rx_qgrp->splitq.bufq_sets[k].refillqs[j];
			}

			if (test_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags)) {
				q->rx_hsplit_en = true;
				q->rx_hbuf_size = IDPF_HDR_BUF_SIZE;
			}
			q->rxq_grp = rx_qgrp;

setup_rxq:
			idpf_rxq_init(vport, q_grp, q, (i * num_rxq) + j);
		}
	}

err_alloc:
	if (err)
		idpf_rxq_group_rel(q_grp);

	return err;
}

/**
 * idpf_vport_queue_grp_alloc_all - Allocate queue resources for vport
 * @vport: Vport to use
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_vport_queue_grp_alloc_all(struct idpf_vport *vport,
					  struct idpf_q_grp *q_grp)
{
	u16 num_txq, num_rxq;
	int err;

	idpf_vport_calc_numq_per_grp(q_grp, &num_txq, &num_rxq);

	err = idpf_txq_group_alloc(vport, q_grp, num_txq);
	if (err)
		goto err_out;

	err = idpf_rxq_group_alloc(vport, q_grp, num_rxq);
	if (err)
		goto err_out;

	return 0;

err_out:
	idpf_vport_queue_grp_rel_all(q_grp);

	return err;
}

/**
 * idpf_vport_queue_alloc_all - Allocate all resources for queues
 * @vport: Virtual port
 * @q_grp: Queue resources
 *
 * Allocate memory for queues associated with a vport including descriptor
 * rings and buffers.  Returns 0 on success, negative on failure.
 */
int idpf_vport_queue_alloc_all(struct idpf_vport *vport,
			       struct idpf_q_grp *q_grp)
{
#ifdef HAVE_ETF_SUPPORT
	struct idpf_vport_user_config_data *config_data;
#endif /* HAVE_ETF_SUPPORT */
	int err;
#ifdef HAVE_ETF_SUPPORT
	int i;
#endif

	err = idpf_vport_queue_grp_alloc_all(vport, q_grp);
	if (err)
		goto err_out;

	err = idpf_tx_desc_alloc_all(vport, q_grp);
	if (err)
		goto err_out;

	err = idpf_rx_desc_alloc_all(q_grp);
	if (err)
		goto err_out;

	err = idpf_fast_path_txq_init(vport, q_grp);
	if (err)
		goto err_out;

	idpf_init_cached_phc_time(vport, q_grp);

#ifdef HAVE_ETF_SUPPORT
	config_data = &vport->adapter->vport_config[vport->idx]->user_config;
	/* Initialize flow scheduling for queues that were requested
	 * before the interface was brought up
	 */
	for (i = 0; i < vport->num_txq; i++) {
		if (test_bit(i, config_data->etf_qenable)) {
			idpf_queue_set(FLOW_SCH_EN, vport->txqs[i]);
			idpf_queue_set(ETF_EN, vport->txqs[i]);
		}
	}

#endif /* HAVE_ETF_SUPPORT */
#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(vport)) {
		int j;

		for (j = vport->xdp_txq_offset; j < vport->num_txq; j++)
			idpf_queue_set(XDP, vport->txqs[j]);
	}

#endif /* HAVE_XDP_SUPPORT */
	return 0;

err_out:
	idpf_vport_queues_rel(vport, q_grp);

	return err;
}

/**
 * idpf_tx_handle_sw_marker - Handle queue marker packet
 * @tx_q: tx queue to handle software marker
 */
static void idpf_tx_handle_sw_marker(struct idpf_queue *tx_q)
{
	struct idpf_vport *vport = tx_q->vport;
	int i;

	idpf_queue_clear(SW_MARKER, tx_q);
	/* Hardware must write marker packets to all queues associated with
	 * completion queues. So check if all queues received marker packets
	 */
	for (i = 0; i < vport->num_txq; i++) {
		/* If we're still waiting on any other TXQ marker completions,
		 * just return now since we cannot wake up the marker_wq yet.
		 */
		if (idpf_queue_has(SW_MARKER, vport->txqs[i]))
			return;
	}

	/* Drain complete */
	set_bit(IDPF_VPORT_SW_MARKER, vport->flags);
	wake_up(&vport->sw_marker_wq);
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
/**
 * idpf_tx_hw_tstamp - report hw timestamp from completion desc to stack
 * @txq: pointer to txq struct
 * @skb: original skb
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 */
static void idpf_tx_hw_tstamp(struct idpf_queue *txq, struct sk_buff *skb,
			      u8 *desc_ts)
{
	struct skb_shared_hwtstamps hwtstamps = { };
	u64 ext_tstamp;
	u32 tstamp;

	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) ||
		   !txq->tstmp_en))
		return;

	tstamp = (desc_ts[0] | (desc_ts[1] << 8) | (desc_ts[2] << 16));
	tstamp = tstamp << txq->tx.cmpl_tstamp_ns_s;

	ext_tstamp =
		idpf_ptp_tstamp_extend_32b_to_64b(*txq->cached_phc_time,
						  tstamp);
	hwtstamps.hwtstamp = ns_to_ktime(ext_tstamp);

	skb_tstamp_tx(skb, &hwtstamps);
}
#else
static inline void idpf_tx_hw_tstamp(struct idpf_queue *txq,
				     struct sk_buff *skb, u8 *desc_ts) { }
#endif /* CONFIG_PTP_1588_CLOCK && CONFIG_PTP */

/**
 * idpf_tx_read_tstamp - schedule a work to read Tx timestamp value
 * @txq: queue to read the timestamp from
 * @skb: socket buffer to provide Tx timestamp value
 *
 * Schedule a work to read Tx timestamp value generated once the packet is
 * transmitted.
 */
static void idpf_tx_read_tstamp(struct idpf_queue *txq, struct sk_buff *skb)
{
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	struct idpf_ptp_tx_tstamp_status *tx_tstamp_status;
	u32 i;

	tx_tstamp_caps = txq->cached_tstamp_caps;
	spin_lock_bh(&tx_tstamp_caps->status_lock);

	for (i = 0; i < tx_tstamp_caps->num_entries; i++) {
		tx_tstamp_status = &tx_tstamp_caps->tx_tstamp_status[i];
		if (tx_tstamp_status->state != IDPF_PTP_FREE)
			continue;

		tx_tstamp_status->skb = skb;
		tx_tstamp_status->state = IDPF_PTP_REQUEST;

		/* Fetch timestamp from completion descriptor through
		 * virtchnl msg to report to stack.
		 */
		queue_work(system_unbound_wq, txq->tstamp_task);
		break;
	}

	spin_unlock_bh(&tx_tstamp_caps->status_lock);
}

/**
 * idpf_tx_handle_reinject_expire - handler for miss completion timer
 * @timer: pointer to timer that expired
 */
static void idpf_tx_handle_reinject_expire(struct timer_list *timer)
{
	struct idpf_reinject_timer *timer_info = timer_container_of(timer_info, timer, timer);
	struct idpf_queue *txq = timer_info->txq;
	struct netdev_queue *nq;

	dev_consume_skb_any(timer_info->skb);

	/* Update BQL */
	nq = netdev_get_tx_queue(txq->vport->netdev, txq->idx);
	netdev_tx_completed_queue(nq, timer_info->gso_segs, timer_info->bytes);

	u64_stats_update_begin(&txq->stats_sync);
	u64_stats_inc(&txq->vport->port_stats.tx_reinjection_timeouts);
	u64_stats_update_end(&txq->stats_sync);

	kfree(timer_info);
}

/**
 * idpf_tx_start_reinject_timer - start timer to wait for reinject completion
 * @txq: pointer to queue struct
 * @tx_buf: first buffer of the packet being reinjected
 * @compl_tag: completion tag of the packet being reinjected
 *
 * Return: 0 on success, negative on failure
 */
static int idpf_tx_start_reinject_timer(struct idpf_queue *txq,
					struct idpf_tx_buf *tx_buf,
					u32 compl_tag)
{
	struct idpf_reinject_timer *reinject_timer;
	int err = 0;

	reinject_timer = kzalloc(sizeof(*reinject_timer), GFP_ATOMIC);
	if (!reinject_timer)
		return -ENOMEM;

	reinject_timer->txq = txq;
	reinject_timer->skb = tx_buf->skb;
	reinject_timer->bytes = tx_buf->bytes;
	reinject_timer->gso_segs = tx_buf->packets;

	timer_setup(&reinject_timer->timer, idpf_tx_handle_reinject_expire, 0);
	mod_timer(&reinject_timer->timer, jiffies + msecs_to_jiffies(4 * HZ));

	err = xa_err(xa_store(&txq->reinject_timers, compl_tag,
			      reinject_timer, GFP_ATOMIC));
	if (err)
		kfree(reinject_timer);

	return err;
}

#define idpf_tx_splitq_clean_bump_ntc(txq, ntc, desc, buf)	\
do {								\
	if (unlikely(++(ntc) == (txq)->desc_count)) {		\
		ntc = 0;					\
		buf = (txq)->tx.bufs;				\
		desc = IDPF_FLEX_TX_DESC(txq, 0);		\
	} else {						\
		(buf)++;					\
		(desc)++;					\
	}							\
} while (0)

/**
 * idpf_tx_splitq_clean - Reclaim resources from buffer queue
 * @tx_q: Tx queue to clean
 * @end: queue index until which it should be cleaned
 * @napi_budget: Used to determine if we are in netpoll
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @descs_only: true if queue is using flow-based scheduling and should
 * not clean buffers at this time
 *
 * Cleans the queue descriptor ring. If the queue is using queue-based
 * scheduling, the buffers will be cleaned as well. If the queue is using
 * flow-based scheduling, only the descriptors are cleaned at this time.
 * Separate packet completion events will be reported on the completion queue,
 * and the buffers will be cleaned separately. The stats are not updated from
 * this function when using flow-based scheduling.
 */
static void idpf_tx_splitq_clean(struct idpf_queue *tx_q, u16 end,
				 int napi_budget,
				 struct libeth_sq_napi_stats *cleaned,
				 bool descs_only)
{
	union idpf_tx_flex_desc *next_pending_desc = NULL;
	union idpf_tx_flex_desc *tx_desc;
	u16 ntc = tx_q->next_to_clean;
	struct libeth_cq_pp cp = {
		.dev	= tx_q->dev,
		.ss	= cleaned,
		.napi	= !!napi_budget,
	};
	struct idpf_tx_buf *tx_buf;

	if (descs_only) {
		/* Bump ring index to mark as cleaned. */
		tx_q->next_to_clean = end;
		return;
	}

	tx_desc = IDPF_FLEX_TX_DESC(tx_q, ntc);
	next_pending_desc = IDPF_FLEX_TX_DESC(tx_q, end);
	tx_buf = &tx_q->tx.bufs[ntc];

	while (tx_desc != next_pending_desc) {
		u16 eop_idx;

		/* If this entry in the ring was used as a context descriptor,
		 * it's corresponding entry in the buffer ring is reserved.  We
		 * can skip this descriptor since there is no buffer to clean.
		 */
		if (tx_buf->type == LIBETH_SQE_CTX)
			goto fetch_next_txq_desc;

		eop_idx = tx_buf->rs_idx;
		libeth_tx_complete(tx_buf, &cp);

		/* unmap remaining buffers */
		while (ntc != eop_idx) {
			idpf_tx_splitq_clean_bump_ntc(tx_q, ntc,
						      tx_desc, tx_buf);

			/* unmap any remaining paged data */
			libeth_tx_complete(tx_buf, &cp);
		}

fetch_next_txq_desc:
		idpf_tx_splitq_clean_bump_ntc(tx_q, ntc, tx_desc, tx_buf);
	}

	tx_q->next_to_clean = ntc;
}

/**
 * idpf_tx_clean_bufs - clean flow scheduling TX queue buffers
 * @txq: queue to clean
 * @buf_id: packet's starting buffer ID, from completion descriptor
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 * @budget: Used to determine if we are in netpoll
 *
 * Clean all buffers associated with the packet starting at buf_id. Returns the
 * byte/segment count for the cleaned packet.
 */
static void idpf_tx_clean_bufs(struct idpf_queue *txq, u16 buf_id,
			       struct libeth_sq_napi_stats *cleaned,
			       u8 *desc_ts, int budget)
{
	struct idpf_tx_buf *tx_buf = NULL;
	struct libeth_cq_pp cp = {
		.dev	= txq->dev,
		.ss	= cleaned,
		.napi	= !!budget,
	};

	tx_buf = &txq->tx.bufs[buf_id];
	if (tx_buf->type == LIBETH_SQE_SKB) {
		/* fetch timestamp from completion descriptor to report to
		 * stack.
		 */
		idpf_tx_hw_tstamp(txq, tx_buf->skb, desc_ts);
	} else if (tx_buf->type == (enum libeth_sqe_type)LIBETH_SQE_SKB_TSTAMP) {
		if (skb_shinfo(tx_buf->skb)->tx_flags & SKBTX_IN_PROGRESS)
			idpf_tx_read_tstamp(txq, tx_buf->skb);

		tx_buf->type = LIBETH_SQE_SKB;
	} else if (tx_buf->type != LIBETH_SQE_XDP_TX) {
		return;
	}

	libeth_tx_complete(tx_buf, &cp);
	idpf_post_buf_refill(txq->tx.refillq, buf_id);

	while (idpf_tx_buf_next(tx_buf) != IDPF_TXBUF_NULL) {
		buf_id = idpf_tx_buf_next(tx_buf);

		tx_buf = &txq->tx.bufs[buf_id];
		libeth_tx_complete(tx_buf, &cp);
		idpf_post_buf_refill(txq->tx.refillq, buf_id);
	}
}

/**
 * idpf_tx_handle_miss_completion - handle packet on the exception path
 * @txq: Tx ring to clean
 * @desc: pointer to completion queue descriptor to extract completion
 * information from
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @compl_tag: unique completion tag of packet
 * @budget: Used to determine if we are in netpoll
 *
 * Handle a miss completion which signals the packet is taking the execption
 * path. In the usual flow, the miss completion signals the start of expection
 * path processing. Upon receiving a miss completion, we can unmap all buffers
 * associated with the packet, but hold on to the skb. We expect a reinject
 * completion, but it is not guaranteed, so we will start a timer to make sure
 * the skb is freed in a reasonable amount of time (before a Tx timeout is
 * triggered by the stack).
 *
 * If the timer cannot be started, we will clean this packet as if it were an
 * RS completion and the reinject completion will be ignored.
 *
 * In the rare case the reinject completion is processed first (due to a rare
 * timing situation with an LSO packet primarily), the miss completion is the
 * end of the exception path handling and we finish cleaning the packet
 * normally. Note: we set it to the skb type to include DMA unmapping as part
 * of the cleaning.
 *
 * Cleaned bytes/packets are only relevant if we're finishing up the reinject
 * completion and freeing the skb. Otherwise, the stats are 0 / irrelevant.
 */
static void
idpf_tx_handle_miss_completion(struct idpf_queue *txq,
			       struct idpf_splitq_tx_compl_desc *desc,
			       struct libeth_sq_napi_stats *cleaned,
			       u16 compl_tag, int budget)
{
	struct idpf_tx_buf *tx_buf = &txq->tx.bufs[compl_tag];

	if (unlikely(tx_buf->type == (enum libeth_sqe_type)LIBETH_SQE_REINJECT)) {
		/* Reinject completion was received first. No other completion
		 * is expected for this packet, clean it normally.
		 */
		tx_buf->type = LIBETH_SQE_SKB;
		goto clean_pkt;
	}

	if (idpf_tx_start_reinject_timer(txq, tx_buf, compl_tag)) {
		netdev_err(txq->netdev,
			   "Failed to start reinject timer, BQL may be inaccurate.\n");
		goto clean_pkt;
	}

	tx_buf->type = (enum libeth_sqe_type)LIBETH_SQE_MISS;

clean_pkt:
	idpf_tx_clean_bufs(txq, compl_tag, cleaned, desc->ts, budget);
}

/**
 * idpf_tx_handle_rs_completion - clean a single packet and all of its buffers
 * whether on the buffer ring or in the hash table
 * @txq: Tx ring to clean
 * @desc: pointer to completion queue descriptor to extract completion
 * information from
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @budget: Used to determine if we are in netpoll
 *
 * Returns bytes/packets cleaned
 */
static void
idpf_tx_handle_rs_completion(struct idpf_queue *txq,
			     struct idpf_splitq_tx_compl_desc *desc,
			     struct libeth_sq_napi_stats *cleaned,
			     int budget)
{
	/* RS completion contains queue head for queue based scheduling or
	 * completion tag for flow based scheduling.
	 */
	u16 rs_compl_val = le16_to_cpu(desc->q_head_compl_tag.q_head);

	if (!idpf_queue_has(FLOW_SCH_EN, txq))
		return idpf_tx_splitq_clean(txq, rs_compl_val, budget, cleaned,
					    false);

	/* Check for miss completion in tag if enabled */
	if (unlikely(idpf_queue_has(MISS_TAG_EN, txq) &&
		     rs_compl_val & IDPF_TX_SPLITQ_MISS_COMPL_TAG)) {
		rs_compl_val &= ~IDPF_TX_SPLITQ_MISS_COMPL_TAG;

		return idpf_tx_handle_miss_completion(txq, desc, cleaned,
						      rs_compl_val, budget);
	}
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL

	if (txq->xsk_pool)
		return idpf_tx_splitq_clean_zc(txq, rs_compl_val, cleaned);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	idpf_tx_clean_bufs(txq, rs_compl_val, cleaned, desc->ts, budget);
}

/**
 * idpf_tx_handle_reinject_completion
 * @txq: Tx ring to clean
 * @desc: pointer to completion queue descriptor to extract completion
 * information from
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @budget: Used to determine if we are in netpoll
 */
static void
idpf_tx_handle_reinject_completion(struct idpf_queue *txq,
				   struct idpf_splitq_tx_compl_desc *desc,
				   struct libeth_sq_napi_stats *cleaned,
				   int budget)
{
	u16 compl_tag = le16_to_cpu(desc->q_head_compl_tag.compl_tag);
	struct idpf_tx_buf *tx_buf = &txq->tx.bufs[compl_tag];
	struct idpf_reinject_timer *reinject_timer;
	struct libeth_cq_pp cp = {
		.dev	= txq->dev,
		.ss	= cleaned,
		.napi	= !!budget,
	};

	if (tx_buf->type == (enum libeth_sqe_type)LIBETH_SQE_MISS) {
		reinject_timer = xa_erase(&txq->reinject_timers, compl_tag);
		if (unlikely(!reinject_timer))
			/* Either timer expired or we failed to create the
			 * timer.  In either case, nothing more to do since SKB
			 * has already been consumed.
			 */
			return;

		timer_delete(&reinject_timer->timer);
		kfree(reinject_timer);

		/* Reset type to REINJECT to consume skb and update stats. */
		tx_buf->type = (enum libeth_sqe_type)LIBETH_SQE_REINJECT;
		libeth_tx_complete(tx_buf, &cp);
	} else if (tx_buf->type == LIBETH_SQE_SKB) {
		u16 next_pkt_idx;

		/* This is a scenario in which the reinject completion arrives
		 * before the miss completion.  We can simply move the
		 * descriptor ring next_to_clean to after this packet since we
		 * know all descriptors up to this point have been read by HW.
		 * We will clean the packet and all of its buffers associated
		 * with this completion tag upon receiving the miss completion,
		 * and clean the others upon receiving their respective RS
		 * completions.
		 */
		tx_buf->type = (enum libeth_sqe_type)LIBETH_SQE_REINJECT;

		next_pkt_idx = tx_buf->rs_idx + 1;
		if (unlikely(next_pkt_idx >= txq->desc_count))
			next_pkt_idx = 0;

		txq->next_to_clean = next_pkt_idx;
	}

	/* If we get here with this tag, it means we either received a regular
	 * completion already or the timer expired on the miss completion.  In
	 * either case, everything should already be cleaned up and we should
	 * ignore this completion.
	 */
}

/**
 * idpf_tx_clean_complq - Reclaim resources on completion queue
 * @complq: Tx ring to clean
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
static bool idpf_tx_clean_complq(struct idpf_queue *complq, int budget,
				 int *cleaned)
{
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	u64 sharedrxq_clean_incomplete, complq_clean_incomplete;
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
	struct idpf_splitq_tx_compl_desc *tx_desc;
	struct idpf_vport *vport = complq->vport;
	s16 ntc = complq->next_to_clean;
	bool clean_completed = false;
	unsigned int complq_budget;
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bool xsk_completed = true;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
	struct idpf_queue *tx_q;
	bool complq_ok = true;
	int i;

	complq_budget = vport->compln_clean_budget;
	tx_desc = IDPF_SPLITQ_TX_COMPLQ_DESC(complq, ntc);
	ntc -= complq->desc_count;

	do {
		struct libeth_sq_napi_stats cleaned_stats = { };
		u16 hw_head, compl_tag;
		int rel_tx_qid;
		u8 ctype;	/* completion type */
		u16 gen;

		/* if the descriptor isn't done, no work yet to do */
		gen = le16_get_bits(tx_desc->qid_comptype_gen,
				    IDPF_TXD_COMPLQ_GEN_M);
		if (idpf_queue_has(GEN_CHK, complq) != gen)
			break;

		/* Find necessary info of TX queue to clean buffers */
		rel_tx_qid = le16_get_bits(tx_desc->qid_comptype_gen,
					   IDPF_TXD_COMPLQ_QID_M);
		if (unlikely(rel_tx_qid >= complq->txq_grp->num_txq)) {
			dev_err(idpf_adapter_to_dev(vport->adapter),
				"TxQ not found\n");
			goto fetch_next_desc;
		}

		tx_q = complq->txq_grp->txqs[rel_tx_qid];

		/* Determine completion type */
		ctype = le16_get_bits(tx_desc->qid_comptype_gen,
				      IDPF_TXD_COMPLQ_COMPL_TYPE_M);
		switch (ctype) {
		case IDPF_TXD_COMPLT_RE:
			hw_head = le16_to_cpu(tx_desc->q_head_compl_tag.q_head);

			idpf_tx_splitq_clean(tx_q, hw_head, budget,
					     &cleaned_stats, true);
			break;
		case IDPF_TXD_COMPLT_RS:
			idpf_tx_handle_rs_completion(tx_q, tx_desc,
						     &cleaned_stats, budget);
			break;
		case IDPF_TXD_COMPLT_SW_MARKER:
			idpf_tx_handle_sw_marker(tx_q);
			break;
		case IDPF_TXD_COMPLT_RULE_MISS:
			compl_tag =
				le16_to_cpu(tx_desc->q_head_compl_tag.compl_tag);

			idpf_tx_handle_miss_completion(tx_q, tx_desc,
						       &cleaned_stats,
						       compl_tag, budget);
			break;
		case IDPF_TXD_COMPLT_REINJECTED:
			idpf_tx_handle_reinject_completion(tx_q, tx_desc,
							   &cleaned_stats,
							   budget);
			break;
		default:
			dev_err(idpf_adapter_to_dev(vport->adapter),
				"Unknown TX completion type: %d\n",
				ctype);
			goto fetch_next_desc;
		}

		u64_stats_update_begin(&tx_q->stats_sync);
		u64_stats_add(&tx_q->q_stats.tx.packets, cleaned_stats.packets);
		u64_stats_add(&tx_q->q_stats.tx.bytes, cleaned_stats.bytes);
		tx_q->cleaned_pkts += cleaned_stats.packets;
		tx_q->cleaned_bytes += cleaned_stats.bytes;
		complq->tx.num_completions++;
		u64_stats_update_end(&tx_q->stats_sync);

fetch_next_desc:
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= complq->desc_count;
			tx_desc = IDPF_SPLITQ_TX_COMPLQ_DESC(complq, 0);
			idpf_queue_change(GEN_CHK, complq);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		complq_budget--;
	} while (likely(complq_budget));

#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	if (unlikely(!complq_budget))
		complq->q_vector->complq_clean_incomplete++;

	complq_clean_incomplete = complq->q_vector->complq_clean_incomplete;
	sharedrxq_clean_incomplete =
		complq->q_vector->sharedrxq_clean_incomplete;

#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
	/* Store the state of the complq to be used later in deciding if a
	 * TXQ can be started again
	 */
	if (unlikely(IDPF_TX_COMPLQ_PENDING(complq->txq_grp) >
		     IDPF_TX_COMPLQ_OVERFLOW_THRESH(complq)))
		complq_ok = false;

	for (i = 0; i < complq->txq_grp->num_txq; ++i) {
		struct netdev_queue *nq;

		tx_q = complq->txq_grp->txqs[i];

#ifdef HAVE_XDP_SUPPORT
		if (idpf_queue_has(XDP, tx_q)) {
#ifdef HAVE_NETDEV_BPF_XSK_POOL
			/* In splitq implementation we do not track Tx
			 * descriptors.  Instead, we know the Tx completion
			 * status from the completion queue only. Moreover, for
			 * AF_XDP we support asynchronous Tx by waking up the
			 * NAPI context and performing descriptor cleaning.  In
			 * such a scenario, we have to explicitly trigger an
			 * 'xmit' action from here for all AF_XDP queues.
			 * Otherwise, no packet would be xmitted (because we
			 * look at the completion queue first).
			 */
			if (tx_q->xsk_pool)
				xsk_completed = xsk_completed && idpf_tx_splitq_xmit_zc(tx_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
			*cleaned += tx_q->cleaned_pkts;
			tx_q->cleaned_bytes = 0;
			tx_q->cleaned_pkts = 0;
			continue;
		}

#endif /* HAVE_XDP_SUPPORT */
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
		u64_stats_update_begin(&tx_q->stats_sync);
		u64_stats_add(&tx_q->q_stats.tx.sharedrxq_clean_incomplete,
			      sharedrxq_clean_incomplete);
		u64_stats_add(&tx_q->q_stats.tx.complq_clean_incomplete,
			      complq_clean_incomplete);
		u64_stats_update_end(&tx_q->stats_sync);

#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
		/* We didn't clean anything on this queue, move along */
		if (!tx_q->cleaned_bytes)
			continue;

		*cleaned += tx_q->cleaned_pkts;

		/* Update BQL */
		nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
		netdev_tx_completed_queue(nq, tx_q->cleaned_pkts, tx_q->cleaned_bytes);

		/* Reset cleaned stats for the next time this queue is cleaned */
		tx_q->cleaned_bytes = 0;
		tx_q->cleaned_pkts = 0;

		/* Check if the TXQ needs to and can be restarted */
		if (unlikely(netif_tx_queue_stopped(nq) && complq_ok &&
			     netif_carrier_ok(tx_q->vport->netdev) &&
			     (IDPF_DESC_UNUSED(tx_q) >= IDPF_TX_WAKE_THRESH))) {
			/* Make sure any other threads stopping queue after
			 * this see new next_to_clean.
			 */
			smp_mb();
			netif_tx_wake_queue(nq);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
			u64_stats_update_begin(&tx_q->stats_sync);
			u64_stats_inc(&tx_q->q_stats.tx.busy_q_restarts);
			u64_stats_update_end(&tx_q->stats_sync);
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
		}
	}

	ntc += complq->desc_count;
	complq->next_to_clean = ntc;

	clean_completed = !!complq_budget;
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	clean_completed = clean_completed && xsk_completed;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	return clean_completed;
}

/**
 * idpf_tx_splitq_build_ctb - populate command tag and size for queue
 * based scheduling descriptors
 * @desc: descriptor to populate
 * @params: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
void idpf_tx_splitq_build_ctb(union idpf_tx_flex_desc *desc,
			      struct idpf_tx_splitq_params *params,
			      u16 td_cmd, u16 size)
{
	desc->q.qw1.cmd_dtype =
		le16_encode_bits(params->dtype, IDPF_FLEX_TXD_QW1_DTYPE_M);
	desc->q.qw1.cmd_dtype |=
		le16_encode_bits(td_cmd, IDPF_FLEX_TXD_QW1_CMD_M);
	desc->q.qw1.buf_size = cpu_to_le16(size);
	desc->q.qw1.l2tags.l2tag1 = cpu_to_le16(params->td_tag);
}

/**
 * idpf_tx_splitq_build_flow_desc - populate command tag and size for flow
 * scheduling descriptors
 * @desc: descriptor to populate
 * @params: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
void idpf_tx_splitq_build_flow_desc(union idpf_tx_flex_desc *desc,
				    struct idpf_tx_splitq_params *params,
				    u16 td_cmd, u16 size)
{
	desc->flow.qw1.cmd_dtype = (u16)params->dtype | td_cmd;
	desc->flow.qw1.rxr_bufsize = cpu_to_le16((u16)size);
	desc->flow.qw1.compl_tag = cpu_to_le16(params->compl_tag);

	desc->flow.qw1.ts[0] = params->offload.desc_ts[0];
	desc->flow.qw1.ts[1] = params->offload.desc_ts[1];
	desc->flow.qw1.ts[2] = params->offload.desc_ts[2];
}

/**
 * idpf_tx_splitq_has_room - check if enough Tx splitq resources are available
 * @tx_q: the queue to be checked
 * @descs_needed: number of descriptors required for this packet
 * @bufs_needed: number of Tx buffers required for this packet
 *
 * Return: 0 if no room available, 1 otherwise
 */
static int idpf_txq_has_room(struct idpf_queue *tx_q, u32 descs_needed,
			     u32 bufs_needed)
{
	if (IDPF_DESC_UNUSED(tx_q) < descs_needed ||
	    IDPF_TX_COMPLQ_PENDING(tx_q->txq_grp) >
		IDPF_TX_COMPLQ_OVERFLOW_THRESH(tx_q->txq_grp->complq) ||
	    idpf_tx_splitq_get_free_bufs(tx_q->tx.refillq) < bufs_needed)
		return 0;
	return 1;
}

/**
 * idpf_tx_maybe_stop_splitq - 1st level check for Tx splitq stop conditions
 * @tx_q: the queue to be checked
 * @descs_needed: number of descriptors required for this packet
 * @bufs_needed: number of buffers needed for this packet
 *
 * Return: 0 if stop is not needed
 */
static int idpf_tx_maybe_stop_splitq(struct idpf_queue *tx_q,
				     u32 descs_needed,
				     u32 bufs_needed)
{
	/* Since we have multiple resources to check for splitq, our
	 * start,stop_thrs becomes a boolean check instead of a count
	 * threshold.
	 */
	if (netif_subqueue_maybe_stop(tx_q->netdev, tx_q->idx,
				      idpf_txq_has_room(tx_q, descs_needed,
							bufs_needed),
				      1, 1))
		return 0;

	u64_stats_update_begin(&tx_q->stats_sync);
	u64_stats_inc(&tx_q->q_stats.tx.q_busy);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	if (IDPF_DESC_UNUSED(tx_q) < descs_needed)
		u64_stats_inc(&tx_q->q_stats.tx.busy_low_txq_descs);
	if (IDPF_TX_COMPLQ_PENDING(tx_q->txq_grp) >
	    IDPF_TX_COMPLQ_OVERFLOW_THRESH(tx_q->txq_grp->complq))
		u64_stats_inc(&tx_q->q_stats.tx.busy_too_many_pend_compl);
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
	u64_stats_update_end(&tx_q->stats_sync);

	return -EBUSY;
}

/**
 * idpf_tx_buf_hw_update - Store the new tail value
 * @tx_q: queue to bump
 * @val: new tail index
 * @xmit_more: more skb's pending
 *
 * The naming here is special in that 'hw' signals that this function is about
 * to do a register write to update our queue status. We know this can only
 * mean tail here as HW should be owning head for TX.
 */
void idpf_tx_buf_hw_update(struct idpf_queue *tx_q, u32 val,
			   bool xmit_more)
{
	struct netdev_queue *nq;

	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	tx_q->next_to_use = val;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();

	/* notify HW of packet */
	if (netif_xmit_stopped(nq) || !xmit_more) {
		writel(val, tx_q->tail);
#ifndef SPIN_UNLOCK_IMPLIES_MMIOWB

		/* we need this if more than one processor can write to our tail
		 * at a time, it synchronizes IO on IA64/Altix systems
		 */
		mmiowb();
#endif /* !SPIN_UNLOCK_IMPLIES_MMIOWB */
	}
}

/**
 * idpf_tx_desc_count_required - calculate number of Tx descriptors needed
 * @txq: queue to send buffer on
 * @skb: send buffer
 * @bufs_needed: (output) number of buffers needed for this skb.
 *
 * Return: number of data descriptors and buffers needed for this skb.
 */
unsigned int idpf_tx_res_count_required(struct idpf_queue *txq,
					struct sk_buff *skb,
					u32 *bufs_needed)
{
	const struct skb_shared_info *shinfo;
	unsigned int count = 0, i;

	count += !!skb_headlen(skb);

	if (!skb_is_nonlinear(skb))
		return count;

	shinfo = skb_shinfo(skb);
	*bufs_needed += shinfo->nr_frags;
	for (i = 0; i < shinfo->nr_frags; i++) {
		unsigned int size;

		size = skb_frag_size(&shinfo->frags[i]);

		/* We only need to use the idpf_size_to_txd_count check if the
		 * fragment is going to span multiple descriptors,
		 * i.e. size >= 16K.
		 */
		if (size >= SZ_16K)
			count += idpf_size_to_txd_count(size);
		else
			count++;
	}

	if (idpf_chk_linearize(skb, txq->tx_max_bufs, count)) {
		if (__skb_linearize(skb))
			return 0;

		count = idpf_size_to_txd_count(skb->len);
		u64_stats_update_begin(&txq->stats_sync);
		u64_stats_inc(&txq->q_stats.tx.linearize);
		u64_stats_update_end(&txq->stats_sync);
	}

	return count;
}

/**
 * idpf_tx_splitq_bump_ntu - adjust NTU and generation
 * @txq: the tx ring to wrap
 * @ntu: ring index to bump
 */
static inline unsigned int idpf_tx_splitq_bump_ntu(struct idpf_queue *txq,
						   u16 ntu)
{
	ntu++;

	if (ntu == txq->desc_count)
		ntu = 0;

	return ntu;
}

/**
 * idpf_tx_splitq_pkt_err_unmap - Unmap buffers and bump tail in case of error
 * @txq: Tx queue to unwind
 * @params: pointer to splitq params struct
 * @first: starting buffer for packet to unmap
 */
static void idpf_tx_splitq_pkt_err_unmap(struct idpf_queue *txq,
					 struct idpf_tx_splitq_params *params,
					 struct idpf_tx_buf *first)
{
	struct idpf_sw_queue *refillq = txq->tx.refillq;
	struct libeth_sq_napi_stats ss = { };
	struct idpf_tx_buf *tx_buf = first;
	struct libeth_cq_pp cp = {
		.dev    = txq->dev,
		.ss     = &ss,
	};

	u64_stats_update_begin(&txq->stats_sync);
	u64_stats_inc(&txq->q_stats.tx.dma_map_errs);
	u64_stats_update_end(&txq->stats_sync);

	libeth_tx_complete(tx_buf, &cp);
	while (idpf_tx_buf_next(tx_buf) != IDPF_TXBUF_NULL) {
		tx_buf = &txq->tx.bufs[idpf_tx_buf_next(tx_buf)];
		libeth_tx_complete(tx_buf, &cp);
	}

	/* Update tail in case netdev_xmit_more was previously true. */
	idpf_tx_buf_hw_update(txq, params->prev_ntu, false);

	if (!refillq)
		return;

	/* Restore refillq state to avoid leaking tags. */
	if (params->prev_refill_gen != idpf_queue_has(RFL_GEN_CHK, refillq))
		idpf_queue_change(RFL_GEN_CHK, refillq);
	refillq->next_to_clean = params->prev_refill_ntc;
}

/**
 * idpf_tx_splitq_map - Build the Tx flex descriptor
 * @tx_q: queue to send buffer on
 * @params: pointer to splitq params struct
 * @first: first buffer info buffer to use
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit flex descriptor.
 */
static void idpf_tx_splitq_map(struct idpf_queue *tx_q,
			       struct idpf_tx_splitq_params *params,
			       struct idpf_tx_buf *first)
{
	union idpf_tx_flex_desc *tx_desc;
	unsigned int data_len, size;
	struct idpf_tx_buf *tx_buf;
	u16 i = tx_q->next_to_use;
	struct netdev_queue *nq;
	struct sk_buff *skb;
	skb_frag_t *frag;
	u32 next_buf_id;
	u16 td_cmd = 0;
	dma_addr_t dma;

	skb = first->skb;

	td_cmd = params->offload.td_cmd;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = IDPF_FLEX_TX_DESC(tx_q, i);

	dma = dma_map_single(tx_q->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;
	first->nr_frags = 0;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IDPF_TX_MAX_DESC_DATA_ALIGNED;

		if (unlikely(dma_mapping_error(tx_q->dev, dma))) {
			idpf_tx_buf_next(tx_buf) = IDPF_TXBUF_NULL;
			return idpf_tx_splitq_pkt_err_unmap(tx_q, params,
							    first);
		}

		first->nr_frags++;
		tx_buf->type = LIBETH_SQE_FRAG;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* buf_addr is in same location for both desc types */
		tx_desc->q.buf_addr = cpu_to_le64(dma);

		/* The stack can send us fragments that are too large for a
		 * single descriptor i.e. frag size > 16K-1. We will need to
		 * split the fragment across multiple descriptors in this case.
		 * To adhere to HW alignment restrictions, the fragment needs
		 * to be split such that the first chunk ends on a 4K boundary
		 * and all subsequent chunks start on a 4K boundary. We still
		 * want to send as much data as possible though, so our
		 * intermediate descriptor chunk size will be 12K.
		 *
		 * For example, consider a 32K fragment mapped to DMA addr 2600.
		 * ------------------------------------------------------------
		 * |                    frag_size = 32K                       |
		 * ------------------------------------------------------------
		 * |2600		  |16384	    |28672
		 *
		 * 3 descriptors will be used for this fragment. The HW expects
		 * the descriptors to contain the following:
		 * ------------------------------------------------------------
		 * | size = 13784         | size = 12K      | size = 6696     |
		 * | dma = 2600           | dma = 16384     | dma = 28672     |
		 * ------------------------------------------------------------
		 *
		 * We need to first adjust the max_data for the first chunk so
		 * that it ends on a 4K boundary. By negating the value of the
		 * DMA address and taking only the low order bits, we're
		 * effectively calculating
		 *	4K - (DMA addr lower order bits) =
		 *				bytes to next boundary.
		 *
		 * Add that to our base aligned max_data (12K) and we have
		 * our first chunk size. In the example above,
		 *	13784 = 12K + (4096-2600)
		 *
		 * After guaranteeing the first chunk ends on a 4K boundary, we
		 * will give the intermediate descriptors 12K chunks and
		 * whatever is left to the final descriptor. This ensures that
		 * all descriptors used for the remaining chunks of the
		 * fragment start on a 4K boundary and we use as few
		 * descriptors as possible.
		 */
		max_data += -dma & (IDPF_TX_MAX_READ_REQ_SIZE - 1);
		while (unlikely(size > IDPF_TX_MAX_DESC_DATA)) {
			idpf_tx_splitq_build_desc(tx_desc, params, td_cmd,
						  max_data);

			if (unlikely(++i == tx_q->desc_count)) {
				tx_desc = IDPF_FLEX_TX_DESC(tx_q, 0);
				i = 0;
			} else {
				tx_desc++;
			}

			/* Adjust the DMA offset and the remaining size of the
			 * fragment.  On the first iteration of this loop,
			 * max_data will be >= 12K and <= 16K-1.  On any
			 * subsequent iteration of this loop, max_data will
			 * always be 12K.
			 */
			dma += max_data;
			size -= max_data;

			/* Reset max_data since remaining chunks will be 12K
			 * at most
			 */
			max_data = IDPF_TX_MAX_DESC_DATA_ALIGNED;

			/* buf_addr is in same location for both desc types */
			tx_desc->q.buf_addr = cpu_to_le64(dma);
		}

		if (!data_len)
			break;

		idpf_tx_splitq_build_desc(tx_desc, params, td_cmd, size);

		if (unlikely(++i == tx_q->desc_count)) {
			tx_desc = IDPF_FLEX_TX_DESC(tx_q, 0);
			i = 0;
		} else {
			tx_desc++;
		}

		if (idpf_queue_has(FLOW_SCH_EN, tx_q)) {
			if (unlikely(!idpf_tx_get_free_buf_id(tx_q->tx.refillq,
							      &next_buf_id))) {
				idpf_tx_buf_next(tx_buf) = IDPF_TXBUF_NULL;
				return idpf_tx_splitq_pkt_err_unmap(tx_q, params,
								    first);
			}
		} else {
			next_buf_id = i;
		}
		idpf_tx_buf_next(tx_buf) = next_buf_id;
		tx_buf = &tx_q->tx.bufs[next_buf_id];

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_q->dev, frag, 0, size,
				       DMA_TO_DEVICE);
	}

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(skb);

	first->type = LIBETH_SQE_SKB;
	if (params->offload.tx_flags & IDPF_TX_FLAGS_TSYN)
		first->type = (enum libeth_sqe_type)LIBETH_SQE_SKB_TSTAMP;

	/* write last descriptor with RS and EOP bits */
	first->rs_idx = i;
	idpf_tx_buf_next(tx_buf) = IDPF_TXBUF_NULL;
	td_cmd |= params->eop_cmd;
	idpf_tx_splitq_build_desc(tx_desc, params, td_cmd, size);
	i = idpf_tx_splitq_bump_ntu(tx_q, i);

	tx_q->txq_grp->num_completions_pending++;

	/* record bytecount for BQL */
	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_sent_queue(nq, first->bytes);

	idpf_tx_buf_hw_update(tx_q, i, netdev_xmit_more());
}

/**
 * idpf_tso - computes mss and TSO length to prepare for TSO
 * @skb: pointer to skb
 * @off: pointer to struct that holds offload parameters
 *
 * Returns error (negative) if TSO was requested but cannot be applied to the
 * given skb, 0 if TSO does not apply to the given skb, or 1 otherwise.
 */
int idpf_tso(struct sk_buff *skb, struct idpf_tx_offload_params *off)
{
	const struct skb_shared_info *shinfo;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	u32 paylen, l4_start;
	int err;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	shinfo = skb_shinfo(skb);

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize outer IP header fields */
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else if (ip.v6->version == 6) {
		ip.v6->payload_len = 0;
	}

	l4_start = skb_transport_offset(skb);

	/* remove payload length from checksum */
	paylen = skb->len - l4_start;

	switch (shinfo->gso_type & ~SKB_GSO_DODGY) {
	case SKB_GSO_TCPV4:
	case SKB_GSO_TCPV6:
		csum_replace_by_diff(&l4.tcp->check,
				     (__force __wsum)htonl(paylen));
		off->tso_hdr_len = __tcp_hdrlen(l4.tcp) + l4_start;
		break;
#ifdef NETIF_F_GSO_UDP_L4
	case SKB_GSO_UDP_L4:
		csum_replace_by_diff(&l4.udp->check,
				     (__force __wsum)htonl(paylen));
		off->tso_hdr_len = sizeof(struct udphdr) + l4_start;
		l4.udp->len = htons(shinfo->gso_size + sizeof(struct udphdr));
		break;
#endif /* NETIF_F_GSO_UDP_L4 */
	default:
		return -EINVAL;
	}

	off->tso_len = skb->len - off->tso_hdr_len;
	off->mss = shinfo->gso_size;
	off->tso_segs = shinfo->gso_segs;

	off->tx_flags |= IDPF_TX_FLAGS_TSO;

	return 1;
}

/**
 * idpf_get_flow_sche_tstamp - fetch timestamp from SKB for
 * flow scheduling offload
 * @skb: send buffer to extract timestamp from
 * @txq: pointer to txq
 * @offload: pointer to offload parameters struct
 */
static void idpf_get_flow_sche_tstamp(struct sk_buff *skb,
				      struct idpf_queue *txq,
				      struct idpf_tx_offload_params *offload)
{
	struct idpf_adapter *adapter = txq->vport->adapter;
#ifdef HAVE_ETF_SUPPORT
	u64 ts_ns = skb->skb_mstamp_ns;
#else
	u64 ts_ns = ktime_to_ns(skb->tstamp);
#endif /* HAVE_ETF_SUPPORT */
	u64 cur_time, ts_val;

	if (unlikely(adapter->dev_ops.reg_ops.read_master_time))
		cur_time =
			adapter->dev_ops.reg_ops.read_master_time(&adapter->hw);
	else
	/* When PTM support is enabled host time will be synced with
	 * master timer.
	 */
	cur_time = ktime_get_real_ns();

	/* The format of the timestamp is the 23 least significant bits of
	 * absolute time in units of X ns. Bit 23 indicates overflow if the
	 * given timestamp is beyond current horizon. Zero means no timestamp,
	 * so if the 23 lsb and overflow bit are zero, the timestamp should be
	 * written as 1.
	 */
	if (!ts_ns) {
		offload->desc_ts[0] = 0x1;

		return;
	}

	if (ts_ns > cur_time + txq->vport->tw_horizon) {
		/* Set only the SW overflow bit for the whole timestamp field */
		offload->desc_ts[2] = IDPF_TXD_FLOW_SCH_HORIZON_OVERFLOW_M;

		return;
	}

	ts_val = max(ts_ns, cur_time) >> txq->vport->tw_ts_gran_s;
	offload->desc_ts[0] = FIELD_GET(0xff, ts_val);
	offload->desc_ts[1] = FIELD_GET(0xff, ts_val >> 8);
	offload->desc_ts[2] = FIELD_GET(0x7f, ts_val >> 16);
}

#ifdef IDPF_ADD_PROBES
/**
 * idpf_tx_extra_counters - Add more tx queue stats
 * @txq: transmit queue
 * @tx_buf: send buffer
 * @off: pointer to offloads struct
 *
 * Increments additional offload counters
 */
void idpf_tx_extra_counters(struct idpf_queue *txq, struct idpf_tx_buf *tx_buf,
			    struct idpf_tx_offload_params *off)
{
	struct idpf_extra_stats *extra_stats =
		&txq->vport->port_stats.extra_stats;
	struct sk_buff *skb = tx_buf->skb;
	u8 l4_proto = 0;
	__be16 protocol;

	protocol = vlan_get_protocol(skb);

	u64_stats_update_begin(&txq->vport->port_stats.stats_sync);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (protocol == htons(ETH_P_IP)) {
			struct iphdr *v4 =
				(struct iphdr *)skb_network_header(skb);

			u64_stats_inc(&extra_stats->tx_ip4_cso);
			l4_proto = v4->protocol;
		} else if (protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *v6 =
				(struct ipv6hdr *)skb_network_header(skb);

			l4_proto = v6->nexthdr;
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
			u64_stats_inc(&extra_stats->tx_udp_cso);
			break;
		case IPPROTO_TCP:
			u64_stats_inc(&extra_stats->tx_tcp_cso);
			break;
		case IPPROTO_SCTP:
			u64_stats_inc(&extra_stats->tx_sctp_cso);
		default:
			break;
		}
	}

	if (off->tx_flags & IDPF_TX_FLAGS_TSO) {
#ifdef NETIF_F_GSO_UDP_L4
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			u64_stats_add(&extra_stats->tx_udp_segs,
				      tx_buf->packets);
		else
#endif /* NETIF_F_GSO_UDP_L4 */
			u64_stats_add(&extra_stats->tx_tcp_segs,
				      tx_buf->packets);
	}
	u64_stats_update_end(&txq->vport->port_stats.stats_sync);
}

#endif /* IDPF_ADD_PROBES */
/**
 * idpf_tx_splitq_get_ctx_desc - grab next desc and update buffer ring
 * @txq: queue to put context descriptor on
 *
 * Since the TX buffer rings mimics the descriptor ring, update the tx buffer
 * ring entry to reflect that this index is a context descriptor
 */
static union idpf_flex_tx_ctx_desc *
idpf_tx_splitq_get_ctx_desc(struct idpf_queue *txq)
{
	union idpf_flex_tx_ctx_desc *desc;
	int i = txq->next_to_use;

	/* grab the next descriptor */
	desc = IDPF_FLEX_TX_CTX_DESC(txq, i);
	txq->next_to_use = idpf_tx_splitq_bump_ntu(txq, i);

	return desc;
}

/**
 * idpf_tx_drop_skb - free the SKB and bump tail if necessary
 * @tx_q: queue to send buffer on
 * @skb: pointer to skb
 */
netdev_tx_t idpf_tx_drop_skb(struct idpf_queue *tx_q, struct sk_buff *skb)
{
	u64_stats_update_begin(&tx_q->stats_sync);
	u64_stats_inc(&tx_q->q_stats.tx.skb_drops);
	u64_stats_update_end(&tx_q->stats_sync);

	idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
/**
 * idpf_tx_tstamp - set up context descriptor for hardware timestamp
 * @tx_q: queue to send buffer on
 * @skb: pointer to the SKB we're sending
 * @off: pointer to the offload struct
 *
 * Return: Positive index number on success, negative otherwise.
 */
int idpf_tx_tstamp(struct idpf_queue *tx_q, struct sk_buff *skb,
		   struct idpf_tx_offload_params *off)
{
	int err;
	u32 idx;

	/* only timestamp the outbound packet if the user has requested it */
	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)))
		return -1;

	if (!idpf_ptp_get_txq_tstamp_capability(tx_q))
		return -1;

	/* Tx timestamps cannot be sampled when doing TSO */
	if (off->tx_flags & IDPF_TX_FLAGS_TSO)
		return -1;

	/* Grab an open timestamp slot */
	err = idpf_ptp_request_ts(tx_q, skb, &idx);
	if (err)
		return -1;

	off->tx_flags |= IDPF_TX_FLAGS_TSYN;

	return idx;
}

/**
 * idpf_tx_set_tstamp_desc - Set the Tx descriptor fields needed to generate
 *			     PHY Tx timestamp
 * @ctx_desc: Context descriptor
 * @idx: Index of the Tx timestamp latch
 */
void idpf_tx_set_tstamp_desc(union idpf_flex_tx_ctx_desc *ctx_desc, u32 idx)
{
	ctx_desc->tsyn.qw1.cmd_dtype =
		cpu_to_le16(FIELD_PREP(IDPF_TXD_QW1_CMD_M,
				       IDPF_TX_CTX_DESC_TSYN));
	ctx_desc->tsyn.qw1.cmd_dtype |=
		cpu_to_le16(FIELD_PREP(IDPF_TXD_QW1_DTYPE_M,
				       IDPF_TX_DESC_DTYPE_CTX));
	ctx_desc->tsyn.qw1.tsyn_reg_l =
		cpu_to_le16(FIELD_PREP(IDPF_TX_DESC_CTX_TSYN_L_M,
				       idx));
	ctx_desc->tsyn.qw1.tsyn_reg_h =
		cpu_to_le16(FIELD_PREP(IDPF_TX_DESC_CTX_TSYN_H_M,
				       idx >> 2));
}
#endif /* CONFIG_PTP_1588_CLOCK && CONFIG_PTP */

/**
 * idpf_tx_splitq_need_re - check whether RE bit needs to be set
 * @tx_q: the tx ring to verify
 *
 * Return: true if RE bit needs to be set, false otherwise
 */
static inline bool idpf_tx_splitq_need_re(struct idpf_queue *tx_q)
{
	int gap = tx_q->next_to_use - tx_q->tx.last_re;

	gap += (gap < 0) ? tx_q->desc_count : 0;

	return gap >= IDPF_TX_SPLITQ_RE_MIN_GAP;
}

/**
 * idpf_tx_prepare_vlan_tag - prepare context descriptor with VLAN tag
 * @tx_q: TX queue to get the next available descriptor
 * @skb: send buffer to extract the VLAN tag
 */
static void idpf_tx_prepare_vlan_tag(struct idpf_queue *tx_q,
				     struct sk_buff *skb)
{
	union idpf_flex_tx_ctx_desc *ctx_desc;
	u64 qw1;

	qw1 = FIELD_PREP(IDPF_TX_FLEX_CTX_DTYPE_M,
			 IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_CTX) |
	      IDPF_TX_FLEX_CTX_DESC_CMD_L2TAG1 |
	      FIELD_PREP(IDPF_TX_FLEX_CTX_L2TAG1_M, skb_vlan_tag_get(skb));

	ctx_desc = idpf_tx_splitq_get_ctx_desc(tx_q);
	ctx_desc->qw1 = cpu_to_le64(qw1);
}

/**
 * idpf_tx_splitq_frame - Sends buffer on Tx ring using flex descriptors
 * @skb: send buffer
 * @tx_q: queue to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t idpf_tx_splitq_frame(struct sk_buff *skb,
					struct idpf_queue *tx_q)
{
	struct idpf_tx_splitq_params tx_params = {
		.prev_ntu = tx_q->next_to_use,
	};
	int vlan_tag = skb_vlan_tag_present(skb);
	union idpf_flex_tx_ctx_desc *ctx_desc;
	struct idpf_tx_buf *first;
	u32 count, buf_count = 1;
	u32 buf_id;
	int tso;
	int idx;

	count = idpf_tx_res_count_required(tx_q, skb, &buf_count);
	if (unlikely(!count))
		return idpf_tx_drop_skb(tx_q, skb);

	tso = idpf_tso(skb, &tx_params.offload);
	if (unlikely(tso < 0))
		return idpf_tx_drop_skb(tx_q, skb);

	/* Check for splitq specific TX resources */
	count += tso + vlan_tag;
	if (idpf_tx_maybe_stop_splitq(tx_q, count, buf_count)) {
		idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);
		return NETDEV_TX_BUSY;
	}

	if (tso) {
		/* If tso is needed, set up context desc */
		u16 seg_idx = min_t(u16, IDPF_MAX_SEGS,
				    tx_params.offload.tso_segs) - 1;
		ctx_desc = idpf_tx_splitq_get_ctx_desc(tx_q);

		ctx_desc->tso.qw1.cmd_dtype =
				cpu_to_le16(IDPF_TX_DESC_DTYPE_FLEX_TSO_CTX |
					    IDPF_TX_FLEX_CTX_DESC_CMD_TSO);
		ctx_desc->tso.qw0.flex_tlen =
				cpu_to_le32(tx_params.offload.tso_len &
					    IDPF_TXD_FLEX_CTX_TLEN_M);
		ctx_desc->tso.qw0.mss_rt =
				cpu_to_le16(tx_params.offload.mss &
					    IDPF_TXD_FLEX_CTX_MSS_RT_M);
		ctx_desc->tso.qw0.hdr_len = tx_params.offload.tso_hdr_len;

		u64_stats_update_begin(&tx_q->stats_sync);
		u64_stats_inc(&tx_q->q_stats.tx.lso_pkts);
		u64_stats_add(&tx_q->q_stats.tx.lso_segs_tot,
			      tx_params.offload.tso_segs);
		u64_stats_add(&tx_q->q_stats.tx.lso_bytes, skb->data_len);
		u64_stats_inc(&tx_q->q_stats.tx.segs[seg_idx]);
		u64_stats_update_end(&tx_q->stats_sync);
	}

	/* According to HW packet rules, context descriptor order should be:
	 * TSO context descriptor followed by non TSO context descriptors.
	 */
	if (vlan_tag)
		idpf_tx_prepare_vlan_tag(tx_q, skb);

	idx = idpf_tx_tstamp(tx_q, skb, &tx_params.offload);
	if (idx != -1) {
		ctx_desc = idpf_tx_splitq_get_ctx_desc(tx_q);
		idpf_tx_set_tstamp_desc(ctx_desc, idx);
	}

	if (idpf_queue_has(FLOW_SCH_EN, tx_q)) {
		struct idpf_sw_queue *refillq = tx_q->tx.refillq;
		if (unlikely(idpf_queue_has(ETF_EN, tx_q)))
			idpf_get_flow_sche_tstamp(skb, tx_q, &tx_params.offload);

		/* Save refillq state in case of a packet rollback.  Otherwise,
		 * the tags will be leaked since they will be popped from the
		 * refillq but never reposted during cleaning.
		 */
		tx_params.prev_refill_gen =
			idpf_queue_has(RFL_GEN_CHK, refillq);
		tx_params.prev_refill_ntc = refillq->next_to_clean;

		if (unlikely(!idpf_tx_get_free_buf_id(tx_q->tx.refillq,
						      &buf_id))) {
			if (tx_params.prev_refill_gen !=
			    idpf_queue_has(RFL_GEN_CHK, refillq))
				idpf_queue_change(RFL_GEN_CHK, refillq);
			refillq->next_to_clean = tx_params.prev_refill_ntc;

			tx_q->next_to_use = tx_params.prev_ntu;
			return idpf_tx_drop_skb(tx_q, skb);
		}
		tx_params.compl_tag = buf_id;

		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_params.eop_cmd = IDPF_TXD_FLEX_FLOW_CMD_EOP;
		/* Set the RE bit to periodically "clean" the descriptor ring.
		 * MIN_GAP is set to MIN_RING size to ensure it will be set at
		 * least once each time around the ring.
		 */
		if (idpf_tx_splitq_need_re(tx_q)) {
			tx_params.eop_cmd |= IDPF_TXD_FLEX_FLOW_CMD_RE;
			tx_q->txq_grp->num_completions_pending++;
			tx_q->tx.last_re = tx_q->next_to_use;
		}

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_params.offload.td_cmd |= IDPF_TXD_FLEX_FLOW_CMD_CS_EN;

	} else {
		buf_id = tx_q->next_to_use;

		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_params.eop_cmd = IDPF_TXD_LAST_DESC_CMD;

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_params.offload.td_cmd |= IDPF_TX_FLEX_DESC_CMD_CS_EN;
	}

	first = &tx_q->tx.bufs[buf_id];
	first->skb = skb;

	if (tso) {
		first->packets = tx_params.offload.tso_segs;
		first->bytes = skb->len +
			((first->packets - 1) * tx_params.offload.tso_hdr_len);
	} else {
		first->packets = 1;
		first->bytes = max_t(unsigned int, skb->len, ETH_ZLEN);
	}

#ifdef IDPF_ADD_PROBES
	idpf_tx_extra_counters(tx_q, first, &tx_params.offload);

#endif /* IDPF_ADD_PROBES */
	idpf_tx_splitq_map(tx_q, &tx_params, first);

	return NETDEV_TX_OK;
}

/**
 * idpf_tx_splitq_start - Selects the right Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t idpf_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_queue *tx_q;

	if (unlikely(skb_get_queue_mapping(skb) >= vport->num_txq)) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	tx_q = vport->txqs[skb_get_queue_mapping(skb)];

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, tx_q->tx_min_pkt_len)) {
		idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);
		return NETDEV_TX_OK;
	}

	return idpf_tx_splitq_frame(skb, tx_q);
}

/**
 * idpf_ptype_to_htype - get a hash type
 * @decoded: Decoded Rx packet type related fields
 *
 * Returns appropriate hash type (such as PKT_HASH_TYPE_L2/L3/L4) to be used by
 * skb_set_hash based on PTYPE as parsed by HW Rx pipeline and is part of
 * Rx desc.
 */
enum
pkt_hash_types idpf_ptype_to_htype(const struct idpf_rx_ptype_decoded *decoded)
{
	if (!decoded->known)
		return PKT_HASH_TYPE_NONE;
	if (decoded->payload_layer == IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2 &&
	    decoded->inner_prot)
		return PKT_HASH_TYPE_L4;
	if (decoded->payload_layer == IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2 &&
	    decoded->outer_ip)
		return PKT_HASH_TYPE_L3;
	if (decoded->outer_ip == IDPF_RX_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

/**
 * idpf_rx_hash - set the hash value in the skb
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @rx_desc: Receive descriptor
 * @decoded: Decoded Rx packet type related fields
 */
static void idpf_rx_hash(struct idpf_queue *rxq, struct sk_buff *skb,
			 struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
			 struct idpf_rx_ptype_decoded *decoded)
{
	u32 hash;

	if (unlikely(!idpf_is_feature_ena(rxq->vport, NETIF_F_RXHASH)))
		return;

	hash = le16_to_cpu(rx_desc->hash1) |
	       (rx_desc->ff2_mirrid_hash2.hash2 << 16) |
	       (rx_desc->hash3 << 24);

	skb_set_hash(skb, hash, idpf_ptype_to_htype(decoded));
}

#ifdef IDPF_ADD_PROBES
/**
 * idpf_rx_extra_counters - Add more stats counters
 * @rxq: receive queue
 * @inner_prot: packet inner protocol
 * @ipv4: is ipv4
 * @csum_bits: checksum fields extracted from the descriptor
 * @splitq: is splitq or singleq
 *
 * Increments additional offload counters.
 */
void idpf_rx_extra_counters(struct idpf_queue *rxq, u32 inner_prot,
			    bool ipv4, struct idpf_rx_csum_decoded *csum_bits,
			    bool splitq)
{
	struct idpf_extra_stats *extra_stats =
					&rxq->vport->port_stats.extra_stats;

	u64_stats_update_begin(&rxq->vport->port_stats.stats_sync);
	if (ipv4) {
		if (csum_bits->ipe | csum_bits->eipe)
			u64_stats_inc(&extra_stats->rx_ip4_cso_err);
		u64_stats_inc(&extra_stats->rx_ip4_cso);
	}

	if (csum_bits->l4e) {
		switch (inner_prot) {
		case IDPF_RX_PTYPE_INNER_PROT_TCP:
			u64_stats_inc(&extra_stats->rx_tcp_cso_err);
			break;
		case IDPF_RX_PTYPE_INNER_PROT_UDP:
			u64_stats_inc(&extra_stats->rx_udp_cso_err);
			break;
		case IDPF_RX_PTYPE_INNER_PROT_SCTP:
			u64_stats_inc(&extra_stats->rx_sctp_cso_err);
			break;
		default:
			break;
		}
	}

	switch (inner_prot) {
	case IDPF_RX_PTYPE_INNER_PROT_TCP:
		u64_stats_inc(&extra_stats->rx_tcp_cso);
		break;
	case IDPF_RX_PTYPE_INNER_PROT_UDP:
		u64_stats_inc(&extra_stats->rx_udp_cso);
		break;
	case IDPF_RX_PTYPE_INNER_PROT_SCTP:
		u64_stats_inc(&extra_stats->rx_sctp_cso);
		break;
	default:
		break;
	}
	u64_stats_update_end(&rxq->vport->port_stats.stats_sync);
}

#endif /* IDPF_ADD_PROBES */
/**
 * idpf_rx_csum - Indicate in skb if checksum is good
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @csum_bits: checksum fields extracted from the descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * skb->protocol must be set before this function is called
 */
static void idpf_rx_csum(struct idpf_queue *rxq, struct sk_buff *skb,
			 struct idpf_rx_csum_decoded *csum_bits,
			 struct idpf_rx_ptype_decoded *decoded)
{
#ifdef IDPF_ADD_PROBES
	struct idpf_port_stats *port_stats = &rxq->vport->port_stats;
#endif /* IDPF_ADD_PROBES */
	bool ipv4, ipv6;

	/* check if Rx checksum is enabled */
	if (unlikely(!idpf_is_feature_ena(rxq->vport, NETIF_F_RXCSUM)))
		return;

	/* check if HW has decoded the packet and checksum */
	if (!(csum_bits->l3l4p))
		return;

	ipv4 = IDPF_RX_PTYPE_TO_IPV(decoded, IDPF_RX_PTYPE_OUTER_IPV4);
	ipv6 = IDPF_RX_PTYPE_TO_IPV(decoded, IDPF_RX_PTYPE_OUTER_IPV6);

#ifdef IDPF_ADD_PROBES
	idpf_rx_extra_counters(rxq, decoded->inner_prot, ipv4, csum_bits,
			       true);

#endif /* IDPF_ADD_PROBES */
	if (ipv4 && (csum_bits->ipe || csum_bits->eipe))
		goto checksum_fail;

	if (ipv6 && csum_bits->ipv6exadd)
		return;

	/* HW checksum will be invalid if vlan stripping is not enabled and
	 * packet has an outer vlan tag. raw_csum_inv will also not be set
	 * even though it's invalid.
	 */
	if (unlikely(eth_type_vlan(skb->protocol)))
		return;

	/* check for L4 errors and handle packets that were not able to be
	 * checksummed
	 */
	if (csum_bits->l4e)
		goto checksum_fail;

#ifdef IDPF_ADD_PROBES
	u64_stats_update_begin(&port_stats->stats_sync);
#endif /* IDPF_ADD_PROBES */
	/* Only report checksum unnecessary for ICMP, TCP, UDP, or SCTP */
	switch (decoded->inner_prot) {
	case IDPF_RX_PTYPE_INNER_PROT_ICMP:
	case IDPF_RX_PTYPE_INNER_PROT_TCP:
	case IDPF_RX_PTYPE_INNER_PROT_UDP:
		if (!csum_bits->raw_csum_inv) {
			u16 csum = csum_bits->raw_csum;

			skb->csum = csum_unfold((__force __sum16)~swab16(csum));
			skb->ip_summed = rxq->gen_rxcsum_status;
#ifdef IDPF_ADD_PROBES
			u64_stats_inc(&port_stats->extra_stats.rx_csum_complete);
#endif /* IDPF_ADD_PROBES */
		} else {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef IDPF_ADD_PROBES
			u64_stats_inc(&port_stats->extra_stats.rx_csum_unnecessary);
#endif /* IDPF_ADD_PROBES */
		}
		break;
	case IDPF_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef IDPF_ADD_PROBES
		u64_stats_inc(&port_stats->extra_stats.rx_csum_unnecessary);
#endif /* IDPF_ADD_PROBES */
		break;
	default:
		break;
	}
#ifdef IDPF_ADD_PROBES
	u64_stats_update_end(&port_stats->stats_sync);
#endif /* IDPF_ADD_PROBES */

	return;

checksum_fail:
	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_inc(&rxq->q_stats.rx.hw_csum_err);
	u64_stats_update_end(&rxq->stats_sync);
}

/**
 * idpf_rx_splitq_extract_csum_bits - Extract checksum bits from descriptor
 * @rx_desc: receive descriptor
 * @csum: structure to extract checksum fields
 *
 **/
static void idpf_rx_splitq_extract_csum_bits(struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
					     struct idpf_rx_csum_decoded *csum)
{
	u8 qword0, qword1;

	qword0 = rx_desc->status_err0_qw0;
	qword1 = rx_desc->status_err0_qw1;

	csum->ipe = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_IPE_M,
			      qword1);
	csum->eipe = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EIPE_M,
			       qword1);
	csum->l4e = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_L4E_M,
			      qword1);
	csum->l3l4p = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L3L4P_M,
				qword1);
	csum->ipv6exadd = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_IPV6EXADD_M,
				    qword0);
	csum->raw_csum_inv =
		le16_get_bits(rx_desc->ptype_err_fflags0,
			      VIRTCHNL2_RX_FLEX_DESC_ADV_RAW_CSUM_INV_M);
	csum->raw_csum = le16_to_cpu(rx_desc->misc.raw_cs);
}

/**
 * idpf_rx_rsc - Set the RSC fields in the skb
 * @rxq : Rx descriptor ring packet is being transacted on
 * @skb : pointer to current skb being populated
 * @rx_desc: Receive descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * Return 0 on success and error code on failure
 *
 * Populate the skb fields with the total number of RSC segments, RSC payload
 * length and packet type.
 */
static int idpf_rx_rsc(struct idpf_queue *rxq, struct sk_buff *skb,
		       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
		       struct idpf_rx_ptype_decoded *decoded)
{
	u16 rsc_segments, rsc_seg_len;
	u16 rsc_seg_stat;
	bool ipv4, ipv6;
	int len;

	if (unlikely(!decoded->outer_ip))
		return -EINVAL;

	rsc_seg_len = le16_to_cpu(rx_desc->misc.rscseglen);
	if (unlikely(!rsc_seg_len))
		return -EINVAL;

	ipv4 = IDPF_RX_PTYPE_TO_IPV(decoded, IDPF_RX_PTYPE_OUTER_IPV4);
	ipv6 = IDPF_RX_PTYPE_TO_IPV(decoded, IDPF_RX_PTYPE_OUTER_IPV6);

	if (unlikely(!(ipv4 ^ ipv6)))
		return -EINVAL;

	rsc_segments = DIV_ROUND_UP(skb->data_len, rsc_seg_len);
	if (unlikely(rsc_segments == 1))
		return 0;

	NAPI_GRO_CB(skb)->count = rsc_segments;
	skb_shinfo(skb)->gso_size = rsc_seg_len;

	skb_reset_network_header(skb);

	if (ipv4) {
		struct iphdr *ipv4h = ip_hdr(skb);

#ifdef SIMICS_BUILD
		ipv4h->check = 0;
		ipv4h->check = ip_fast_csum((u8 *)ipv4h, ipv4h->ihl);
#endif /* SIMICS_BUILD */
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

		/* Reset and set transport header offset in skb */
		skb_set_transport_header(skb, sizeof(struct iphdr));
		len = skb->len - skb_transport_offset(skb);

		/* Compute the TCP pseudo header checksum*/
		tcp_hdr(skb)->check =
			~tcp_v4_check(len, ipv4h->saddr, ipv4h->daddr, 0);
	} else {
		struct ipv6hdr *ipv6h = ipv6_hdr(skb);

		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));
		len = skb->len - skb_transport_offset(skb);
		tcp_hdr(skb)->check =
			~tcp_v6_check(len, &ipv6h->saddr, &ipv6h->daddr, 0);
	}

	tcp_gro_complete(skb);

	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_inc(&rxq->q_stats.rx.rsc_pkts);
	rsc_seg_stat = min_t(u16, IDPF_MAX_SEGS, rsc_segments) - 1;
	u64_stats_inc(&rxq->q_stats.rx.segs[rsc_seg_stat]);
	u64_stats_add(&rxq->q_stats.rx.rsc_segs_tot, rsc_segments);
	u64_stats_add(&rxq->q_stats.rx.rsc_bytes, skb->data_len);
	u64_stats_update_end(&rxq->stats_sync);

	return 0;
}

/**
 * idpf_rx_hwtstamp - check for an RX timestamp and pass up
 *		      the stack
 * @rxq: pointer to the rx queue that receives the timestamp
 * @rx_desc: pointer to rx descritpor containing timestamp
 * @skb: skb to put timestamp in
 */
static void idpf_rx_hwtstamp(struct idpf_queue *rxq,
			     struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
			     struct sk_buff *skb)
{
	u64 cached_time, ts_ns;
	u32 ts_high;

	if (!(rx_desc->ts_low & VIRTCHNL2_RX_FLEX_TSTAMP_VALID))
		return;

	cached_time = READ_ONCE(*rxq->cached_phc_time);

	ts_high = le32_to_cpu(rx_desc->ts_high);
	ts_ns = idpf_ptp_tstamp_extend_32b_to_64b(cached_time, ts_high);

	*skb_hwtstamps(skb) = (struct skb_shared_hwtstamps) {
		.hwtstamp = ns_to_ktime(ts_ns),
	};
}

/**
 * idpf_rx_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @rx_desc: Receive descriptor
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, protocol, and
 * other fields within the skb.
 */
int idpf_rx_process_skb_fields(struct idpf_queue *rxq,
			       struct sk_buff *skb,
			       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	struct idpf_rx_csum_decoded csum_bits = { };
	struct idpf_rx_ptype_decoded decoded;
	u16 rx_ptype;

	rx_ptype = le16_get_bits(rx_desc->ptype_err_fflags0,
				 VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_M);

	skb->protocol = eth_type_trans(skb, rxq->vport->netdev);

	decoded = rxq->vport->rx_ptype_lkup[rx_ptype];
#ifdef IDPF_ADD_PROBES
	u64_stats_update_begin(&rxq->vport->port_stats.stats_sync);
	u64_stats_inc(&rxq->vport->ptype_stats[rx_ptype]);
	u64_stats_update_end(&rxq->vport->port_stats.stats_sync);
#endif /* IDPF_ADD_PROBES */
	/* If we don't know the ptype we can't do anything else with it. Just
	 * pass it up the stack as-is.
	 */
	if (!decoded.known)
		return 0;

	/* process RSS/hash */
	idpf_rx_hash(rxq, skb, rx_desc, &decoded);
	if (!rxq->tstmp_en)
		goto skip_tstamp;

	idpf_rx_hwtstamp(rxq, rx_desc, skb);

skip_tstamp:
	if (le16_get_bits(rx_desc->hdrlen_flags,
			  VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_M))
		return idpf_rx_rsc(rxq, skb, rx_desc, &decoded);

	idpf_rx_splitq_extract_csum_bits(rx_desc, &csum_bits);
	idpf_rx_csum(rxq, skb, &csum_bits, &decoded);

	return 0;
}

/**
 * idpf_rx_buf_adjust_pg - Prepare rx buffer for reuse
 * @rx_buf: Rx buffer to adjust
 * @size: Size of adjustment
 *
 * Update the offset within page so that rx buf will be ready to be reused.
 * For systems with PAGE_SIZE < 8192 this function will flip the page offset
 * so the second half of page assigned to rx buffer will be used, otherwise
 * the offset is moved by the @size bytes
 */
#ifdef HAVE_XDP_SUPPORT
void idpf_rx_buf_adjust_pg(struct idpf_rx_buf *rx_buf, unsigned int size)
#endif /* HAVE_XDP_SUPPORT */
{
	struct idpf_page_info *pinfo;

	pinfo = &rx_buf->page_info[rx_buf->page_indx];

	if (PAGE_SIZE < 8192)
		if (rx_buf->buf_size > IDPF_RX_BUF_2048)
			/* flip to second page */
			rx_buf->page_indx = !rx_buf->page_indx;
		else
			/* flip page offset to other buffer */
			pinfo->page_offset ^= size;
	else
		/* move offset up to the next cache line */
		pinfo->page_offset += size;
}

/**
 * idpf_rx_can_reuse_page - Determine if page can be reused for another rx
 * @rx_buf: buffer containing the page
 *
 * If page is reusable, we have a green light for calling idpf_reuse_rx_page,
 * which will assign the current buffer to the buffer that next_to_alloc is
 * pointing to; otherwise, the dma mapping needs to be destroyed and
 * page freed
 */
bool idpf_rx_can_reuse_page(struct idpf_rx_buf *rx_buf)
{
	unsigned int last_offset = PAGE_SIZE - rx_buf->buf_size;
	struct idpf_page_info *pinfo;
	unsigned int pagecnt_bias;
	struct page *page;

	pinfo = &rx_buf->page_info[rx_buf->page_indx];
	pagecnt_bias = pinfo->pagecnt_bias;
	page = pinfo->page;

	if (unlikely(!dev_page_is_reusable(page)))
		return false;

	if (PAGE_SIZE < 8192) {
		if (unlikely((page_count(page) - pagecnt_bias) >
			     pinfo->reuse_bias))
			return false;
	} else if (pinfo->page_offset > last_offset) {
		return false;
	}

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (unlikely(pagecnt_bias == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		pinfo->pagecnt_bias = USHRT_MAX;
	}
#else
	if (likely(!pagecnt_bias)) {
		get_page(page);
		pinfo->pagecnt_bias = 1;
	}
#endif

	return true;
}

/**
 * idpf_rx_frame_truesize - Returns an actual size of Rx frame in memory
 * @buf: pointer to buffer metadata struct
 * @size: Packet length from rx_desc
 *
 * Returns an actual size of Rx frame in memory, considering page size
 * and SKB data alignment.
 */
static unsigned int idpf_rx_frame_truesize(struct idpf_rx_buf *buf,
					   unsigned int size)
{
	return PAGE_SIZE >= 8192 ? SKB_DATA_ALIGN(size) : buf->buf_size;
}

/**
 * idpf_rx_add_frag - Add contents of Rx buffer to sk_buff as a frag
 * @rx_buf: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buf->page to the skb.
 * It will just attach the page as a frag to the skb.
 * The function will then update the page offset.
 */
void idpf_rx_add_frag(struct idpf_rx_buf *rx_buf, struct sk_buff *skb,
		      unsigned int size)
{
	unsigned int truesize = idpf_rx_frame_truesize(rx_buf, size);
	struct idpf_page_info *pinfo;

	pinfo = &rx_buf->page_info[rx_buf->page_indx];
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, pinfo->page,
			pinfo->page_offset, size, truesize);

	idpf_rx_buf_adjust_pg(rx_buf, truesize);
}

/**
 * idpf_rx_get_buf_page - Fetch Rx buffer page and synchronize data for use
 * @dev: device struct
 * @rx_buf: Rx buf to fetch page for
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer page from the ring and synchronize it
 * for use by the CPU.
 */
void idpf_rx_get_buf_page(struct device *dev, struct idpf_rx_buf *rx_buf,
			  const unsigned int size)
{
	struct idpf_page_info *pinfo;
	u32 offset;

	pinfo = &rx_buf->page_info[rx_buf->page_indx];

	/* we are reusing so sync this buffer for CPU use */
	offset = pinfo->page_offset - pinfo->default_offset;
	dma_sync_single_range_for_cpu(dev, pinfo->dma, offset,
				      size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	pinfo->pagecnt_bias--;
}

/**
 * idpf_rx_construct_skb - Allocate skb and populate it
 * @rxq: Rx descriptor queue
 * @rx_buf: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates an skb. It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
struct sk_buff *idpf_rx_construct_skb(struct idpf_queue *rxq,
				      struct idpf_rx_buf *rx_buf,
				      unsigned int size)
{
	unsigned int headlen, truesize;
	struct idpf_page_info *pinfo;
	struct sk_buff *skb;
	void *va;

	BUILD_BUG_ON(IDPF_RX_HDR_SIZE < IDPF_MIN_RX_HDR_SIZE);

	pinfo = &rx_buf->page_info[rx_buf->page_indx];
	va = page_address(pinfo->page) + pinfo->page_offset;

	/* prefetch first cache line of first page */
	net_prefetch(va);
	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rxq->q_vector->napi, IDPF_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx);

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > IDPF_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, va, IDPF_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), va, ALIGN(headlen, sizeof(long)));

	/* if we exhaust the linear part then add what is left as a frag */
	size -= headlen;
	if (!size) {
		/* buffer is unused, reset bias back to rx_buf; data was copied
		 * onto skb's linear part so there's no need for adjusting
		 * page offset and we can reuse this buffer as-is
		 */
		pinfo->pagecnt_bias++;
		return skb;
	}

	truesize = idpf_rx_frame_truesize(rx_buf, size);
	skb_add_rx_frag(skb, 0, pinfo->page,
			pinfo->page_offset + headlen, size,
			truesize);
	/* buffer is used by skb, update page_offset */
	idpf_rx_buf_adjust_pg(rx_buf, truesize);

	return skb;
}

/**
 * idpf_rx_hdr_construct_skb - Allocate skb and populate it from header buffer
 * @rxq: Rx descriptor queue
 * @va: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates an skb. It then populates it with the page data from
 * the current receive descriptor, taking care to set up the skb correctly.
 * This specifically uses a header buffer to start building the skb.
 */
static struct sk_buff *idpf_rx_hdr_construct_skb(struct idpf_queue *rxq,
						 const void *va,
						 unsigned int size)
{
	struct sk_buff *skb;

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rxq->q_vector->napi, size);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx);

	memcpy(__skb_put(skb, size), va, ALIGN(size, sizeof(long)));

	/* Prefetct first cache line of next frame headers. */
	prefetch((u8 *)va + IDPF_HDR_BUF_SIZE);

	return skb;
}

/**
 * idpf_rx_splitq_test_staterr - tests bits in Rx descriptor
 * status and error fields
 * @stat_err_field: field from descriptor to test bits in
 * @stat_err_bits: value to mask
 *
 */
static bool idpf_rx_splitq_test_staterr(const u8 stat_err_field,
					const u8 stat_err_bits)
{
	return !!(stat_err_field & stat_err_bits);
}

/**
 * idpf_get_vlan_tci - extract VLAN TCI from the RX descriptor
 * @rx_desc: RX descriptor to extract from
 */
static u16 idpf_get_vlan_tci(const struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	if (FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L2TAG1P_M,
		      rx_desc->status_err0_qw0))
		return le16_to_cpu(rx_desc->l2tag1);

	return 0;
}

/**
 * idpf_receive_skb - wrapper to insert VLAN tag into skb and call
 *		      napi_gro_receive
 * @q: RX queue to get the VLAN tag and napi info
 * @skb: skb to fill the data into
 * @vlan_tci: VLAN TCI extracted from the descriptor
 */
static void idpf_receive_skb(struct idpf_queue *q, struct sk_buff *skb,
			     u16 vlan_tci)
{
	if (vlan_tci & VLAN_VID_MASK)
		__vlan_hwaccel_put_tag(skb, q->rx.vlan_proto, vlan_tci);

	napi_gro_receive(&q->q_vector->napi, skb);
}

/**
 * idpf_rx_splitq_is_eop - process handling of EOP buffers
 * @rx_desc: Rx descriptor for current buffer
 *
 * If the buffer is an EOP buffer, this function exits returning true,
 * otherwise return false indicating that this is in fact a non-EOP buffer.
 */
static bool idpf_rx_splitq_is_eop(struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	/* if we are the last buffer then there is nothing else to do */
	return likely(idpf_rx_splitq_test_staterr(rx_desc->status_err0_qw1,
						  IDPF_RXD_EOF_SPLITQ));
}

/**
 * idpf_rx_splitq_recycle_buf - Attempt to recycle or realloc buffer
 * @rxq: Receive queue
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buf. It will either
 * recycle the buffer or unmap it and free the associated resources. The buffer
 * will then be placed on a refillq where it will later be reclaimed by the
 * corresponding bufq.
 *
 * This works based on page flipping. If we assume e.g., a 4k page, it will be
 * divided into two 2k buffers. We post the first half to hardware and, after
 * using it, flip to second half of the page with idpf_adjust_pg_offset and
 * post that to hardware. The third time through we'll flip back to first half
 * of page and check if stack is still using it, if not we can reuse the buffer
 * as is, otherwise we'll drain it and get a new page.
 */
static void idpf_rx_splitq_recycle_buf(struct idpf_queue *rxq,
				       struct idpf_rx_buf *rx_buf)
{
	struct idpf_page_info *pinfo = &rx_buf->page_info[rx_buf->page_indx];

	if (idpf_rx_can_reuse_page(rx_buf)) {
		u64_stats_update_begin(&rxq->stats_sync);
		u64_stats_inc(&rxq->q_stats.rx.page_recycles);
		u64_stats_update_end(&rxq->stats_sync);
		return;
	}

	/* we are not reusing the buffer so unmap it */
#ifndef HAVE_STRUCT_DMA_ATTRS
	dma_unmap_page_attrs(rxq->dev, pinfo->dma, PAGE_SIZE,
			     DMA_FROM_DEVICE, IDPF_RX_DMA_ATTR);
#else
	dma_unmap_page(rxq->dev, pinfo->dma, PAGE_SIZE, DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */
	__page_frag_cache_drain(pinfo->page, pinfo->pagecnt_bias);

	/* clear contents of buffer_info */
	pinfo->page = NULL;

	/* It's possible the alloc can fail here but there's not much
	 * we can do, bufq will have to try and realloc to fill the
	 * hole.
	 */
	idpf_alloc_page(rxq->dev, pinfo);
	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_inc(&rxq->q_stats.rx.page_reallocs);
	u64_stats_update_end(&rxq->stats_sync);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_prepare_xdp_tx_splitq_desc - Prepare TX descriptor for XDP in single
 *				     queue mode
 * @xdpq:      Pointer to XDP TX queue
 * @dma:       Address of DMA buffer used for XDP TX.
 * @idx:       Index of the TX buffer in the queue.
 * @size:      Size of data to be transmitted.
 * @tx_params:  Pointer to TX parameters structure.
 */
void idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				     u16 idx, u32 size,
				     struct idpf_tx_splitq_params *tx_params)
{
	union idpf_tx_flex_desc *tx_desc;

	tx_desc = IDPF_FLEX_TX_DESC(xdpq, idx);
	tx_desc->q.buf_addr = cpu_to_le64(dma);

	if (unlikely(idpf_queue_has(FLOW_SCH_EN, xdpq))) {
		tx_params->dtype = IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_params->eop_cmd = IDPF_TXD_FLEX_FLOW_CMD_EOP;
	} else {
		tx_params->dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_params->eop_cmd = IDPF_TXD_LAST_DESC_CMD;
	}

	idpf_tx_splitq_build_desc(tx_desc, tx_params,
				  tx_params->eop_cmd | tx_params->offload.td_cmd,
				  size);
}

/**
 * idpf_xmit_xdpq - submit single packet to XDP queue for transmission
 * @xdp: frame data to transmit
 * @xdpq: XDP queue for transmission
 */
#ifdef HAVE_XDP_FRAME_STRUCT
int idpf_xmit_xdpq(struct xdp_frame *xdp, struct idpf_queue *xdpq)
#else
int idpf_xmit_xdpq(struct xdp_buff *xdp, struct idpf_queue *xdpq)
#endif
{
	struct idpf_tx_splitq_params tx_params = { };
	u16 ntu = xdpq->next_to_use;
	struct idpf_tx_buf *tx_buf;
	dma_addr_t dma;
	void *data;
	u32 buf_id;
	u32 size;

	if (unlikely(!xdp))
		return IDPF_XDP_CONSUMED;

	if (unlikely(!IDPF_DESC_UNUSED(xdpq)))
		return IDPF_XDP_CONSUMED;

#ifdef HAVE_XDP_FRAME_STRUCT
	size = xdp->len;
#else
	size = xdp->data_end - xdp->data;
#endif
	data = xdp->data;

	dma = dma_map_single(xdpq->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(xdpq->dev, dma))
		return IDPF_XDP_CONSUMED;

	if (unlikely(idpf_queue_has(FLOW_SCH_EN, xdpq))) {
		/* Xdp only uses a single buffer. No need to save refillq state
		 * for rollback like we do in the standard data path.
		 */
		if (unlikely(!idpf_tx_get_free_buf_id(xdpq->tx.refillq,
						      &buf_id)))
			return IDPF_XDP_CONSUMED;

		tx_params.compl_tag = buf_id;
	} else {
		buf_id = ntu;
	}

	tx_buf = &xdpq->tx.bufs[buf_id];
	tx_buf->bytes = size;
	tx_buf->packets = 1;
#ifdef HAVE_XDP_FRAME_STRUCT
	tx_buf->xdpf = xdp;
#else
	tx_buf->raw = data;
#endif
	idpf_tx_buf_compl_tag(&xdpq->tx.bufs[buf_id]) = tx_params.compl_tag;

	/* record length, and DMA address */
	dma_unmap_len_set(tx_buf, len, size);
	dma_unmap_addr_set(tx_buf, dma, dma);

#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
	INDIRECT_CALL_2(xdpq->vport->xdp_prepare_tx_desc,
			idpf_prepare_xdp_tx_splitq_desc,
			idpf_prepare_xdp_tx_singleq_desc,
			xdpq, dma, ntu, size, &tx_params);
#else
	xdpq->vport->xdp_prepare_tx_desc(xdpq, dma, ntu, size, &tx_params);
#endif /* HAVE_INDIRECT_CALL_WRAPPER_HEADER */

	/* Make certain all of the status bits have been updated
	 * before next_to_watch is written.
	 */
	smp_wmb();

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	xdpq->xdp_tx_active++;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	tx_buf->type = LIBETH_SQE_XDP_TX;
	tx_buf->rs_idx = ntu;
	xdpq->next_to_use = idpf_tx_splitq_bump_ntu(xdpq, ntu);

	return IDPF_XDP_TX;
}

#ifdef HAVE_XDP_FRAME_STRUCT
/**
 * idpf_xdp_xmit - submit packets to xdp ring for transmission
 * @dev: netdev
 * @n: number of xdp frames to be transmitted
 * @frames: xdp frames to be transmitted
 * @flags: transmit flags
 *
 * Returns number of frames successfully sent. Frames that fail are
 * free'ed via XDP return API.
 * For error cases, a negative errno code is returned and no-frames
 * are transmitted (caller must handle freeing frames).
 */
int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags)
#else
int idpf_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp)
#endif /* HAVE_XDP_FRAME_STRUCT */
{
	struct idpf_netdev_priv *np = netdev_priv(dev);
	unsigned int queue_index = smp_processor_id();
	struct idpf_vport *vport = np->vport;
	struct idpf_queue *xdpq;
#ifdef HAVE_XDP_FRAME_STRUCT
	int i, drops = 0;
#else
	int err;
#endif /* HAVE_XDP_FRAME_STRUCT */

	if (!test_bit(IDPF_VPORT_UP, np->state))
		return -ENETDOWN;
	if (unlikely(!netif_carrier_ok(dev) || !vport->link_up))
		return -ENETDOWN;
	if (!idpf_xdp_is_prog_ena(vport) || !vport->num_xdp_txq)
		return -ENXIO;

#ifdef HAVE_XDP_FRAME_STRUCT
	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;
#endif
	queue_index %= vport->num_xdp_txq;
	xdpq = vport->txqs[queue_index + vport->xdp_txq_offset];
#ifdef HAVE_XDP_FRAME_STRUCT
	for (i = 0; i < n; ++i) {
		struct xdp_frame *xdpf = frames[i];
		int err;

		err = idpf_xmit_xdpq(xdpf, xdpq);
		if (err != IDPF_XDP_TX) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
			break;
		}
	}

	if (unlikely(flags & XDP_XMIT_FLUSH))
		idpf_xdpq_update_tail(xdpq);

	return n - drops;
#else
	err = idpf_xmit_xdpq(xdp, xdpq);
	return err == IDPF_XDP_TX ? 0 : -EFAULT;
#endif /* HAVE_XDP_FRAME_STRUCT */
}

#ifndef NO_NDO_XDP_FLUSH
/**
 * idpf_xdp_flush - flush xdp ring and transmit all submitted packets
 * @dev: netdev
 */
void idpf_xdp_flush(struct net_device *dev)
{
	struct idpf_netdev_priv *np = netdev_priv(dev);
	unsigned int queue_index = smp_processor_id();
	struct idpf_vport *vport = np->vport;

	if (!test_bit(IDPF_VPORT_UP, np->state))
		return;

	if (!idpf_xdp_is_prog_ena(vport) || queue_index >= vport->num_xdp_txq)
		return;

	idpf_xdpq_update_tail(vport->txqs[queue_index + vport->xdp_txq_offset]);
}

#endif /* NO_NDO_XDP_FLUSH */
/**
 * idpf_run_xdp - Executes an XDP program on initialized xdp_buff
 * @rxq: Rx queue
 * @xdpq: XDP Tx queue
 * @xdp_prog: XDP program to run
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns IDPF_XDP_PASS for packets to be sent up the stack, IDPF_XDP_CONSUMED
 * otherwise.
 */
static int idpf_run_xdp(struct idpf_queue *rxq, struct idpf_queue *xdpq,
			struct bpf_prog *xdp_prog, struct xdp_buff *xdp)
{
	u32 act = bpf_prog_run_xdp(xdp_prog, xdp);
	int err, result = IDPF_XDP_PASS;

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
#ifdef HAVE_XDP_FRAME_STRUCT
		return idpf_xmit_xdpq(xdp_convert_buff_to_frame(xdp), xdpq);
#else
		return idpf_xmit_xdpq(xdp, xdpq);
#endif
	case XDP_REDIRECT:
		err = xdp_do_redirect(rxq->vport->netdev, xdp, xdp_prog);
		result = !err ? IDPF_XDP_REDIR : IDPF_XDP_CONSUMED;
		break;
	default:
		bpf_warn_invalid_xdp_action(rxq->vport->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rxq->vport->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		return IDPF_XDP_CONSUMED;
	}

	return result;
}

/**
 * idpf_rx_xdp - Initialize an xdp_buff and run XDP program
 * @rxq: current queue
 * @xdpq: XDP Tx queue
 * @rx_buf: buffer with a received packet
 * @size: size of the packet
 *
 * Returns IDPF_XDP_PASS for packets to be sent up the stack, IDPF_XDP_CONSUMED
 * otherwise.
 */
int idpf_rx_xdp(struct idpf_queue *rxq, struct idpf_queue *xdpq,
		struct idpf_rx_buf *rx_buf, unsigned int size)
{
	struct idpf_page_info *pinfo = &rx_buf->page_info[rx_buf->page_indx];

	struct bpf_prog *xdp_prog;
	struct xdp_buff xdp = { };
	int xdp_res;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	if (!xdp_prog) {
		rcu_read_unlock();
		return IDPF_XDP_PASS;
	}

	xdp.data = page_address(pinfo->page) + pinfo->page_offset;
	xdp.data_hard_start = xdp.data - XDP_PACKET_HEADROOM;
	xdp.data_meta = xdp.data;
	xdp.data_end = xdp.data + size;
#ifdef HAVE_XDP_BUFF_RXQ
	xdp.rxq = &rxq->xdp_rxq;
#endif /* HAVE_XDP_BUFF_RXQ */
#ifdef HAVE_XDP_BUFF_FRAME_SZ
	xdp.frame_sz = idpf_rx_frame_truesize(rx_buf, size);
#endif /* HAVE_XDP_BUFF_FRAME_SZ */

	xdp_res = idpf_run_xdp(rxq, xdpq, xdp_prog, &xdp);
	rcu_read_unlock();

	return xdp_res;
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * idpf_rx_splitq_clean - Clean completed descriptors from Rx queue
 * @rxq: Rx descriptor queue to retrieve receive buffer queue
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing. The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 */
static int idpf_rx_splitq_clean(struct idpf_queue *rxq, int budget)
{
	int total_rx_bytes = 0, total_rx_pkts = 0;
#ifdef HAVE_XDP_SUPPORT
	unsigned int xdp_res, xdp_xmit = 0;
	struct idpf_queue *xdpq = NULL;
#endif /* HAVE_XDP_SUPPORT */
	struct sk_buff *skb = rxq->rx.skb;
	u16 ntc = rxq->next_to_clean;

#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(rxq->vport))
		xdpq = idpf_get_related_xdp_queue(rxq);
#endif /* HAVE_XDP_SUPPORT */

	/* Process Rx packets bounded by budget */
	while (likely(total_rx_pkts < budget)) {
		struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc;
		struct idpf_sw_queue *refillq = NULL;
		struct idpf_rxq_set *rxq_set = NULL;
		struct idpf_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *desc;
		unsigned int pkt_len = 0;
		unsigned int hdr_len = 0;
		u16 gen_id, buf_id = 0;
		 /* Header buffer overflow only valid for header split */
		bool hbo = false;
		u16 vlan_tci;
		int bufq_id;
		u8 rxdid;

#ifdef HAVE_XDP_SUPPORT
		xdp_res = IDPF_XDP_PASS;

#endif /* HAVE_XDP_SUPPORT */
		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		desc = IDPF_RX_DESC(rxq, ntc);
		rx_desc = (struct virtchnl2_rx_flex_desc_adv_nic_3 *)desc;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc
		 */
		dma_rmb();

		/* if the descriptor isn't done, no work yet to do */
		gen_id = le16_get_bits(rx_desc->pktlen_gen_bufq_id,
				       VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M);

		if (idpf_queue_has(GEN_CHK, rxq) != gen_id)
			break;

		rxdid = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_M,
				  rx_desc->rxdid_ucast);
		if (rxdid != VIRTCHNL2_RXDID_2_FLEX_SPLITQ) {
			ntc = idpf_rx_bump_ntc(rxq, ntc);
			u64_stats_update_begin(&rxq->stats_sync);
			u64_stats_inc(&rxq->q_stats.rx.bad_descs);
			u64_stats_update_end(&rxq->stats_sync);
			continue;
		}

		pkt_len = le16_get_bits(rx_desc->pktlen_gen_bufq_id,
					VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M);

		bufq_id = le16_get_bits(rx_desc->pktlen_gen_bufq_id,
					VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M);

		hbo = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_HBO_M,
				rx_desc->status_err0_qw1);

		if (unlikely(hbo)) {
			/* If a header buffer overflow, occurs, i.e. header is
			 * too large to fit in the header split buffer, HW will
			 * put the entire packet, including headers, in the
			 * data/payload buffer.
			 */
			u64_stats_update_begin(&rxq->stats_sync);
			u64_stats_inc(&rxq->q_stats.rx.hsplit_buf_ovf);
			u64_stats_update_end(&rxq->stats_sync);
			goto bypass_hsplit;
		}

		hdr_len = le16_get_bits(rx_desc->hdrlen_flags,
					VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_M);

bypass_hsplit:
		rxq_set = container_of(rxq, struct idpf_rxq_set, rxq);
		refillq = rxq_set->refillq[bufq_id];

		buf_id = le16_to_cpu(rx_desc->buf_id);

		if (pkt_len) {
			rx_buf = &rxq->rx.bufq_bufs[bufq_id][buf_id];
			idpf_rx_get_buf_page(rxq->dev, rx_buf, pkt_len);
		}

		if (hdr_len) {
			const void *va = (void *)rxq->rx.bufq_hdr_bufs[bufq_id][buf_id];

			skb = idpf_rx_hdr_construct_skb(rxq, va, hdr_len);
			u64_stats_update_begin(&rxq->stats_sync);
			u64_stats_inc(&rxq->q_stats.rx.hsplit_pkts);
			u64_stats_update_end(&rxq->stats_sync);
		}

#ifdef HAVE_XDP_SUPPORT
		if (pkt_len && xdpq)
			xdp_res = idpf_rx_xdp(rxq, xdpq, rx_buf, pkt_len);

		if (xdp_res) {
			if (xdp_res & (IDPF_XDP_TX | IDPF_XDP_REDIR)) {
				unsigned int truesize =
					idpf_rx_frame_truesize(rx_buf, pkt_len);

				xdp_xmit |= xdp_res;
				idpf_rx_buf_adjust_pg(rx_buf, truesize);
			} else {
				rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			}
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			idpf_rx_splitq_recycle_buf(rxq, rx_buf);
			idpf_post_buf_refill(refillq, buf_id);
			ntc = idpf_rx_bump_ntc(rxq, ntc);
			continue;
		}
#endif /* HAVE_XDP_SUPPORT */

		if (pkt_len) {
			if (skb)
				idpf_rx_add_frag(rx_buf, skb, pkt_len);
			else
				skb = idpf_rx_construct_skb(rxq, rx_buf,
							    pkt_len);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf)
				rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			break;
		}

		if (rx_buf)
			idpf_rx_splitq_recycle_buf(rxq, rx_buf);
		idpf_post_buf_refill(refillq, buf_id);

		ntc = idpf_rx_bump_ntc(rxq, ntc);
		/* skip if it is non EOP desc */
		if (!idpf_rx_splitq_is_eop(rx_desc))
			continue;

		vlan_tci = idpf_get_vlan_tci(rx_desc);

		/* pad skb if needed (to make valid ethernet frame) */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* protocol */
		if (unlikely(idpf_rx_process_skb_fields(rxq, skb, rx_desc))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* send completed skb up the stack */
		idpf_receive_skb(rxq, skb, vlan_tci);
		skb = NULL;

		/* update budget accounting */
		total_rx_pkts++;
	}

	rxq->next_to_clean = ntc;

#ifdef HAVE_XDP_SUPPORT
	if (xdpq)
		idpf_finalize_xdp_rx(xdpq, xdp_xmit);

#endif /* HAVE_XDP_SUPPORT */
	rxq->rx.skb = skb;
	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_add(&rxq->q_stats.rx.packets, total_rx_pkts);
	u64_stats_add(&rxq->q_stats.rx.bytes, total_rx_bytes);
	u64_stats_update_end(&rxq->stats_sync);

	/* guarantee a trip back through this routine if there was a failure */
	return total_rx_pkts;
}

/**
 * idpf_rx_update_bufq_desc - Update buffer queue descriptor
 * @bufq: Pointer to the buffer queue
 * @refill_desc: SW Refill queue descriptor containing buffer ID
 * @buf_desc: Buffer queue descriptor
 *
 * Return 0 on success and negative on failure.
 */
static int idpf_rx_update_bufq_desc(struct idpf_queue *bufq, u32 refill_desc,
				    struct virtchnl2_splitq_rx_buf_desc *buf_desc)
{
	struct idpf_page_info *pinfo;
	struct idpf_rx_buf *buf;
	u16 buf_id;
	u32 offset;

	buf_id = FIELD_GET(IDPF_RFL_BI_BUFID_M, refill_desc);

	buf = &bufq->rx.bufs[buf_id];
	pinfo = &buf->page_info[buf->page_indx];

	/* It's possible page alloc failed during rxq clean, try to
	 * recover here.
	 */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (bufq->xsk_pool) {
		if (unlikely(!buf->xdp))
			if (idpf_rx_update_bufq_desc_zc(buf, bufq, pinfo,
							buf_desc, buf_id))
				return -ENOMEM;
	} else if (unlikely(!pinfo->page && idpf_alloc_page(bufq->dev, pinfo)))
#else
	if (unlikely(!pinfo->page && idpf_alloc_page(bufq->dev, pinfo)))
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		return -ENOMEM;

	offset = pinfo->page_offset - pinfo->default_offset;
	dma_sync_single_range_for_device(bufq->dev, pinfo->dma, offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);
	buf_desc->pkt_addr =
		cpu_to_le64(pinfo->dma + pinfo->page_offset);
	buf_desc->qword0.buf_id = cpu_to_le16(buf_id);

	if (!bufq->rx_hsplit_en)
		return 0;

	buf_desc->hdr_addr = cpu_to_le64(bufq->rx.hdr_buf_pa +
					 (u32)buf_id * IDPF_HDR_BUF_SIZE);

	return 0;
}

/**
 * idpf_rx_clean_refillq - Clean refill queue buffers
 * @bufq: buffer queue to post buffers back to
 * @refillq: refill queue to clean
 *
 * This function takes care of the buffer refill management
 */
static void idpf_rx_clean_refillq(struct idpf_queue *bufq,
				  struct idpf_sw_queue *refillq)
{
	struct virtchnl2_splitq_rx_buf_desc *buf_desc;
	u16 bufq_nta = bufq->next_to_alloc;
	u32 ntc = refillq->next_to_clean;
	int cleaned = 0;
	u16 gen;

	buf_desc = IDPF_SPLITQ_RX_BUF_DESC(bufq, bufq_nta);

	/* make sure we stop at ring wrap in the unlikely case ring is full */
	while (likely(cleaned < refillq->desc_count)) {
		u32 refill_desc = IDPF_SPLITQ_RX_BI_DESC(refillq, ntc);
		bool failure;

		gen = FIELD_GET(IDPF_RFL_BI_GEN_M, refill_desc);
		if (idpf_queue_has(RFL_GEN_CHK, refillq) != gen)
			break;

		failure = idpf_rx_update_bufq_desc(bufq, refill_desc,
						   buf_desc);
		if (failure)
			break;

		if (unlikely(++ntc == refillq->desc_count)) {
			idpf_queue_change(RFL_GEN_CHK, refillq);
			ntc = 0;
		}

		if (unlikely(++bufq_nta == bufq->desc_count)) {
			buf_desc = IDPF_SPLITQ_RX_BUF_DESC(bufq, 0);
			bufq_nta = 0;
		} else {
			buf_desc++;
		}

		cleaned++;
	}

	if (!cleaned)
		return;

	/* We want to limit how many transactions on the bus we trigger with
	 * tail writes so we only do it in strides. It's also important we
	 * align the write to a multiple of 8 as required by HW.
	 */
	if (((bufq->next_to_use <= bufq_nta ? 0 : bufq->desc_count) +
	    bufq_nta - bufq->next_to_use) >= IDPF_RX_BUF_POST_STRIDE)
		idpf_rx_buf_hw_update(bufq, ALIGN_DOWN(bufq_nta,
						       IDPF_RX_BUF_POST_STRIDE));

	/* update next to alloc since we have filled the ring */
	refillq->next_to_clean = ntc;
	bufq->next_to_alloc = bufq_nta;
}

/**
 * idpf_rx_clean_refillq_all - Clean all refill queues
 * @bufq: buffer queue with refill queues
 *
 * Iterates through all refill queues assigned to the buffer queue assigned to
 * this vector.  Returns true if clean is complete within budget, false
 * otherwise.
 */
static void idpf_rx_clean_refillq_all(struct idpf_queue *bufq)
{
	struct idpf_bufq_set *bufq_set;
	int i;

	bufq_set = container_of(bufq, struct idpf_bufq_set, bufq);
	for (i = 0; i < bufq_set->num_refillqs; i++)
		idpf_rx_clean_refillq(bufq, &bufq_set->refillqs[i]);
}

/**
 * idpf_vport_intr_clean_queues - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 *
 */
static irqreturn_t idpf_vport_intr_clean_queues(int __always_unused irq,
						void *data)
{
	struct idpf_q_vector *q_vector = data;

	q_vector->total_events++;
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * idpf_vport_intr_napi_del_all - Unregister napi for all q_vectors in vport
 * @intr_grp: Interrupt resources
 *
 */
static void idpf_vport_intr_napi_del_all(struct idpf_intr_grp *intr_grp)
{
	u16 v_idx;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++)
		netif_napi_del(&intr_grp->q_vectors[v_idx].napi);
}

/**
 * idpf_vport_intr_napi_dis_all - Disable NAPI for all q_vectors in the vport
 * @intr_grp: Interrupt resources
 */
static void idpf_vport_intr_napi_dis_all(struct idpf_intr_grp *intr_grp)
{
	int v_idx;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++)
		napi_disable(&intr_grp->q_vectors[v_idx].napi);
}

/**
 * idpf_vport_intr_rel - Free memory allocated for interrupt vectors
 * @vgrp: Queue and interrupt resource group
 *
 * Free the memory allocated for interrupt vectors  associated to a vport
 */
void idpf_vport_intr_rel(struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	int v_idx;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[v_idx];

		kfree(q_vector->bufq);
		q_vector->bufq = NULL;
		kfree(q_vector->tx);
		q_vector->tx = NULL;
		kfree(q_vector->rx);
		q_vector->rx = NULL;

#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		free_cpumask_var(q_vector->affinity_mask);
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
	}

	kfree(intr_grp->q_vectors);
	intr_grp->q_vectors = NULL;
}

/**
 * idpf_vport_intr_rel_irq - Free the IRQ association with the OS
 * @vport: main vport structure
 * @intr_grp: Interrupt resources
 */
static void idpf_vport_intr_rel_irq(struct idpf_vport *vport,
				    struct idpf_intr_grp *intr_grp)
{
	struct idpf_adapter *adapter = vport->adapter;
	int vector;

	for (vector = 0; vector < intr_grp->num_q_vectors; vector++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[vector];
		int irq_num, vidx;

		vidx = intr_grp->q_vector_idxs[vector];
		irq_num = adapter->msix_entries[vidx].vector;

#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_notifier(irq_num, NULL);
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
		kfree(free_irq(irq_num, q_vector));
		kfree(q_vector->name);
		q_vector->name = NULL;
	}
}

/**
 * idpf_vport_intr_dis_irq_all - Disable all interrupts
 * @intr_grp: Interrupt resources
 */
static void idpf_vport_intr_dis_irq_all(struct idpf_intr_grp *intr_grp)
{
	struct idpf_q_vector *q_vector = intr_grp->q_vectors;
	int q_idx;

	for (q_idx = 0; q_idx < intr_grp->num_q_vectors; q_idx++)
		writel(0, q_vector[q_idx].intr_reg.dyn_ctl);
}

/**
 * idpf_vport_intr_buildreg_itr - Enable default interrupt generation settings
 * @q_vector: pointer to q_vector
 */
static u32 idpf_vport_intr_buildreg_itr(struct idpf_q_vector *q_vector)
{
	u32 itr_val = q_vector->intr_reg.dyn_ctl_intena_m;
	int type = IDPF_NO_ITR_UPDATE_IDX;
	u16 itr = 0;

	if (q_vector->wb_on_itr) {
		/*
		 * Trigger a software interrupt when exiting wb_on_itr, to make
		 * sure we catch any pending write backs that might have been
		 * missed due to interrupt state transition.
		 */
		itr_val |= q_vector->intr_reg.dyn_ctl_swint_trig_m |
			   q_vector->intr_reg.dyn_ctl_sw_itridx_ena_m;
		type = IDPF_SW_ITR_UPDATE_IDX;
		itr = IDPF_ITR_20K;
	}

	itr &= IDPF_ITR_MASK;
	/* Don't clear PBA because that can cause lost interrupts that
	 * came in while we were cleaning/polling
	 */
	itr_val |= (type << q_vector->intr_reg.dyn_ctl_itridx_s) |
		   (itr << (q_vector->intr_reg.dyn_ctl_intrvl_s - 1));

	return itr_val;
}

/**
 * idpf_update_dim_sample - Update dim sample with packets and bytes
 * @q_vector: the vector associated with the interrupt
 * @dim_sample: dim sample to update
 * @dim: dim instance structure
 * @packets: total packets
 * @bytes: total bytes
 *
 * Update the dim sample with the packets and bytes which are passed to this
 * function. Set the dim state appropriately if the dim settings gets stale.
 */
static void idpf_update_dim_sample(struct idpf_q_vector *q_vector,
				   struct dim_sample *dim_sample,
				   struct dim *dim, u64 packets, u64 bytes)
{
	dim_update_sample(q_vector->total_events, packets, bytes, dim_sample);
	dim_sample->comp_ctr = 0;

	/* if dim settings get stale, like when not updated for 1 second or
	 * longer, force it to start again. This addresses the frequent case
	 * of an idle queue being switched to by the scheduler.
	 */
	if (ktime_ms_delta(dim_sample->time, dim->start_sample.time) >= HZ)
		dim->state = DIM_START_MEASURE;
}

/**
 * idpf_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the queue is not configured to dynamic ITR.
 */
static void idpf_net_dim(struct idpf_q_vector *q_vector)
{
	struct dim_sample dim_sample = { };
	u64 packets, bytes;
	u32 i;

	if (!IDPF_ITR_IS_DYNAMIC(q_vector->tx_intr_mode))
		goto check_rx_itr;

	for (i = 0, packets = 0, bytes = 0; i < q_vector->num_txq; i++) {
		struct idpf_queue *txq = q_vector->tx[i];
		unsigned int start;

		do {
			start = u64_stats_fetch_begin(&txq->stats_sync);
			packets += u64_stats_read(&txq->q_stats.tx.packets);
			bytes += u64_stats_read(&txq->q_stats.tx.bytes);
		} while (u64_stats_fetch_retry(&txq->stats_sync, start));
	}

	idpf_update_dim_sample(q_vector, &dim_sample, &q_vector->tx_dim,
			       packets, bytes);
	net_dim(&q_vector->tx_dim, &dim_sample);

check_rx_itr:
	if (!IDPF_ITR_IS_DYNAMIC(q_vector->rx_intr_mode))
		return;

	for (i = 0, packets = 0, bytes = 0; i < q_vector->num_rxq; i++) {
		struct idpf_queue *rxq = q_vector->rx[i];
		unsigned int start;

		do {
			start = u64_stats_fetch_begin(&rxq->stats_sync);
			packets += u64_stats_read(&rxq->q_stats.rx.packets);
			bytes += u64_stats_read(&rxq->q_stats.rx.bytes);
		} while (u64_stats_fetch_retry(&rxq->stats_sync, start));
	}

	idpf_update_dim_sample(q_vector, &dim_sample, &q_vector->rx_dim,
			       packets, bytes);
	net_dim(&q_vector->rx_dim, &dim_sample);
}

/**
 * idpf_vport_intr_update_itr_ena_irq - Update itr and re-enable MSIX interrupt
 * @q_vector: q_vector for which itr is being updated and interrupt enabled
 *
 * Update the net_dim() algorithm and re-enable the interrupt associated with
 * this vector.
 */
void idpf_vport_intr_update_itr_ena_irq(struct idpf_q_vector *q_vector)
{
	u32 intval;

	/* net_dim() updates ITR out-of-band using a work item */
	idpf_net_dim(q_vector);

	intval = idpf_vport_intr_buildreg_itr(q_vector);
	q_vector->wb_on_itr = false;

	writel(intval, q_vector->intr_reg.dyn_ctl);
}

#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
/**
 * idpf_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * Callback function registered via irq_set_affinity_notifier function
 * so that river can receive changes to the irq affinity masks.
 */
static void
idpf_irq_affinity_notify(struct irq_affinity_notify *notify,
			 const cpumask_t *mask)
{
	struct idpf_vec_affinity_config *affinity_config =
		container_of(notify, struct idpf_vec_affinity_config, affinity_notify);

#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
	cpumask_copy(&affinity_config->affinity_mask, mask);
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
}

/**
 * idpf_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * Callback function registered via irq_set_affinity_notifier function to
 * inform the driver that it will no longer receive notifications.
 */
static void idpf_irq_affinity_release(struct kref __always_unused *ref) {}

#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
/**
 * idpf_vport_intr_req_irq - get MSI-X vectors from the OS for the vport
 * @vport: main vport structure
 * @intr_grp: Interrupt resources
 * @basename: name for the vector
 */
static int idpf_vport_intr_req_irq(struct idpf_vport *vport,
				   struct idpf_intr_grp *intr_grp,
				   char *basename)
{
	struct idpf_adapter *adapter = vport->adapter;
#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
	struct irq_affinity_notify *affinity_notify;
	struct idpf_vport_config *vport_config;
	cpumask_t *mask;
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
	int vector, err, irq_num, vidx;
	const char *vec_name;

	for (vector = 0; vector < intr_grp->num_q_vectors; vector++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[vector];
		char *name;

		vidx = intr_grp->q_vector_idxs[vector];
		irq_num = adapter->msix_entries[vidx].vector;

		if (q_vector->num_rxq && q_vector->num_txq)
			vec_name = "TxRx";
		else if (q_vector->num_rxq)
			vec_name = "Rx";
		else if (q_vector->num_txq)
			vec_name = "Tx";
		else
			continue;

		name = kasprintf(GFP_KERNEL, "%s-%s-%d", basename, vec_name,
				 vidx);
		err = request_irq(irq_num, idpf_vport_intr_clean_queues, 0,
				  name, q_vector);
		if (err) {
			netdev_err(vport->netdev,
				   "Request_irq failed, error: %d\n", err);
			goto free_q_irqs;
		}
#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		if (vector >= MAX_NUM_VEC_AFFINTY)
			continue;

		/* assign the mask for this irq */
		vport_config = adapter->vport_config[vport->idx];
		affinity_notify = &vport_config->affinity_config[vector].affinity_notify;
		affinity_notify->notify = idpf_irq_affinity_notify;
		affinity_notify->release = idpf_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, affinity_notify);

		/* Apply the current mask */
		mask = &vport_config->affinity_config[vector].affinity_mask;
#ifdef HAVE_EXPORTED_IRQ_SET_AFFINITY
		irq_set_affinity(irq_num, mask);
#else /* HAVE_EXPORTED_IRQ_SET_AFFINITY */
		irq_set_affinity_hint(irq_num, mask);
#endif /* !HAVE_EXPORTED_IRQ_SET_AFFINITY */
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
	}

	return 0;

free_q_irqs:
	while (--vector >= 0) {
		vidx = intr_grp->q_vector_idxs[vector];
		irq_num = adapter->msix_entries[vidx].vector;
		kfree(free_irq(irq_num, &intr_grp->q_vectors[vector]));
		kfree(intr_grp->q_vectors[vector].name);
		intr_grp->q_vectors[vector].name = NULL;
	}
	return err;
}

/**
 * idpf_vport_intr_write_itr - Write ITR value to the ITR register
 * @q_vector: q_vector structure
 * @itr: Interrupt throttling rate
 * @tx: Tx or Rx ITR
 */
void idpf_vport_intr_write_itr(struct idpf_q_vector *q_vector, u16 itr, bool tx)
{
	struct idpf_intr_reg *intr_reg;

	if (tx && !q_vector->tx)
		return;
	else if (!tx && !q_vector->rx)
		return;

	intr_reg = &q_vector->intr_reg;
	writel(ITR_REG_ALIGN(itr) >> IDPF_ITR_GRAN_S,
	       tx ? intr_reg->tx_itr : intr_reg->rx_itr);
}

/**
 * idpf_vport_intr_ena_irq_all - Enable IRQ for the given vport
 * @vport: main vport structure
 * @intr_grp: Interrupt resources
 */
static void idpf_vport_intr_ena_irq_all(struct idpf_vport *vport,
					struct idpf_intr_grp *intr_grp)
{
	bool dynamic;
	int q_idx;
	u16 itr;

	for (q_idx = 0; q_idx < intr_grp->num_q_vectors; q_idx++) {
		struct idpf_q_vector *qv = &intr_grp->q_vectors[q_idx];

		/* Write the default ITR values */
		if (qv->num_txq) {
			dynamic = IDPF_ITR_IS_DYNAMIC(qv->tx_intr_mode);
			itr = vport->tx_itr_profile[qv->tx_dim.profile_ix];
			idpf_vport_intr_write_itr(qv, dynamic ?
						  itr : qv->tx_itr_value,
						  true);
		}

		if (qv->num_rxq) {
			dynamic = IDPF_ITR_IS_DYNAMIC(qv->rx_intr_mode);
			itr = vport->rx_itr_profile[qv->rx_dim.profile_ix];
			idpf_vport_intr_write_itr(qv, dynamic ?
						  itr : qv->rx_itr_value,
						  false);
		}

		if (qv->num_txq || qv->num_rxq)
			idpf_vport_intr_update_itr_ena_irq(qv);
	}
}

/**
 * idpf_vport_intr_set_wb_on_itr - Enable WB on ITR to tell HW to
 * writeback descriptors when interrupts are disabled
 * @q_vector: pointer to queue vector struct
 */
void idpf_vport_intr_set_wb_on_itr(struct idpf_q_vector *q_vector)
{
	u32 dyn_ctl_itridx_s = q_vector->intr_reg.dyn_ctl_itridx_s;

	if (q_vector->wb_on_itr)
		return;

	q_vector->wb_on_itr = true;

	writel((q_vector->intr_reg.dyn_ctl_wb_on_itr_m |
	       (IDPF_NO_ITR_UPDATE_IDX << dyn_ctl_itridx_s) |
	       q_vector->intr_reg.dyn_ctl_intena_msk_m),
	       q_vector->intr_reg.dyn_ctl);
}

/**
 * idpf_vport_intr_deinit - Release all vector associations for the vport
 * @vport: main vport structure
 * @intr_grp: Interrupt resources
 */
void idpf_vport_intr_deinit(struct idpf_vport *vport,
			    struct idpf_intr_grp *intr_grp)
{
	idpf_vport_intr_dis_irq_all(intr_grp);
	idpf_vport_intr_napi_dis_all(intr_grp);
	idpf_vport_intr_napi_del_all(intr_grp);
	idpf_vport_intr_rel_irq(vport, intr_grp);
}

/**
 * idpf_tx_dim_work - Call back from the stack
 * @work: work queue structure
 */
static void idpf_tx_dim_work(struct work_struct *work)
{
	struct idpf_q_vector *q_vector;
	struct idpf_vport *vport;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	q_vector = container_of(dim, struct idpf_q_vector, tx_dim);
	vport = q_vector->vport;

	if (dim->profile_ix >= ARRAY_SIZE(vport->tx_itr_profile))
		dim->profile_ix = ARRAY_SIZE(vport->tx_itr_profile) - 1;

	/* look up the values in our local table */
	itr = vport->tx_itr_profile[dim->profile_ix];

	idpf_vport_intr_write_itr(q_vector, itr, true);

	dim->state = DIM_START_MEASURE;
}

/**
 * idpf_rx_dim_work - Call back from the stack
 * @work: work queue structure
 */
static void idpf_rx_dim_work(struct work_struct *work)
{
	struct idpf_q_vector *q_vector;
	struct idpf_vport *vport;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	q_vector = container_of(dim, struct idpf_q_vector, rx_dim);
	vport = q_vector->vport;

	if (dim->profile_ix >= ARRAY_SIZE(vport->rx_itr_profile))
		dim->profile_ix = ARRAY_SIZE(vport->rx_itr_profile) - 1;

	/* look up the values in our local table */
	itr = vport->rx_itr_profile[dim->profile_ix];

	idpf_vport_intr_write_itr(q_vector, itr, false);

	dim->state = DIM_START_MEASURE;
}

/**
 * idpf_init_dim - Set up dynamic interrupt moderation
 * @qv: q_vector structure
 */
static void idpf_init_dim(struct idpf_q_vector *qv)
{
	INIT_WORK(&qv->tx_dim.work, idpf_tx_dim_work);
	qv->tx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qv->tx_dim.profile_ix = IDPF_DIM_DEFAULT_PROFILE_IX;

	INIT_WORK(&qv->rx_dim.work, idpf_rx_dim_work);
	qv->rx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qv->rx_dim.profile_ix = IDPF_DIM_DEFAULT_PROFILE_IX;
}

/**
 * idpf_vport_intr_napi_ena_all - Enable NAPI for all q_vectors in the vport
 * @intr_grp: Interrupt resources
 */
static void idpf_vport_intr_napi_ena_all(struct idpf_intr_grp *intr_grp)
{
	int q_idx;

	for (q_idx = 0; q_idx < intr_grp->num_q_vectors; q_idx++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[q_idx];

		idpf_init_dim(q_vector);
		napi_enable(&q_vector->napi);
	}
}

/**
 * idpf_tx_splitq_clean_all- Clean completion queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool idpf_tx_splitq_clean_all(struct idpf_q_vector *q_vec, int budget,
				     int *cleaned)
{
	u16 num_txq = q_vec->num_txq;
	bool clean_complete = true;
	int i, budget_per_q;

	if (unlikely(!num_txq))
		return true;

	budget_per_q = DIV_ROUND_UP(budget, num_txq);
	for (i = 0; i < num_txq; i++)
		clean_complete &= idpf_tx_clean_complq(q_vec->tx[i],
						       budget_per_q, cleaned);

	return clean_complete;
}

/**
 * idpf_rx_splitq_clean_all- Clean completion queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool idpf_rx_splitq_clean_all(struct idpf_q_vector *q_vec, int budget,
				     int *cleaned)
{
	u16 num_rxq = q_vec->num_rxq;
	bool clean_complete = true;
	int pkts_cleaned = 0;
	int i, budget_per_q;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	budget_per_q = num_rxq ? max(budget / num_rxq, 1) : 0;
	for (i = 0; i < num_rxq; i++) {
		struct idpf_queue *rxq = q_vec->rx[i];
		int pkts_cleaned_per_q;

#ifdef HAVE_NETDEV_BPF_XSK_POOL
		pkts_cleaned_per_q = rxq->xsk_pool ? idpf_rx_splitq_clean_zc(rxq, budget_per_q) :
						     idpf_rx_splitq_clean(rxq, budget_per_q);
#else
		pkts_cleaned_per_q = idpf_rx_splitq_clean(rxq, budget_per_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		/* if we clean as many as budgeted, we must not be done */
		if (pkts_cleaned_per_q >= budget_per_q)
			clean_complete = false;
		pkts_cleaned += pkts_cleaned_per_q;
	}
	*cleaned = pkts_cleaned;

	for (i = 0; i < q_vec->num_bufq; i++)
		idpf_rx_clean_refillq_all(q_vec->bufq[i]);

	return clean_complete;
}

/**
 * idpf_vpo/rt_splitq_napi_poll - NAPI handler
 * @napi: struct from which you get q_vector
 * @budget: budget provided by stack
 */
static int idpf_vport_splitq_napi_poll(struct napi_struct *napi, int budget)
{
	struct idpf_q_vector *q_vector =
				container_of(napi, struct idpf_q_vector, napi);
	int work_done = 0, tx_wd = 0;
	bool clean_complete;

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(!budget)) {
		idpf_tx_splitq_clean_all(q_vector, budget, &work_done);
		return 0;
	}

	clean_complete = idpf_rx_splitq_clean_all(q_vector, budget, &work_done);
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	if (unlikely(!clean_complete))
		q_vector->sharedrxq_clean_incomplete++;
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
	clean_complete &= idpf_tx_splitq_clean_all(q_vector, budget, &tx_wd);

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		idpf_vport_intr_set_wb_on_itr(q_vector);
		return budget;
	}

	/* Switch to poll mode in the tear-down path after sending disable
	 * queues virtchnl message, as the interrupts will be disabled after
	 * that
	 */
	if (unlikely(q_vector->num_txq && idpf_queue_has(POLL_MODE,
							 q_vector->tx[0])))
		return budget;

	work_done = min_t(int, work_done, budget - 1);

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (napi_complete_done(napi, work_done))
		idpf_vport_intr_update_itr_ena_irq(q_vector);
	else
		idpf_vport_intr_set_wb_on_itr(q_vector);

	return work_done;
}

/**
 * idpf_vport_intr_map_vector_to_qs - Map vectors to queues
 * @vgrp: Queue and interrupt resource group
 */
static void idpf_vport_intr_map_vector_to_qs(struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	u16 num_txq_grp = q_grp->num_txq_grp;
	struct idpf_txq_group *tx_qgrp;
	struct idpf_rxq_group *rx_qgrp;
	struct idpf_queue *q, *bufq;
	int qv_idx, bufq_vidx = 0;
	u16 q_index;
	int i, j;

	for (i = 0, qv_idx = 0; i < q_grp->num_rxq_grp; i++) {
		u16 num_rxq;

		rx_qgrp = &q_grp->rxq_grps[i];
		if (idpf_is_queue_model_split(q_grp->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			if (qv_idx >= intr_grp->num_q_vectors)
				qv_idx = 0;

			if (idpf_is_queue_model_split(q_grp->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			q->q_vector = &intr_grp->q_vectors[qv_idx];
			q_index = q->q_vector->num_rxq;
			q->q_vector->rx[q_index] = q;
			q->q_vector->num_rxq++;
			qv_idx++;
		}

		if (idpf_is_queue_model_split(q_grp->rxq_model)) {
			for (j = 0; j < q_grp->num_bufqs_per_qgrp; j++) {
				bufq = &rx_qgrp->splitq.bufq_sets[j].bufq;
				bufq->q_vector = &intr_grp->q_vectors[bufq_vidx];
				q_index = bufq->q_vector->num_bufq;
				bufq->q_vector->bufq[q_index] = bufq;
				bufq->q_vector->num_bufq++;
			}
			if (++bufq_vidx >= intr_grp->num_q_vectors)
				bufq_vidx = 0;
		}
	}

	/* In splitq, we want to map the vectors for TX to the complqs as they
	 * will do the cleaning and reporting.
	 */
	for (i = 0, qv_idx = 0; i < num_txq_grp; i++) {
		u16 num_txq;

		tx_qgrp = &q_grp->txq_grps[i];
		num_txq = tx_qgrp->num_txq;

		if (idpf_is_queue_model_split(q_grp->txq_model)) {
			if (qv_idx >= intr_grp->num_q_vectors)
				qv_idx = 0;

			q = tx_qgrp->complq;
			q->q_vector = &intr_grp->q_vectors[qv_idx];
			q_index = q->q_vector->num_txq;
			q->q_vector->tx[q_index] = q;
			q->q_vector->num_txq++;
			qv_idx++;
		} else {
			for (j = 0; j < num_txq; j++) {
				if (qv_idx >= intr_grp->num_q_vectors)
					qv_idx = 0;

				q = tx_qgrp->txqs[j];
				q->q_vector = &intr_grp->q_vectors[qv_idx];
				q_index = q->q_vector->num_txq;
				q->q_vector->tx[q_index] = q;
				q->q_vector->num_txq++;

				qv_idx++;
			}
		}
	}
}

/**
 * idpf_vport_intr_init_vec_idx - Initialize the vector indexes
 * @vport: virtual port
 * @intr_grp: Interrupt resources
 *
 * Initialize vector indexes with values returened over mailbox
 */
static int idpf_vport_intr_init_vec_idx(struct idpf_vport *vport,
					struct idpf_intr_grp *intr_grp)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_alloc_vectors *ac;
	u16 *vecids, total_vecs;
	int i;

	ac = adapter->req_vec_chunks;
	if (!ac) {
		for (i = 0; i < intr_grp->num_q_vectors; i++)
			intr_grp->q_vectors[i].v_idx = intr_grp->q_vector_idxs[i];

		return 0;
	}

	total_vecs = idpf_get_reserved_vecs(adapter);
	vecids = kcalloc(total_vecs, sizeof(u16), GFP_KERNEL);
	if (!vecids)
		return -ENOMEM;

	idpf_get_vec_ids(adapter, vecids, total_vecs, &ac->vchunks);

	for (i = 0; i < intr_grp->num_q_vectors; i++)
		intr_grp->q_vectors[i].v_idx = vecids[intr_grp->q_vector_idxs[i]];

	kfree(vecids);

	return 0;
}

/**
 * idpf_vport_intr_napi_add_all- Register napi handler for all qvectors
 * @vport: virtual port structure
 * @vgrp: Queue and interrupt resource group
 */
static void idpf_vport_intr_napi_add_all(struct idpf_vport *vport,
					 struct idpf_vgrp *vgrp)
{
	int (*napi_poll)(struct napi_struct *napi, int budget);
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	u16 v_idx;

	if (idpf_is_queue_model_split(vgrp->q_grp.txq_model))
		napi_poll = idpf_vport_splitq_napi_poll;
	else
		napi_poll = idpf_vport_singleq_napi_poll;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[v_idx];
#ifdef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		int irq_num;
		u16 qv_idx;

		qv_idx = vgrp->intr_grp.q_vector_idxs[v_idx];
		irq_num = vport->adapter->msix_entries[qv_idx].vector;

		netif_napi_add_config(vport->netdev, &q_vector->napi,
				      napi_poll, v_idx);
		netif_napi_set_irq(&q_vector->napi, irq_num);
#else /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
		netif_napi_add(vport->netdev, &q_vector->napi, napi_poll);
#endif
	}
}

/**
 * idpf_vport_intr_alloc - Allocate memory for interrupt vectors
 * @vport: virtual port
 * @vgrp: Queue and interrupt resource group
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int idpf_vport_intr_alloc(struct idpf_vport *vport, struct idpf_vgrp *vgrp)
{
	u16 txqs_per_vector, rxqs_per_vector, bufq_per_vector, num_txq_vec_need;
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_vport_user_config_data *user_config;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	struct idpf_q_vector *q_vector;
	struct idpf_q_coalesce *q_coal;
	u16 idx = vport->idx;
	u32 v_idx;

	user_config = &vport->adapter->vport_config[idx]->user_config;
	intr_grp->q_vectors = kcalloc(intr_grp->num_q_vectors,
				      sizeof(struct idpf_q_vector),
				      GFP_KERNEL);
	if (!intr_grp->q_vectors)
		return -ENOMEM;

	/* In splitq the completion queues get the vectors instead of the TX
	 * queues
	 */
	num_txq_vec_need = idpf_is_queue_model_split(q_grp->txq_model) ?
					q_grp->num_complq : q_grp->num_txq;
	txqs_per_vector = DIV_ROUND_UP(num_txq_vec_need,
				       intr_grp->num_q_vectors);
	rxqs_per_vector = DIV_ROUND_UP(q_grp->num_rxq, intr_grp->num_q_vectors);

#ifdef HAVE_XDP_SUPPORT
	/* For XDP we assign both Tx and XDP Tx queues
	 * to the same q_vector.
	 * Reserve doubled number of Tx queues per vector.
	 */
	if (idpf_xdp_is_prog_ena(vport))
		txqs_per_vector *= 2;

#endif /* HAVE_XDP_SUPPORT */
	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++) {
		q_vector = &intr_grp->q_vectors[v_idx];
		q_coal = &user_config->q_coalesce[v_idx];
		q_vector->vport = vport;

		q_vector->tx_itr_value = q_coal->tx_coalesce_usecs;
		q_vector->tx_intr_mode = q_coal->tx_intr_mode;
		q_vector->tx_itr_idx = VIRTCHNL2_ITR_IDX_1;

		q_vector->rx_itr_value = q_coal->rx_coalesce_usecs;
		q_vector->rx_intr_mode = q_coal->rx_intr_mode;
		q_vector->rx_itr_idx = VIRTCHNL2_ITR_IDX_0;

#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		if (!zalloc_cpumask_var(&q_vector->affinity_mask, GFP_KERNEL))
			goto error;
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
		q_vector->tx = kcalloc(txqs_per_vector,
				       sizeof(struct idpf_queue *),
				       GFP_KERNEL);
		if (!q_vector->tx)
			goto error;

		q_vector->rx = kcalloc(rxqs_per_vector,
				       sizeof(struct idpf_queue *),
				       GFP_KERNEL);
		if (!q_vector->rx)
			goto error;

		if (!idpf_is_queue_model_split(q_grp->rxq_model))
			continue;
		bufq_per_vector = q_grp->num_bufqs_per_qgrp * rxqs_per_vector;
		q_vector->bufq = kcalloc(bufq_per_vector,
					 sizeof(struct idpf_queue *),
					 GFP_KERNEL);
		if (!q_vector->bufq)
			goto error;
	}

	return 0;

error:
	idpf_vport_intr_rel(vgrp);

	return -ENOMEM;
}

/**
 * idpf_vport_intr_init - Setup all vectors for the given vport
 * @vport: virtual port
 * @vgrp: Queue and interrupt resource group
 *
 * Returns 0 on success or negative on failure
 */
int idpf_vport_intr_init(struct idpf_vport *vport, struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_adapter *adapter = vport->adapter;
	char *int_name;
	int err;

	err = idpf_vport_intr_init_vec_idx(vport, intr_grp);
	if (err)
		return err;

	idpf_vport_intr_map_vector_to_qs(vgrp);
	idpf_vport_intr_napi_add_all(vport, vgrp);

	err = adapter->dev_ops.reg_ops.intr_reg_init(vport, intr_grp);
	if (err)
		goto unroll_vectors_alloc;

	int_name = kasprintf(GFP_KERNEL, "%s-%s",
			     dev_driver_string(idpf_adapter_to_dev(adapter)),
			     vport->netdev->name);

	err = idpf_vport_intr_req_irq(vport, intr_grp, int_name);
	kfree(int_name);
	if (err)
		goto unroll_vectors_alloc;

	return 0;

unroll_vectors_alloc:
	idpf_vport_intr_napi_del_all(intr_grp);

	return err;
}

/**
 * idpf_vport_intr_ena - Enable NAPI and all vectors for the given vport
 * @vport: virtual port
 * @vgrp: Queue and interrupt resource group
 */
void idpf_vport_intr_ena(struct idpf_vport *vport, struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;

	idpf_vport_intr_napi_ena_all(intr_grp);
	idpf_vport_intr_ena_irq_all(vport, intr_grp);
}

/**
 * idpf_config_rss - Send virtchnl messages to configure RSS
 * @vport: Virtual port
 * @rss_data: Associated RSS data
 *
 * Return 0 on success, negative on failure
 */
int idpf_config_rss(struct idpf_vport *vport, struct idpf_rss_data *rss_data)
{
	int err;

	err = idpf_send_get_set_rss_key_msg(vport, rss_data, false);
	if (err)
		return err;

	return idpf_send_get_set_rss_lut_msg(vport, rss_data, false);
}

/**
 * idpf_fill_dflt_rss_lut - Fill the indirection table with the default values
 * @vport: Virtual port structure
 * @rss_data: Associated RSS data
 * @q_grp: Queue resources
 */
static void idpf_fill_dflt_rss_lut(struct idpf_vport *vport,
				   struct idpf_rss_data *rss_data,
				   struct idpf_q_grp *q_grp)
{
	u16 num_active_rxq = q_grp->num_rxq;
	int i;

#ifdef HAVE_XDP_SUPPORT
	/* When we use this code for legacy devices (e.g. in AVF driver), some
	 * Rx queues may not be used because we would not be able to create XDP
	 * Tx queues for them. In such a case do not add their queue IDs to the
	 * RSS LUT by setting the number of active Rx queues to XDP Tx queues
	 * count.
	 */
	if (idpf_xdp_is_prog_ena(vport))
		num_active_rxq -= vport->num_xdp_rxq;
#endif /* HAVE_XDP_SUPPORT */

	for (i = 0; i < rss_data->rss_lut_size; i++) {
		rss_data->rss_lut[i] = i % num_active_rxq;
		rss_data->cached_lut[i] = rss_data->rss_lut[i];
	}
}

/**
 * idpf_init_rss - Allocate and initialize RSS resources
 * @vport: Virtual port
 * @rss_data: Associated RSS data
 * @q_grp: Queue resources
 *
 * Return 0 on success, negative on failure
 */
int idpf_init_rss(struct idpf_vport *vport, struct idpf_rss_data *rss_data,
		  struct idpf_q_grp *q_grp)
{
	u32 lut_size;

	lut_size = rss_data->rss_lut_size * sizeof(u32);
	rss_data->rss_lut = kzalloc(lut_size, GFP_KERNEL);
	if (!rss_data->rss_lut)
		return -ENOMEM;

	rss_data->cached_lut = kzalloc(lut_size, GFP_KERNEL);
	if (!rss_data->cached_lut) {
		kfree(rss_data->rss_lut);
		rss_data->rss_lut = NULL;
		return -ENOMEM;
	}

	if (!(rss_data->rss_lut_size % q_grp->num_rxq))
		goto fill_dflt;

	memset(rss_data->rss_lut, 0, rss_data->rss_lut_size * sizeof(u32));

fill_dflt:
	/* Fill the default RSS lut values*/
	idpf_fill_dflt_rss_lut(vport, rss_data, q_grp);

	return idpf_config_rss(vport, rss_data);
}

/**
 * idpf_deinit_rss - Release RSS resources
 * @rss_data: Associated RSS data
 */
void idpf_deinit_rss(struct idpf_rss_data *rss_data)
{
	kfree(rss_data->cached_lut);
	rss_data->cached_lut = NULL;
	kfree(rss_data->rss_lut);
	rss_data->rss_lut = NULL;
}
