/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#include "kcompat.h"
#include <linux/timer.h>
#ifdef HAVE_GRO_HEADER
#include <net/gro.h>
#endif /* HAVE_GRO_HEADER */
#include "idpf.h"
#include "idpf_lan_txrx.h"

/**
 * idpf_buf_lifo_push - push a buffer pointer onto stack
 * @stack: pointer to stack struct
 * @buf: pointer to buf to push
 *
 * Returns 0 on success, negative on failure
 **/
static int idpf_buf_lifo_push(struct idpf_buf_lifo *stack,
			      struct idpf_tx_stash *buf)
{
	if (unlikely(stack->top == stack->size))
		return -ENOSPC;

	stack->bufs[stack->top++] = buf;

	return 0;
}

/**
 * idpf_buf_lifo_pop - pop a buffer pointer from stack
 * @stack: pointer to stack struct
 **/
static struct idpf_tx_stash *idpf_buf_lifo_pop(struct idpf_buf_lifo *stack)
{
	if (unlikely(!stack->top))
		return NULL;

	return stack->bufs[--stack->top];
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

	adapter->tx_timeout_count++;

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
	netdev_err(netdev, "Detected Tx timeout: Count %d, Queue: %d\n",
		   adapter->tx_timeout_count, txqueue);
#else
	netdev_err(netdev, "Detected Tx timeout: Count %d\n",
		   adapter->tx_timeout_count);
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
	if (!idpf_is_reset_in_prog(adapter)) {
		set_bit(IDPF_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}
}

/**
 * idpf_tx_buf_rel - Release a Tx buffer
 * @tx_q: the queue that owns the buffer
 * @tx_buf: the buffer to free
 */
static void idpf_tx_buf_rel(struct idpf_queue *tx_q, struct idpf_tx_buf *tx_buf)
{
	if (tx_buf->type == IDPF_TX_BUF_SKB ||
	    tx_buf->type == IDPF_TX_BUF_XDP) {
		if (dma_unmap_len(tx_buf, len))
			dma_unmap_single(tx_q->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IDPF_Q_XDP, tx_q->flags))
#ifdef HAVE_XDP_FRAME_STRUCT
			xdp_return_frame(tx_buf->xdpf);
#else
			page_frag_free(tx_buf->raw_buf);
#endif /* HAVE_XDP_FRAME_STRUCT */
		else
			dev_kfree_skb_any(tx_buf->skb);
#else
		dev_kfree_skb_any(tx_buf->skb);
#endif /* HAVE_XDP_SUPPORT */
	} else if (tx_buf->type == IDPF_TX_BUF_FRAG) {
		dma_unmap_page(tx_q->dev,
			       dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len),
			       DMA_TO_DEVICE);
	}

	tx_buf->skb = NULL;
	tx_buf->nr_frags = 0;
	tx_buf->type = IDPF_TX_BUF_EMPTY;
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * idpf_tx_buf_rel_all - Free any empty Tx buffers
 * @txq: queue to be cleaned
 */
static void idpf_tx_buf_rel_all(struct idpf_queue *txq)
{
	struct idpf_tx_stash *stash;
	struct hlist_node *tmp;
	u16 i, tag;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (test_bit(__IDPF_Q_XDP, txq->flags) && txq->xsk_pool) {
		idpf_xsk_cleanup_xdpq(txq);
		return;
	}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	/* Buffers already cleared, nothing to do */
	if (!txq->tx.bufs)
		return;

	/* Free all the Tx buffer sk_buffs */
	for (i = 0; i < txq->desc_count; i++)
		idpf_tx_buf_rel(txq, &txq->tx.bufs[i]);

	kfree(txq->tx.bufs);
	txq->tx.bufs = NULL;

	if (!txq->buf_stack.bufs)
		return;

	/* If a TX timeout occurred, there are potentially still bufs in the
	 * hash table, free them here.
	 */
	hash_for_each_safe(txq->sched_buf_hash, tag, tmp, stash, hlist) {
		if (stash) {
			idpf_tx_buf_rel(txq, &stash->buf);
			hash_del(&stash->hlist);
			idpf_buf_lifo_push(&txq->buf_stack, stash);
		}
	}

	for (i = 0; i < txq->buf_stack.size; i++)
		kfree(txq->buf_stack.bufs[i]);

	kfree(txq->buf_stack.bufs);
	txq->buf_stack.bufs = NULL;
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
	if (bufq) {
		idpf_tx_buf_rel_all(txq);
#ifdef HAVE_XDP_SUPPORT

		if (!test_bit(__IDPF_Q_XDP, txq->flags))
			netdev_tx_reset_queue(netdev_get_tx_queue(txq->vport->netdev,
								  txq->idx));
#elif
		netdev_tx_reset_queue(netdev_get_tx_queue(txq->vport->netdev,
							  txq->idx));
#endif /* HAVE_XDP_SUPPORT */
	}

	if (!txq->desc_ring)
		return;
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
	int i;

	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return;

	for (i = 0; i < q_grp->num_txq; i++)
		idpf_tx_desc_rel(q_grp->txqs[i], true);

	if (!idpf_is_queue_model_split(q_grp->txq_model))
		return;

	for (i = 0; i < q_grp->num_complq; i++)
		idpf_tx_desc_rel(&q_grp->complqs[i], false);
}

/**
 * idpf_tx_buf_alloc_all - Allocate memory for all buffer resources
 * @tx_q: queue for which the buffers are allocated
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_tx_buf_alloc_all(struct idpf_queue *tx_q)
{
	int buf_size;
	int i;

	/* Allocate book keeping buffers only. Buffers to be supplied to HW
	 * are allocated by kernel network stack and received as part of skb
	 */
	buf_size = sizeof(struct idpf_tx_buf) * tx_q->desc_count;
	tx_q->tx.bufs = kzalloc(buf_size, GFP_KERNEL);
	if (!tx_q->tx.bufs)
		return -ENOMEM;

	/* Initialize tx buf stack for out-of-order completions if
	 * flow scheduling offload is enabled
	 */
	tx_q->buf_stack.bufs = kcalloc(tx_q->desc_count,
				       sizeof(struct idpf_tx_stash *),
				       GFP_KERNEL);
	if (!tx_q->buf_stack.bufs)
		return -ENOMEM;

	tx_q->buf_stack.size = tx_q->desc_count;
	tx_q->buf_stack.top = tx_q->desc_count;

	for (i = 0; i < tx_q->desc_count; i++) {
		tx_q->buf_stack.bufs[i] = kzalloc(sizeof(*tx_q->buf_stack.bufs[i]),
						  GFP_KERNEL);
		if (!tx_q->buf_stack.bufs[i])
			return -ENOMEM;
	}

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
	u32 desc_sz;
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
	set_bit(__IDPF_Q_GEN_CHK, tx_q->flags);

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
	u16 compl_tag_w = IDPF_TX_SPLITQ_COMPL_TAG_WIDTH;
	int i, err;

	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return 0;

	if (idpf_is_cap_ena(vport->adapter, IDPF_OTHER_CAPS,
			    VIRTCHNL2_CAP_MISS_COMPL_TAG))
		compl_tag_w = IDPF_TX_SPLITQ_COMPL_TAG_WIDTH - 1;

	/* Setup buffer queues. In single queue model buffer queues and
	 * completion queues will be same.
	 */
	for (i = 0; i < q_grp->num_txq; i++) {
		struct idpf_queue *txq = q_grp->txqs[i];
		u8 gen_bits = 0;
		u16 bufidx_mask;

		err = idpf_tx_desc_alloc(txq, true);
		if (err)
			return err;

		if (!is_splitq)
			continue;

		txq->compl_tag_cur_gen = 0;

		/* Determine the number of bits in the bufid mask and add one
		 * to get the start of the generation bits
		 */
		bufidx_mask = txq->desc_count - 1;
		while (bufidx_mask >> 1) {
			txq->compl_tag_gen_s++;
			bufidx_mask = bufidx_mask >> 1;
		}
		txq->compl_tag_gen_s++;

		gen_bits = compl_tag_w - txq->compl_tag_gen_s;
		txq->compl_tag_gen_max = GETMAXVAL(gen_bits);

		/* Set bufid mask based on location of first gen bit; it cannot
		 * simply be the descriptor ring size-1 since we can have size
		 * values where not all of those bits are set.
		 */
		txq->compl_tag_bufid_m = GETMAXVAL(txq->compl_tag_gen_s);
	}

	if (!is_splitq)
		return 0;

	for (i = 0; i < q_grp->num_complq; i++) {
		err = idpf_tx_desc_alloc(&q_grp->complqs[i], false);
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

	if (q->rx_hsplit_en)
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

	splitq_rx_desc = IDPF_SPLITQ_RX_BUF_DESC(bufq, nta);
	buf = &bufq->rx.bufs[buf_id];
	pinfo = &buf->page_info[buf->page_indx];

	if (bufq->rx_hsplit_en) {
		splitq_rx_desc->hdr_addr =
			cpu_to_le64(bufq->rx.hdr_buf_pa +
				    (u32)buf_id * IDPF_HDR_BUF_SIZE);
	}

	dma_sync_single_range_for_device(bufq->dev, pinfo->dma,
					 pinfo->page_offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);
	splitq_rx_desc->pkt_addr = cpu_to_le64(pinfo->dma +
					       pinfo->page_offset);
	splitq_rx_desc->qword0.buf_id = cpu_to_le16(buf_id);

	nta++;
	if (unlikely(nta == bufq->desc_count))
		nta = 0;
	bufq->next_to_alloc = nta;
}

/**
 * idpf_p2p_rx_post_buf_desc - Post buffer to bufq descriptor ring
 * @bufq: buffer queue to post to
 * @buf_id: buffer id to post
 */
static void idpf_p2p_rx_post_buf_desc(struct idpf_queue *bufq, u16 buf_id)
{
	struct virtchnl2_splitq_16byte_rx_buf_desc *desc = NULL;
	u16 nta = bufq->next_to_alloc;
	struct idpf_page_info *pinfo;
	struct idpf_rx_buf *buf;

	desc = IDPF_P2P_SPLITQ_RX_BUF_DESC(bufq, nta);
	buf = &bufq->rx.bufs[buf_id];
	pinfo = &buf->page_info[buf->page_indx];

	dma_sync_single_range_for_device(bufq->dev, pinfo->dma,
					 pinfo->page_offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);
	desc->pkt_addr = cpu_to_le64(pinfo->dma +
					       pinfo->page_offset);
	desc->qword0.buf_id = cpu_to_le16(buf_id);

	nta++;
	if (unlikely(nta == bufq->desc_count))
		nta = 0;
	bufq->next_to_alloc = nta;
}

/**
 * idpf_rx_post_init_bufs - Post initial buffers to bufq
 * @bufq: Buffer queue to post working set to
 */
static void idpf_rx_post_init_bufs(struct idpf_queue *bufq)
{
	u16 i, working_set = IDPF_RX_BUFQ_WORKING_SET(bufq);

	if (bufq->vgrp_type == IDPF_GRP_TYPE_P2P) {
		for (i = 0; i < working_set; i++)
			idpf_p2p_rx_post_buf_desc(bufq, i);

		goto hw_update;
	}

	for (i = 0; i < working_set; i++)
		idpf_rx_post_buf_desc(bufq, i);

hw_update:
	idpf_rx_buf_hw_update(bufq, bufq->next_to_alloc & ~(bufq->rx_buf_stride - 1));
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

	idpf_rx_post_init_bufs(q);

	return 0;
}

/**
 * idpf_rx_post_buf_refill - Post buffer id to refill queue
 * @refillq: Refill queue to post to
 * @buf_id: Buffer id to post
 */
void idpf_rx_post_buf_refill(struct idpf_sw_queue *refillq, u16 buf_id)
{
	u16 nta = refillq->next_to_alloc;

	/* Store the buffer ID and the SW maintained GEN bit to the refillq */
	refillq->ring[nta] =
		((buf_id << IDPF_RX_BI_BUFID_S) & IDPF_RX_BI_BUFID_M) |
		(!!(test_bit(__IDPF_Q_GEN_CHK, refillq->flags)) <<
		IDPF_RX_BI_GEN_S);

	if (unlikely(++nta == refillq->desc_count)) {
		nta = 0;
		change_bit(__IDPF_Q_GEN_CHK, refillq->flags);
	}
	refillq->next_to_alloc = nta;
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
	if (idpf_xsk_is_zc_bufq(q))
		return 0;

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
	u16 i;

	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return 0;

	vport->txqs = kcalloc(q_grp->num_txq, sizeof(struct idpf_queue *),
			      GFP_KERNEL);
	if (!vport->txqs)
		return -ENOMEM;

	vport->num_txq = q_grp->num_txq;
	for (i = 0; i < q_grp->num_txq; i++)
		vport->txqs[i] = q_grp->txqs[i];

	return 0;
}

/**
 * idpf_fast_path_txq_deinit - Release fast path TX queue array
 * @vport: Vport structure
 *
 * Returns 0 on success, negative on failure
 */
static void idpf_fast_path_txq_deinit(struct idpf_vport *vport)
{
	kfree(vport->txqs);
	vport->txqs = NULL;
}

/**
 * idpf_rx_buf_alloc_all - Allocate memory for all buffer resources
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_rx_buf_alloc_all(struct idpf_q_grp *q_grp)
{
	bool is_splitq = idpf_is_queue_model_split(q_grp->rxq_model);
	int numq, i, err;

	numq = is_splitq ? q_grp->num_bufq : q_grp->num_rxq;

	for (i = 0; i < numq; i++) {
		struct idpf_queue *q;

		/* In splitq, the buffers are managed by the buffer queue and
		 * the RX queues instead just get a pointer to the buffer ring
		 * to make an skb. In singleq the RX queue will directly own
		 * the buffer ring.
		 */
		q = is_splitq ? &q_grp->bufqs[i] : q_grp->rxqs[i];

		err = idpf_rx_buf_alloc(q, is_splitq);
		if (err)
			return err;
	}

	return 0;
}

/**
 * idpf_refillq_desc_alloc - Allocate ring for refillqs
 * @refillq: Queue to allocate ring for
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_refillq_desc_alloc(struct idpf_sw_queue *refillq)
{
	refillq->ring = kcalloc(refillq->desc_count, sizeof(u16), GFP_KERNEL);
	if (!refillq->ring)
		return -ENOMEM;

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

	if (q->vgrp_type == IDPF_GRP_TYPE_P2P)
		q->size = q->desc_count * (is_bufq ?
			  sizeof(struct virtchnl2_splitq_16byte_rx_buf_desc) :
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
 * idpf_rx_desc_alloc_all - allocate all RX queues resources
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rx_desc_alloc_all(struct idpf_q_grp *q_grp)
{
	int i, err;

	for (i = 0; i < q_grp->num_rxq; i++) {
		err = idpf_rx_desc_alloc(q_grp->rxqs[i], false);
		if (err)
			return err;
	}

	if (!idpf_is_queue_model_split(q_grp->rxq_model))
		return 0;

	for (i = 0; i < q_grp->num_bufq; i++) {
		struct idpf_queue *bufq = &q_grp->bufqs[i];

		err = idpf_rx_desc_alloc(bufq, true);
		if (err)
			return err;

		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			continue;

		err = idpf_refillq_desc_alloc(&q_grp->refillqs[i]);
		if (err)
			return err;
	}

	return 0;
}

/**
 * idpf_tx_queue_rel_all - Release all resources for TX queues
 * @q_grp: Queue resources
 */
static void idpf_tx_queue_rel_all(struct idpf_q_grp *q_grp)
{
	int i;

	idpf_tx_desc_rel_all(q_grp);

	for (i = 0; i < q_grp->num_complq; i++) {
		kfree(q_grp->complqs[i].tx.txqs);
		q_grp->complqs[i].tx.txqs = NULL;
	}

	kfree(q_grp->complqs);
	q_grp->complqs = NULL;

	for (i = 0; i < q_grp->num_txq; i++) {
		kfree(q_grp->txqs[i]);
		q_grp->txqs[i] = NULL;
	}

	kfree(q_grp->txqs);
	q_grp->txqs = NULL;
}

/**
 * idpf_rxq_rel - Release resources for RX queue
 * @q_grp: Queue resources
 * @rxq: RX queue to release resources on
 * @bufq_per_rxq: Number of buffer queues per RX queue
 */
static void idpf_rxq_rel(struct idpf_q_grp *q_grp, struct idpf_queue *rxq,
			 u16 bufq_per_rxq)
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

	for (i = 0; i < bufq_per_rxq; i++) {
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
	idpf_rx_buf_rel_all(bufq);

	if (!bufq->desc_ring)
		return;
	dma_free_coherent(bufq->dev, bufq->size, bufq->desc_ring,
			  bufq->dma);
	bufq->desc_ring = NULL;
}

/**
 * idpf_rx_queue_rel_all - Release all receive queue resources
 * @q_grp: Queue resources
 */
static void idpf_rx_queue_rel_all(struct idpf_q_grp *q_grp)
{
	int i;

	if (!idpf_is_queue_model_split(q_grp->rxq_model))
		goto rxq_rel;

	for (i = 0; i < q_grp->num_bufq; i++) {
		idpf_bufq_rel(&q_grp->bufqs[i]);
		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			continue;
		kfree(q_grp->refillqs[i].ring);
	}

	kfree(q_grp->bufqs);
	q_grp->bufqs = NULL;
	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		goto rxq_rel;

	kfree(q_grp->refillqs);
	q_grp->refillqs = NULL;

rxq_rel:
	for (i = 0; i < q_grp->num_rxq; i++) {
		idpf_rxq_rel(q_grp, q_grp->rxqs[i], q_grp->bufq_per_rxq);
#ifdef HAVE_XDP_BUFF_RXQ
		if (xdp_rxq_info_is_reg(&q_grp->rxqs[i]->xdp_rxq))
			xdp_rxq_info_unreg(&q_grp->rxqs[i]->xdp_rxq);
#endif /* HAVE_XDP_BUFF_RXQ */
		kfree(q_grp->rxqs[i]);
		q_grp->rxqs[i] = NULL;
	}

	kfree(q_grp->rxqs);
	q_grp->rxqs = NULL;
}

/**
 * idpf_vport_queue_rel_all - Free memory for all queues
 * @vport: virtual port
 * @q_grp: Queue resources
 *
 * Free the memory allocated for queues associated to a vport
 */
void idpf_vport_queue_rel_all(struct idpf_vport *vport,
			      struct idpf_q_grp *q_grp)
{
	idpf_tx_queue_rel_all(q_grp);
	idpf_rx_queue_rel_all(q_grp);
	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return;

	idpf_fast_path_txq_deinit(vport);
}

/**
 * idpf_vport_vgrp_init_num_qs - Initialize vgrp number of queues
 * @vport: Vport to initialize queues
 * @q_grp: Queue resources
 */
void idpf_vport_vgrp_init_num_qs(struct idpf_vport *vport,
				 struct idpf_q_grp *q_grp)
{
	struct virtchnl2_queue_group_info *qg_info;

	qg_info = idpf_get_queue_group_info(q_grp->req_qs_chunks);
	q_grp->num_txq = le16_to_cpu(qg_info->num_tx_q);
	q_grp->num_rxq = le16_to_cpu(qg_info->num_rx_q);

	if (idpf_is_queue_model_split(q_grp->txq_model))
		q_grp->num_complq = le16_to_cpu(qg_info->num_tx_complq);
	if (idpf_is_queue_model_split(q_grp->rxq_model))
		q_grp->num_bufq = le16_to_cpu(qg_info->num_rx_bufq);

	/* Adjust number of buffer queues per Rx queue group */
	if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
		q_grp->bufq_per_rxq = 0;
		q_grp->bufq_size[0] = IDPF_RX_BUF_2048;

		return;
	}

	q_grp->bufq_per_rxq = IDPF_P2P_BUFQ_PER_VGRP;

	/* Bufq[0] default buffer size is 4K */
	q_grp->bufq_size[0] = IDPF_RX_BUF_4096;
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

	if (idpf_is_queue_model_split(q_grp->txq_model)) {
		vport->num_xdp_complq = vport->num_xdp_txq;
		vport->xdp_complq_offset = vport->xdp_txq_offset;
	}

adjust_bufqs:
#endif /* HAVE_XDP_SUPPORT */
	/* Adjust number of buffer queues per Rx queue */
	if (!idpf_is_queue_model_split(q_grp->rxq_model)) {
		q_grp->bufq_per_rxq = 0;
		q_grp->num_bufq = 0;
		q_grp->bufq_size[0] = IDPF_RX_BUF_2048;
		return;
	}

#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(vport)) {
		/* After loading the XDP program we will have only one buffer
		 * queue per group with buffer size 4kB.
		 */
		q_grp->bufq_per_rxq = IDPF_SINGLE_BUFQ_PER_RXQ;
		q_grp->bufq_size[0] = IDPF_RX_BUF_4096;
		q_grp->num_bufq = q_grp->num_rxq * q_grp->bufq_per_rxq;
		return;
	}
#endif /* HAVE_XDP_SUPPORT */

	q_grp->bufq_per_rxq = IDPF_MAX_BUFQS_PER_RXQ;
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
	u32 num_req_txq_desc, num_req_rxq_desc;
	u8 num_bufqs = q_grp->bufq_per_rxq;
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
	int num_bufq_per_rxq = IDPF_MAX_BUFQS_PER_RXQ;
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
			num_bufq_per_rxq = IDPF_SINGLE_BUFQ_PER_RXQ;
			num_txq += num_rxq;
		}
#endif /* HAVE_XDP_SUPPORT */
	} else {
		int num_cpus = num_online_cpus();

		num_txq = min_t(int, max_q->max_txq, num_cpus);
		num_rxq = min_t(int, max_q->max_rxq, num_cpus);
	}

	if (idpf_is_queue_model_split(le16_to_cpu(vport_msg->txq_model)))
		num_complq = num_txq * IDPF_TXQ_PER_COMPLQ;

	if (idpf_is_queue_model_split(le16_to_cpu(vport_msg->rxq_model))) {
		num_bufq = num_rxq * num_bufq_per_rxq;
	}

	vport_msg->num_tx_q = cpu_to_le16(num_txq);
	vport_msg->num_tx_complq = cpu_to_le16(num_complq);
	vport_msg->num_rx_q = cpu_to_le16(num_rxq);
	vport_msg->num_rx_bufq = cpu_to_le16(num_bufq);
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
 * idpf_txq_alloc - Allocate all TX queue resources
 * @vport: Vport to allocate TX queues for
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_txq_alloc(struct idpf_vport *vport, struct idpf_q_grp *q_grp)
{
	struct idpf_adapter *adapter = vport->adapter;
	bool flow_sch_en, miss_compl_tag_en;
	int i;

	flow_sch_en = !idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
				       VIRTCHNL2_CAP_SPLITQ_QSCHED);
	miss_compl_tag_en = idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
					    VIRTCHNL2_CAP_MISS_COMPL_TAG);

	q_grp->txqs = kcalloc(q_grp->num_txq, sizeof(struct idpf_queue *),
			      GFP_KERNEL);
	if (!q_grp->txqs)
		return -ENOMEM;

	for (i = 0; i < q_grp->num_txq; i++) {
		struct idpf_queue *txq;

		txq = kzalloc(sizeof(*txq), GFP_KERNEL);

		if (!txq)
			return -ENOMEM;

		q_grp->txqs[i] = txq;
		txq->vport = vport;
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
		if (adapter->iommu_byp.ddev)
			txq->dev = adapter->iommu_byp.ddev;
		else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
		txq->dev = idpf_adapter_to_dev(adapter);
		txq->idx = i;
		txq->desc_count = q_grp->txq_desc_count;
		txq->tx_max_bufs = idpf_get_max_tx_bufs(adapter);
		txq->crc_enable = vport->crc_enable;
		txq->tx_min_pkt_len = idpf_get_min_tx_pkt_len(adapter);

		if (flow_sch_en) {
			set_bit(__IDPF_Q_FLOW_SCH_EN, txq->flags);
			if (q_grp->type == IDPF_GRP_TYPE_P2P)
				continue;
			hash_init(txq->sched_buf_hash);

			if (miss_compl_tag_en)
				set_bit(__IDPF_Q_MISS_TAG_EN, txq->flags);
		}
	}

	if (!idpf_is_queue_model_split(q_grp->txq_model))
		return 0;

	q_grp->complqs = kcalloc(q_grp->num_complq, sizeof(*q_grp->complqs),
				 GFP_KERNEL);
	if (!q_grp->complqs)
		return -ENOMEM;

	for (i = 0; i < q_grp->num_complq; i++) {
		struct idpf_queue *complq = &q_grp->complqs[i];
		int j;

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
		if (adapter->iommu_byp.ddev)
			complq->dev = adapter->iommu_byp.ddev;
		else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
		complq->dev = idpf_adapter_to_dev(adapter);
		complq->desc_count = q_grp->complq_desc_count;
		complq->vport = vport;
		complq->idx = i;

		complq->tx.txqs = kcalloc(IDPF_TXQ_PER_COMPLQ,
					  sizeof(struct idpf_queue *),
					  GFP_KERNEL);
		if (!complq->tx.txqs)
			return -ENOMEM;

		if (flow_sch_en)
			set_bit(__IDPF_Q_FLOW_SCH_EN, complq->flags);

		for (j = 0; j < IDPF_TXQ_PER_COMPLQ; j++) {
			struct idpf_queue *txq;

			txq = idpf_txq_from_rel_qid(q_grp, complq, j);
			/* It's possible there's an odd number of TX queues to
			 * map to complqs, just return in that case. There
			 * should only ever be one complq that doesn't have a
			 * full IDPF_TXQ_PER_COMPLQ mapped to it, so we're done
			 * here.
			 */
			if (!txq)
				return 0;

			txq->tx.complq = complq;
			txq->tx.rel_qid = j;
			complq->tx.txqs[j] = txq;
			complq->tx.num_txq++;
		}
	}

	return 0;
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
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter = vport->adapter;

	config_data = &adapter->vport_config[vport->idx]->user_config;

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
	if (test_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags)) {
		q->rx_hsplit_en = true;
		q->rx_hbuf_size = IDPF_HDR_BUF_SIZE;
	}
	set_bit(__IDPF_Q_GEN_CHK, q->flags);
}

/**
 * idpf_bufq_init - Initialize all bufqs on vport
 * @vport: Associated vport with bufqs
 * @q_grp: Queue resources
 */
static void idpf_bufq_init(struct idpf_vport *vport, struct idpf_q_grp *q_grp)
{
	int i;

	for (i = 0; i < q_grp->num_bufq; i++) {
		struct idpf_queue *bufq = &q_grp->bufqs[i];
		int idx = i % q_grp->bufq_per_rxq;

		__idpf_rxq_init(vport, bufq);
		bufq->idx = i;
		bufq->rx.rxq_idx = i / q_grp->bufq_per_rxq;
		bufq->desc_count = q_grp->bufq_desc_count[idx];
		bufq->rx_buf_size = q_grp->bufq_size[idx];
		bufq->rx_buf_stride = IDPF_RX_BUF_STRIDE;
		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			bufq->vgrp_type = IDPF_GRP_TYPE_P2P;
	}
}

/**
 * idpf_refillq_init - Initialize all refillqs on vport
 * @vport: Associated vport with refillqs
 * @q_grp: Queue resources
 */
static void idpf_refillq_init(struct idpf_vport *vport,
			      struct idpf_q_grp *q_grp)
{
	struct idpf_sw_queue *refillq;
	int i;

	for (i = 0; i < q_grp->num_bufq; i++) {
		refillq = &q_grp->refillqs[i];

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
		if (vport->adapter->iommu_byp.ddev)
			refillq->dev = vport->adapter->iommu_byp.ddev;
		else
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
		refillq->dev = idpf_adapter_to_dev(vport->adapter);
		refillq->desc_count =
			q_grp->bufq_desc_count[i % q_grp->bufq_per_rxq];
		set_bit(__IDPF_Q_GEN_CHK, refillq->flags);
		set_bit(__IDPF_RFLQ_GEN_CHK, refillq->flags);
	}
}

/**
 * idpf_rxq_init - Initialize all RX queue fields
 * @vport: Associated vport
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rxq_init(struct idpf_vport *vport, struct idpf_q_grp *q_grp)
{
	int i;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq;

		rxq = kzalloc(sizeof(struct idpf_queue), GFP_KERNEL);
		if (!rxq)
			return -ENOMEM;

		q_grp->rxqs[i] = rxq;
		__idpf_rxq_init(vport, rxq);
		rxq->idx = i;
		rxq->rx.rxq_idx = i;
		rxq->desc_count = q_grp->rxq_desc_count;
		/* In splitq mode, RXQ buffer size should be set to that of the
		 * first buffer queue associated with this RXQ
		 */
		rxq->rx_buf_size = q_grp->bufq_size[0];
		rxq->rx_max_pkt_size = vport->netdev->mtu + IDPF_PACKET_HDR_PAD;
		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			rxq->vgrp_type = IDPF_GRP_TYPE_P2P;

		idpf_rxq_set_descids(q_grp, rxq);
	}

	return 0;
}

/**
 * idpf_rxq_alloc - Allocate all RX queue resources
 * @vport: Vport to allocate rxqs for
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_rxq_alloc(struct idpf_vport *vport, struct idpf_q_grp *q_grp)
{
	int err;

	q_grp->rxqs = kcalloc(q_grp->num_rxq, sizeof(struct idpf_queue *),
			      GFP_KERNEL);
	if (!q_grp->rxqs)
		return -ENOMEM;

	err = idpf_rxq_init(vport, q_grp);
	if (err)
		return err;

	if (!idpf_is_queue_model_split(q_grp->rxq_model))
		return 0;

	q_grp->bufqs = kcalloc(q_grp->num_bufq, sizeof(struct idpf_queue),
			       GFP_KERNEL);
	if (!q_grp->bufqs)
		return -ENOMEM;

	idpf_bufq_init(vport, q_grp);

	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return 0;

	/* As only 1:M configuration is accounted now with 1 RX queue and
	 * M buffer queues, number of refillqs will be equal to that of the
	 * buffer queues
	 */
	q_grp->refillqs = kcalloc(q_grp->num_bufq,
				  sizeof(struct idpf_sw_queue), GFP_KERNEL);
	if (!q_grp->refillqs)
		return -ENOMEM;

	idpf_refillq_init(vport, q_grp);

	return 0;
}

/**
 * idpf_vport_queue_alloc - Allocate queue resources for vport
 * @vport: Vport to use
 * @q_grp: Queue resources
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_vport_queue_alloc(struct idpf_vport *vport,
				  struct idpf_q_grp *q_grp)
{
	int err;

	err = idpf_txq_alloc(vport, q_grp);
	if (err)
		return err;

	err = idpf_rxq_alloc(vport, q_grp);
	if (err)
		return err;

	return 0;
}

/**
 * idpf_rx_map_refillqs - Link RX and buffer queues to refillqs
 * @q_grp: Queue resources
 */
static void idpf_rx_map_refillqs(struct idpf_q_grp *q_grp)
{
	int i, j;

	if (q_grp->type == IDPF_GRP_TYPE_P2P)
		return;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];

		rxq->rx.num_refillq = q_grp->bufq_per_rxq;
		rxq->rx.refillqs = &q_grp->refillqs[i * q_grp->bufq_per_rxq];
		for (j = 0; j < q_grp->bufq_per_rxq; j++) {
			int offset = idpf_rx_bufq_offset(q_grp, i, j);
			struct idpf_queue *bufq;

			bufq = &q_grp->bufqs[offset];
			bufq->rx.num_refillq = IDPF_DFLT_SPLITQ_RXQ_PER_BUFQ;
			bufq->rx.refillqs = &q_grp->refillqs[offset];
		}
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
	int i, j;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];

		rxq->rx.bufq_bufs = kcalloc(q_grp->bufq_per_rxq,
					    sizeof(struct idpf_rx_buf *),
					    GFP_KERNEL);
		if (!rxq->rx.bufq_bufs)
			return -ENOMEM;

		if (rxq->rx_hsplit_en) {
			rxq->rx.bufq_hdr_bufs = kcalloc(q_grp->bufq_per_rxq,
							sizeof(void *),
							GFP_KERNEL);
			if (!rxq->rx.bufq_hdr_bufs)
				return -ENOMEM;
		}

		for (j = 0; j < q_grp->bufq_per_rxq; j++) {
			const int offset = idpf_rx_bufq_offset(q_grp, i, j);
			struct idpf_queue *bufq = &q_grp->bufqs[offset];
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

	return 0;
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

	err = idpf_vport_queue_alloc(vport, q_grp);
	if (err)
		goto err_out;

	err = idpf_tx_desc_alloc_all(vport, q_grp);
	if (err)
		goto err_out;

	err = idpf_rx_desc_alloc_all(q_grp);
	if (err)
		goto err_out;

	err = idpf_rx_buf_alloc_all(q_grp);
	if (err)
		goto err_out;

	err = idpf_fast_path_txq_init(vport, q_grp);
	if (err)
		goto err_out;

	if (idpf_is_queue_model_split(q_grp->rxq_model)) {
		idpf_rx_map_refillqs(q_grp);
		err = idpf_rx_map_buffer_rings(q_grp);
		if (err)
			goto err_out;
	}

#ifdef HAVE_ETF_SUPPORT
	config_data = &vport->adapter->vport_config[vport->idx]->user_config;
	/* Initialize flow scheduling for queues that were requested
	 * before the interface was brought up
	 */
	for (i = 0; i < q_grp->num_txq; i++) {
		if (test_bit(i, config_data->etf_qenable)) {
			set_bit(__IDPF_Q_FLOW_SCH_EN, q_grp->txqs[i]->flags);
			set_bit(__IDPF_Q_ETF_EN, q_grp->txqs[i]->flags);
		}
	}

#endif /* HAVE_ETF_SUPPORT */
#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(vport)) {
		int j;

		for (j = vport->xdp_txq_offset; j < q_grp->num_txq; j++)
			set_bit(__IDPF_Q_XDP, q_grp->txqs[j]->flags);
	}

#endif /* HAVE_XDP_SUPPORT */
	return 0;

err_out:
	idpf_vport_queue_rel_all(vport, q_grp);

	return err;
}

/**
 * idpf_tx_handle_sw_marker - Handle queue marker packet
 * @tx_q: tx queue to handle software marker
 */
static void idpf_tx_handle_sw_marker(struct idpf_queue *tx_q)
{
	struct idpf_vport *vport = tx_q->vport;
	struct idpf_q_grp *q_grp;
	int i;

	clear_bit(__IDPF_Q_SW_MARKER, tx_q->flags);
	/* Hardware must write marker packets to all queues associated with
	 * completion queues. So check if all queues received marker packets
	 */
	q_grp = &vport->dflt_grp.q_grp;
	for (i = 0; i < q_grp->num_txq; i++)
		/* If we're still waiting on any other TXQ marker completions,
		 * just return now since we cannot wake up the marker_wq yet.
		 */
		if (test_bit(__IDPF_Q_SW_MARKER, q_grp->txqs[i]->flags))
			return;

	/* Drain complete */
	set_bit(IDPF_VPORT_SW_MARKER, vport->flags);
	wake_up(&vport->sw_marker_wq);
}

/**
 * idpf_tx_splitq_unmap_hdr - unmap DMA buffer for header
 * @tx_q: tx queue to clean buffer from
 * @tx_buf: buffer to be cleaned
 */
static void idpf_tx_splitq_unmap_hdr(struct idpf_queue *tx_q,
				     struct idpf_tx_buf *tx_buf)
{
	/* unmap skb header data */
	dma_unmap_single(tx_q->dev,
			 dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len),
			 DMA_TO_DEVICE);

	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * idpf_tx_splitq_clean_hdr - Clean TX buffer resources for header portion of
 * packet
 * @tx_q: tx queue to clean buffer from
 * @tx_buf: buffer to be cleaned
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @napi_budget: Used to determine if we are in netpoll
 */
static void idpf_tx_splitq_clean_hdr(struct idpf_queue *tx_q,
				     struct idpf_tx_buf *tx_buf,
				     struct idpf_cleaned_stats *cleaned,
				     int napi_budget)
{
#ifdef HAVE_XDP_SUPPORT
	if (test_bit(__IDPF_Q_XDP, tx_q->flags))
#ifdef HAVE_XDP_FRAME_STRUCT
		xdp_return_frame(tx_buf->xdpf);
#else
		page_frag_free(tx_buf->raw_buf);
#endif
	else
		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);
#else
	napi_consume_skb(tx_buf->skb, napi_budget);
#endif /* HAVE_XDP_SUPPORT */

	if (dma_unmap_len(tx_buf, len))
		idpf_tx_splitq_unmap_hdr(tx_q, tx_buf);

	/* clear tx_buf data */
	tx_buf->type = IDPF_TX_BUF_EMPTY;
	tx_buf->nr_frags = 0;
	cleaned->bytes += tx_buf->bytecount;
	cleaned->packets += tx_buf->gso_segs;
}

/**
 * idpf_tx_clean_stashed_bufs - clean bufs that were stored for
 * out of order completions
 * @txq: queue to clean
 * @compl_tag: completion tag of packet to clean (from completion descriptor)
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @budget: Used to determine if we are in netpoll
 */
static void
idpf_tx_clean_stashed_bufs(struct idpf_queue *txq, u16 compl_tag, u8 *desc_ts,
			   struct idpf_cleaned_stats *cleaned, int budget)
{
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps = txq->vport->tx_tstamp_caps;
	struct idpf_ptp_tx_tstamp_status *tx_tstamp_status;
	struct idpf_tx_stash *stash;
	struct hlist_node *tmp_buf;
	u16 i;

	/* Buffer completion */
	hash_for_each_possible_safe(txq->sched_buf_hash, stash, tmp_buf,
				    hlist, compl_tag) {
		if (unlikely(stash->buf.compl_tag != compl_tag))
			continue;

		hash_del(&stash->hlist);

		switch (stash->buf.type) {
		case IDPF_TX_BUF_SKB_TSTAMP:
			if (!(skb_shinfo(stash->buf.skb)->tx_flags & SKBTX_IN_PROGRESS))
				goto skip_tx_tstamp;

			for (i = 0; i < tx_tstamp_caps->num_entries; i++) {
				tx_tstamp_status = &tx_tstamp_caps->tx_tstamp_status[i];
				if (tx_tstamp_status->state == IDPF_PTP_FREE) {
					tx_tstamp_status->skb = stash->buf.skb;
					tx_tstamp_status->state = IDPF_PTP_REQUEST;

					/* Fetch timestamp from completion
					 * descriptor through virtchnl msg to
					 * report to stack.
					 */
					mod_delayed_work(txq->vport->tstamp_wq,
							 &txq->vport->tstamp_task,
							 0);
					break;
				}
			}
skip_tx_tstamp:
			idpf_tx_splitq_clean_hdr(txq, &stash->buf, cleaned,
						 budget);
			break;
		case IDPF_TX_BUF_SKB:
			if (unlikely(stash->miss_pkt))
				del_timer(&stash->reinject_timer);

#ifdef HAVE_XDP_SUPPORT
			fallthrough;
		case IDPF_TX_BUF_XDP:
#endif /* HAVE_XDP_SUPPORT */
			idpf_tx_splitq_clean_hdr(txq, &stash->buf, cleaned,
						 budget);
			break;
		case IDPF_TX_BUF_FRAG:
			dma_unmap_page(txq->dev,
				       dma_unmap_addr(&stash->buf, dma),
				       dma_unmap_len(&stash->buf, len),
				       DMA_TO_DEVICE);
			dma_unmap_len_set(&stash->buf, len, 0);
			break;
		default:
			break;
		}

		/* Push shadow buf back onto stack */
		idpf_buf_lifo_push(&txq->buf_stack, stash);
	}
}

/**
 * idpf_tx_find_stashed_bufs - fetch "first" buffer for a packet with the given
 * completion tag
 * @txq: queue to clean
 * @compl_tag: completion tag of packet to clean (from completion descriptor)
 */
static struct idpf_tx_stash *idpf_tx_find_stashed_bufs(struct idpf_queue *txq,
						       u16 compl_tag)
{
	struct idpf_tx_stash *stash;

	/* Buffer completion */
	hash_for_each_possible(txq->sched_buf_hash, stash, hlist, compl_tag) {
		if (unlikely(stash->buf.compl_tag != (int)compl_tag))
			continue;

		if (stash->buf.skb)
			return stash;
	}

	return NULL;
}

/**
 * idpf_tx_handle_reinject_expire - handler for miss completion timer
 * @timer: pointer to timer that expired
 */
static void idpf_tx_handle_reinject_expire(struct timer_list *timer)
{
	struct idpf_tx_stash *stash = from_timer(stash, timer, reinject_timer);
	struct idpf_cleaned_stats cleaned = { };
	struct idpf_queue *txq = stash->txq;
	struct netdev_queue *nq;

	idpf_tx_clean_stashed_bufs(txq, stash->buf.compl_tag, NULL, &cleaned, 0);

	/* Update BQL */
	nq = netdev_get_tx_queue(txq->vport->netdev, txq->idx);
	netdev_tx_completed_queue(nq, cleaned.packets, cleaned.bytes);

	u64_stats_update_begin(&txq->stats_sync);
	u64_stats_inc(&txq->vport->port_stats.tx_reinjection_timeouts);
	u64_stats_update_end(&txq->stats_sync);
}

/**
 * idpf_tx_start_reinject_timer - start timer to wait for reinject completion
 * @txq: pointer to queue struct
 * @stash: stash of packet to start timer for
 */
static void idpf_tx_start_reinject_timer(struct idpf_queue *txq,
					 struct idpf_tx_stash *stash)
{
	/* Back pointer to txq so timer expire handler knows what to
	 * clean if timer expires.
	 */
	stash->txq = txq;
	stash->miss_pkt = true;
	timer_setup(&stash->reinject_timer, idpf_tx_handle_reinject_expire, 0);
	mod_timer(&stash->reinject_timer, jiffies + msecs_to_jiffies(4 * HZ));
}

/**
 * idpf_stash_flow_sch_buf - store buffer parameters info to be freed at a
 * later time (only relevant for flow scheduling mode)
 * @txq: Tx queue to clean
 * @tx_buf: buffer to store
 * @compl_type: type of completion, determines what extra steps need to be
 * taken when stashing, such as starting the reinject timer on a miss
 * completion. Only IDPF_TXD_COMPLT_RULE_MISS and IDPF_TXD_COMPLT_REINJECTED
 * are relevant
 */
static int idpf_stash_flow_sch_buf(struct idpf_queue *txq,
				   struct idpf_tx_buf *tx_buf,
				   u8 compl_type)
{
	struct idpf_tx_stash *stash;

	if (unlikely(!tx_buf->type))
		return 0;

	stash = idpf_buf_lifo_pop(&txq->buf_stack);
	if (unlikely(!stash)) {
		net_err_ratelimited("%s: No out-of-order TX buffers left!\n",
				    txq->vport->netdev->name);
		return -ENOMEM;
	}

	/* Store buffer params in shadow buffer */
	stash->buf.skb = tx_buf->skb;
	stash->buf.bytecount = tx_buf->bytecount;
	stash->buf.gso_segs = tx_buf->gso_segs;
	stash->buf.type = tx_buf->type;
	stash->buf.nr_frags = tx_buf->nr_frags;
	dma_unmap_addr_set(&stash->buf, dma, dma_unmap_addr(tx_buf, dma));
	dma_unmap_len_set(&stash->buf, len, dma_unmap_len(tx_buf, len));
	stash->buf.compl_tag = tx_buf->compl_tag;

	if (unlikely(compl_type == IDPF_TXD_COMPLT_RULE_MISS))
		idpf_tx_start_reinject_timer(txq, stash);
	else if (unlikely(compl_type == IDPF_TXD_COMPLT_REINJECTED))
		stash->miss_pkt = true;
	else
		stash->miss_pkt = false;

	/* Add buffer to buf_hash table to be freed later */
	hash_add(txq->sched_buf_hash, &stash->hlist, stash->buf.compl_tag);

	tx_buf->type = IDPF_TX_BUF_EMPTY;
	tx_buf->nr_frags = 0;

	return 0;
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
 * @compl_type: type of completion, forwarded to stash function
 *
 * Cleans the queue descriptor ring. If the queue is using queue-based
 * scheduling, the buffers will be cleaned as well. If the queue is using
 * flow-based scheduling, only the descriptors are cleaned at this time.
 * Separate packet completion events will be reported on the completion queue,
 * and the buffers will be cleaned separately. The stats are not updated from
 * this function when using flow-based scheduling.
 *
 * Furthermore, in flow scheduling mode, check to make sure there are enough
 * reserve buffers to stash the packet. If there are not, return early, which
 * will leave next_to_clean pointing to the packet that failed to be stashed.
 * Return false in this scenario. Otherwise, return true.
 */
static bool
idpf_tx_splitq_clean(struct idpf_queue *tx_q, u16 end, int napi_budget,
		     struct idpf_cleaned_stats *cleaned, bool descs_only,
		     u8 compl_type)
{
	union idpf_tx_flex_desc *next_pending_desc = NULL;
	union idpf_tx_flex_desc *tx_desc;
	u16 ntc = tx_q->next_to_clean;
	struct idpf_tx_buf *tx_buf;
	bool clean_complete = true;

	tx_desc = IDPF_FLEX_TX_DESC(tx_q, ntc);
	next_pending_desc = IDPF_FLEX_TX_DESC(tx_q, end);
	tx_buf = &tx_q->tx.bufs[ntc];

	while (tx_desc != next_pending_desc) {
		u16 eop_idx;

		/* If this entry in the ring was used as a context descriptor,
		 * it's corresponding entry in the buffer ring is reserved.  We
		 * can skip this descriptor since there is no buffer to clean.
		 */
		if (tx_buf->type == IDPF_TX_BUF_RSVD)
			goto fetch_next_txq_desc;

		eop_idx = tx_buf->eop_idx;

		if (descs_only) {
			if (IDPF_TX_BUF_RSV_UNUSED(tx_q) < tx_buf->nr_frags) {
				clean_complete = false;
				goto tx_splitq_clean_out;
			}

			idpf_stash_flow_sch_buf(tx_q, tx_buf, compl_type);

			while (ntc != eop_idx) {
				idpf_tx_splitq_clean_bump_ntc(tx_q, ntc,
							      tx_desc, tx_buf);

				if (!tx_buf->type)
					continue;

				idpf_stash_flow_sch_buf(tx_q, tx_buf, compl_type);
			}
		} else {
			idpf_tx_splitq_clean_hdr(tx_q, tx_buf, cleaned, napi_budget);

			/* unmap remaining buffers */
			while (ntc != eop_idx) {
				idpf_tx_splitq_clean_bump_ntc(tx_q, ntc,
							      tx_desc, tx_buf);

				/* unmap any remaining paged data */
				if (tx_buf->type == IDPF_TX_BUF_FRAG) {
					dma_unmap_page(tx_q->dev,
						       dma_unmap_addr(tx_buf, dma),
						       dma_unmap_len(tx_buf, len),
						       DMA_TO_DEVICE);
					dma_unmap_len_set(tx_buf, len, 0);
				}
			}

		}

fetch_next_txq_desc:
		idpf_tx_splitq_clean_bump_ntc(tx_q, ntc, tx_desc, tx_buf);
	}

tx_splitq_clean_out:
	tx_q->next_to_clean = ntc;

	return clean_complete;
}

#define idpf_tx_clean_buf_ring_bump_ntc(txq, ntc, buf)	\
do {							\
	(buf)++;					\
	(ntc)++;					\
	if (unlikely((ntc) == (txq)->desc_count)) {	\
		buf = (txq)->tx.bufs;			\
		ntc = 0;				\
	}						\
} while (0)

/**
 * idpf_tx_clean_buf_ring - clean flow scheduling TX queue buffers
 * @txq: queue to clean
 * @compl_tag: completion tag of packet to clean (from completion descriptor)
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 * @budget: Used to determine if we are in netpoll
 *
 * Cleans all buffers for a single packet associated with the input completion
 * tag from the TX buffer ring. If an out-of-order completion is received,
 * packets prior to the given completion tag packet will be stashed in the hash
 * table if possible. Returns the byte/segment count for the cleaned packet
 * associated this completion tag.
 */
static bool idpf_tx_clean_buf_ring(struct idpf_queue *txq, u16 compl_tag,
				   struct idpf_cleaned_stats *cleaned,
				   u8 *desc_ts, int budget)
{
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps = txq->vport->tx_tstamp_caps;
	struct idpf_ptp_tx_tstamp_status *tx_tstamp_status;
	u16 idx = compl_tag & txq->compl_tag_bufid_m;
	u16 ntc, eop_idx, orig_idx = idx;
	struct idpf_tx_buf *tx_buf;
	u16 i;

	tx_buf = &txq->tx.bufs[idx];

	if (unlikely(tx_buf->compl_tag != compl_tag))
		return false;

	switch (tx_buf->type) {
	case IDPF_TX_BUF_SKB_TSTAMP:
		if (!(skb_shinfo(tx_buf->skb)->tx_flags & SKBTX_IN_PROGRESS))
			goto skip_tx_tstamp;

		for (i = 0; i < tx_tstamp_caps->num_entries; i++) {
			tx_tstamp_status = &tx_tstamp_caps->tx_tstamp_status[i];
			if (tx_tstamp_status->state == IDPF_PTP_FREE) {
				tx_tstamp_status->skb = tx_buf->skb;
				tx_tstamp_status->state = IDPF_PTP_REQUEST;

				/* Fetch timestamp from completion descriptor
				 * through virtchnl msg to report to stack.
				 */
				mod_delayed_work(txq->vport->tstamp_wq,
						 &txq->vport->tstamp_task,
						 0);
				break;
			}
		}
skip_tx_tstamp:
		eop_idx = tx_buf->eop_idx;
		idpf_tx_splitq_clean_hdr(txq, tx_buf, cleaned, budget);
		break;
	case IDPF_TX_BUF_SKB:
#ifdef HAVE_XDP_SUPPORT
		fallthrough;
	case IDPF_TX_BUF_XDP:
#endif /* HAVE_XDP_SUPPORT */
		eop_idx = tx_buf->eop_idx;
		idpf_tx_splitq_clean_hdr(txq, tx_buf, cleaned, budget);
		break;
	default:
		return false;
	}

	while (idx != eop_idx) {
		idpf_tx_clean_buf_ring_bump_ntc(txq, idx, tx_buf);

		if (tx_buf->type == IDPF_TX_BUF_FRAG) {
			dma_unmap_page(txq->dev,
				       dma_unmap_addr(tx_buf, dma),
				       dma_unmap_len(tx_buf, len),
				       DMA_TO_DEVICE);
			dma_unmap_len_set(tx_buf, len, 0);
		}

		tx_buf->type = IDPF_TX_BUF_EMPTY;
	}

	/* It's possible the packet we just cleaned was an out of order
	 * completion, which means we can we can stash the buffers starting
	 * from the original next_to_clean and reuse the descriptors. We need
	 * to compare the descriptor ring next_to_clean packet's "first" buffer
	 * to the "first" buffer of the packet we just cleaned to determine if
	 * this is the case. Howevever, next_to_clean can point to either a
	 * reserved buffer that corresponds to a context descriptor used for the
	 * next_to_clean packet (TSO packet) or the "first" buffer (single
	 * packet). The orig_idx from the packet we just cleaned will always
	 * point to the "first" buffer. If next_to_clean points to a reserved
	 * buffer, let's bump ntc once and start the comparison from there.
	 */
	ntc = txq->next_to_clean;
	tx_buf = &txq->tx.bufs[ntc];
	while (tx_buf->type == IDPF_TX_BUF_RSVD)
		idpf_tx_clean_buf_ring_bump_ntc(txq, ntc, tx_buf);

	if (tx_buf == &txq->tx.bufs[orig_idx] ||
	    (tx_buf->type != IDPF_TX_BUF_SKB && tx_buf->type != IDPF_TX_BUF_XDP))
		goto update_ntc_out;

	/* If ntc still points to a different "first" buffer, clean the
	 * descriptor ring and stash all of the buffers for later cleaning. If
	 * we cannot stash all of the buffers, next_to_clean will point to the
	 * "first" buffer of the packet that could not be stashed and cleaning
	 * will start there next time.
	 */
	if (unlikely(!idpf_tx_splitq_clean(txq, orig_idx, budget, cleaned,
					   true, IDPF_TXD_COMPLT_RS)))
		goto clean_buf_ring_out;

	/* Otherwise, bump idx to point to the start of the next packet and
	 * update next_to_clean to reflect the cleaning that was done above.
	 */
update_ntc_out:
	idpf_tx_clean_buf_ring_bump_ntc(txq, idx, tx_buf);
	txq->next_to_clean = idx;

clean_buf_ring_out:
	return true;
}

/**
 * idpf_tx_handle_miss_completion
 * @txq: Tx ring to clean
 * @desc: pointer to completion queue descriptor to extract completion
 * information from
 * @cleaned: pointer to stats struct to track cleaned packets/bytes
 * @budget: Used to determine if we are in netpoll
 * @compl_tag: unique completion tag of packet
 *
 * Determines where the packet is located, the hash table or the ring. If the
 * packet is on the ring, the ring cleaning function will take care of freeing
 * the DMA buffers and stash the SKB. The stashing function, called inside the
 * ring cleaning function, will take care of starting the timer.
 *
 * If packet is already in the hashtable, determine if we need to finish up the
 * reinject completion or start the timer to wait for the reinject completion.
 *
 * Returns cleaned bytes/packets only if we're finishing up the reinject
 * completion and freeing the skb. Otherwise, the stats are 0 / irrelevant
 */
static void
idpf_tx_handle_miss_completion(struct idpf_queue *txq,
			       struct idpf_splitq_tx_compl_desc *desc,
			       struct idpf_cleaned_stats *cleaned,
			       u16 compl_tag, int budget)
{
	struct idpf_tx_stash *stash;

	/* First determine if this packet was already stashed */
	stash = idpf_tx_find_stashed_bufs(txq, compl_tag);
	if (!stash) {
		u16 idx = compl_tag & txq->compl_tag_bufid_m;
		struct idpf_tx_buf *tx_buf;

		tx_buf = &txq->tx.bufs[idx];

		if (unlikely(tx_buf->type == IDPF_TX_BUF_MISS)) {
			/* In the unlikely event we received the reinject
			 * completion first AND it failed to be stashed to the
			 * hash table, the packet is still be on the ring.  No
			 * other completion is expected for this packet, so
			 * clean it normally. Reset the buf type field to SKB
			 * to trigger the full cleaning in the call to
			 * idpf_tx_clean_buf_ring below.
			 */
			tx_buf->type = IDPF_TX_BUF_SKB;
		} else {
			/* Otherwise, since we received a miss completion
			 * first, we free all of the buffers, but cannot free
			 * the skb or update the stack BQL yet. Stash the skb
			 * and start the timer to wait for the reinject
			 * completion.
			 */
			idpf_tx_splitq_unmap_hdr(txq, tx_buf);
			idpf_stash_flow_sch_buf(txq, tx_buf,
						IDPF_TXD_COMPLT_RULE_MISS);
			/* Reset buf type to use clean_buf_ring routine to clean
			 * remaining buffers. It will be set to empty there.
			 */
			tx_buf->type = IDPF_TX_BUF_MISS;
		}

		idpf_tx_clean_buf_ring(txq, compl_tag, cleaned, desc->ts,
				       budget);
	} else {
		if (stash->miss_pkt)
			/* If it was previously stashed because
			 * of a reinject completion, we can go
			 * ahead and clean everything up
			 */
			idpf_tx_clean_stashed_bufs(txq, compl_tag, desc->ts,
						   cleaned, budget);
		else
			/* If it was previously stashed because
			 * of an RE completion, we just need to
			 * start the timer while we wait for
			 * the reinject completion
			 */
			idpf_tx_start_reinject_timer(txq, stash);
	}
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
			     struct idpf_cleaned_stats *cleaned,
			     int budget)
{
	u16 compl_tag;

	if (!test_bit(__IDPF_Q_FLOW_SCH_EN, txq->flags)) {
		u16 head = le16_to_cpu(desc->q_head_compl_tag.q_head);

		idpf_tx_splitq_clean(txq, head, budget, cleaned, false,
				     IDPF_TXD_COMPLT_RS);

		return;
	}

	compl_tag = le16_to_cpu(desc->q_head_compl_tag.compl_tag);
	/* Check for miss completion in tag if enabled */
	if (unlikely(test_bit(__IDPF_Q_MISS_TAG_EN, txq->flags) &&
		     compl_tag & IDPF_TX_SPLITQ_MISS_COMPL_TAG)) {
		compl_tag &= ~IDPF_TX_SPLITQ_MISS_COMPL_TAG;

		return idpf_tx_handle_miss_completion(txq, desc, cleaned,
						      compl_tag, budget);
	}
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL

	if (txq->xsk_pool)
		return idpf_tx_splitq_clean_zc(txq, compl_tag, cleaned);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	/* If we didn't clean anything on the ring, this packet must be
	 * in the hash table. Go clean it there.
	 */
	if (!idpf_tx_clean_buf_ring(txq, compl_tag, cleaned, desc->ts, budget))
		idpf_tx_clean_stashed_bufs(txq, compl_tag, desc->ts, cleaned,
					   budget);
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
				   struct idpf_cleaned_stats *cleaned,
				   int budget)
{
	u16 compl_tag = le16_to_cpu(desc->q_head_compl_tag.compl_tag);
	struct idpf_tx_stash *stash;

	/* First check if the packet has already been stashed because of a miss
	 * completion
	 */
	stash = idpf_tx_find_stashed_bufs(txq, compl_tag);
	if (stash) {
		if (stash->miss_pkt)
			/* If it was previously stashed because of a miss
			 * completion, we can go ahead and clean everything up
			 */
			idpf_tx_clean_stashed_bufs(txq, compl_tag, desc->ts,
						   cleaned, budget);
		else
			/* If it was previously stashed because of a RE or out
			 * of order RS completion, it means we received the
			 * reinject completion before the miss completion.
			 * However, since the packet did take the miss path, it
			 * is guaranteed to get a miss completion. Therefore,
			 * mark it as a miss path packet in the hash table so
			 * it will be cleaned upon receiving the miss
			 * completion.
			 */
			stash->miss_pkt = true;
	} else {
		u16 idx = compl_tag & txq->compl_tag_bufid_m;
		struct idpf_tx_buf *tx_buf;
		u16 next_pkt_idx;

		/* If it was not in the hash table, the packet is still on the
		 * ring.  This is another scenario in which the reinject
		 * completion arrives before the miss completion.  We can
		 * simply stash all of the buffers associated with this packet
		 * and any buffers on the ring prior to it.  We will clean the
		 * packet and all of its buffers associated with this
		 * completion tag upon receiving the miss completion, and clean
		 * the others upon receiving their respective RS completions.
		 */
		tx_buf = &txq->tx.bufs[idx];
		tx_buf->type = IDPF_TX_BUF_MISS;

		next_pkt_idx = tx_buf->eop_idx + 1;
		if (unlikely(next_pkt_idx >= txq->desc_count))
			next_pkt_idx = 0;

		idpf_tx_splitq_clean(txq, next_pkt_idx, budget, cleaned, true,
				     IDPF_TXD_COMPLT_REINJECTED);
	}

	/* If the packet is not in the ring or hash table, it means we either
	 * received a regular completion already or the timer expired on the
	 * miss completion.  In either case, everything should already be
	 * cleaned up and we should ignore this completion.
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
		struct idpf_cleaned_stats cleaned_stats = { };
		u16 hw_head, compl_tag;
		int rel_tx_qid;
		u8 ctype;	/* completion type */
		u16 gen;

		/* if the descriptor isn't done, no work yet to do */
		gen = (le16_to_cpu(tx_desc->qid_comptype_gen) &
		      IDPF_TXD_COMPLQ_GEN_M) >> IDPF_TXD_COMPLQ_GEN_S;
		if (test_bit(__IDPF_Q_GEN_CHK, complq->flags) != gen)
			break;

		/* Find necessary info of TX queue to clean buffers */
		rel_tx_qid = (le16_to_cpu(tx_desc->qid_comptype_gen) &
			 IDPF_TXD_COMPLQ_QID_M) >> IDPF_TXD_COMPLQ_QID_S;
		if (unlikely(rel_tx_qid >= complq->tx.num_txq)) {
			dev_err(idpf_adapter_to_dev(vport->adapter),
				"TxQ not found\n");
			goto fetch_next_desc;
		}

		tx_q = complq->tx.txqs[rel_tx_qid];

		/* Determine completion type */
		ctype = (le16_to_cpu(tx_desc->qid_comptype_gen) &
			IDPF_TXD_COMPLQ_COMPL_TYPE_M) >>
			IDPF_TXD_COMPLQ_COMPL_TYPE_S;
		switch (ctype) {
		case IDPF_TXD_COMPLT_RE:
			hw_head = le16_to_cpu(tx_desc->q_head_compl_tag.q_head);

			idpf_tx_splitq_clean(tx_q, hw_head, budget,
					     &cleaned_stats, true,
					     IDPF_TXD_COMPLT_RE);
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
		complq->tx.num_compl++;
		u64_stats_update_end(&tx_q->stats_sync);

fetch_next_desc:
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= complq->desc_count;
			tx_desc = IDPF_SPLITQ_TX_COMPLQ_DESC(complq, 0);
			change_bit(__IDPF_Q_GEN_CHK, complq->flags);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		complq_budget--;
	} while (likely(complq_budget));

	/* Store the state of the complq to be used later in deciding if a
	 * TXQ can be started again
	 */
	if (unlikely(IDPF_TX_COMPLQ_PENDING(complq) >
		     IDPF_TX_COMPLQ_OVERFLOW_THRESH(complq)))
		complq_ok = false;

	for (i = 0; i < complq->tx.num_txq; i++) {
		struct netdev_queue *nq;

		tx_q = complq->tx.txqs[i];

#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IDPF_Q_XDP, tx_q->flags)) {
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
			     !IDPF_TX_BUF_RSV_LOW(tx_q) &&
			     (IDPF_DESC_UNUSED(tx_q) >= IDPF_TX_WAKE_THRESH))) {
			/* Make sure any other threads stopping queue after
			 * this see new next_to_clean.
			 */
			smp_mb();
			netif_tx_wake_queue(nq);
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
		cpu_to_le16(params->dtype & IDPF_FLEX_TXD_QW1_DTYPE_M);
	desc->q.qw1.cmd_dtype |=
		cpu_to_le16((td_cmd << IDPF_FLEX_TXD_QW1_CMD_S) &
			    IDPF_FLEX_TXD_QW1_CMD_M);
	desc->q.qw1.buf_size = cpu_to_le16((u16)size);
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
 * __idpf_tx_maybe_stop_common - 2nd level check for common Tx stop conditions
 * @tx_q: the queue to be checked
 * @size: the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 */
static int __idpf_tx_maybe_stop_common(struct idpf_queue *tx_q,
				       unsigned int size)
{
	netif_stop_subqueue(tx_q->vport->netdev, tx_q->idx);

	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(IDPF_DESC_UNUSED(tx_q) < size))
		return -EBUSY;

	/* A reprieve! - use start_subqueue because it doesn't call schedule */
	netif_start_subqueue(tx_q->vport->netdev, tx_q->idx);

	return 0;
}

/**
 * idpf_tx_maybe_stop_common - 1st level check for common Tx stop conditions
 * @tx_q: the queue to be checked
 * @size: number of descriptors we want to assure is available
 *
 * Returns 0 if stop is not needed
 */
int idpf_tx_maybe_stop_common(struct idpf_queue *tx_q, unsigned int size)
{
	if (likely(IDPF_DESC_UNUSED(tx_q) >= size))
		return 0;

	u64_stats_update_begin(&tx_q->stats_sync);
	u64_stats_inc(&tx_q->q_stats.tx.q_busy);
	u64_stats_update_end(&tx_q->stats_sync);

	return __idpf_tx_maybe_stop_common(tx_q, size);
}

/**
 * idpf_tx_maybe_stop_splitq - 1st level check for Tx splitq stop conditions
 * @tx_q: the queue to be checked
 * @descs_needed: number of descriptors required for this packet
 *
 * Returns 0 if stop is not needed
 */
static int idpf_tx_maybe_stop_splitq(struct idpf_queue *tx_q,
				     unsigned int descs_needed)
{
	if (idpf_tx_maybe_stop_common(tx_q, descs_needed))
		return -EBUSY;

	/* If there are too many outstanding completions expected on the
	 * completion queue, stop the TX queue to give the device some time to
	 * catch up
	 */
	if (unlikely(IDPF_TX_COMPLQ_PENDING(tx_q->tx.complq) >
		     IDPF_TX_COMPLQ_OVERFLOW_THRESH(tx_q->tx.complq)))
		goto splitq_stop;

	/* Also check for available book keeping buffers; if we are low, stop
	 * the queue to wait for more completions
	 */
	if (unlikely(IDPF_TX_BUF_RSV_LOW(tx_q)))
		goto splitq_stop;

	return 0;

splitq_stop:
	u64_stats_update_begin(&tx_q->stats_sync);
	u64_stats_inc(&tx_q->q_stats.tx.q_busy);
	u64_stats_update_end(&tx_q->stats_sync);
	netif_stop_subqueue(tx_q->vport->netdev, tx_q->idx);

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

	idpf_tx_maybe_stop_common(tx_q, IDPF_TX_DESC_NEEDED);

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
 * __idpf_chk_linearize - Check skb is not using too many buffers
 * @skb: send buffer
 * @max_bufs: maximum number of buffers
 *
 * For TSO we need to count the TSO header and segment payload separately.  As
 * such we need to check cases where we have max_bufs-1 fragments or more as we
 * can potentially require max_bufs+1 DMA transactions, 1 for the TSO header, 1
 * for the segment payload in the first descriptor, and another max_buf-1 for
 * the fragments.
 */
static bool __idpf_chk_linearize(struct sk_buff *skb, unsigned int max_bufs)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	const skb_frag_t *frag, *stale;
	int nr_frags, sum;

	/* no need to check if number of frags is less than max_bufs - 1 */
	nr_frags = shinfo->nr_frags;
	if (nr_frags < (max_bufs - 1))
		return false;

	/* We need to walk through the list and validate that each group
	 * of max_bufs-2 fragments totals at least gso_size.
	 */
	nr_frags -= max_bufs - 2;
	frag = &shinfo->frags[0];

	/* Initialize size to the negative value of gso_size minus 1.  We use
	 * this as the worst case scenario in which the frag ahead of us only
	 * provides one byte which is why we are limited to max_bufs-2
	 * descriptors for a single transmit as the header and previous
	 * fragment are already consuming 2 descriptors.
	 */
	sum = 1 - shinfo->gso_size;

	/* Add size of frags 0 through 4 to create our initial sum */
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);

	/* Walk through fragments adding latest fragment, testing it, and
	 * then removing stale fragments from the sum.
	 */
	for (stale = &shinfo->frags[0];; stale++) {
		int stale_size = skb_frag_size(stale);

		sum += skb_frag_size(frag++);

		/* The stale fragment may present us with a smaller
		 * descriptor than the actual fragment size. To account
		 * for that we need to remove all the data on the front and
		 * figure out what the remainder would be in the last
		 * descriptor associated with the fragment.
		 */
		if (stale_size > IDPF_TX_MAX_DESC_DATA) {
			int align_pad = -(skb_frag_off(stale)) &
					(IDPF_TX_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= IDPF_TX_MAX_DESC_DATA_ALIGNED;
				stale_size -= IDPF_TX_MAX_DESC_DATA_ALIGNED;
			} while (stale_size > IDPF_TX_MAX_DESC_DATA);
		}

		/* if sum is negative we failed to make sufficient progress */
		if (sum < 0)
			return true;

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	return false;
}

/**
 * idpf_chk_linearize - Check if skb exceeds max descriptors per packet
 * @skb: send buffer
 * @max_bufs: maximum scatter gather buffers for single packet
 * @count: number of buffers this packet needs
 *
 * Make sure we don't exceed maximum scatter gather buffers for a single
 * packet. We have to do some special checking around the boundary (max_bufs-1)
 * if TSO is on since we need count the TSO header and payload separately.
 * E.g.: a packet with 7 fragments can require 9 DMA transactions; 1 for TSO
 * header, 1 for segment payload, and then 7 for the fragments.
 */
bool idpf_chk_linearize(struct sk_buff *skb, unsigned int max_bufs,
			unsigned int count)
{
	if (likely(count < max_bufs))
		return false;
	if (skb_is_gso(skb))
		return __idpf_chk_linearize(skb, max_bufs);

	return count > max_bufs;
}

/**
 * idpf_tx_desc_count_required - calculate number of Tx descriptors needed
 * @txq: queue to send buffer on
 * @skb: send buffer
 *
 * Returns number of data descriptors needed for this skb.
 */
unsigned int idpf_tx_desc_count_required(struct idpf_queue *txq,
					 struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo;
	unsigned int count = 0, i;

	count += !!skb_headlen(skb);

	if (!skb_is_nonlinear(skb))
		return count;

	shinfo = skb_shinfo(skb);
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
 * idpf_tx_dma_map_error - handle TX DMA map errors
 * @txq: queue to send buffer on
 * @skb: send buffer
 * @first: original first buffer info buffer for packet
 * @idx: starting point on ring to unwind
 */
void idpf_tx_dma_map_error(struct idpf_queue *txq, struct sk_buff *skb,
			   struct idpf_tx_buf *first, u16 idx)
{
	u64_stats_update_begin(&txq->stats_sync);
	u64_stats_inc(&txq->q_stats.tx.dma_map_errs);
	u64_stats_update_end(&txq->stats_sync);

	for (;;) {
		struct idpf_tx_buf *tx_buf;

		tx_buf = &txq->tx.bufs[idx];
		idpf_tx_buf_rel(txq, tx_buf);
		if (tx_buf == first)
			break;
		if (idx == 0)
			idx = txq->desc_count;
		idx--;
	}

	if (skb_is_gso(skb)) {
		union idpf_tx_flex_desc *tx_desc;

		/* If we failed a DMA mapping for a TSO packet, we will have
		 * used one additional descriptor for a context descriptor.
		 * Reset that here.
		 */
		tx_desc = IDPF_FLEX_TX_DESC(txq, idx);
		memset(tx_desc, 0, sizeof(union idpf_flex_tx_ctx_desc));
		if (idx == 0)
			idx = txq->desc_count;
		idx--;
	}

	/* Update tail in case netdev_xmit_more was previously true */
	idpf_tx_buf_hw_update(txq, idx, false);
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

	if (ntu == txq->desc_count) {
		ntu = 0;
		txq->compl_tag_cur_gen = IDPF_TX_ADJ_COMPL_TAG_GEN(txq);
	}

	return ntu;
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
	struct idpf_queue *complq;
	struct netdev_queue *nq;
	struct sk_buff *skb;
	skb_frag_t *frag;
	u16 td_cmd = 0;
	dma_addr_t dma;

	skb = first->skb;

	td_cmd = params->offload.td_cmd;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = IDPF_FLEX_TX_DESC(tx_q, i);

	dma = dma_map_single(tx_q->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	params->compl_tag =
		(tx_q->compl_tag_cur_gen << tx_q->compl_tag_gen_s) | i;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IDPF_TX_MAX_DESC_DATA_ALIGNED;

		if (dma_mapping_error(tx_q->dev, dma))
			return idpf_tx_dma_map_error(tx_q, skb, first, i);

		first->nr_frags++;
		tx_buf->compl_tag = params->compl_tag;
		tx_buf->type = IDPF_TX_BUF_FRAG;

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
				tx_buf = tx_q->tx.bufs;
				tx_desc = IDPF_FLEX_TX_DESC(tx_q, 0);
				i = 0;
				tx_q->compl_tag_cur_gen =
					IDPF_TX_ADJ_COMPL_TAG_GEN(tx_q);
			} else {
				tx_buf++;
				tx_desc++;
			}

			/* Since this packet has a buffer that is going to span
			 * multiple descriptors, it's going to leave holes in
			 * to the TX buffer ring. To ensure these holes do not
			 * cause issues in the cleaning routines, we will clear
			 * them of any stale data and assign them the same
			 * completion tag as the current packet. Then when the
			 * packet is being cleaned, the cleaning routines will
			 * simply pass over these holes and finish cleaning the
			 * rest of the packet.
			 */
			tx_buf->type = IDPF_TX_BUF_EMPTY;

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
			tx_buf = tx_q->tx.bufs;
			tx_desc = IDPF_FLEX_TX_DESC(tx_q, 0);
			i = 0;
			tx_q->compl_tag_cur_gen = IDPF_TX_ADJ_COMPL_TAG_GEN(tx_q);
		} else {
			tx_buf++;
			tx_desc++;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_q->dev, frag, 0, size,
				       DMA_TO_DEVICE);
	}

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(skb);

	first->type = IDPF_TX_BUF_SKB;
	if (params->offload.tx_flags & IDPF_TX_FLAGS_TSYN)
		first->type = IDPF_TX_BUF_SKB_TSTAMP;

	/* write last descriptor with RS and EOP bits */
	first->eop_idx = i;
	td_cmd |= params->eop_cmd;
	idpf_tx_splitq_build_desc(tx_desc, params, td_cmd, size);
	i = idpf_tx_splitq_bump_ntu(tx_q, i);

	/* Update complq on how many completions to expect. */
	complq = tx_q->tx.complq;
	complq->tx.num_compl_pend++;

	/* record bytecount for BQL */
	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_sent_queue(nq, first->bytecount);

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
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
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

	if (!shinfo->gso_size)
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

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
				      tx_buf->gso_segs);
		else
#endif /* NETIF_F_GSO_UDP_L4 */
			u64_stats_add(&extra_stats->tx_tcp_segs,
				      tx_buf->gso_segs);
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

	txq->tx.bufs[i].type = IDPF_TX_BUF_RSVD;

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

/**
 * idpf_tx_tstamp - set up context descriptor for hardware timestamp
 * @tx_q: queue to send buffer on
 * @index: requested index of the tstamp latch
 * @off: pointer to the offload struct
 * @skb: pointer to the SKB we're sending
 */
static bool idpf_tx_tstamp(struct idpf_queue *tx_q, u8 *index,
			   struct idpf_tx_offload_params *off, struct sk_buff *skb)
{
	enum idpf_ptp_access access;
	s8 idx = 0;

	/* Tx timestamps cannot be sampled when doing TSO */
	if (off->tx_flags & IDPF_TX_FLAGS_TSO)
		return false;

	/* only timestamp the outbound packet if the user has requested it */
	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)))
		return false;

	access = tx_q->vport->adapter->ptp.tx_tstamp_access;
	if (access != IDPF_PTP_MAILBOX)
		return false;

	/* Grab an open timestamp slot */
	idx = idpf_ptp_request_ts(tx_q->vport, skb);
	if (idx < 0)
		return false;

	off->tx_flags |= IDPF_TX_FLAGS_TSYN;
	*index = idx;

	return true;
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
	struct idpf_tx_splitq_params tx_params = { };
	struct idpf_tx_buf *first;
	unsigned int count;
	int tso;
	u8 idx;

	count = idpf_tx_desc_count_required(tx_q, skb);
	if (unlikely(!count))
		return idpf_tx_drop_skb(tx_q, skb);

	tso = idpf_tso(skb, &tx_params.offload);
	if (unlikely(tso < 0))
		return idpf_tx_drop_skb(tx_q, skb);

	/* Check for splitq specific TX resources */
	count += (IDPF_TX_DESCS_PER_CACHE_LINE + tso);
	if (idpf_tx_maybe_stop_splitq(tx_q, count)) {
		idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);
		return NETDEV_TX_BUSY;
	}

	if (tso) {
		/* If tso is needed, set up context desc */
		union idpf_flex_tx_ctx_desc *ctx_desc =
			idpf_tx_splitq_get_ctx_desc(tx_q);

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
		u64_stats_update_end(&tx_q->stats_sync);
	} else if (idpf_tx_tstamp(tx_q, &idx, &tx_params.offload, skb)) {
		union idpf_flex_tx_ctx_desc *ctx_desc = idpf_tx_splitq_get_ctx_desc(tx_q);

		ctx_desc->tsyn.qw1.cmd_dtype =
			cpu_to_le16(FIELD_PREP(IDPF_TXD_QW1_CMD_M,
					       IDPF_TX_CTX_DESC_TSYN));

		ctx_desc->tsyn.qw1.cmd_dtype |=
			cpu_to_le16(FIELD_PREP(IDPF_TXD_QW1_DTYPE_M,
					       IDPF_TX_DESC_DTYPE_CTX));

		ctx_desc->tsyn.qw1.tsyn_reg_l =
			cpu_to_le16(FIELD_PREP(IDPF_TX_DESC_CTX_TSYN_L_M,
					       idx));

		/* Shift index as two first bits are already written */
		ctx_desc->tsyn.qw1.tsyn_reg_h =
			cpu_to_le16(FIELD_PREP(IDPF_TX_DESC_CTX_TSYN_H_M,
					       idx >> 2));
	}
	/* record the location of the first descriptor for this packet */
	first = &tx_q->tx.bufs[tx_q->next_to_use];
	first->skb = skb;

	if (tso) {
		first->gso_segs = tx_params.offload.tso_segs;
		first->bytecount = skb->len +
			(first->gso_segs - 1) * tx_params.offload.tso_hdr_len;
	} else {
		first->gso_segs = 1;
		first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	}

#ifdef IDPF_ADD_PROBES
	idpf_tx_extra_counters(tx_q, first, &tx_params.offload);

#endif /* IDPF_ADD_PROBES */
	if (test_bit(__IDPF_Q_FLOW_SCH_EN, tx_q->flags)) {
		if (unlikely(test_bit(__IDPF_Q_ETF_EN, tx_q->flags)))
			idpf_get_flow_sche_tstamp(skb, tx_q, &tx_params.offload);

		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_params.eop_cmd = IDPF_TXD_FLEX_FLOW_CMD_EOP;
		/* Set the RE bit to catch any packets that may have not been
		 * stashed during RS completion cleaning. MIN_GAP is set to
		 * MIN_RING size to ensure it will be set at least once each
		 * time around the ring.
		 */
		if (!(tx_q->next_to_use % IDPF_TX_SPLITQ_RE_MIN_GAP)) {
			struct idpf_queue *complq = tx_q->tx.complq;

			tx_params.eop_cmd |= IDPF_TXD_FLEX_FLOW_CMD_RE;
			complq->tx.num_compl_pend++;
		}

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_params.offload.td_cmd |= IDPF_TXD_FLEX_FLOW_CMD_CS_EN;

	} else {
		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_params.eop_cmd = IDPF_TXD_LAST_DESC_CMD;

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_params.offload.td_cmd |= IDPF_TX_FLEX_DESC_CMD_CS_EN;
	}

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

	/* Only report checksum unnecessary for ICMP, TCP, UDP, or SCTP */
	switch (decoded->inner_prot) {
	case IDPF_RX_PTYPE_INNER_PROT_ICMP:
	case IDPF_RX_PTYPE_INNER_PROT_TCP:
	case IDPF_RX_PTYPE_INNER_PROT_UDP:
		if (!csum_bits->raw_csum_inv) {
			u16 csum = csum_bits->raw_csum;

			skb->csum = csum_unfold((__force __sum16)~swab16(csum));
			skb->ip_summed = CHECKSUM_COMPLETE;
#ifdef IDPF_ADD_PROBES
			u64_stats_update_begin(&port_stats->stats_sync);
			u64_stats_inc(&port_stats->extra_stats.rx_csum_complete);
			u64_stats_update_end(&port_stats->stats_sync);
#endif /* IDPF_ADD_PROBES */
		} else {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef IDPF_ADD_PROBES
			u64_stats_update_begin(&port_stats->stats_sync);
			u64_stats_inc(&port_stats->extra_stats.rx_csum_unnecessary);
			u64_stats_update_end(&port_stats->stats_sync);
#endif /* IDPF_ADD_PROBES */
		}
		break;
	case IDPF_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		break;
	}
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

	csum->ipe = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_IPE_S),
			      qword1);
	csum->eipe = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EIPE_S),
			       qword1);
	csum->l4e = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_L4E_S),
			      qword1);
	csum->l3l4p = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L3L4P_S),
				qword1);
	csum->ipv6exadd = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_IPV6EXADD_S),
				    qword0);
	csum->raw_csum_inv = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_FF0_S),
				       le16_to_cpu(rx_desc->ptype_err_fflags0));
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

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);

	if (ipv4) {
		struct iphdr *ipv4h = ip_hdr(skb);

		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

		/* Reset and set transport header offset in skb */
		skb_set_transport_header(skb, ETH_HLEN + sizeof(*ipv4h));
		len = skb->len - skb_transport_offset(skb);

		/* Compute the TCP pseudo header checksum*/
		tcp_hdr(skb)->check =
			~tcp_v4_check(len, ipv4h->saddr, ipv4h->daddr, 0);
	} else {
		struct ipv6hdr *ipv6h = ipv6_hdr(skb);

		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
		skb_set_transport_header(skb, ETH_HLEN + sizeof(*ipv6h));
		len = skb->len - skb_transport_offset(skb);
		tcp_hdr(skb)->check =
			~tcp_v6_check(len, &ipv6h->saddr, &ipv6h->daddr, 0);
	}

	tcp_gro_complete(skb);

	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_inc(&rxq->q_stats.rx.rsc_pkts);
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

	cached_time = READ_ONCE(rxq->rx_cached_phctime);

	if (rx_desc->ts_low & VIRTCHNL2_RX_FLEX_TSTAMP_VALID) {
		ts_high = le32_to_cpu(rx_desc->ts_high);
		ts_ns = idpf_ptp_tstamp_extend_32b_to_64b(cached_time, ts_high);
		skb_hwtstamps(skb)->hwtstamp = ns_to_ktime(ts_ns);
	}
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

	rx_ptype = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_M,
			     le16_to_cpu(rx_desc->ptype_err_fflags0));

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
	if (!rxq->ptp_rx)
		goto skip_tstamp;

	idpf_rx_hwtstamp(rxq, rx_desc, skb);

skip_tstamp:
	if (FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_M,
		      le16_to_cpu(rx_desc->hdrlen_flags)))
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

	pinfo = &rx_buf->page_info[rx_buf->page_indx];

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(dev, pinfo->dma,
				      pinfo->page_offset, size,
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
	skb = __napi_alloc_skb(&rxq->q_vector->napi, IDPF_RX_HDR_SIZE,
			       GFP_ATOMIC);
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
	skb = __napi_alloc_skb(&rxq->q_vector->napi, size, GFP_ATOMIC);
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
static bool
idpf_rx_splitq_test_staterr(const u8 stat_err_field, const u8 stat_err_bits)
{
	return !!(stat_err_field & stat_err_bits);
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
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_prepare_xdp_tx_splitq_desc - Prepare TX descriptor for XDP in single
 *				     queue mode
 * @xdpq:      Pointer to XDP TX queue
 * @dma:       Address of DMA buffer used for XDP TX.
 * @idx:       Index of the TX buffer in the queue.
 * @size:      Size of data to be transmitted.
 */
void idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				     u16 idx, u32 size)
{
	struct idpf_tx_splitq_params tx_params = { };
	union idpf_tx_flex_desc *tx_desc;

	tx_desc = IDPF_FLEX_TX_DESC(xdpq, idx);
	tx_desc->q.buf_addr = cpu_to_le64(dma);

	tx_params.compl_tag =
		(xdpq->compl_tag_cur_gen << xdpq->compl_tag_gen_s) | idx;

	if (unlikely(test_bit(__IDPF_Q_FLOW_SCH_EN, xdpq->flags))) {
		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_params.eop_cmd = IDPF_TXD_FLEX_FLOW_CMD_EOP;
	} else {
		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_params.eop_cmd = IDPF_TXD_LAST_DESC_CMD;
	}

	idpf_tx_splitq_build_desc(tx_desc, &tx_params,
				  tx_params.eop_cmd | tx_params.offload.td_cmd,
				  size);

	xdpq->tx.bufs[idx].compl_tag = tx_params.compl_tag;
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
	u16 ntu = xdpq->next_to_use;
	struct idpf_tx_buf *tx_buf;
	dma_addr_t dma;
	void *data;
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

	tx_buf = &xdpq->tx.bufs[ntu];
	tx_buf->bytecount = size;
	tx_buf->gso_segs = 1;
#ifdef HAVE_XDP_FRAME_STRUCT
	tx_buf->xdpf = xdp;
#else
	tx_buf->raw_buf = data;
#endif

	/* record length, and DMA address */
	dma_unmap_len_set(tx_buf, len, size);
	dma_unmap_addr_set(tx_buf, dma, dma);

#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
	INDIRECT_CALL_2(xdpq->vport->xdp_prepare_tx_desc,
			idpf_prepare_xdp_tx_splitq_desc,
			idpf_prepare_xdp_tx_singleq_desc,
			xdpq, dma, ntu, size);
#else
	xdpq->vport->xdp_prepare_tx_desc(xdpq, dma, ntu, size);
#endif /* HAVE_INDIRECT_CALL_WRAPPER_HEADER */

	/* Make certain all of the status bits have been updated
	 * before next_to_watch is written.
	 */
	smp_wmb();

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	xdpq->xdp_tx_active++;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	tx_buf->type = IDPF_TX_BUF_XDP;
	tx_buf->eop_idx = ntu;
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

	if (!np->active)
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

	if (!np->active)
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
		struct idpf_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *desc;
		unsigned int pkt_len = 0;
		unsigned int hdr_len = 0;
		u16 gen_id, buf_id = 0;
		 /* Header buffer overflow only valid for header split */
		bool hbo = false;
		int bufq_id;
		u8 rxdid;

#ifdef HAVE_XDP_SUPPORT
		xdp_res = IDPF_XDP_PASS;

#endif /* HAVE_XDP_SUPPORT */
		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		desc = IDPF_RX_DESC(rxq, ntc);
		rx_desc = (struct virtchnl2_rx_flex_desc_adv_nic_3 *)desc;

		/* if the descriptor isn't done, no work yet to do */
		gen_id = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		gen_id = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M, gen_id);

		if (test_bit(__IDPF_Q_GEN_CHK, rxq->flags) != gen_id)
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

		pkt_len = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		pkt_len = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M,
				    pkt_len);

		hbo = FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_HBO_S),
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

		hdr_len = le16_to_cpu(rx_desc->hdrlen_flags);
		hdr_len = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_M,
				    hdr_len);

bypass_hsplit:
		bufq_id = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		bufq_id = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M,
				    bufq_id);

		refillq = &rxq->rx.refillqs[bufq_id];

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
			idpf_rx_post_buf_refill(refillq, buf_id);
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
		idpf_rx_post_buf_refill(refillq, buf_id);

		ntc = idpf_rx_bump_ntc(rxq, ntc);
		/* skip if it is non EOP desc */
		if (!idpf_rx_splitq_is_eop(rx_desc))
			continue;

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
		skb->protocol = eth_type_trans(skb, rxq->vport->netdev);
		napi_gro_receive(&rxq->q_vector->napi, skb);
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
static int idpf_rx_update_bufq_desc(struct idpf_queue *bufq, u16 refill_desc,
				    struct virtchnl2_splitq_rx_buf_desc *buf_desc)
{
	struct idpf_page_info *pinfo;
	struct idpf_rx_buf *buf;
	u16 buf_id;

	buf_id = FIELD_GET(IDPF_RX_BI_BUFID_M, refill_desc);

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
	dma_sync_single_range_for_device(bufq->dev, pinfo->dma,
					 pinfo->page_offset,
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
	u16 ntc = refillq->next_to_clean;
	bool failure = false;
	int cleaned = 0;
	u16 gen;

	buf_desc = IDPF_SPLITQ_RX_BUF_DESC(bufq, bufq_nta);

	/* make sure we stop at ring wrap in the unlikely case ring is full */
	while (likely(cleaned < refillq->desc_count)) {
		u16 refill_desc = IDPF_SPLITQ_RX_BI_DESC(refillq, ntc);

		gen = FIELD_GET(IDPF_RX_BI_GEN_M, refill_desc);
		if (test_bit(__IDPF_RFLQ_GEN_CHK, refillq->flags) != gen)
			break;

		failure = idpf_rx_update_bufq_desc(bufq, refill_desc,
						   buf_desc);
		if (failure)
			break;

		if (unlikely(++ntc == refillq->desc_count)) {
			change_bit(__IDPF_RFLQ_GEN_CHK, refillq->flags);
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
 * this vector. Returns true if clean is complete within budget, false
 * otherwise.
 */
static void idpf_rx_clean_refillq_all(struct idpf_queue *bufq)
{
	int i;

	for (i = 0; i < bufq->rx.num_refillq; i++)
		idpf_rx_clean_refillq(bufq, &bufq->rx.refillqs[i]);
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

	if (intr_grp->type == IDPF_GRP_TYPE_P2P)
		return;

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

	if (intr_grp->type == IDPF_GRP_TYPE_P2P)
		return;

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
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	int i, v_idx;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[v_idx];

		kfree(q_vector->bufq);
		q_vector->bufq = NULL;
		kfree(q_vector->tx);
		q_vector->tx = NULL;
		kfree(q_vector->rx);
		q_vector->rx = NULL;
	}

	for (i = 0; i < q_grp->num_rxq; i++)
		q_grp->rxqs[i]->q_vector = NULL;

	if (idpf_is_queue_model_split(q_grp->txq_model))
		for (i = 0; i < q_grp->num_complq; i++)
			q_grp->complqs[i].q_vector = NULL;
	else
		for (i = 0; i < q_grp->num_txq; i++)
			q_grp->txqs[i]->q_vector = NULL;

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

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(irq_num, NULL);
		free_irq(irq_num, q_vector);
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
 * @type: itr index
 * @itr: itr value
 */
static u32 idpf_vport_intr_buildreg_itr(struct idpf_q_vector *q_vector,
					const int type, u16 itr)
{
	u32 itr_val;

	itr &= IDPF_ITR_MASK;
	/* Don't clear PBA because that can cause lost interrupts that
	 * came in while we were cleaning/polling
	 */
	itr_val = q_vector->intr_reg.dyn_ctl_intena_m |
		  (type << q_vector->intr_reg.dyn_ctl_itridx_s) |
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
	net_dim(&q_vector->tx_dim, dim_sample);

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
	net_dim(&q_vector->rx_dim, dim_sample);
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
	intval = idpf_vport_intr_buildreg_itr(q_vector,
					      IDPF_NO_ITR_UPDATE_IDX, 0);

	writel(intval, q_vector->intr_reg.dyn_ctl);
	q_vector->wb_on_itr = false;
}

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
	int vector, err, irq_num, vidx;
	const char *vec_name;

	for (vector = 0; vector < intr_grp->num_q_vectors; vector++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[vector];

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

		q_vector->name = kasprintf(GFP_KERNEL, "%s-%s-%d",
					   basename, vec_name, vidx);

		err = request_irq(irq_num, idpf_vport_intr_clean_queues, 0,
				  q_vector->name, q_vector);
		if (err) {
			netdev_err(vport->netdev,
				   "Request_irq failed, error: %d\n", err);
			goto free_q_irqs;
		}
		/* assign the mask for this irq */
		irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);
	}

	return 0;

free_q_irqs:
	while (--vector >= 0) {
		vidx = intr_grp->q_vector_idxs[vector];
		irq_num = adapter->msix_entries[vidx].vector;
		free_irq(irq_num, &intr_grp->q_vectors[vector]);
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
 * idpf_vport_p2p_intr_set_wb_on_itr - Enable WB on ITR for P2P queue vectors
 * @q_vector: pointer to queue vector struct
 */
static void idpf_vport_p2p_intr_set_wb_on_itr(struct idpf_q_vector *q_vector)
{
	u32 dyn_ctl_itridx_s = q_vector->intr_reg.dyn_ctl_itridx_s;

	writel((q_vector->intr_reg.dyn_ctl_wb_on_itr_m |
	       (IDPF_NO_ITR_UPDATE_IDX << dyn_ctl_itridx_s) |
	       q_vector->intr_reg.dyn_ctl_intena_msk_m),
	       q_vector->intr_reg.dyn_ctl);
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

		if ((qv->num_txq || qv->num_rxq) && qv->wb_on_itr) {
			idpf_vport_p2p_intr_set_wb_on_itr(qv);
			continue;
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
	idpf_vport_intr_napi_dis_all(intr_grp);
	idpf_vport_intr_napi_del_all(intr_grp);
	idpf_vport_intr_dis_irq_all(intr_grp);
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

	if (intr_grp->type == IDPF_GRP_TYPE_P2P)
		return;

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
		/* if we clean as many as budgeted, we must not
		 * be done
		 */
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
	bool clean_complete;
	int work_done = 0;

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(!budget)) {
		idpf_tx_splitq_clean_all(q_vector, budget, &work_done);
		return 0;
	}

	clean_complete = idpf_rx_splitq_clean_all(q_vector, budget, &work_done);
	clean_complete &= idpf_tx_splitq_clean_all(q_vector, budget, &work_done);

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		idpf_vport_intr_set_wb_on_itr(q_vector);
		return budget;
	}

	work_done = min_t(int, work_done, budget - 1);

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (likely(napi_complete_done(napi, work_done)))
		idpf_vport_intr_update_itr_ena_irq(q_vector);
	else
		idpf_vport_intr_set_wb_on_itr(q_vector);

	/* Switch to poll mode in the tear-down path after sending disable
	 * queues virtchnl message, as the interrupts will be disabled after
	 * that
	 */
	if (unlikely(q_vector->num_txq && test_bit(__IDPF_Q_POLL_MODE,
						   q_vector->tx[0]->flags)))
		return budget;
	else
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
	int i, j, num_txq;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];
		int qv_idx = i % intr_grp->num_q_vectors;

		rxq->q_vector = &intr_grp->q_vectors[qv_idx];
		rxq->q_vector->rx[rxq->q_vector->num_rxq] = rxq;
		rxq->q_vector->num_rxq++;

		if (!idpf_is_queue_model_split(q_grp->rxq_model))
			continue;

		for (j = 0; j < q_grp->bufq_per_rxq; j++) {
			int offset = idpf_rx_bufq_offset(q_grp, i, j);
			struct idpf_queue *bufq;

			bufq = &q_grp->bufqs[offset];
			bufq->q_vector = &intr_grp->q_vectors[qv_idx];
			bufq->q_vector->bufq[bufq->q_vector->num_bufq] = bufq;
			bufq->q_vector->num_bufq++;
		}
	}

	/* In splitq, we want to map the vectors for TX to the complqs as they
	 * will do the cleaning and reporting.
	 */
	num_txq = idpf_is_queue_model_split(q_grp->txq_model) ?
		q_grp->num_complq : q_grp->num_txq;

	for (i = 0; i < num_txq; i++) {
		int qv_idx = i % intr_grp->num_q_vectors;
		struct idpf_queue *q;

		q = idpf_is_queue_model_split(q_grp->txq_model) ?
			&q_grp->complqs[i] : q_grp->txqs[i];

		q->q_vector = &intr_grp->q_vectors[qv_idx];
		q->q_vector->tx[q->q_vector->num_txq] = q;
		q->q_vector->num_txq++;
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

	if (intr_grp->type == IDPF_GRP_TYPE_P2P)
		return;

	if (idpf_is_queue_model_split(vgrp->q_grp.txq_model))
		napi_poll = idpf_vport_splitq_napi_poll;
	else
		napi_poll = idpf_vport_singleq_napi_poll;

	for (v_idx = 0; v_idx < intr_grp->num_q_vectors; v_idx++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[v_idx];

		netif_napi_add(vport->netdev, &q_vector->napi, napi_poll);

		/* only set affinity_mask if the CPU is online */
		if (cpu_online(v_idx))
			cpumask_set_cpu(v_idx, &q_vector->affinity_mask);
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
	u16 txqs_per_vector, rxqs_per_vector, num_txq_vec_need;
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	struct idpf_q_vector *q_vector;
	int i, err;

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
	for (i = 0; i < intr_grp->num_q_vectors; i++) {
		q_vector = &intr_grp->q_vectors[i];
		q_vector->vport = vport;

		q_vector->tx_itr_value = IDPF_ITR_TX_DEF;
		q_vector->tx_intr_mode = IDPF_ITR_DYNAMIC;
		q_vector->tx_itr_idx = VIRTCHNL2_ITR_IDX_1;

		q_vector->rx_itr_value = IDPF_ITR_RX_DEF;
		q_vector->rx_intr_mode = IDPF_ITR_DYNAMIC;
		q_vector->rx_itr_idx = VIRTCHNL2_ITR_IDX_0;

		q_vector->tx = kcalloc(txqs_per_vector,
				       sizeof(struct idpf_queue *),
				       GFP_KERNEL);
		if (!q_vector->tx) {
			err = -ENOMEM;
			goto error;
		}

		q_vector->rx = kcalloc(rxqs_per_vector,
				       sizeof(struct idpf_queue *),
				       GFP_KERNEL);
		if (!q_vector->rx) {
			err = -ENOMEM;
			goto error;
		}

		if (!idpf_is_queue_model_split(q_grp->rxq_model))
			continue;
		q_vector->bufq = kcalloc(q_grp->bufq_per_rxq * rxqs_per_vector,
					 sizeof(struct idpf_queue *),
					 GFP_KERNEL);
		if (!q_vector->bufq) {
			err = -ENOMEM;
			goto error;
		}
	}

	return 0;

error:
	idpf_vport_intr_rel(vgrp);
	return err;
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
	idpf_vport_intr_napi_ena_all(intr_grp);
	if (vgrp->type == IDPF_GRP_TYPE_P2P) {
		u16 qv_idx;

		for (qv_idx = 0; qv_idx < intr_grp->num_q_vectors; qv_idx++)
			intr_grp->q_vectors[qv_idx].wb_on_itr = true;
	}

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

	idpf_vport_intr_ena_irq_all(vport, intr_grp);

	return 0;

unroll_vectors_alloc:
	idpf_vport_intr_napi_dis_all(intr_grp);
	idpf_vport_intr_napi_del_all(intr_grp);

	return err;
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
