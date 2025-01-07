/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#include "idpf.h"

/**
 * idpf_vid_to_vport - Translate vport id to vport pointer
 * @adapter: private data struct
 * @v_id: vport id to translate
 *
 * Returns vport matching v_id, NULL if not found.
 */
static
struct idpf_vport *idpf_vid_to_vport(struct idpf_adapter *adapter, u32 v_id)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);
	int i;

	for (i = 0; i < num_max_vports; i++)
		if (adapter->vport_ids[i] == v_id)
			return adapter->vports[i];

	return NULL;
}

/**
 * idpf_handle_event_link - Handle link event message
 * @adapter: private data struct
 * @v2e: virtchnl event message
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_handle_event_link(struct idpf_adapter *adapter,
				  const struct virtchnl2_event *v2e)
{
	struct idpf_netdev_priv *np;
	struct idpf_vport *vport;

	vport = idpf_vid_to_vport(adapter, le32_to_cpu(v2e->vport_id));
	if (!vport) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Failed to find vport_id %d for link event\n",
				    v2e->vport_id);
		return -EINVAL;
	}

	np = netdev_priv(vport->netdev);
	np->link_speed_mbps = le32_to_cpu(v2e->link_speed);

	if (vport->link_up == v2e->link_status)
		return 0;

	vport->link_up = v2e->link_status;

	if (!np->active)
		return 0;

	if (vport->link_up) {
		netif_tx_start_all_queues(vport->netdev);
		netif_carrier_on(vport->netdev);
	} else {
		netif_tx_stop_all_queues(vport->netdev);
		netif_carrier_off(vport->netdev);
	}

	return 0;
}

/**
 * idpf_recv_event_msg - Receive virtchnl event message
 * @adapter: Driver specific private structure
 * @ctlq_msg: msg received for event
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_recv_event_msg(struct idpf_adapter *adapter,
			       const struct idpf_ctlq_msg *ctlq_msg)
{
	int payload_size = ctlq_msg->ctx.indirect.payload->size;
	struct virtchnl2_event *v2e;
	int err = 0;
	u16 adi_id;
	u32 event;

	if (payload_size < sizeof(*v2e)) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Failed to receive valid payload for event msg (op %d len %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode,
				    payload_size);
		return -EINVAL;
	}

	v2e = (struct virtchnl2_event *)ctlq_msg->ctx.indirect.payload->va;
	event = le32_to_cpu(v2e->event);

	switch (event) {
	case VIRTCHNL2_EVENT_LINK_CHANGE:
		err = idpf_handle_event_link(adapter, v2e);
		break;
	case VIRTCHNL2_EVENT_START_RESET_ADI:
		adi_id = le16_to_cpu(v2e->adi_id);
		if (adapter->dev_ops.notify_adi_reset)
			adapter->dev_ops.notify_adi_reset(adapter, adi_id,
							  false);
		break;
	case VIRTCHNL2_EVENT_FINISH_RESET_ADI:
		adi_id = le16_to_cpu(v2e->adi_id);
		if (adapter->dev_ops.notify_adi_reset)
			adapter->dev_ops.notify_adi_reset(adapter, adi_id,
							  true);
		break;
	default:
		dev_err(idpf_adapter_to_dev(adapter),
			"Unknown event %d from PF\n", event);
		err = -EINVAL;
	}

	return err;
}

/**
 * idpf_mb_clean - Reclaim the send mailbox queue entries
 * @adapter: Driver specific private structure
 *
 * Reclaim the send mailbox queue entries to be used to send further messages
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_mb_clean(struct idpf_adapter *adapter)
{
	u16 i, num_q_msg = IDPF_DFLT_MBX_Q_LEN;
	struct idpf_ctlq_msg **q_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	q_msg = kcalloc(num_q_msg, sizeof(struct idpf_ctlq_msg *), GFP_ATOMIC);
	if (!q_msg)
		return -ENOMEM;

	err = idpf_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
	if (err)
		goto err_kfree;

	for (i = 0; i < num_q_msg; i++) {
		if (!q_msg[i])
			continue;
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem)
			dmam_free_coherent(idpf_adapter_to_dev(adapter), dma_mem->size,
					   dma_mem->va, dma_mem->pa);
		kfree(q_msg[i]);
		kfree(dma_mem);
	}

err_kfree:
	kfree(q_msg);
	return err;
}

/**
 * idpf_ptp_is_mb_msg - Check if the message is PTP-related
 * @op: virtchnl opcode
 *
 * Returns true if msg is PTP-related, false otherwise
 */
static bool idpf_ptp_is_mb_msg(u32 op)
{
	switch (op) {
	case VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP:
	case VIRTCHNL2_OP_PTP_GET_DEV_CLK_TIME:
	case VIRTCHNL2_OP_PTP_GET_CROSS_TIME:
	case VIRTCHNL2_OP_PTP_SET_DEV_CLK_TIME:
	case VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_FINE:
	case VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_TIME:
	case VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP_CAPS:
		return true;
	default:
		return false;
	}
}

/**
 * idpf_send_mb_msg - Send message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchnl opcode
 * @msg_size: size of the payload
 * @msg: pointer to buffer holding the payload
 * @cookie: unique SW cookie per message
 *
 * Will prepare the control queue message and initiates the send api
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg, u16 cookie)
{
	bool is_ptp_msg, ptp_secondary_mbx;
	struct idpf_ctlq_msg *ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int err = 0;

	/* If we are here and a reset is detected nothing much can be
	 * done. This thread should silently abort and expected to
	 * be corrected with a new run either by user or driver
	 * flows after reset
	 */
	if (idpf_is_reset_detected(adapter))
		return 0;

	err = idpf_mb_clean(adapter);
	if (err)
		return err;

	ctlq_msg = kzalloc(sizeof(*ctlq_msg), GFP_ATOMIC);
	if (!ctlq_msg)
		return -ENOMEM;

	dma_mem = kzalloc(sizeof(*dma_mem), GFP_ATOMIC);
	if (!dma_mem) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	memset(ctlq_msg, 0, sizeof(struct idpf_ctlq_msg));

	ctlq_msg->func_id = 0;
	ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_pf;

	/* If the message is PTP-related and the secondary mailbox is available,
	 * send the message through the secondary mailbox
	 */
	is_ptp_msg = idpf_ptp_is_mb_msg(op);
	ptp_secondary_mbx = adapter->ptp.secondary_mbx.valid;

	if (is_ptp_msg && ptp_secondary_mbx) {
		ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_peer_drv;
		ctlq_msg->func_id = adapter->ptp.secondary_mbx.peer_mbx_q_id;
		ctlq_msg->host_id = adapter->ptp.secondary_mbx.peer_id;
	}

	ctlq_msg->data_len = msg_size;
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = VIRTCHNL2_STATUS_SUCCESS;
	dma_mem->size = IDPF_CTLQ_MAX_BUF_LEN;
	dma_mem->va = dmam_alloc_coherent(idpf_adapter_to_dev(adapter), dma_mem->size,
					  &dma_mem->pa, GFP_ATOMIC);
	if (!dma_mem->va) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}
	/* It's possible we're just sending an opcode but no buffer */
	if (msg && msg_size)
		memcpy(dma_mem->va, msg, msg_size);
	ctlq_msg->ctx.indirect.payload = dma_mem;
	ctlq_msg->ctx.sw_cookie.data = cookie;

	err = idpf_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err)
		goto send_error;

	return 0;
send_error:
	dmam_free_coherent(idpf_adapter_to_dev(adapter), dma_mem->size, dma_mem->va,
			   dma_mem->pa);
dma_alloc_error:
	kfree(dma_mem);
dma_mem_error:
	kfree(ctlq_msg);
	return err;
}

/* API for virtchnl "transaction" support ("xn" for short), aka. hma RPCs.
 *
 * We are reusing the completion lock to serialize the accesses to the
 * transaction state for simplicity, but it could be its own separate synchro
 * as well. For now, this API is only used from within a workqueue context;
 * raw_spin_lock() is enough.
 */
/**
 * idpf_vc_xn_lock - Request exclusive access to vc transaction
 * @xn: struct idpf_vc_xn* to access
 */
#ifdef HAVE_COMPLETION_RAW_SPINLOCK
#define idpf_vc_xn_lock(xn)			\
	raw_spin_lock(&(xn)->completed.wait.lock)
#else
#define idpf_vc_xn_lock(xn)			\
	spin_lock(&(xn)->completed.wait.lock)
#endif /* HAVE_COMPLETION_RAW_SPINLOCK */

/**
 * idpf_vc_xn_unlock - Release exclusive access to vc transaction
 * @xn: struct idpf_vc_xn* to access
 */
#ifdef HAVE_COMPLETION_RAW_SPINLOCK
#define idpf_vc_xn_unlock(xn)		\
	raw_spin_unlock(&(xn)->completed.wait.lock)
#else
#define idpf_vc_xn_unlock(xn)		\
	spin_unlock(&(xn)->completed.wait.lock)
#endif /* HAVE_COMPLETION_RAW_SPINLOCK */

/**
 * idpf_vc_xn_release_bufs - Release reference to reply buffer(s) and
 * reset the transaction state.
 * @xn: struct idpf_vc_xn to update
 */
static void idpf_vc_xn_release_bufs(struct idpf_vc_xn *xn)
{
	xn->reply.iov_base = NULL;
	xn->reply.iov_len = 0;

	if (xn->state != IDPF_VC_XN_SHUTDOWN)
		xn->state = IDPF_VC_XN_IDLE;
}

/**
 * idpf_init_vc_xn_completion - Initialize virtchnl completion object
 * @vcxn_mngr: pointer to vc transaction manager struct
 */
void idpf_init_vc_xn_completion(struct idpf_vc_xn_manager *vcxn_mngr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vcxn_mngr->ring); i++) {
		struct idpf_vc_xn *xn = &vcxn_mngr->ring[i];

		init_completion(&xn->completed);
	}
}

/**
 * idpf_vc_xn_init - Initialize virtchnl transaction object
 * @vcxn_mngr: pointer to vc transaction manager struct
 */
void idpf_vc_xn_init(struct idpf_vc_xn_manager *vcxn_mngr)
{
	int i;

	if (WARN_ONCE(vcxn_mngr->active, "Attempt to init vcxn_mngr already active\n"))
		return;

	INIT_LIST_HEAD(&vcxn_mngr->free_xns);
	spin_lock_init(&vcxn_mngr->xn_list_lock);

	for (i = 0; i < ARRAY_SIZE(vcxn_mngr->ring); i++) {
		struct idpf_vc_xn *xn = &vcxn_mngr->ring[i];

		idpf_vc_xn_lock(xn);
		xn->state = IDPF_VC_XN_IDLE;
		xn->idx = i;
		idpf_vc_xn_release_bufs(xn);
		reinit_completion(&xn->completed);
		INIT_LIST_HEAD(&xn->free_list);
		list_add(&xn->free_list, &vcxn_mngr->free_xns);
		idpf_vc_xn_unlock(xn);
	}
	WRITE_ONCE(vcxn_mngr->active, true);
}

/**
 * idpf_vc_xn_shutdown - Uninitialize virtchnl transaction object
 * @vcxn_mngr: pointer to vc transaction manager struct
 *
 * All waiting threads will be worken-up and their transaction aborted. Further
 * operations on that object will fail.
 */
void idpf_vc_xn_shutdown(struct idpf_vc_xn_manager *vcxn_mngr)
{
	struct list_head *curs, *tmp;
	int i;

	if (!vcxn_mngr->active)
		return;

	spin_lock_bh(&vcxn_mngr->xn_list_lock);
	list_for_each_safe(curs, tmp, &vcxn_mngr->free_xns)
		list_del(curs);
	spin_unlock_bh(&vcxn_mngr->xn_list_lock);

	for (i = 0; i < ARRAY_SIZE(vcxn_mngr->ring); i++) {
		struct idpf_vc_xn *xn = &vcxn_mngr->ring[i];

		idpf_vc_xn_lock(xn);
		xn->state = IDPF_VC_XN_SHUTDOWN;
		idpf_vc_xn_release_bufs(xn);
		idpf_vc_xn_unlock(xn);
		complete_all(&xn->completed);
	}
	WRITE_ONCE(vcxn_mngr->active, false);
}

/**
 * idpf_vc_xn_pop_free - Pop a free transaction from free list
 * @vcxn_mngr: transaction manager to pop from
 *
 * Returns NULL if no free transactions
 */
static struct idpf_vc_xn *idpf_vc_xn_pop_free(struct idpf_vc_xn_manager *vcxn_mngr)
{
	struct idpf_vc_xn *xn;

	spin_lock_bh(&vcxn_mngr->xn_list_lock);
	if (list_empty(&vcxn_mngr->free_xns)) {
		spin_unlock_bh(&vcxn_mngr->xn_list_lock);
		return NULL;
	}

	xn = list_first_entry(&vcxn_mngr->free_xns, struct idpf_vc_xn,
			      free_list);
	list_del(&xn->free_list);
	xn->salt = vcxn_mngr->salt++;
	spin_unlock_bh(&vcxn_mngr->xn_list_lock);

	return xn;
}

/**
 * idpf_vc_xn_push_free - Push a free transaction to free list
 * @vcxn_mngr: transaction manager to push to
 * @xn: transaction to push
 */
static void idpf_vc_xn_push_free(struct idpf_vc_xn_manager *vcxn_mngr,
				 struct idpf_vc_xn *xn)
{
	spin_lock_bh(&vcxn_mngr->xn_list_lock);
	INIT_LIST_HEAD(&xn->free_list);
	list_add(&xn->free_list, &vcxn_mngr->free_xns);
	spin_unlock_bh(&vcxn_mngr->xn_list_lock);
}

/**
 * idpf_vc_xn_exec - Perform a send/recv virtchnl transaction
 * @adapter: driver specific private structure with vcxn_mngr
 * @params: parameters for this particular transaction including
 *   -vc_op: virtchanel operation to send
 *   -send_buf: kvec iov for send buf and len
 *   -recv_buf: kvec iov for recv buf and len (ignored if NULL)
 *   -timeout_ms: timeout waiting for a reply (milliseconds)
 *   -async: don't wait for message reply, will lose caller context
 *   -async_handler: callback to handle async replies
 *
 * @returns >= 0 for success, the size of the initial reply (may or may not be
 * >= @recv_buf.iov_len, but we never overflow @@recv_buf_iov_base). < 0 for
 * error.
 */
ssize_t idpf_vc_xn_exec(struct idpf_adapter *adapter,
			struct idpf_vc_xn_params params)
{
	struct kvec *send_buf = &params.send_buf;
	struct idpf_vc_xn *xn;
	ssize_t retval;
	int timeout;
	u16 cookie;

	xn = idpf_vc_xn_pop_free(&adapter->vcxn_mngr);
	/* no free transactions available */
	if (!xn)
		return -EBUSY;

	idpf_vc_xn_lock(xn);
	if (xn->state == IDPF_VC_XN_SHUTDOWN) {
		retval = -ENXIO;
		goto only_unlock;
	} else if (xn->state != IDPF_VC_XN_IDLE) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "There should only be idle transactions in free list (idx %d op %d)\n",
				    xn->idx, xn->vc_op);
		retval = -EBUSY;
		goto only_unlock;
	}

	xn->reply = params.recv_buf;
	xn->reply_sz = 0;
	xn->state = params.async ? IDPF_VC_XN_ASYNC : IDPF_VC_XN_WAITING;
	xn->vc_op = params.vc_op;
	xn->async_handler = params.async_handler;
	idpf_vc_xn_unlock(xn);

	if (!params.async)
		reinit_completion(&xn->completed);
	cookie = FIELD_PREP(IDPF_VC_XN_SALT_M, xn->salt) |
		 FIELD_PREP(IDPF_VC_XN_IDX_M, xn->idx);

	retval = idpf_send_mb_msg(adapter, params.vc_op,
				  send_buf->iov_len, (u8 *)send_buf->iov_base,
				  cookie);
	if (retval) {
		idpf_vc_xn_lock(xn);
		if (xn->state != IDPF_VC_XN_SHUTDOWN)
			WARN_ON_ONCE(xn->state != IDPF_VC_XN_WAITING);
		goto release_and_unlock;
	}

	if (params.async)
		return 0;
	timeout = params.timeout_ms;
	WARN_ONCE(!timeout, "Timeout should not be zero, it will timeout immediately! (op %d)\n",
		  params.vc_op);
	wait_for_completion_timeout(&xn->completed, msecs_to_jiffies(timeout));

	/* no need to check the return value: we check the final state of the
	 * transaction below.
	 */
	idpf_vc_xn_lock(xn);
	switch (xn->state) {
	case IDPF_VC_XN_SHUTDOWN:
		retval = -ENXIO;
		goto only_unlock;
	case IDPF_VC_XN_WAITING:
		dev_notice_ratelimited(idpf_adapter_to_dev(adapter), "Transaction timed-out (op %d, %dms)\n",
				       params.vc_op, timeout);
		retval = -ETIMEDOUT;
		break;
	case IDPF_VC_XN_COMPLETED_SUCCESS:
		retval = xn->reply_sz;
		break;
	case IDPF_VC_XN_COMPLETED_FAILED:
		dev_notice_ratelimited(idpf_adapter_to_dev(adapter), "Transaction failed (op %d)\n",
				       params.vc_op);
		retval = -EIO;
		break;
	default:
		/* Invalid state. */
		WARN_ON_ONCE(1);
		retval = -EIO;
		break;
	}

release_and_unlock:
	idpf_vc_xn_release_bufs(xn);
	idpf_vc_xn_push_free(&adapter->vcxn_mngr, xn);
	/* If we receive a VC reply after here, it will be dropped. */
only_unlock:
	idpf_vc_xn_unlock(xn);
	return retval;
}

/**
 * idpf_vc_xn_forward_async - Handle async reply receives
 * @adapter: private data struct
 * @xn: transaction to handle
 * @ctlq_msg: corresponding ctlq_msg
 *
 * For async sends we're going to lose the caller's context so, if an
 * async_handler was provided, it can deal with the reply, otherwise we'll just
 * check and report if there is an error.
 */
static int
idpf_vc_xn_forward_async(struct idpf_adapter *adapter, struct idpf_vc_xn *xn,
			 const struct idpf_ctlq_msg *ctlq_msg)
{
	int err = 0;

	if (ctlq_msg->cookie.mbx.chnl_opcode != xn->vc_op) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Async message opcode does not match transaction opcode (msg: %d) (xn: %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode, xn->vc_op);
		xn->reply_sz = 0;
		err = -EINVAL;
		goto release_bufs;
	}

	if (xn->async_handler) {
		err = xn->async_handler(adapter, xn, ctlq_msg);
		goto release_bufs;
	}

	if (ctlq_msg->cookie.mbx.chnl_retval) {
		xn->reply_sz = 0;
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Async message failure (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		err = -EINVAL;
	}

release_bufs:
	idpf_vc_xn_release_bufs(xn);
	idpf_vc_xn_push_free(&adapter->vcxn_mngr, xn);

	return err;
}

/**
 * idpf_vc_xn_forward_reply - copy a reply back to receiving thread
 * @adapter: driver specific private structure with vcxn_mngr
 * @ctlq_msg: controlq message to send back to receiving thread
 */
static int
idpf_vc_xn_forward_reply(struct idpf_adapter *adapter,
			 const struct idpf_ctlq_msg *ctlq_msg)
{
	const void *payload = NULL;
	size_t payload_size = 0;
	struct idpf_vc_xn *xn;
	u16 msg_info;
	int err = 0;
	u16 xn_idx;
	u16 salt;

	msg_info = ctlq_msg->ctx.sw_cookie.data;
	xn_idx = FIELD_GET(IDPF_VC_XN_IDX_M, msg_info);
	if (xn_idx >= ARRAY_SIZE(adapter->vcxn_mngr.ring)) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Out of bounds cookie received: %02x\n",
				    xn_idx);
		return -EINVAL;
	}
	xn = &adapter->vcxn_mngr.ring[xn_idx];
	salt = FIELD_GET(IDPF_VC_XN_SALT_M, msg_info);
	if (xn->salt != salt) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Transaction salt does not match (%02x != %02x)\n",
				    xn->salt, salt);
		return -EINVAL;
	}

	idpf_vc_xn_lock(xn);
	switch (xn->state) {
	case IDPF_VC_XN_WAITING:
		/* success */
		break;
	case IDPF_VC_XN_IDLE:
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Unexpected or belated VC reply (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		fallthrough;
	case IDPF_VC_XN_SHUTDOWN:
		err = -EINVAL;
		goto out_unlock;
	case IDPF_VC_XN_ASYNC:
		err = idpf_vc_xn_forward_async(adapter, xn, ctlq_msg);
		idpf_vc_xn_unlock(xn);
		return err;
	default:
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Overwriting VC reply (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		err = -EBUSY;
		goto out_unlock;
	}

	if (ctlq_msg->cookie.mbx.chnl_opcode != xn->vc_op) {
		dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Message opcode does not match transaction opcode (msg: %d) (xn: %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode, xn->vc_op);
		xn->reply_sz = 0;
		xn->state = IDPF_VC_XN_COMPLETED_FAILED;
		err = -EINVAL;
		goto out_unlock;
	}

	if (ctlq_msg->cookie.mbx.chnl_retval) {
		xn->reply_sz = 0;
		xn->state = IDPF_VC_XN_COMPLETED_FAILED;
		err = -EINVAL;
		goto out_unlock;
	}

	if (ctlq_msg->data_len) {
		payload = ctlq_msg->ctx.indirect.payload->va;
		payload_size = ctlq_msg->data_len;
	}

	xn->reply_sz = payload_size;
	xn->state = IDPF_VC_XN_COMPLETED_SUCCESS;

	if (xn->reply.iov_base && xn->reply.iov_len && payload_size)
		memcpy(xn->reply.iov_base, payload,
		       min_t(size_t, xn->reply.iov_len, payload_size));

out_unlock:
	idpf_vc_xn_unlock(xn);
	/* we _cannot_ hold lock while calling complete */
	complete(&xn->completed);

	return err;
}

/**
 * idpf_recv_mb_msg - Receive message over mailbox
 * @adapter: Driver specific private structure
 *
 * Will receive control queue message and posts the receive buffer. Returns 0
 * on success and negative on failure.
 */
int idpf_recv_mb_msg(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_msg ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int post_err, err = 0;
	u16 num_recv;

	while (!err) {
		/* This will get <= num_recv messages and output how many
		 * actually received on num_recv.
		 */
		num_recv = 1;
		err = idpf_ctlq_recv(adapter->hw.arq, &num_recv, &ctlq_msg);
		if (err || !num_recv)
			break;

		if (ctlq_msg.data_len) {
			dma_mem = ctlq_msg.ctx.indirect.payload;
		} else {
			dma_mem = NULL;
			num_recv = 0;
		}

		if (ctlq_msg.cookie.mbx.chnl_opcode == VIRTCHNL2_OP_EVENT)
			idpf_recv_event_msg(adapter, &ctlq_msg);
		else
			err = idpf_vc_xn_forward_reply(adapter, &ctlq_msg);

		post_err = idpf_ctlq_post_rx_buffs(&adapter->hw,
						   adapter->hw.arq,
						   &num_recv, &dma_mem);

		/* If post failed clear the only buffer we supplied */
		if (post_err) {
			if (dma_mem)
				dmam_free_coherent(idpf_adapter_to_dev(adapter),
						   dma_mem->size, dma_mem->va,
						   dma_mem->pa);
			break;
		}
	}

	return err;
}

/**
 * idpf_show_mbx_info - display MBX descriptor info
 * @adapter: Driver private data structure
 */
static inline void idpf_show_mbx_info(struct idpf_adapter *adapter)
{
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 dyn_ctl = le32_to_cpu(adapter->caps.mailbox_dyn_ctl);
	struct idpf_ctlq_info *q = adapter->hw.asq;
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_hw *hw = &adapter->hw;

	dev_info(dev, "MBX TXQ: head = %x, tail = %x\n",
		 rd32(hw, q->reg.head), rd32(hw, q->reg.tail));
	q = adapter->hw.arq;
	dev_info(dev, "MBX RXQ: head = %x, tail = %x\n",
		 rd32(hw, q->reg.head), rd32(hw, q->reg.tail));

	intr->dyn_ctl = idpf_get_reg_addr(adapter, dyn_ctl);
	if (intr->dyn_ctl)
		dev_info(dev, "DYN_CTL = %x\n", readl(intr->dyn_ctl));
}

/**
 * idpf_wait_for_marker_event - wait for software marker response
 * @vport: virtual port data structure
 * @q_grp: Queue resources
 *
 * Returns 0 success, negative on failure.
 **/
static int idpf_wait_for_marker_event(struct idpf_vport *vport,
				      struct idpf_q_grp *q_grp)
{
	int event;
	int i;

	for (i = 0; i < q_grp->num_txq; i++)
		set_bit(__IDPF_Q_SW_MARKER, q_grp->txqs[i]->flags);

	event = wait_event_timeout(vport->sw_marker_wq,
				   test_and_clear_bit(IDPF_VPORT_SW_MARKER,
						      vport->flags),
				   msecs_to_jiffies(500));

	for (i = 0; i < q_grp->num_txq; i++)
		clear_bit(__IDPF_Q_POLL_MODE, q_grp->txqs[i]->flags);

	if (event)
		return 0;

	dev_warn(idpf_adapter_to_dev(vport->adapter), "Failed to receive marker packets\n");
	return -ETIMEDOUT;
}

/**
 * idpf_send_ver_msg - send virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl version message.  Returns 0 on success, negative on failure.
 */
static int idpf_send_ver_msg(struct idpf_adapter *adapter)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_version_info vvi;
	ssize_t reply_sz;
	u32 major, minor;
	int err = 0;

	if (adapter->virt_ver_maj) {
		vvi.major = cpu_to_le32(adapter->virt_ver_maj);
		vvi.minor = cpu_to_le32(adapter->virt_ver_min);
	} else {
		vvi.major = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MAJOR);
		vvi.minor = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MINOR);
	}

	xn_params.vc_op = VIRTCHNL2_OP_VERSION;
	xn_params.send_buf.iov_base = &vvi;
	xn_params.send_buf.iov_len = sizeof(vvi);
	xn_params.recv_buf = xn_params.send_buf;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(vvi))
		return -EIO;

	major = le32_to_cpu(vvi.major);
	minor = le32_to_cpu(vvi.minor);

	if (major > IDPF_VIRTCHNL_VERSION_MAJOR) {
		dev_warn(idpf_adapter_to_dev(adapter), "Virtchnl major version greater than supported\n");
		return -EINVAL;
	}

	if (major == IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor > IDPF_VIRTCHNL_VERSION_MINOR)
		dev_warn(idpf_adapter_to_dev(adapter), "Virtchnl minor version not matched\n");

	/* If we have a mismatch, resend version to update receiver on what
	 * version we will use.
	 */
	if (!adapter->virt_ver_maj &&
	    major != IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor != IDPF_VIRTCHNL_VERSION_MINOR)
		err = -EAGAIN;

	adapter->virt_ver_maj = major;
	adapter->virt_ver_min = minor;

	return err;
}

/**
 * idpf_send_get_caps_msg - Send virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_get_caps_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities caps = { };
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;

	caps.csum_caps =
		cpu_to_le32(VIRTCHNL2_CAP_TX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_GENERIC);

	caps.seg_caps =
		cpu_to_le32(VIRTCHNL2_CAP_SEG_IPV4_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV4_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV4_SCTP		|
			    VIRTCHNL2_CAP_SEG_IPV6_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV6_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV6_SCTP		|
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL);

	caps.rss_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RSS_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV4_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV4_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV4_OTHER	|
			    VIRTCHNL2_CAP_RSS_IPV6_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV6_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV6_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV6_OTHER);

	caps.hsplit_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6);

	caps.rsc_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RSC_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSC_IPV6_TCP);

	caps.other_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RDMA			|
			    VIRTCHNL2_CAP_SRIOV			|
			    VIRTCHNL2_CAP_MACFILTER		|
			    VIRTCHNL2_CAP_SPLITQ_QSCHED		|
			    VIRTCHNL2_CAP_PROMISC		|
			    VIRTCHNL2_CAP_EDT			|
			    VIRTCHNL2_CAP_PTP			|
			    VIRTCHNL2_CAP_OEM			|
			    VIRTCHNL2_CAP_MISS_COMPL_TAG	|
			    VIRTCHNL2_CAP_LOOPBACK);

	xn_params.vc_op = VIRTCHNL2_OP_GET_CAPS;
	xn_params.send_buf.iov_base = &caps;
	xn_params.send_buf.iov_len = sizeof(caps);
	xn_params.recv_buf.iov_base = &adapter->caps;
	xn_params.recv_buf.iov_len = sizeof(struct virtchnl2_get_capabilities);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(struct virtchnl2_get_capabilities))
		return -EIO;

	return 0;
}
/**
 * idpf_ptp_get_caps - Send virtchnl get ptp capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
int idpf_ptp_get_caps(struct idpf_adapter *adapter)
{
	struct virtchnl2_ptp_get_caps send_ptp_caps_msg = { };
	struct virtchnl2_ptp_get_caps *recv_ptp_caps_msg;
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_ptp *ptp = &adapter->ptp;
	enum idpf_ptp_access access_type;
	int reply_sz;
	int err = 0;

	recv_ptp_caps_msg = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);

	if (!recv_ptp_caps_msg)
		return -ENOMEM;

	send_ptp_caps_msg.caps =
		cpu_to_le32(VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME |
			    VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME_MB |
			    VIRTCHNL2_CAP_PTP_GET_CROSS_TIME |
			    VIRTCHNL2_CAP_PTP_GET_CROSS_TIME_MB |
			    VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME_MB |
			    VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK_MB |
			    VIRTCHNL2_CAP_PTP_TX_TSTAMPS_MB);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_GET_CAPS;
	xn_params.send_buf.iov_base = &send_ptp_caps_msg;
	xn_params.send_buf.iov_len = sizeof(send_ptp_caps_msg);
	xn_params.recv_buf.iov_base = recv_ptp_caps_msg;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto free_recv_buf;
	} else if (reply_sz < sizeof(struct virtchnl2_ptp_get_caps)) {
		err = -EIO;
		goto free_recv_buf;
	}

	ptp->caps = le32_to_cpu(recv_ptp_caps_msg->caps);
	ptp->base_incval = le64_to_cpu(recv_ptp_caps_msg->base_incval);
	ptp->max_adj = le32_to_cpu(recv_ptp_caps_msg->max_adj);

	ptp->secondary_mbx.peer_mbx_q_id = le16_to_cpu(recv_ptp_caps_msg->peer_mbx_q_id);

	/* if the ptp_mb_q_id holds invalid value (0xFFFF), the secondary
	 * mailbox is not supported
	 */
	ptp->secondary_mbx.valid = (ptp->secondary_mbx.peer_mbx_q_id == 0xFFFF) ? 0 : 1;
	if (ptp->secondary_mbx.valid)
		ptp->secondary_mbx.peer_id = recv_ptp_caps_msg->peer_id;

	/* Determine the access type for the PTP features */
	idpf_ptp_get_features_access(adapter);

	access_type = ptp->get_dev_clk_time_access;
	if (access_type == IDPF_PTP_DIRECT) {
		struct virtchnl2_ptp_clk_reg_offsets co = recv_ptp_caps_msg->clk_offsets;

		ptp->dev_clk_regs.dev_clk_ns_l = le32_to_cpu(co.dev_clk_ns_l);
		ptp->dev_clk_regs.dev_clk_ns_h = le32_to_cpu(co.dev_clk_ns_h);
		ptp->dev_clk_regs.phy_clk_ns_l = le32_to_cpu(co.phy_clk_ns_l);
		ptp->dev_clk_regs.phy_clk_ns_h = le32_to_cpu(co.phy_clk_ns_h);
		ptp->dev_clk_regs.cmd_sync = le32_to_cpu(co.cmd_sync_trigger);
	}

	access_type = ptp->get_cross_tstamp_access;
	if (access_type == IDPF_PTP_DIRECT) {
		struct virtchnl2_ptp_cross_time_reg_offsets cto = recv_ptp_caps_msg->cross_time_offsets;

		ptp->dev_clk_regs.sys_time_ns_l = le32_to_cpu(cto.sys_time_ns_l);
		ptp->dev_clk_regs.sys_time_ns_h = le32_to_cpu(cto.sys_time_ns_h);
		ptp->dev_clk_regs.cmd_sync = le32_to_cpu(cto.cmd_sync_trigger);
	}

	access_type = ptp->adj_dev_clk_time_access;
	if (access_type == IDPF_PTP_DIRECT) {
		struct virtchnl2_ptp_clk_adj_reg_offsets cadjo = recv_ptp_caps_msg->clk_adj_offsets;

		ptp->dev_clk_regs.cmd = le32_to_cpu(cadjo.dev_clk_cmd_type);
		ptp->dev_clk_regs.incval_l = le32_to_cpu(cadjo.dev_clk_incval_l);
		ptp->dev_clk_regs.incval_h = le32_to_cpu(cadjo.dev_clk_incval_h);
		ptp->dev_clk_regs.shadj_l = le32_to_cpu(cadjo.dev_clk_shadj_l);
		ptp->dev_clk_regs.shadj_h = le32_to_cpu(cadjo.dev_clk_shadj_h);
		ptp->dev_clk_regs.phy_cmd = le32_to_cpu(cadjo.phy_clk_cmd_type);
		ptp->dev_clk_regs.phy_incval_l = le32_to_cpu(cadjo.phy_clk_incval_l);
		ptp->dev_clk_regs.phy_incval_h = le32_to_cpu(cadjo.phy_clk_incval_h);
		ptp->dev_clk_regs.phy_shadj_l = le32_to_cpu(cadjo.phy_clk_shadj_l);
		ptp->dev_clk_regs.phy_shadj_h = le32_to_cpu(cadjo.phy_clk_shadj_h);
	}

free_recv_buf:
	kfree(recv_ptp_caps_msg);

	return err;
}

/**
 * idpf_ptp_get_vport_tstamps_caps - Send virtchnl to get tstamps caps for vport
 * @vport: Virtual port structure
 *
 * Send virtchnl get vport tstamps caps message to receive the set of tstamp
 * capabilities per vport. Returns 0 on success, negative otherwise.
 */
static int idpf_ptp_get_vport_tstamps_caps(struct idpf_vport *vport)
{
	struct virtchnl2_ptp_get_vport_tx_tstamp_caps send_tx_tstamp_caps;
	struct virtchnl2_ptp_get_vport_tx_tstamp_caps *rcv_tx_tstamp_caps;
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp, *tmp;
	struct idpf_vc_xn_params xn_params = { };
	enum idpf_ptp_access access_type;
	int err = 0, i, reply_sz;
	struct list_head *head;
	unsigned long flags;
	u16 num_latches;
	u32 size;

	access_type = vport->adapter->ptp.tx_tstamp_access;
	if (access_type == IDPF_PTP_NONE)
		return -EOPNOTSUPP;

	rcv_tx_tstamp_caps = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!rcv_tx_tstamp_caps)
		return -ENOMEM;

	send_tx_tstamp_caps.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP_CAPS;
	xn_params.send_buf.iov_base = &send_tx_tstamp_caps;
	xn_params.send_buf.iov_len = sizeof(struct virtchnl2_ptp_get_vport_tx_tstamp_caps);
	xn_params.recv_buf.iov_base = rcv_tx_tstamp_caps;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto get_tstamp_caps_out;
	}

	num_latches = le16_to_cpu(rcv_tx_tstamp_caps->num_latches);
	size = struct_size(rcv_tx_tstamp_caps, tstamp_latches, num_latches);
	if (reply_sz < size) {
		err = -EIO;
		goto get_tstamp_caps_out;
	}

	tx_tstamp_caps = kzalloc(sizeof(struct idpf_ptp_vport_tx_tstamp_caps),
				 GFP_ATOMIC);
	if (!tx_tstamp_caps) {
		err = -ENOMEM;
		goto get_tstamp_caps_out;
	}

	vport->tx_tstamp_caps = tx_tstamp_caps;

	tx_tstamp_caps->num_entries = num_latches;
	INIT_LIST_HEAD(&tx_tstamp_caps->latches_in_use);
	INIT_LIST_HEAD(&tx_tstamp_caps->latches_free);

	spin_lock_init(&tx_tstamp_caps->lock_free);
	spin_lock_init(&tx_tstamp_caps->lock_in_use);

	tx_tstamp_caps->tstamp_ns_lo_bit = rcv_tx_tstamp_caps->tstamp_ns_lo_bit;

	tx_tstamp_caps->tx_tstamp_status = kcalloc(tx_tstamp_caps->num_entries,
						   sizeof(struct idpf_ptp_tx_tstamp_status),
						   GFP_ATOMIC);
	if (!tx_tstamp_caps->tx_tstamp_status) {
		err = -ENOMEM;
		goto err_free_tstamp_caps;
	}

	for (i = 0; i < tx_tstamp_caps->num_entries; i++) {
		ptp_tx_tstamp = kzalloc(sizeof(*ptp_tx_tstamp), GFP_ATOMIC);
		if (!ptp_tx_tstamp) {
			err = -ENOMEM;
			goto err_free_ptp_tx_stamp_list;
		}

		if (access_type == IDPF_PTP_DIRECT) {
			ptp_tx_tstamp->tx_latch_reg_offset_l =
				le32_to_cpu(rcv_tx_tstamp_caps->tstamp_latches[i].tx_latch_reg_offset_l);
			ptp_tx_tstamp->tx_latch_reg_offset_h =
				le32_to_cpu(rcv_tx_tstamp_caps->tstamp_latches[i].tx_latch_reg_offset_h);
		}

		ptp_tx_tstamp->idx = rcv_tx_tstamp_caps->tstamp_latches[i].index;

		spin_lock_irqsave(&tx_tstamp_caps->lock_free, flags);
		list_add(&ptp_tx_tstamp->list_member, &tx_tstamp_caps->latches_free);
		spin_unlock_irqrestore(&tx_tstamp_caps->lock_free, flags);

		tx_tstamp_caps->tx_tstamp_status[i].state = IDPF_PTP_FREE;
	}

	goto get_tstamp_caps_out;

err_free_ptp_tx_stamp_list:
	spin_lock_irqsave(&tx_tstamp_caps->lock_free, flags);
	head = &tx_tstamp_caps->latches_free;
	list_for_each_entry_safe(ptp_tx_tstamp, tmp, head, list_member) {
		list_del(&ptp_tx_tstamp->list_member);
		kfree(ptp_tx_tstamp);
	}
	spin_unlock_irqrestore(&tx_tstamp_caps->lock_free, flags);
err_free_tstamp_caps:
	kfree(tx_tstamp_caps);
get_tstamp_caps_out:
	kfree(rcv_tx_tstamp_caps);
	return err;
}

/**
 * idpf_ptp_get_dev_clk_time - Send virtchnl get device clk time message
 * @adapter: Driver specific private structure
 * @dev_clk_time: Pointer to the device clock structure where the value is set
 *
 * Send virtchnl get time message to get the time of the clock. Returns 0 on
 * success, negative otherwise.
 */
int idpf_ptp_get_dev_clk_time(struct idpf_adapter *adapter,
			      struct idpf_ptp_dev_timers *dev_clk_time)
{
	struct virtchnl2_ptp_get_dev_clk_time get_dev_clk_time_msg;
	struct idpf_vc_xn_params xn_params = { };
	int reply_sz;

	xn_params.vc_op = VIRTCHNL2_OP_PTP_GET_DEV_CLK_TIME;
	xn_params.send_buf.iov_base = &get_dev_clk_time_msg;
	xn_params.send_buf.iov_len = sizeof(struct virtchnl2_ptp_get_dev_clk_time);
	xn_params.recv_buf.iov_base = &get_dev_clk_time_msg;
	xn_params.recv_buf.iov_len = sizeof(struct virtchnl2_ptp_get_dev_clk_time);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(struct virtchnl2_ptp_get_dev_clk_time))
		return -EIO;

	dev_clk_time->dev_clk_time_ns = le64_to_cpu(get_dev_clk_time_msg.dev_time_ns);

	return 0;
}

/**
 * idpf_ptp_get_cross_time - Send virtchnl get cross time message
 * @adapter: Driver specific private structure
 * @cross_time: Pointer to the device clock structure where the value is set
 *
 * Send virtchnl get cross time message to get the time of the clock and the
 * system time. Returns 0 on success, negative otherwise.
 */
int idpf_ptp_get_cross_time(struct idpf_adapter *adapter,
			    struct idpf_ptp_dev_timers *cross_time)
{
	struct virtchnl2_ptp_get_cross_time cross_time_msg;
	struct idpf_vc_xn_params xn_params = { };
	int reply_sz;

	xn_params.vc_op = VIRTCHNL2_OP_PTP_GET_CROSS_TIME;
	xn_params.send_buf.iov_base = &cross_time_msg;
	xn_params.send_buf.iov_len = sizeof(struct virtchnl2_ptp_get_cross_time);
	xn_params.recv_buf.iov_base = &cross_time_msg;
	xn_params.recv_buf.iov_len = sizeof(struct virtchnl2_ptp_get_cross_time);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(struct virtchnl2_ptp_get_cross_time))
		return -EIO;

	cross_time->dev_clk_time_ns = le64_to_cpu(cross_time_msg.dev_time_ns);
	cross_time->sys_time_ns = le64_to_cpu(cross_time_msg.sys_time_ns);

	return 0;
}

/**
 * idpf_ptp_set_dev_clk_time - Send virtchnl set device time message
 * @adapter: Driver specific private structure
 * @time: New time value
 *
 * Send virtchnl set time message to set the time of the clock. Returns 0 on
 * success, negative otherwise.
 */
int idpf_ptp_set_dev_clk_time(struct idpf_adapter *adapter, u64 time)
{
	struct virtchnl2_ptp_set_dev_clk_time set_dev_clk_time_msg = { };
	struct idpf_vc_xn_params xn_params = { };
	int reply_sz;

	set_dev_clk_time_msg.dev_time_ns = cpu_to_le64(time);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_SET_DEV_CLK_TIME;
	xn_params.send_buf.iov_base = &set_dev_clk_time_msg;
	xn_params.send_buf.iov_len = sizeof(set_dev_clk_time_msg);
	xn_params.recv_buf.iov_base = &set_dev_clk_time_msg;
	xn_params.recv_buf.iov_len = sizeof(set_dev_clk_time_msg);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(set_dev_clk_time_msg))
		return -EIO;

	return 0;
}

/**
 * idpf_ptp_adj_dev_clk_time - Send virtchnl adj device clock time message
 * @adapter: Driver specific private structure
 * @delta: Offset in nanoseconds to adjust the time by
 *
 * Send virtchnl adj time message to adjust the clock by the indicated delta.
 * Returns 0 on success, negative otherwise.
 */
int idpf_ptp_adj_dev_clk_time(struct idpf_adapter *adapter, s64 delta)
{
	struct virtchnl2_ptp_adj_dev_clk_time adj_dev_clk_time_msg = { };
	struct idpf_vc_xn_params xn_params = { };
	int reply_sz;

	adj_dev_clk_time_msg.delta = cpu_to_le64(delta);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_TIME;
	xn_params.send_buf.iov_base = &adj_dev_clk_time_msg;
	xn_params.send_buf.iov_len = sizeof(adj_dev_clk_time_msg);
	xn_params.recv_buf.iov_base = &adj_dev_clk_time_msg;
	xn_params.recv_buf.iov_len = sizeof(adj_dev_clk_time_msg);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(adj_dev_clk_time_msg))
		return -EIO;

	return 0;
}

/**
 * idpf_ptp_adj_dev_clk_fine - Send virtchnl adj time message
 * @adapter: Driver specific private structure
 * @incval: Source timer increment value per clock cycle
 *
 * Send virtchnl adj fine message to adjust the frequency of the clock by
 * incval. Returns 0 on success, negative otherwise.
 */
int idpf_ptp_adj_dev_clk_fine(struct idpf_adapter *adapter, u64 incval)
{
	struct virtchnl2_ptp_adj_dev_clk_fine adj_dev_clk_fine_msg = { };
	struct idpf_vc_xn_params xn_params = { };
	int reply_sz;

	adj_dev_clk_fine_msg.incval = cpu_to_le64(incval);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_FINE;
	xn_params.send_buf.iov_base = &adj_dev_clk_fine_msg;
	xn_params.send_buf.iov_len = sizeof(adj_dev_clk_fine_msg);
	xn_params.recv_buf.iov_base = &adj_dev_clk_fine_msg;
	xn_params.recv_buf.iov_len = sizeof(adj_dev_clk_fine_msg);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(adj_dev_clk_fine_msg))
		return -EIO;

	return 0;
}

/**
 * idpf_ptp_get_tx_tstamp_async_handler - Async callback for getting tx tstamps
 * @adapter: Driver specific private structure
 * @xn: transaction for message
 * @ctlq_msg: received message
 *
 * Read the tstamps Tx tstamp values from a received message and put them
 * directly to the skb. The number of timestamps to read is specified by
 * the virtchnl message.
 *
 * Returns 0 on success, negative otherwise.
 */
static int idpf_ptp_get_tx_tstamp_mb_async_handler(struct idpf_adapter *adapter,
						   struct idpf_vc_xn *xn,
						   const struct idpf_ctlq_msg *ctlq_msg)
{
	struct virtchnl2_ptp_get_vport_tx_tstamp_latches *recv_tx_tstamp_latches_msg;
	bool vport_found = false, tracker_found = false, idx_found = false;
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	struct skb_shared_hwtstamps shhwtstamps = {};
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp;
	u8 tstamp_ns_lo_bit, valid, idx;
	struct idpf_vport *vport;
	u16 i, id, num_latches;
	struct list_head *head;
	struct sk_buff *skb;
	u64 tstamp;

	recv_tx_tstamp_latches_msg = (struct virtchnl2_ptp_get_vport_tx_tstamp_latches *)
				     ctlq_msg->ctx.indirect.payload->va;

	idpf_for_each_vport(adapter, i) {
		vport = adapter->vports[i];

		if (!vport)
			continue;

		if (vport->vport_id == le32_to_cpu(recv_tx_tstamp_latches_msg->vport_id)) {
			tx_tstamp_caps = vport->tx_tstamp_caps;
			vport_found = true;
			break;
		}
	}

	if (!vport_found)
		return -EINVAL;

	head = &tx_tstamp_caps->latches_in_use;
	tstamp_ns_lo_bit = tx_tstamp_caps->tstamp_ns_lo_bit;
	num_latches = le16_to_cpu(recv_tx_tstamp_latches_msg->num_latches);

	for (i = 0; i < num_latches; i++) {
		unsigned long flags;

		idx = recv_tx_tstamp_latches_msg->tstamp_latches[i].index;
		valid = recv_tx_tstamp_latches_msg->tstamp_latches[i].valid;

		if (!valid)
			continue;

		spin_lock_irqsave(&tx_tstamp_caps->lock_in_use, flags);
		list_for_each_entry(ptp_tx_tstamp, head, list_member) {
			if (idx == ptp_tx_tstamp->idx) {
				idx_found = true;
				list_del(&ptp_tx_tstamp->list_member);
				break;
			}
		}
		spin_unlock_irqrestore(&tx_tstamp_caps->lock_in_use, flags);

		if (!idx_found)
			continue;

		ptp_tx_tstamp->tstamp = le64_to_cpu(recv_tx_tstamp_latches_msg->tstamp_latches[i].tstamp);
		ptp_tx_tstamp->tstamp >>= tstamp_ns_lo_bit;

		tstamp = idpf_ptp_extend_ts(vport->adapter, ptp_tx_tstamp->tstamp);

		for (id = 0; id < tx_tstamp_caps->num_entries; id++) {
			if (ptp_tx_tstamp->skb == tx_tstamp_caps->tx_tstamp_status[id].skb &&
			    tx_tstamp_caps->tx_tstamp_status[id].state == IDPF_PTP_READ_VALUE) {
				tx_tstamp_caps->tx_tstamp_status[id].state = IDPF_PTP_FREE;
				tracker_found = true;
				break;
			}
		}

		if (!tracker_found)
			continue;

		shhwtstamps.hwtstamp = ns_to_ktime(tstamp);
		skb = ptp_tx_tstamp->skb;
		skb_tstamp_tx(skb, &shhwtstamps);

		dev_kfree_skb_any(skb);

		spin_lock_irqsave(&tx_tstamp_caps->lock_free, flags);
		list_add(&ptp_tx_tstamp->list_member,
			 &tx_tstamp_caps->latches_free);
		spin_unlock_irqrestore(&tx_tstamp_caps->lock_free, flags);
	}

	return 0;
}

/**
 * idpf_ptp_get_tx_tstamp - Send virtchnl get tx timestamp latches message
 * @vport: Virtual port structure
 *
 * Send virtchnl get tx tstamp message to read the value of the HW timestamp.
 * The message contains a list of indexes set in the Tx descriptors.
 *
 * Returns 0 on success, negative otherwise.
 */
int idpf_ptp_get_tx_tstamp_mb(struct idpf_vport *vport)
{
	struct virtchnl2_ptp_get_vport_tx_tstamp_latches *send_tx_tstamp_latches_msg;
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps = vport->tx_tstamp_caps;
	struct list_head *head = &tx_tstamp_caps->latches_in_use;
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp;
	int reply_sz, msg_size, size, err = 0;
	unsigned long flags;
	u16 id = 0, i;

	size = struct_size(send_tx_tstamp_latches_msg, tstamp_latches,
			   tx_tstamp_caps->num_entries);
	send_tx_tstamp_latches_msg = kzalloc(size, GFP_KERNEL);

	if (!send_tx_tstamp_latches_msg)
		return -ENOMEM;

	spin_lock_irqsave(&tx_tstamp_caps->lock_in_use, flags);
	list_for_each_entry(ptp_tx_tstamp, head, list_member) {
		for (i = 0; i < tx_tstamp_caps->num_entries; i++) {
			if (tx_tstamp_caps->tx_tstamp_status[i].skb == ptp_tx_tstamp->skb  &&
			    tx_tstamp_caps->tx_tstamp_status[i].state == IDPF_PTP_REQUEST) {
				send_tx_tstamp_latches_msg->tstamp_latches[id].index =
					ptp_tx_tstamp->idx;
				tx_tstamp_caps->tx_tstamp_status[i].state = IDPF_PTP_READ_VALUE;
				id++;
			}
		}
	}
	spin_unlock_irqrestore(&tx_tstamp_caps->lock_in_use, flags);

	send_tx_tstamp_latches_msg->vport_id = cpu_to_le32(vport->vport_id);
	send_tx_tstamp_latches_msg->num_latches = cpu_to_le16(id);

	/* Calculate the size of message based on number of requested Tx
	 * timestamp latches.
	 */
	msg_size = struct_size(send_tx_tstamp_latches_msg, tstamp_latches, id);

	xn_params.vc_op = VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP;
	xn_params.send_buf.iov_base = send_tx_tstamp_latches_msg;
	xn_params.send_buf.iov_len = msg_size;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.async = true;
	xn_params.async_handler = idpf_ptp_get_tx_tstamp_mb_async_handler;

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0)
		err = reply_sz;

	kfree(send_tx_tstamp_latches_msg);

	return err;
}

/**
 * idpf_vport_alloc_max_qs - Allocate max queues for a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;
	u16 default_vports = idpf_get_default_vports(adapter);
	u16 max_rx_q, max_tx_q, max_bufq, max_complq;

	mutex_lock(&adapter->queue_lock);

	max_rx_q = le16_to_cpu(caps->max_rx_q) / default_vports;
	max_tx_q = le16_to_cpu(caps->max_tx_q) / default_vports;
	max_bufq = le16_to_cpu(caps->max_rx_bufq) / default_vports;
	max_complq = le16_to_cpu(caps->max_tx_complq) / default_vports;

	if (adapter->num_alloc_vports < default_vports) {
		if (default_vports == 1) {
			max_q->max_rxq = max_rx_q;
			max_q->max_txq = max_tx_q;
		} else {
			max_q->max_rxq = min_t(u16, max_rx_q, IDPF_MAX_Q);
			max_q->max_txq = min_t(u16, max_tx_q, IDPF_MAX_Q);
		}
	} else {
		max_q->max_rxq = IDPF_MIN_Q;
		max_q->max_txq = IDPF_MIN_Q;
	}

	/* In splitq model, recalculate RX and TX queues based on the
	 * availability of buffer and completion queues. Skip this for
	 * singleq model as buffer and completion queues will be zero.
	 */
	if (max_bufq) {
		max_q->max_rxq = min_t(u16, max_q->max_rxq,
				       max_bufq / IDPF_MAX_BUFQS_PER_RXQ);
		max_q->max_bufq = max_q->max_rxq * IDPF_MAX_BUFQS_PER_RXQ;
	}

	if (max_complq) {
		max_q->max_txq = min_t(u16, max_q->max_txq, max_complq);
		max_q->max_complq = max_q->max_txq;
	}

	if (avail_queues->avail_rxq < max_q->max_rxq ||
	    avail_queues->avail_txq < max_q->max_txq ||
	    avail_queues->avail_bufq < max_q->max_bufq ||
	    avail_queues->avail_complq < max_q->max_complq) {
		mutex_unlock(&adapter->queue_lock);

		return -EINVAL;
	}

	avail_queues->avail_rxq -= max_q->max_rxq;
	avail_queues->avail_txq -= max_q->max_txq;
	avail_queues->avail_bufq -= max_q->max_bufq;
	avail_queues->avail_complq -= max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);

	return 0;
}

/**
 * idpf_vport_dealloc_max_qs - Deallocate max queues of a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues;

	mutex_lock(&adapter->queue_lock);
	avail_queues = &adapter->avail_queues;

	avail_queues->avail_rxq += max_q->max_rxq;
	avail_queues->avail_txq += max_q->max_txq;
	avail_queues->avail_bufq += max_q->max_bufq;
	avail_queues->avail_complq += max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);
}

/**
 * idpf_init_avail_queues - Initialize available queues on the device
 * @adapter: Driver specific private structure
 */
static void idpf_init_avail_queues(struct idpf_adapter *adapter)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;

	avail_queues->avail_rxq = le16_to_cpu(caps->max_rx_q);
	avail_queues->avail_txq = le16_to_cpu(caps->max_tx_q);
	avail_queues->avail_bufq = le16_to_cpu(caps->max_rx_bufq);
	avail_queues->avail_complq = le16_to_cpu(caps->max_tx_complq);
}

/**
 * idpf_get_reg_intr_vecs - Get vector queue register offset
 * @vport: virtual port structure
 * @reg_vals: Register offsets to store in
 *
 * Returns number of regsiters that got populated
 */
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals)
{
	struct virtchnl2_vector_chunks *chunks;
	struct idpf_vec_regs reg_val;
	u16 num_vchunks, num_vec;
	int num_regs = 0, i, j;

	chunks = &vport->adapter->req_vec_chunks->vchunks;
	num_vchunks = le16_to_cpu(chunks->num_vchunks);

	for (j = 0; j < num_vchunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u32 dynctl_reg_spacing;
		u32 itrn_reg_spacing;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		reg_val.dyn_ctl_reg = le32_to_cpu(chunk->dynctl_reg_start);
		reg_val.itrn_reg = le32_to_cpu(chunk->itrn_reg_start);
		reg_val.itrn_index_spacing = le32_to_cpu(chunk->itrn_index_spacing);

		dynctl_reg_spacing = le32_to_cpu(chunk->dynctl_reg_spacing);
		itrn_reg_spacing = le32_to_cpu(chunk->itrn_reg_spacing);

		for (i = 0; i < num_vec; i++) {
			reg_vals[num_regs].dyn_ctl_reg = reg_val.dyn_ctl_reg;
			reg_vals[num_regs].itrn_reg = reg_val.itrn_reg;
			reg_vals[num_regs].itrn_index_spacing =
						reg_val.itrn_index_spacing;

			reg_val.dyn_ctl_reg += dynctl_reg_spacing;
			reg_val.itrn_reg += itrn_reg_spacing;
			num_regs++;
		}
	}

	return num_regs;
}

/**
 * idpf_vport_get_q_reg - Get the queue registers for the vport
 * @reg_vals: register values needing to be set
 * @num_regs: amount we expect to fill
 * @q_type: queue model
 * @chunks: queue regs received over mailbox
 *
 * This function parses the queue register offsets from the queue register
 * chunk information, with a specific queue type and stores it into the array
 * passed as an argument. It returns the actual number of queue registers that
 * are filled.
 */
static int idpf_vport_get_q_reg(u32 *reg_vals, int num_regs, u32 q_type,
				struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	int reg_filled = 0, i;
	u32 reg_val;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;
		u16 num_q;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		reg_val = le64_to_cpu(chunk->qtail_reg_start);
		for (i = 0; i < num_q && reg_filled < num_regs; i++) {
			reg_vals[reg_filled++] = reg_val;
			reg_val += le32_to_cpu(chunk->qtail_reg_spacing);
		}
	}

	return reg_filled;
}

/**
 * __idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 * @q_grp: Queue resources
 * @reg_vals: registers we are initializing
 * @num_regs: how many registers there are in total
 * @q_type: queue model
 */
static void __idpf_queue_reg_init(struct idpf_vport *vport,
				  struct idpf_q_grp *q_grp, u32 *reg_vals,
				  int num_regs, u32 q_type)
{
	struct idpf_adapter *adapter = vport->adapter;
	u16 i, numq;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		numq = q_grp->num_txq;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		numq = q_grp->num_rxq;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		numq = q_grp->num_bufq;
		break;
	default:
		return;
	}

	for (i = 0; i < numq; i++) {
		struct idpf_queue *q;

		switch (q_type) {
		case VIRTCHNL2_QUEUE_TYPE_TX:
			q = q_grp->txqs[i];
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX:
			q = q_grp->rxqs[i];
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			q = &q_grp->bufqs[i];
			break;
		}

		q->tail = idpf_get_reg_addr(adapter, reg_vals[i]);
	}
}

/**
 * idpf_get_queue_reg_chunks - Retrieve queue chunks from vport
 * @vport: Vport with queue chunks
 */
struct virtchnl2_queue_reg_chunks *
idpf_get_queue_reg_chunks(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;

	vport_config = vport->adapter->vport_config[vport->idx];
	if (vport_config->req_qs_chunks)
		return &vport_config->req_qs_chunks->chunks;
	else
		return &vport->adapter->vport_params_recvd[vport->idx]->chunks;
}

/**
 * idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 * @q_grp: Queue resources
 * @chunks: Queue register info
 *
 * Return 0 on success, negative on failure
 */
int idpf_queue_reg_init(struct idpf_vport *vport, struct idpf_q_grp *q_grp,
			struct virtchnl2_queue_reg_chunks *chunks)
{
	int num_regs, err = 0;
	u32 *reg_vals;

	/* We may never deal with more than 256 same type of queues */
	reg_vals = kzalloc(sizeof(*reg_vals) * IDPF_LARGE_MAX_Q, GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	/* Initialize Tx queue tail register address */
	num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
					VIRTCHNL2_QUEUE_TYPE_TX, chunks);
	if (num_regs < q_grp->num_txq) {
		err = -EINVAL;
		goto free_reg_vals;
	}

	__idpf_queue_reg_init(vport, q_grp, reg_vals, num_regs,
			      VIRTCHNL2_QUEUE_TYPE_TX);
	/* Initialize Rx/buffer queue tail register address based on Rx queue
	 * model
	 */
	if (idpf_is_queue_model_split(q_grp->rxq_model)) {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX_BUFFER,
						chunks);
		if (num_regs < q_grp->num_bufq) {
			err = -EINVAL;
			goto free_reg_vals;
		}

		__idpf_queue_reg_init(vport, q_grp, reg_vals, num_regs,
				      VIRTCHNL2_QUEUE_TYPE_RX_BUFFER);
	} else {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX,
						chunks);
		if (num_regs < q_grp->num_rxq) {
			err = -EINVAL;
			goto free_reg_vals;
		}

		__idpf_queue_reg_init(vport, q_grp, reg_vals, num_regs,
				      VIRTCHNL2_QUEUE_TYPE_RX);
	}

free_reg_vals:
	kfree(reg_vals);

	return err;
}

/**
 * idpf_send_get_edt_caps - Send virtchnl get EDT capability message
 * @adapter: Driver specific private structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_send_get_edt_caps(struct idpf_adapter *adapter)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_edt_caps caps = { };
	ssize_t reply_sz;
	int err;

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_EDT))
		return 0;

	xn_params.vc_op = VIRTCHNL2_OP_GET_EDT_CAPS;
	xn_params.send_buf.iov_base = &caps;
	xn_params.send_buf.iov_len = sizeof(caps);
	xn_params.recv_buf.iov_base = &adapter->edt_caps;
	xn_params.recv_buf.iov_len = sizeof(adapter->edt_caps);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto edt_caps_err;
	}
	if (reply_sz < sizeof(struct virtchnl2_edt_caps)) {
		err = -EIO;
		goto edt_caps_err;
	}

	return 0;

edt_caps_err:
	dev_err(&adapter->pdev->dev, "Failed to receive get EDT capabilities message\n");
	dev_err(&adapter->pdev->dev, "Disabling EDT capabilities\n");
	adapter->edt_caps.tstamp_granularity_ns = 0;
	adapter->edt_caps.time_horizon_ns = 0;
	adapter->caps.other_caps &= cpu_to_le64(~VIRTCHNL2_CAP_EDT);

	return err;
}

/**
 * idpf_send_create_vport_msg - Send virtchnl create vport message
 * @adapter: Driver specific private structure
 * @max_q: vport max queue info
 *
 * send virtchnl creae vport message
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vc_xn_params xn_params = { };
	u16 idx = adapter->next_vport;
	int err, buf_size;
	ssize_t reply_sz;

	buf_size = sizeof(struct virtchnl2_create_vport);
	if (!adapter->vport_params_reqd[idx]) {
		adapter->vport_params_reqd[idx] = kzalloc(buf_size,
							  GFP_KERNEL);
		if (!adapter->vport_params_reqd[idx])
			return -ENOMEM;
	}

	vport_msg = adapter->vport_params_reqd[idx];
	vport_msg->vport_type = cpu_to_le16(VIRTCHNL2_VPORT_TYPE_DEFAULT);
	vport_msg->vport_index = cpu_to_le16(idx);

	if (adapter->req_tx_splitq)
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	if (adapter->req_rx_splitq)
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	idpf_vport_calc_total_qs(adapter, idx, vport_msg, max_q);

	if (!adapter->vport_params_recvd[idx]) {
		adapter->vport_params_recvd[idx] = kzalloc(IDPF_CTLQ_MAX_BUF_LEN,
							   GFP_KERNEL);
		if (!adapter->vport_params_recvd[idx]) {
			err = -ENOMEM;
			goto create_vport_fail_rel_reqd_params;
		}
	}

	xn_params.vc_op = VIRTCHNL2_OP_CREATE_VPORT;
	xn_params.send_buf.iov_base = vport_msg;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.recv_buf.iov_base = adapter->vport_params_recvd[idx];
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto create_vport_fail_rel_recv_params;
	}

	return 0;

create_vport_fail_rel_recv_params:
	kfree(adapter->vport_params_recvd[idx]);
	adapter->vport_params_recvd[idx] = NULL;
create_vport_fail_rel_reqd_params:
	kfree(adapter->vport_params_reqd[idx]);
	adapter->vport_params_reqd[idx] = NULL;
	return err;
}

/**
 * idpf_check_supported_desc_ids - Verify we have required descriptor support
 * @vport: virtual port structure
 *
 * Return 0 on success, error on failure
 */
int idpf_check_supported_desc_ids(struct idpf_vport *vport)
{
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	u64 rx_desc_ids, tx_desc_ids;

	vport_msg = (struct virtchnl2_create_vport *)
				adapter->vport_params_recvd[vport->idx];

	rx_desc_ids = le64_to_cpu(vport_msg->rx_desc_ids);
	tx_desc_ids = le64_to_cpu(vport_msg->tx_desc_ids);

	if (q_grp->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M)) {
			dev_info(idpf_adapter_to_dev(adapter), "Minimum RX descriptor support not provided, using the default\n");
			vport_msg->rx_desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
		}
	} else {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M))
			q_grp->base_rxd = true;
	}

	if (q_grp->txq_model != VIRTCHNL2_QUEUE_MODEL_SPLIT)
		return 0;

	if ((tx_desc_ids & MIN_SUPPORT_TXDID) != MIN_SUPPORT_TXDID) {
		dev_info(idpf_adapter_to_dev(adapter), "Minimum TX descriptor support not provided, using the default\n");
		vport_msg->tx_desc_ids = cpu_to_le64(MIN_SUPPORT_TXDID);
	}
	return 0;
}

/**
 * idpf_send_destroy_vport_msg - Send virtchnl destroy vport message
 * @vport: virtual port data structure
 *
 * Send virtchnl destroy vport message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_destroy_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_DESTROY_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_enable_vport_msg - Send virtchnl enable vport message
 * @vport: virtual port data structure
 *
 * Send enable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_ENABLE_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_disable_vport_msg - Send virtchnl disable vport message
 * @vport: virtual port data structure
 *
 * Send disable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_disable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_DISABLE_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * __idpf_set_txq_info - Helper for populating TX queue config data
 * @q: Queue to populate from, could be a txq or complq
 * @qi: Queue info struct to fill
 * @txq_model: TX queue model
 */
static void __idpf_set_txq_info(struct idpf_queue *q,
				struct virtchnl2_txq_info *qi,
				u16 txq_model)
{
	bool is_splitq = idpf_is_queue_model_split(txq_model);

	qi->queue_id = cpu_to_le32(q->q_id);
	qi->model = cpu_to_le16(txq_model);
	qi->type = cpu_to_le32(q->q_type);
	qi->ring_len = cpu_to_le16(q->desc_count);
	qi->dma_ring_addr = cpu_to_le64(q->dma);
	qi->sched_mode = test_bit(__IDPF_Q_FLOW_SCH_EN, q->flags) && is_splitq ?
			 cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_FLOW) :
			 cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);
}

/**
 * idpf_set_txq_info - Populate a TX queue info struct with queue data
 * @txq: TX queue to populate from
 * @qi: Queue info struct to fill
 * @txq_model: TX queue model
 */
static void idpf_set_txq_info(struct idpf_queue *txq,
			      struct virtchnl2_txq_info *qi,
			      u16 txq_model)
{
	__idpf_set_txq_info(txq, qi, txq_model);

	if (!idpf_is_queue_model_split(txq_model))
		return;

	qi->tx_compl_queue_id = cpu_to_le16(txq->tx.complq->q_id);
	qi->relative_queue_id = cpu_to_le16(txq->tx.rel_qid);
}

/**
 * idpf_p2p_copy_peer_q_info - Copy necessary peer queue info
 * @q: TX or completion queue to copy the info to
 * @peer_q: RX or buffer queue to copy the info from
 * @qi: Queue info struct to fill
 */
static void idpf_p2p_copy_peer_q_info(struct idpf_queue *q,
				      struct idpf_queue *peer_q,
				      struct virtchnl2_txq_info *qi)
{
	q->desc_count = peer_q->desc_count;
	q->dma = peer_q->dma;
	qi->peer_rx_queue_id = cpu_to_le16(peer_q->q_id);
}

/**
 * idpf_send_config_tx_queues_msg - Send virtchnl config tx queues message
 * @vport: virtual port data structure
 * @q_grp: Queue resources
 *
 * Send config tx queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_tx_queues_msg(struct idpf_vport *vport,
					  struct idpf_q_grp *q_grp)
{
	struct virtchnl2_txq_info *qi, *qi_start;
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_config_tx_queues *ctq;
	u16 txq_model = q_grp->txq_model;
	u32 config_sz, chunk_sz, buf_sz;
	int totqs, num_msgs, num_chunks;
	ssize_t reply_sz;
	int i, err = 0;

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	totqs = q_grp->num_txq + q_grp->num_complq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_txq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* We're doing pointer arithmetic so save beginning */
	qi_start = qi;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < q_grp->num_txq; i++, qi++) {
		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			idpf_p2p_copy_peer_q_info(q_grp->txqs[i], q_grp->rxqs[i],
						  qi);
		idpf_set_txq_info(q_grp->txqs[i], qi, txq_model);
	}

	if (idpf_is_queue_model_split(txq_model)) {
		for (i = 0; i < q_grp->num_complq; i++, qi++) {
			qi->qflags |= cpu_to_le16(VIRTCHNL2_TXQ_ENABLE_MISS_COMPL);
			if (q_grp->type == IDPF_GRP_TYPE_P2P) {
				idpf_p2p_copy_peer_q_info(&q_grp->complqs[i],
							  &q_grp->bufqs[i], qi);
				qi->qflags &= cpu_to_le16(~VIRTCHNL2_TXQ_ENABLE_MISS_COMPL);
			}
			__idpf_set_txq_info(&q_grp->complqs[i], qi, txq_model);
		}
	}

	qi = qi_start;

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_sz = sizeof(struct virtchnl2_config_tx_queues);
	chunk_sz = sizeof(struct virtchnl2_txq_info);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   totqs);
	num_msgs = DIV_ROUND_UP(totqs, num_chunks);

	buf_sz = struct_size(ctq, qinfo, num_chunks);
	ctq = kcalloc(buf_sz, sizeof(u8), GFP_KERNEL);
	if (!ctq) {
		err = -ENOMEM;
		goto error;
	}

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	for (i = 0; i < num_msgs; i++) {
		memset(ctq, 0, buf_sz);
		ctq->vport_id = cpu_to_le32(vport->vport_id);
		ctq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(ctq->qinfo, qi, chunk_sz * num_chunks);

		xn_params.send_buf.iov_base = ctq;
		xn_params.send_buf.iov_len = buf_sz;
		reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
		if (reply_sz < 0) {
			err = reply_sz;
			goto mbx_error;
		}

		qi += num_chunks;
		totqs -= num_chunks;
		num_chunks = min(num_chunks, totqs);
		/* Recalculate buffer size */
		buf_sz = struct_size(ctq, qinfo, num_chunks);
	}

mbx_error:
	kfree(ctq);
error:
	kfree(qi_start);

	return err;
}

/**
 * __idpf_set_rxq_info - Helper to commonize parts of filling out queue info
 * @q: Queue to fill from
 * @qi: Queue info structure to fill
 * @rxq_model: RX queue model
 */
static void __idpf_set_rxq_info(struct idpf_queue *q,
				struct virtchnl2_rxq_info *qi,
				u16 rxq_model)
{
	qi->queue_id = cpu_to_le32(q->q_id);
	qi->model = cpu_to_le16(rxq_model);
	qi->type = cpu_to_le32(q->q_type);
	qi->ring_len = cpu_to_le16(q->desc_count);
	qi->dma_ring_addr = cpu_to_le64(q->dma);
	qi->max_pkt_size = cpu_to_le32(q->rx_max_pkt_size);
	qi->data_buffer_size = cpu_to_le32(q->rx_buf_size);

	if (q->rx_hsplit_en) {
		qi->qflags |= cpu_to_le16(VIRTCHNL2_RXQ_HDR_SPLIT);
		qi->hdr_buffer_size = cpu_to_le16(q->rx_hbuf_size);
	}

	if (!idpf_is_queue_model_split(rxq_model))
		return;

	qi->rx_buffer_low_watermark = cpu_to_le16(q->rx_buffer_low_watermark);
#ifdef NETIF_F_GRO_HW
	if (idpf_is_feature_ena(q->vport, NETIF_F_GRO_HW))
		qi->qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);
#endif /* NETIF_F_GRO_HW */
}

/**
 * idpf_set_rxq_info - Fill RX queue info
 * @rxq: RX queue to get the info from
 * @qi: RX queue info structure to fill
 * @bufq_per_rxq: Number of buffer queues per RX queue
 * @rxq_model: RX queue model
 */
static void idpf_set_rxq_info(struct idpf_queue *rxq,
			      struct virtchnl2_rxq_info *qi,
			      u16 bufq_per_rxq, u16 rxq_model)
{
	__idpf_set_rxq_info(rxq, qi, rxq_model);

	qi->qflags |= cpu_to_le16(VIRTCHNL2_RX_DESC_SIZE_32BYTE);
	qi->desc_ids = cpu_to_le64(rxq->rxdids);

	if (!idpf_is_queue_model_split(rxq_model))
		return;

	qi->rx_bufq1_id = cpu_to_le16(rxq->rx.bufq_qids[0]);
	if (bufq_per_rxq > IDPF_SINGLE_BUFQ_PER_RXQ) {
		qi->bufq2_ena = true;
		qi->rx_bufq2_id = cpu_to_le16(rxq->rx.bufq_qids[1]);
	}
}

/**
 * idpf_set_bufq_info - Fill buffer queue info
 * @bufq: Buffer queue to get the info from
 * @qi: RX queue info structure to fill
 * @rxq_model: RX queue model
 */
static void idpf_set_bufq_info(struct idpf_queue *bufq,
			       struct virtchnl2_rxq_info *qi,
			       u16 rxq_model)
{
	__idpf_set_rxq_info(bufq, qi, rxq_model);

	qi->desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
	qi->buffer_notif_stride = bufq->rx_buf_stride;
}

/**
 * idpf_p2p_reset_hdr_split_rsc - Reset header split and RSC queue config info
 * @qi: Structure representing RX queue info
 */
static void idpf_p2p_reset_hdr_split_rsc(struct virtchnl2_rxq_info *qi)
{
	/* P2P doesn't support header split and RSC, so reset those fields */
	qi->qflags &= cpu_to_le16(~VIRTCHNL2_RXQ_HDR_SPLIT);
	qi->qflags &= cpu_to_le16(~VIRTCHNL2_RXQ_RSC);
	qi->hdr_buffer_size = 0;
}

/**
 * idpf_send_config_rx_queues_msg - Send virtchnl config rx queues message
 * @vport: virtual port data structure
 * @q_grp: Queue resources
 *
 * Send config rx queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_rx_queues_msg(struct idpf_vport *vport,
					  struct idpf_q_grp *q_grp)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_rxq_info *qi, *qi_start;
	struct virtchnl2_config_rx_queues *crq;
	u16 rxq_model = q_grp->rxq_model;
	u32 config_sz, chunk_sz, buf_sz;
	int totqs, num_msgs, num_chunks;
	int err = 0, i, k = 0;
	ssize_t reply_sz;

	totqs = q_grp->num_rxq + q_grp->num_bufq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_rxq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* We're going to use pointer arithmetic on qi so save the start */
	qi_start = qi;

	/* Buffer queues *MUST* come before RX queues because HW uses RX queues
	 * to know the buffer size
	 */
	for (i = 0; i < q_grp->num_bufq; i++, qi++) {
		idpf_set_bufq_info(&q_grp->bufqs[i], qi, rxq_model);
		if (q_grp->type == IDPF_GRP_TYPE_P2P)
			idpf_p2p_reset_hdr_split_rsc(qi);
	}

	for (i = 0; i < q_grp->num_rxq; i++, qi++) {
		idpf_set_rxq_info(q_grp->rxqs[i], qi, q_grp->bufq_per_rxq,
				  rxq_model);
		if (q_grp->type == IDPF_GRP_TYPE_P2P) {
			idpf_p2p_reset_hdr_split_rsc(qi);
			qi->qflags &= cpu_to_le16(~VIRTCHNL2_RX_DESC_SIZE_32BYTE);
			qi->qflags |= cpu_to_le16(VIRTCHNL2_RX_DESC_SIZE_16BYTE);
		}
	}

	qi = qi_start;

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_sz = sizeof(struct virtchnl2_config_rx_queues);
	chunk_sz = sizeof(struct virtchnl2_rxq_info);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   totqs);
	num_msgs = DIV_ROUND_UP(totqs, num_chunks);

	buf_sz = struct_size(crq, qinfo, num_chunks);
	crq = kcalloc(buf_sz, sizeof(u8), GFP_KERNEL);
	if (!crq) {
		err = -ENOMEM;
		goto error;
	}

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	for (i = 0, k = 0; i < num_msgs; i++) {
		memset(crq, 0, buf_sz);
		crq->vport_id = cpu_to_le32(vport->vport_id);
		crq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(crq->qinfo, &qi[k], chunk_sz * num_chunks);

		xn_params.send_buf.iov_base = crq;
		xn_params.send_buf.iov_len = buf_sz;
		reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
		if (reply_sz < 0) {
			err = reply_sz;
			goto mbx_error;
		}

		k += num_chunks;
		totqs -= num_chunks;
		num_chunks = min(num_chunks, totqs);
		/* Recalculate buffer size */
		buf_sz = struct_size(crq, qinfo, num_chunks);
	}

mbx_error:
	kfree(crq);
error:
	kfree(qi);
	return err;
}

/**
 * idpf_convert_reg_to_queue_chunks - Copy queue chunk information to the right
 *				      structure
 * @dchunks: Destination chunks to store data to
 * @schunks: Source chunks to copy data from
 * @num_chunks: Number of chunks to copy
 */
static void
idpf_convert_reg_to_queue_chunks(struct virtchnl2_queue_chunk *dchunks,
				 struct virtchnl2_queue_reg_chunk *schunks,
				 u16 num_chunks)
{
	u16 i;

	for (i = 0; i < num_chunks; i++) {
		dchunks[i].type = schunks[i].type;
		dchunks[i].start_queue_id = schunks[i].start_queue_id;
		dchunks[i].num_queues = schunks[i].num_queues;
	}
}

/**
 * idpf_send_ena_dis_queues_msg - Send virtchnl enable or disable
 * queues message
 * @vport: virtual port data structure
 * @chunks: Queue register info
 * @ena: if true enable, false disable
 *
 * Send enable or disable queues virtchnl message. Returns 0 on success,
 * negative on failure.
 */
static int idpf_send_ena_dis_queues_msg(struct idpf_vport *vport,
					struct virtchnl2_queue_reg_chunks *chunks,
					bool ena)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_del_ena_dis_queues *eq;
	u32 num_chunks, buf_sz;
	ssize_t reply_sz;

	if (ena) {
		xn_params.vc_op = VIRTCHNL2_OP_ENABLE_QUEUES;
		xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	} else {
		xn_params.vc_op = VIRTCHNL2_OP_DISABLE_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	}

	num_chunks = le16_to_cpu(chunks->num_chunks);
	buf_sz = struct_size(eq, chunks.chunks, num_chunks);
	eq = kcalloc(num_chunks, buf_sz, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	idpf_convert_reg_to_queue_chunks(eq->chunks.chunks, chunks->chunks,
					 num_chunks);

	xn_params.send_buf.iov_base = eq;
	xn_params.send_buf.iov_len = buf_sz;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	kfree(eq);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_map_unmap_queue_vector_msg - Send virtchnl map or unmap queue
 * vector message
 * @vport: virtual port data structure
 * @vgrp: Queue and interrupt resource group
 * @map: true for map and false for unmap
 *
 * Send map or unmap queue vector virtchnl message.  Returns 0 on success,
 * negative on failure.
 */
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport,
					 struct idpf_vgrp *vgrp,
					 bool map)
{
	struct virtchnl2_queue_vector *vqv, *vqv_start;
	struct virtchnl2_queue_vector_maps *vqvm;
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	u32 config_sz, chunk_sz, buf_sz;
	u32 num_msgs, num_chunks, num_q;
	ssize_t reply_sz;
	int i, err = 0;

	num_q = q_grp->num_txq + q_grp->num_rxq;

	buf_sz = sizeof(*vqv) * num_q;
	vqv = kzalloc(buf_sz, GFP_KERNEL);
	if (!vqv)
		return -ENOMEM;
	/* We're going to do pointer arithmetic so save off start */
	vqv_start = vqv;

	for (i = 0; i < q_grp->num_txq; i++, vqv++) {
		struct idpf_queue *txq = q_grp->txqs[i];
		struct idpf_q_vector *vec;

		vec = idpf_is_queue_model_split(q_grp->txq_model) ?
			txq->tx.complq->q_vector :
			txq->q_vector;

		vqv->queue_type = cpu_to_le32(txq->q_type);
		vqv->queue_id = cpu_to_le32(txq->q_id);
		vqv->vector_id = cpu_to_le16(vec->v_idx);
		vqv->itr_idx = cpu_to_le32(vec->tx_itr_idx);
	}

	for (i = 0; i < q_grp->num_rxq; i++, vqv++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];

		vqv->queue_type = cpu_to_le32(rxq->q_type);
		vqv->queue_id = cpu_to_le32(rxq->q_id);
		vqv->vector_id = cpu_to_le16(rxq->q_vector->v_idx);
		vqv->itr_idx = cpu_to_le32(rxq->q_vector->rx_itr_idx);
	}

	vqv = vqv_start;

	/* Chunk up the vector info into multiple messages */
	config_sz = sizeof(struct virtchnl2_queue_vector_maps);
	chunk_sz = sizeof(struct virtchnl2_queue_vector);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   num_q);
	num_msgs = DIV_ROUND_UP(num_q, num_chunks);

	buf_sz = struct_size(vqvm, qv_maps, num_chunks);
	vqvm = kcalloc(buf_sz, sizeof(u8), GFP_KERNEL);
	if (!vqvm) {
		err = -ENOMEM;
		goto error;
	}

	if (map) {
		xn_params.vc_op = VIRTCHNL2_OP_MAP_QUEUE_VECTOR;
		xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	} else {
		xn_params.vc_op = VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR;
		xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	}

	for (i = 0; i < num_msgs; i++) {
		memset(vqvm, 0, buf_sz);
		xn_params.send_buf.iov_base = vqvm;
		xn_params.send_buf.iov_len = buf_sz;
		vqvm->vport_id = cpu_to_le32(vport->vport_id);
		vqvm->num_qv_maps = cpu_to_le16(num_chunks);
		memcpy(vqvm->qv_maps, vqv, chunk_sz * num_chunks);

		reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
		if (reply_sz < 0) {
			err = reply_sz;
			goto mbx_error;
		}

		vqv += num_chunks;
		num_q -= num_chunks;
		num_chunks = min(num_chunks, num_q);
		/* Recalculate buffer size */
		buf_sz = struct_size(vqvm, qv_maps, num_chunks);
	}

mbx_error:
	kfree(vqvm);
error:
	kfree(vqv_start);
	return err;
}

/**
 * idpf_send_enable_queues_msg - send enable queues virtchnl message
 * @vport: Virtual port private data structure
 * @chunks: Queue register info
 *
 * Will send enable queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_queues_msg(struct idpf_vport *vport,
				struct virtchnl2_queue_reg_chunks *chunks)
{
	return idpf_send_ena_dis_queues_msg(vport, chunks, true);
}

/**
 * idpf_send_disable_queues_msg - send disable queues virtchnl message
 * @vport: Virtual port private data structure
 * @vgrp: Queue and interrupt resource group
 * @chunks: Queue register info
 *
 * Will send disable queues virtchnl message.  Returns 0 on success, negative
 * on failure.
 */
int idpf_send_disable_queues_msg(struct idpf_vport *vport,
				 struct idpf_vgrp *vgrp,
				 struct virtchnl2_queue_reg_chunks *chunks)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	int err, i;

	err = idpf_send_ena_dis_queues_msg(vport, chunks, false);
	if (err)
		return err;

	if (vgrp->type == IDPF_GRP_TYPE_P2P)
		return 0;

	/* switch to poll mode as interrupts will be disabled after disable
	 * queues virtchnl message is sent
	 */
	for (i = 0; i < q_grp->num_txq; i++)
		set_bit(__IDPF_Q_POLL_MODE, q_grp->txqs[i]->flags);

	/* schedule the napi to receive all the marker packets */
	local_bh_disable();
	for (i = 0; i < intr_grp->num_q_vectors; i++)
		napi_schedule(&intr_grp->q_vectors[i].napi);
	local_bh_enable();

	return idpf_wait_for_marker_event(vport, q_grp);
}

/**
 * idpf_send_delete_queues_msg - send delete queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send delete queues virtchnl message. Return 0 on success, negative on
 * failure.
 */
int idpf_send_delete_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_del_ena_dis_queues *eq;
	ssize_t reply_sz;
	u16 num_chunks;
	int buf_size;

	chunks = idpf_get_queue_reg_chunks(vport);

	num_chunks = le16_to_cpu(chunks->num_chunks);
	buf_size = struct_size(eq, chunks.chunks, num_chunks);
	eq = kzalloc(buf_size, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	idpf_convert_reg_to_queue_chunks(eq->chunks.chunks, chunks->chunks,
					 num_chunks);
	xn_params.vc_op = VIRTCHNL2_OP_DEL_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = eq;
	xn_params.send_buf.iov_len = buf_size;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);

	kfree(eq);
	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_config_queues_msg - Send config queues virtchnl message
 * @vport: Virtual port private data structure
 * @q_grp: Queue resources
 *
 * Will send config queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_queues_msg(struct idpf_vport *vport,
				struct idpf_q_grp *q_grp)
{
	int err;

	err = idpf_send_config_tx_queues_msg(vport, q_grp);
	if (err)
		return err;

	return idpf_send_config_rx_queues_msg(vport, q_grp);
}

/**
 * idpf_send_del_queue_grp_msg - Send virtchnl delete queue group message
 * @vport: Virtual port private data structure
 * @aqg: Buffer used to store data received on mailbox
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_del_queue_grp_msg(const struct idpf_vport *vport,
				struct virtchnl2_add_queue_groups *aqg)
{
	struct virtchnl2_queue_group_info *qg_info;
	struct virtchnl2_delete_queue_groups *dqg;
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;
	int err = 0;
	u32 size;

	size = struct_size_t(struct virtchnl2_delete_queue_groups, qg_ids, 1);
	dqg = kzalloc(size, GFP_KERNEL);
	if (!dqg)
		return -ENOMEM;

	qg_info = idpf_get_queue_group_info(aqg);

	dqg->vport_id = cpu_to_le32(vport->vport_id);
	dqg->num_queue_groups = cpu_to_le16(1);
	dqg->qg_ids[0].queue_group_id = qg_info->qg_id.queue_group_id;
	dqg->qg_ids[0].queue_group_type =
				 cpu_to_le16(VIRTCHNL2_QUEUE_GROUP_P2P);

	xn_params.vc_op = VIRTCHNL2_OP_DEL_QUEUE_GROUPS;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = dqg;
	xn_params.send_buf.iov_len = size;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0)
		err = reply_sz;

	kfree(dqg);
	return err;
}

/**
 * idpf_send_add_queue_grp_msg - Send virtchnl add queue group message
 * @vport: Virtual port private data structure
 * @num_tx_q: Number of transmit queues
 * @num_complq: Number of transmit completion queues
 * @num_rx_q: Number of receive queues
 * @num_bufq: Number of receive buffer queues
 * @req_chunks: Buffer to store data received on mailbox
 * @qgrp_id: Queue group id
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_add_queue_grp_msg(const struct idpf_vport *vport, u16 num_tx_q,
				u16 num_complq, u16 num_rx_q, u16 num_bufq,
				struct virtchnl2_add_queue_groups *req_chunks,
				int qgrp_id)
{
	struct virtchnl2_queue_group_info *qg_info;
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_add_queue_groups *aqg;
	ssize_t reply_sz;
	int err = 0;

	aqg = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!aqg)
		return -ENOMEM;

	qg_info = idpf_get_queue_group_info(aqg);

	aqg->vport_id = cpu_to_le32(vport->vport_id);
	aqg->num_queue_groups = cpu_to_le16(1);
	qg_info->qg_id.queue_group_id = cpu_to_le16(qgrp_id);
	qg_info->qg_id.queue_group_type = cpu_to_le16(VIRTCHNL2_QUEUE_GROUP_P2P);
	qg_info->num_tx_q = cpu_to_le16(num_tx_q);
	qg_info->num_tx_complq = cpu_to_le16(num_complq);
	qg_info->num_rx_q = cpu_to_le16(num_rx_q);
	qg_info->num_rx_bufq = cpu_to_le16(num_bufq);

	xn_params.vc_op = VIRTCHNL2_OP_ADD_QUEUE_GROUPS;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = aqg;
	xn_params.send_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.recv_buf.iov_base = req_chunks;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0)
		err = reply_sz;

	kfree(aqg);
	return err;
}

/**
 * idpf_send_add_queues_msg - Send virtchnl add queues message
 * @vport: Virtual port private data structure
 * @num_tx_q: number of transmit queues
 * @num_complq: number of transmit completion queues
 * @num_rx_q: number of receive queues
 * @num_rx_bufq: number of receive buffer queues
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_add_queues_msg(struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq)
{
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_vport_config *vport_config;
	struct virtchnl2_add_queues aq = { };
	struct virtchnl2_add_queues *vc_msg;
	int size, err = 0;
	ssize_t reply_sz;

	vc_msg = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!vc_msg)
		return -ENOMEM;

	vport_config = vport->adapter->vport_config[vport->idx];
	kfree(vport_config->req_qs_chunks);
	vport_config->req_qs_chunks = NULL;

	aq.vport_id = cpu_to_le32(vport->vport_id);
	aq.num_tx_q = cpu_to_le16(num_tx_q);
	aq.num_tx_complq = cpu_to_le16(num_complq);
	aq.num_rx_q = cpu_to_le16(num_rx_q);
	aq.num_rx_bufq = cpu_to_le16(num_rx_bufq);

	xn_params.vc_op = VIRTCHNL2_OP_ADD_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &aq;
	xn_params.send_buf.iov_len = sizeof(aq);
	xn_params.recv_buf.iov_base = vc_msg;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto error;
	}

	/* compare vc_msg num queues with vport num queues */
	if (le16_to_cpu(vc_msg->num_tx_q) != num_tx_q ||
	    le16_to_cpu(vc_msg->num_rx_q) != num_rx_q ||
	    le16_to_cpu(vc_msg->num_tx_complq) != num_complq ||
	    le16_to_cpu(vc_msg->num_rx_bufq) != num_rx_bufq) {
		err = -EINVAL;
		goto error;
	}

	size = struct_size(vc_msg, chunks.chunks,
			   le16_to_cpu(vc_msg->chunks.num_chunks));
	if (reply_sz < size) {
		err = -EIO;
		goto error;
	}
	vport_config->req_qs_chunks = kzalloc(size, GFP_KERNEL);
	if (!vport_config->req_qs_chunks) {
		err = -ENOMEM;
		goto error;
	}
	memcpy(vport_config->req_qs_chunks, vc_msg, size);

error:
	kfree(vc_msg);
	return err;
}

/**
 * idpf_send_alloc_vectors_msg - Send virtchnl alloc vectors message
 * @adapter: Driver specific private structure
 * @num_vectors: number of vectors to be allocated
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors)
{
	struct virtchnl2_alloc_vectors *alloc_vec, *rcvd_vec;
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_alloc_vectors ac = { };
	int size, err = 0;
	ssize_t reply_sz;
	u16 num_vchunks;

	ac.num_vectors = cpu_to_le16(num_vectors);

	rcvd_vec = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!rcvd_vec)
		return -ENOMEM;

	xn_params.vc_op = VIRTCHNL2_OP_ALLOC_VECTORS;
	xn_params.send_buf.iov_base = &ac;
	xn_params.send_buf.iov_len = sizeof(ac);
	xn_params.recv_buf.iov_base = rcvd_vec;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto alloc_vectors_fail;
	}
	num_vchunks = le16_to_cpu(rcvd_vec->vchunks.num_vchunks);
	size = struct_size(rcvd_vec, vchunks.vchunks, num_vchunks);
	if (reply_sz < size) {
		err = -EIO;
		goto alloc_vectors_fail;
	}

	if (size > IDPF_CTLQ_MAX_BUF_LEN) {
		err = -EINVAL;
		goto alloc_vectors_fail;
	}

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;
	adapter->req_vec_chunks = kzalloc(size, GFP_KERNEL);
	if (!adapter->req_vec_chunks) {
		err = -ENOMEM;
		goto alloc_vectors_fail;
	}
	memcpy(adapter->req_vec_chunks, rcvd_vec, size);

	alloc_vec = adapter->req_vec_chunks;
	if (le16_to_cpu(alloc_vec->num_vectors) < num_vectors) {
		kfree(adapter->req_vec_chunks);
		adapter->req_vec_chunks = NULL;
		err = -EINVAL;
	}

alloc_vectors_fail:
	kfree(rcvd_vec);
	return err;
}

/**
 * idpf_send_dealloc_vectors_msg - Send virtchnl de allocate vectors message
 * @adapter: Driver specific private structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_alloc_vectors *ac = adapter->req_vec_chunks;
	struct virtchnl2_vector_chunks *vcs = &ac->vchunks;
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;
	int buf_size;

	buf_size = struct_size(vcs, vchunks, le16_to_cpu(vcs->num_vchunks));

	xn_params.vc_op = VIRTCHNL2_OP_DEALLOC_VECTORS;
	xn_params.send_buf.iov_base = vcs;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;

	return 0;
}

/**
 * idpf_get_max_vfs - Get max number of vfs supported
 * @adapter: Driver specific private structure
 *
 * Returns max number of VFs
 */
static int idpf_get_max_vfs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_sriov_vfs);
}

/**
 * idpf_send_set_sriov_vfs_msg - Send virtchnl set sriov vfs message
 * @adapter: Driver specific private structure
 * @num_vfs: number of virtual functions to be created
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs)
{
	struct virtchnl2_sriov_vfs_info svi = { };
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;

	svi.num_vfs = cpu_to_le16(num_vfs);
	xn_params.vc_op = VIRTCHNL2_OP_SET_SRIOV_VFS;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &svi;
	xn_params.send_buf.iov_len = sizeof(svi);
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_get_stats_msg - Send virtchnl get statistics message
 * @vport: vport to get stats for
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_stats_msg(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct rtnl_link_stats64 *netstats = &np->netstats;
	struct virtchnl2_vport_stats stats_msg = { };
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_vport_stats *stats;
	ssize_t reply_sz;

	if (!np->active)
		return 0;

	stats_msg.vport_id = cpu_to_le32(np->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_GET_STATS;
	xn_params.send_buf.iov_base = (u8 *)&stats_msg;
	xn_params.send_buf.iov_len = sizeof(stats_msg);
	xn_params.recv_buf = xn_params.send_buf;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(np->adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(stats_msg))
		return -EIO;

	spin_lock_bh(&np->stats_lock);

	stats = &stats_msg;
	netstats->rx_packets = le64_to_cpu(stats->rx_unicast) +
			       le64_to_cpu(stats->rx_multicast) +
			       le64_to_cpu(stats->rx_broadcast);
	netstats->rx_bytes = le64_to_cpu(stats->rx_bytes);
	netstats->rx_dropped = le64_to_cpu(stats->rx_discards);
	netstats->rx_over_errors = le64_to_cpu(stats->rx_overflow_drop);
	netstats->rx_length_errors = le64_to_cpu(stats->rx_invalid_frame_length);

	netstats->tx_packets = le64_to_cpu(stats->tx_unicast) +
			       le64_to_cpu(stats->tx_multicast) +
			       le64_to_cpu(stats->tx_broadcast);
	netstats->tx_bytes = le64_to_cpu(stats->tx_bytes);
	netstats->tx_errors = le64_to_cpu(stats->tx_errors);
	netstats->tx_dropped = le64_to_cpu(stats->tx_discards);

	vport->port_stats.vport_stats = stats_msg;

	spin_unlock_bh(&np->stats_lock);

	return 0;
}

/**
 * idpf_send_get_port_stats_msg - Send get physical port representor stats msg
 * @vport: vport to get stats for
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_port_stats_msg(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct rtnl_link_stats64 *netstats = &np->netstats;
	struct virtchnl2_port_stats stats_msg = { };
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_vport_stats *stats;
	int reply_sz;

	stats_msg.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_GET_PORT_STATS;
	xn_params.send_buf.iov_base = (u8 *)&stats_msg;
	xn_params.send_buf.iov_len = sizeof(stats_msg);
	xn_params.recv_buf = xn_params.send_buf;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(stats_msg))
		return -EIO;

	spin_lock_bh(&np->stats_lock);
	stats = &stats_msg.virt_port_stats;
	netstats->rx_packets = le64_to_cpu(stats->rx_unicast) +
			       le64_to_cpu(stats->rx_multicast) +
			       le64_to_cpu(stats->rx_broadcast);
	netstats->rx_bytes = le64_to_cpu(stats->rx_bytes);
	netstats->rx_dropped = le64_to_cpu(stats->rx_discards);
	netstats->rx_over_errors = le64_to_cpu(stats->rx_overflow_drop);
	netstats->rx_length_errors = le64_to_cpu(stats->rx_invalid_frame_length);

	netstats->tx_packets = le64_to_cpu(stats->tx_unicast) +
			       le64_to_cpu(stats->tx_multicast) +
			       le64_to_cpu(stats->tx_broadcast);
	netstats->tx_bytes = le64_to_cpu(stats->tx_bytes);
	netstats->tx_errors = le64_to_cpu(stats->tx_errors);
	netstats->tx_dropped = le64_to_cpu(stats->tx_discards);

	vport->port_stats.vport_stats = stats_msg.virt_port_stats;

	memcpy(vport->port_stats.phy_port_stats, &stats_msg.phy_port_stats,
	       sizeof(*vport->port_stats.phy_port_stats));

	spin_unlock_bh(&np->stats_lock);

	return 0;
}

/**
 * idpf_send_get_set_rss_hash_msg - Send set or get rss hash message
 * @vport: virtual port data structure
 * @get: flag to get or set rss hash
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_hash_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_rss_hash rh = { };
	struct idpf_rss_data *rss_data;
	ssize_t reply_sz;

	rss_data =
		&vport->adapter->vport_config[vport->idx]->user_config.rss_data;
	rh.vport_id = cpu_to_le32(vport->vport_id);
	rh.ptype_groups = cpu_to_le64(rss_data->rss_hash);

	xn_params.send_buf.iov_base = &rh;
	xn_params.send_buf.iov_len = sizeof(rh);

	if (get) {
		xn_params.vc_op = VIRTCHNL2_OP_GET_RSS_HASH;
		xn_params.recv_buf.iov_base = &rh;
		xn_params.recv_buf.iov_len = sizeof(rh);
	} else {
		xn_params.vc_op = VIRTCHNL2_OP_SET_RSS_HASH;
	}
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (!get)
		return 0;
	if (reply_sz < sizeof(rh))
		return -EIO;
	rss_data->rss_hash = le64_to_cpu(rh.ptype_groups);

	return 0;
}

/**
 * idpf_send_get_set_rss_lut_msg - Send virtchnl get or set rss lut message
 * @vport: virtual port data structure
 * @rss_data: Vport associated RSS data
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport,
				  struct idpf_rss_data *rss_data,
				  bool get)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_rss_lut *recv_rl;
	struct virtchnl2_rss_lut *rl;
	int buf_size, lut_buf_size;
	ssize_t reply_sz;
	int i;

	buf_size = struct_size(rl, lut, rss_data->rss_lut_size);
	rl = kzalloc(buf_size, GFP_KERNEL);
	if (!rl)
		return -ENOMEM;
	rl->vport_id = cpu_to_le32(vport->vport_id);

	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = rl;
	xn_params.send_buf.iov_len = buf_size;

	if (get) {
		recv_rl = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
		if (!recv_rl) {
			kfree(rl);
			return -ENOMEM;
		}
		xn_params.vc_op = VIRTCHNL2_OP_GET_RSS_LUT;
		xn_params.recv_buf.iov_base = recv_rl;
		xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	} else {
		rl->lut_entries = cpu_to_le16(rss_data->rss_lut_size);
		for (i = 0; i < rss_data->rss_lut_size; i++)
			rl->lut[i] = cpu_to_le32(rss_data->rss_lut[i]);

		xn_params.vc_op = VIRTCHNL2_OP_SET_RSS_LUT;
	}
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	kfree(rl);
	if (reply_sz < 0)
		return reply_sz;
	if (!get)
		return 0;
	if (reply_sz < sizeof(struct virtchnl2_rss_lut))
		return -EIO;

	lut_buf_size = le16_to_cpu(recv_rl->lut_entries) * sizeof(u32);
	if (reply_sz < lut_buf_size)
		return -EIO;

	/* size didn't change, we can reuse existing lut buf */
	if (rss_data->rss_lut_size == le16_to_cpu(recv_rl->lut_entries))
		goto do_memcpy;

	rss_data->rss_lut_size = le16_to_cpu(recv_rl->lut_entries);
	kfree(rss_data->rss_lut);

	rss_data->rss_lut = kzalloc(lut_buf_size, GFP_KERNEL);
	if (!rss_data->rss_lut) {
		rss_data->rss_lut_size = 0;
		kfree(recv_rl);
		return -ENOMEM;
	}

do_memcpy:
	memcpy(rss_data->rss_lut, recv_rl->lut, rss_data->rss_lut_size);
	kfree(recv_rl);
	return 0;
}

/**
 * idpf_send_get_set_rss_key_msg - Send virtchnl get or set rss key message
 * @vport: virtual port data structure
 * @rss_data: Vport associated RSS data
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport,
				  struct idpf_rss_data *rss_data,
				  bool get)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_rss_key *recv_rk = NULL;
	struct virtchnl2_rss_key *rk;
	ssize_t reply_sz;
	int i, buf_size;
	u16 key_size;

	buf_size = struct_size(rk, key, rss_data->rss_key_size);
	rk = kzalloc(buf_size, GFP_KERNEL);
	if (!rk)
		return -ENOMEM;
	rk->vport_id = cpu_to_le32(vport->vport_id);

	xn_params.send_buf.iov_base = rk;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	if (get) {
		recv_rk = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
		if (!recv_rk) {
			kfree(rk);
			return -ENOMEM;
		}

		xn_params.vc_op = VIRTCHNL2_OP_GET_RSS_KEY;
		xn_params.recv_buf.iov_base = recv_rk;
		xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	} else {
		rk->key_len = cpu_to_le16(rss_data->rss_key_size);
		for (i = 0; i < rss_data->rss_key_size; i++)
			rk->key[i] = rss_data->rss_key[i];

		xn_params.vc_op = VIRTCHNL2_OP_SET_RSS_KEY;
	}

	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);
	kfree(rk);
	if (reply_sz < 0) {
		kfree(recv_rk);
		return reply_sz;
	}
	if (!get)
		return 0;
	if (reply_sz < sizeof(struct virtchnl2_rss_key))
		return -EIO;

	key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
			 le16_to_cpu(recv_rk->key_len));
	if (reply_sz < key_size)
		return -EIO;

	/* key len didn't change, reuse existing buf */
	if (rss_data->rss_key_size == key_size)
		goto do_memcpy;

	rss_data->rss_key_size = key_size;
	kfree(rss_data->rss_key);
	rss_data->rss_key = kzalloc(key_size, GFP_KERNEL);
	if (!rss_data->rss_key) {
		rss_data->rss_key_size = 0;
		kfree(recv_rk);
		return -ENOMEM;
	}

do_memcpy:
	memcpy(rss_data->rss_key, recv_rk->key, rss_data->rss_key_size);
	kfree(recv_rk);
	return 0;
}

/**
 * idpf_fill_ptype_lookup - Fill L3 specific fields in ptype lookup table
 * @ptype: ptype lookup table
 * @pstate: state machine for ptype lookup table
 * @ipv4: ipv4 or ipv6
 * @frag: fragmentation allowed
 *
 */
static void idpf_fill_ptype_lookup(struct idpf_rx_ptype_decoded *ptype,
				   struct idpf_ptype_state *pstate,
				   bool ipv4, bool frag)
{
	if (!pstate->outer_ip || !pstate->outer_frag) {
		ptype->outer_ip = IDPF_RX_PTYPE_OUTER_IP;
		pstate->outer_ip = true;

		if (ipv4)
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV4;
		else
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV6;

		if (frag) {
			ptype->outer_frag = IDPF_RX_PTYPE_FRAG;
			pstate->outer_frag = true;
		}
	} else {
		ptype->tunnel_type = IDPF_RX_PTYPE_TUNNEL_IP_IP;
		pstate->tunnel_state = IDPF_PTYPE_TUNNEL_IP;

		if (ipv4)
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV4;
		else
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV6;

		if (frag)
			ptype->tunnel_end_frag = IDPF_RX_PTYPE_FRAG;
	}
}

/**
 * idpf_send_get_rx_ptype_msg - Send virtchnl for ptype info
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport)
{
	struct idpf_rx_ptype_decoded *ptype_lkup = vport->rx_ptype_lkup;
	struct virtchnl2_get_ptype_info *get_ptype_info, *ptype_info;
	int max_ptype, ptypes_recvd = 0, ptype_offset;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vc_xn_params xn_params = { };
	u16 next_ptype_id = 0;
	int err = 0, i, j, k;
	ssize_t reply_sz;
	bool is_splitq;

	is_splitq = idpf_is_queue_model_split(vport->dflt_grp.q_grp.rxq_model);

	if (is_splitq)
		max_ptype = IDPF_RX_MAX_PTYPE;
	else
		max_ptype = IDPF_RX_MAX_BASE_PTYPE;

	memset(vport->rx_ptype_lkup, 0, sizeof(vport->rx_ptype_lkup));

	get_ptype_info = kzalloc(sizeof(*get_ptype_info), GFP_KERNEL);
	if (!get_ptype_info)
		return -ENOMEM;

	ptype_info = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!ptype_info) {
		err = -ENOMEM;
		goto ptype_rel;
	}

	xn_params.vc_op = VIRTCHNL2_OP_GET_PTYPE_INFO;
	xn_params.send_buf.iov_base = (void *)get_ptype_info;
	xn_params.send_buf.iov_len = sizeof(*get_ptype_info);
	xn_params.recv_buf.iov_base = (void *)ptype_info;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	while (next_ptype_id < max_ptype) {
		get_ptype_info->start_ptype_id = cpu_to_le16(next_ptype_id);

		if ((next_ptype_id + IDPF_RX_MAX_PTYPES_PER_BUF) > max_ptype)
			get_ptype_info->num_ptypes =
				cpu_to_le16(max_ptype - next_ptype_id);
		else
			get_ptype_info->num_ptypes =
				cpu_to_le16(IDPF_RX_MAX_PTYPES_PER_BUF);

		reply_sz = idpf_vc_xn_exec(adapter, xn_params);
		if (reply_sz < 0) {
			err = -EINVAL;
			goto ptype_rel;
		}

		ptypes_recvd += le16_to_cpu(ptype_info->num_ptypes);
		if (ptypes_recvd > max_ptype) {
			err = -EINVAL;
			goto ptype_rel;
		}

		next_ptype_id = le16_to_cpu(get_ptype_info->start_ptype_id) +
				le16_to_cpu(get_ptype_info->num_ptypes);
		ptype_offset = IDPF_RX_PTYPE_HDR_SZ;

		for (i = 0; i < le16_to_cpu(ptype_info->num_ptypes); i++) {
			struct idpf_ptype_state pstate = { };
			struct virtchnl2_ptype *ptype;
			u16 id;

			ptype = (struct virtchnl2_ptype *)
					((u8 *)ptype_info + ptype_offset);

			ptype_offset += IDPF_GET_PTYPE_SIZE(ptype);
			if (ptype_offset > IDPF_CTLQ_MAX_BUF_LEN) {
				err = -EINVAL;
				goto ptype_rel;
			}

			if (le16_to_cpu(ptype->ptype_id_10) ==
							IDPF_INVALID_PTYPE_ID)
				goto ptype_rel;

			if (is_splitq)
				k = le16_to_cpu(ptype->ptype_id_10);
			else
				k = ptype->ptype_id_8;

			if (ptype->proto_id_count)
				ptype_lkup[k].known = 1;

			for (j = 0; j < ptype->proto_id_count; j++) {
				id = le16_to_cpu(ptype->proto_id[j]);
				switch (id) {
				case VIRTCHNL2_PROTO_HDR_GRE:
					if (pstate.tunnel_state ==
							IDPF_PTYPE_TUNNEL_IP) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_MAC:
					ptype_lkup[k].outer_ip =
						IDPF_RX_PTYPE_OUTER_L2;
					if (pstate.tunnel_state ==
							IDPF_TUN_IP_GRE) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_UDP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_UDP;
					break;
				case VIRTCHNL2_PROTO_HDR_TCP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_TCP;
					break;
				case VIRTCHNL2_PROTO_HDR_SCTP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_SCTP;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_ICMP;
					break;
				case VIRTCHNL2_PROTO_HDR_PAY:
					ptype_lkup[k].payload_layer =
						IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMPV6:
				case VIRTCHNL2_PROTO_HDR_IPV6_EH:
				case VIRTCHNL2_PROTO_HDR_PRE_MAC:
				case VIRTCHNL2_PROTO_HDR_POST_MAC:
				case VIRTCHNL2_PROTO_HDR_ETHERTYPE:
				case VIRTCHNL2_PROTO_HDR_SVLAN:
				case VIRTCHNL2_PROTO_HDR_CVLAN:
				case VIRTCHNL2_PROTO_HDR_MPLS:
				case VIRTCHNL2_PROTO_HDR_MMPLS:
				case VIRTCHNL2_PROTO_HDR_PTP:
				case VIRTCHNL2_PROTO_HDR_CTRL:
				case VIRTCHNL2_PROTO_HDR_LLDP:
				case VIRTCHNL2_PROTO_HDR_ARP:
				case VIRTCHNL2_PROTO_HDR_ECP:
				case VIRTCHNL2_PROTO_HDR_EAPOL:
				case VIRTCHNL2_PROTO_HDR_PPPOD:
				case VIRTCHNL2_PROTO_HDR_PPPOE:
				case VIRTCHNL2_PROTO_HDR_IGMP:
				case VIRTCHNL2_PROTO_HDR_AH:
				case VIRTCHNL2_PROTO_HDR_ESP:
				case VIRTCHNL2_PROTO_HDR_IKE:
				case VIRTCHNL2_PROTO_HDR_NATT_KEEP:
				case VIRTCHNL2_PROTO_HDR_L2TPV2:
				case VIRTCHNL2_PROTO_HDR_L2TPV2_CONTROL:
				case VIRTCHNL2_PROTO_HDR_L2TPV3:
				case VIRTCHNL2_PROTO_HDR_GTP:
				case VIRTCHNL2_PROTO_HDR_GTP_EH:
				case VIRTCHNL2_PROTO_HDR_GTPCV2:
				case VIRTCHNL2_PROTO_HDR_GTPC_TEID:
				case VIRTCHNL2_PROTO_HDR_GTPU:
				case VIRTCHNL2_PROTO_HDR_GTPU_UL:
				case VIRTCHNL2_PROTO_HDR_GTPU_DL:
				case VIRTCHNL2_PROTO_HDR_ECPRI:
				case VIRTCHNL2_PROTO_HDR_VRRP:
				case VIRTCHNL2_PROTO_HDR_OSPF:
				case VIRTCHNL2_PROTO_HDR_TUN:
				case VIRTCHNL2_PROTO_HDR_NVGRE:
				case VIRTCHNL2_PROTO_HDR_VXLAN:
				case VIRTCHNL2_PROTO_HDR_VXLAN_GPE:
				case VIRTCHNL2_PROTO_HDR_GENEVE:
				case VIRTCHNL2_PROTO_HDR_NSH:
				case VIRTCHNL2_PROTO_HDR_QUIC:
				case VIRTCHNL2_PROTO_HDR_PFCP:
				case VIRTCHNL2_PROTO_HDR_PFCP_NODE:
				case VIRTCHNL2_PROTO_HDR_PFCP_SESSION:
				case VIRTCHNL2_PROTO_HDR_RTP:
				case VIRTCHNL2_PROTO_HDR_NO_PROTO:
					continue;
				default:
					break;
				}
			}
		}
	}

ptype_rel:
	kfree(ptype_info);
	kfree(get_ptype_info);
	return err;
}

/**
 * idpf_send_ena_dis_loopback_msg - Send virtchnl enable/disable loopback
 *				    message
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_loopback loopback;
	ssize_t reply_sz;

	loopback.vport_id = cpu_to_le32(vport->vport_id);
	loopback.enable = idpf_is_feature_ena(vport, NETIF_F_LOOPBACK);

	xn_params.vc_op = VIRTCHNL2_OP_LOOPBACK;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &loopback;
	xn_params.send_buf.iov_len = sizeof(loopback);
	reply_sz = idpf_vc_xn_exec(vport->adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_create_adi_msg - Send virtchnl create ADI message
 * @adapter: adapter info struct
 * @vchnl_adi: pointer to create ADI struct
 *
 * Send create ADI virtchnl message and receive the result.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_create_adi_msg(struct idpf_adapter *adapter,
			     struct virtchnl2_non_flex_create_adi *vchnl_adi)
{
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;
	size_t iov_len;
	u16 cnt;

	xn_params.vc_op = VIRTCHNL2_OP_NON_FLEX_CREATE_ADI;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = vchnl_adi;
	iov_len = sizeof(*vchnl_adi);
	cnt = le16_to_cpu(vchnl_adi->chunks.num_chunks);
	if (cnt)
		iov_len += (cnt - 1) * sizeof(vchnl_adi->chunks.chunks[0]);
	cnt = le16_to_cpu(vchnl_adi->vchunks.num_vchunks);
	if (cnt)
		iov_len += (cnt - 1) * sizeof(vchnl_adi->vchunks.vchunks[0]);
	xn_params.send_buf.iov_len = iov_len;
	xn_params.recv_buf.iov_base = vchnl_adi;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(*vchnl_adi))
		return -EIO;

	return 0;
}

/**
 * idpf_send_destroy_adi_msg - Send virtchnl enable  message
 * @adapter: adapter info struct
 * @vchnl_adi: pointer to destroy ADI struct
 *
 * Send destroy ADI virtchnl message and receive the result.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_destroy_adi_msg(struct idpf_adapter *adapter,
			      struct virtchnl2_non_flex_destroy_adi *vchnl_adi)
{
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;

	xn_params.vc_op = VIRTCHNL2_OP_NON_FLEX_DESTROY_ADI;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = vchnl_adi;
	xn_params.send_buf.iov_len = sizeof(*vchnl_adi);
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_find_ctlq - Given a type and id, find ctlq info
 * @hw: hardware struct
 * @type: type of ctrlq to find
 * @id: ctlq id to find
 *
 * Returns pointer to found ctlq info struct, NULL otherwise.
 */
static struct idpf_ctlq_info *idpf_find_ctlq(struct idpf_hw *hw,
					     enum idpf_ctlq_type type, int id)
{
	struct idpf_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		if (cq->q_id == id && cq->cq_type == type)
			return cq;

	return NULL;
}

/**
 * idpf_init_dflt_mbx - Setup default mailbox parameters and make request
 * @adapter: adapter info struct
 *
 * Returns 0 on success, negative otherwise
 */
int idpf_init_dflt_mbx(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_create_info ctlq_info[] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		},
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		}
	};
	struct idpf_hw *hw = &adapter->hw;
	int err;

	adapter->dev_ops.reg_ops.ctlq_reg_init(hw, ctlq_info);

	err = idpf_ctlq_init(hw, IDPF_NUM_DFLT_MBX_Q, ctlq_info);
	if (err)
		return err;

	hw->asq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_TX,
				 IDPF_DFLT_MBX_ID);
	hw->arq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_RX,
				 IDPF_DFLT_MBX_ID);

	if (!hw->asq || !hw->arq) {
		idpf_ctlq_deinit(hw);

		return -ENOENT;
	}

	adapter->state = __IDPF_VER_CHECK;

	return 0;
}

/**
 * idpf_deinit_dflt_mbx - Free up ctlqs setup
 * @adapter: Driver specific private data structure
 */
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter)
{
	if (adapter->hw.arq && adapter->hw.asq) {
		idpf_mb_clean(adapter);
		idpf_ctlq_deinit(&adapter->hw);
	}
	adapter->hw.arq = NULL;
	adapter->hw.asq = NULL;
}

/**
 * idpf_vport_params_buf_rel - Release memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will release memory to hold the vport parameters received on MailBox
 */
static void idpf_vport_params_buf_rel(struct idpf_adapter *adapter)
{
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
}

/**
 * idpf_vport_params_buf_alloc - Allocate memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will alloc memory to hold the vport parameters received on MailBox
 */
static int idpf_vport_params_buf_alloc(struct idpf_adapter *adapter)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);

	adapter->vport_params_reqd = kcalloc(num_max_vports,
					     sizeof(*adapter->vport_params_reqd),
					     GFP_KERNEL);
	if (!adapter->vport_params_reqd)
		return -ENOMEM;

	adapter->vport_params_recvd = kcalloc(num_max_vports,
					      sizeof(*adapter->vport_params_recvd),
					      GFP_KERNEL);
	if (!adapter->vport_params_recvd)
		goto err_mem;

	adapter->vport_ids = kcalloc(num_max_vports, sizeof(u32), GFP_KERNEL);
	if (!adapter->vport_ids)
		goto err_mem;

	if (adapter->vport_config)
		return 0;
	adapter->vport_config = kcalloc(num_max_vports,
					sizeof(*adapter->vport_config),
					GFP_KERNEL);
	if (!adapter->vport_config)
		goto err_mem;

	return 0;

err_mem:
	idpf_vport_params_buf_rel(adapter);
	return -ENOMEM;
}

/**
 * idpf_get_oem_caps - Send virtchnl get oem capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl get oem capabilities message.
 * Returns 0 on success, negative on failure.
 */
static int idpf_get_oem_caps(struct idpf_adapter *adapter)
{
	struct virtchnl2_oem_caps oem_caps_msg = {};
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;

	xn_params.vc_op = VIRTCHNL2_OP_GET_OEM_CAPS;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &oem_caps_msg;
	xn_params.send_buf.iov_len = sizeof(oem_caps_msg);
	xn_params.recv_buf.iov_base = &adapter->oem_caps;
	xn_params.recv_buf.iov_len = sizeof(struct virtchnl2_oem_caps);

	reply_sz = idpf_vc_xn_exec(adapter, xn_params);
	if (reply_sz < 0)
		return reply_sz;

	return 0;
}

/**
 * idpf_vc_core_init - Initialize state machine and get driver specific
 * resources
 * @adapter: Driver specific private structure
 *
 * This function will initialize the state machine and request all necessary
 * resources required by the device driver. Once the state machine is
 * initialized, allocate memory to store vport specific information and also
 * requests required interrupts.
 *
 * Returns 0 on success, -EAGAIN function will get called again,
 * otherwise negative on failure.
 */
int idpf_vc_core_init(struct idpf_adapter *adapter)
{
	int task_delay = 30;
	u16 num_max_vports;
	int err = 0;

	while (adapter->state != __IDPF_INIT_SW) {
		switch (adapter->state) {
		case __IDPF_VER_CHECK:
			err = idpf_send_ver_msg(adapter);
			switch (err) {
			case 0:
				/* success, move state machine forward */
				adapter->state = __IDPF_GET_CAPS;
				goto restart;
			case -EAGAIN:
				/* not ready yet, try again */
				adapter->state = __IDPF_VER_CHECK;
				goto restart;
			default:
				/* Something bad happened, try again but only a
				 * few times.
				 */
				goto init_failed;
			}
		case __IDPF_GET_CAPS:
			err = idpf_send_get_caps_msg(adapter);
			if (err)
				goto init_failed;
			adapter->state = __IDPF_INIT_SW;
			break;
		default:
			dev_err(idpf_adapter_to_dev(adapter), "Device is in bad state: %d\n",
				adapter->state);
			err = -EINVAL;
			goto init_failed;
		}
		break;
restart:
		/* Give enough time before proceeding further with
		 * state machine
		 */
		msleep(task_delay);
	}

	pci_sriov_set_totalvfs(adapter->pdev, idpf_get_max_vfs(adapter));
	num_max_vports = idpf_get_max_vports(adapter);
	adapter->max_vports = num_max_vports;
	adapter->vports = kcalloc(num_max_vports, sizeof(*adapter->vports),
				  GFP_KERNEL);
	if (!adapter->vports)
		return -ENOMEM;

	if (!adapter->netdevs) {
		adapter->netdevs = kcalloc(num_max_vports,
					   sizeof(struct net_device *),
					   GFP_KERNEL);
		if (!adapter->netdevs) {
			err = -ENOMEM;
			goto err_netdev_alloc;
		}
	}

	err = idpf_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to alloc vport params buffer: %d\n",
			err);
		goto err_netdev_alloc;
	}

	idpf_send_get_edt_caps(adapter);

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_OEM)) {
		err = idpf_get_oem_caps(adapter);
		if (err)
			dev_err(idpf_adapter_to_dev(adapter), "Failed to receive OEM capabilities\n");
	}

	err = idpf_intr_req(adapter);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "failed to enable interrupt vectors: %d\n",
			err);
		goto err_intr_req;
	}

	err = idpf_ptp_init(adapter);
	if (err)
		dev_err(idpf_adapter_to_dev(adapter), "failed to initialize PTP\n");

	idpf_init_avail_queues(adapter);
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	idpf_adi_core_init(adapter);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	/* Skew the delay for init tasks for each function based on fn number
	 * to prevent every function from making the same call simulatenously.
	 */
	queue_delayed_work(adapter->init_wq, &adapter->init_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));
	adapter->mb_wait_count = 0;

	return 0;

err_intr_req:
	idpf_vport_params_buf_rel(adapter);
err_netdev_alloc:
	/* We're intentionally not freeing netdevs here because we want them
	 * preserved across hard resets. We'll have a chance to clean
	 * everything up on remove so we don't need to worry about leaking
	 * them.
	 */
	kfree(adapter->vports);
	adapter->vports = NULL;
	return err;

init_failed:
	/* Don't retry if we're trying to go down, just bail. */
	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return err;

	if (++adapter->mb_wait_count > IDPF_MB_MAX_ERR) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to establish mailbox communications with hardware\n");
		return -EFAULT;
	}

	dev_err(idpf_adapter_to_dev(adapter), "Failed to initialize virtchnl, wait_count: %d state: %d err: %d, triggering reset\n",
		adapter->mb_wait_count, adapter->state, err);

	/* If it reached here, it is possible that mailbox queue initialization
	 * register writes might not have taken effect. Retry to initialize
	 * the mailbox again
	 */
	adapter->state = __IDPF_VER_CHECK;
	set_bit(IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(task_delay));
	return -EAGAIN;
}

/**
 * idpf_vc_core_deinit - Device deinit routine
 * @adapter: Driver specific private structure
 *
 */
void idpf_vc_core_deinit(struct idpf_adapter *adapter)
{
	idpf_ptp_release(adapter);
	idpf_deinit_task(adapter);
	idpf_intr_rel(adapter);

	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->mbx_task);

	idpf_vport_params_buf_rel(adapter);

	kfree(adapter->vports);
	adapter->vports = NULL;
}

/**
 * idpf_vport_alloc_vec_indexes - Get relative vector indexes
 * @vport: virtual port data struct
 * @vgrp: Queue and interrupt resource group
 *
 * This function requests the vector information required for the vport and
 * stores the vector indexes received from the 'global vector distribution'
 * in the vport's queue vectors array.
 *
 * Return 0 on success, error on failure
 */
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport,
				 struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	struct idpf_vector_info vec_info;
	int num_alloc_vecs;

	vec_info.num_curr_vecs = intr_grp->num_q_vectors;
	vec_info.num_req_vecs = max(q_grp->num_txq, q_grp->num_rxq);
	vec_info.default_vport = vgrp->type == IDPF_GRP_TYPE_P2P ?
					false : vport->default_vport;
	vec_info.index = vport->idx;
#ifdef HAVE_XDP_SUPPORT

	/* Additional XDP Tx queues share the q_vector with regular Tx and Rx
	 * queues to which they are assigned. Also, according to DCR-3692 XDP
	 * shall request additional Tx queues via VIRTCHNL. Therefore, to avoid
	 * exceeding over "vport->q_vector_idxs array", do not request empty
	 * q_vectors for XDP Tx queues.
	 */
	if (idpf_xdp_is_prog_ena(vport))
		vec_info.num_req_vecs = max_t(u16,
					      q_grp->num_txq - vport->num_xdp_txq,
					      q_grp->num_rxq);
#endif /* HAVE_XDP_SUPPORT */

	num_alloc_vecs = idpf_req_rel_vector_indexes(vport->adapter,
						     intr_grp->q_vector_idxs,
						     &vec_info);
	if (num_alloc_vecs <= 0) {
		dev_err(idpf_adapter_to_dev(vport->adapter), "Vector distribution failed: %d\n",
			num_alloc_vecs);
		return -EINVAL;
	}

	intr_grp->num_q_vectors = num_alloc_vecs;

	return 0;
}

/**
 * idpf_vport_dealloc_vec_indexes - Release relative vector indexes
 * @vport: virtual port data struct
 * @vgrp: Queue and interrupt resource group
 */
void idpf_vport_dealloc_vec_indexes(struct idpf_vport *vport,
				    struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_vector_info vec_info;

	vec_info.num_curr_vecs = intr_grp->num_q_vectors;
	vec_info.num_req_vecs = 0;
	vec_info.default_vport = vgrp->type == IDPF_GRP_TYPE_P2P ?
					false : vport->default_vport;
	vec_info.index = vport->idx;

	idpf_req_rel_vector_indexes(vport->adapter, intr_grp->q_vector_idxs,
				    &vec_info);
	kfree(intr_grp->q_vector_idxs);
	intr_grp->q_vector_idxs = NULL;
}

/**
 * idpf_vport_edt_init - Initialize EDT parameters
 * @vport: virtual port to be initialized
 */
static void idpf_vport_edt_init(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	u64 tw_gran_m;

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_EDT))
		return;

	/* Turn timestamp granularity into a bit shift for faster calculation */
	tw_gran_m = le64_to_cpu(adapter->edt_caps.tstamp_granularity_ns) - 1;

	while (tw_gran_m >> 1) {
		vport->tw_ts_gran_s++;
		tw_gran_m = tw_gran_m >> 1;
	}

	vport->tw_ts_gran_s++;
	vport->tw_horizon = le64_to_cpu(adapter->edt_caps.time_horizon_ns);
}

/**
 * idpf_uplink_port_stats_alloc - Allocate memory for uplink port representor
 *				  statistics
 * @vport: Virtual port
 */
static int idpf_uplink_port_stats_alloc(struct idpf_vport *vport)
{
	vport->port_stats.phy_port_stats = kzalloc(sizeof(*vport->port_stats.phy_port_stats),
						   GFP_ATOMIC);
	if (!vport->port_stats.phy_port_stats)
		return -ENOMEM;

	return 0;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_vport_set_xdp_tx_desc_handler - Set a handler function for XDP Tx
 *					descriptor
 * @vport: vport to setup XDP Tx descriptor handler for
 */
static void idpf_vport_set_xdp_tx_desc_handler(struct idpf_vport *vport)
{
	if (vport->dflt_grp.q_grp.txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
		vport->xdp_prepare_tx_desc = idpf_prepare_xdp_tx_singleq_desc;
	else
		vport->xdp_prepare_tx_desc = idpf_prepare_xdp_tx_splitq_desc;
}

#endif /* HAVE_XDP_SUPPORT */
/**
 * idpf_vport_init - Initialize virtual port
 * @vport: virtual port to be initialized
 * @max_q: vport max queue info
 *
 * Will initialize vport with the info received through MB earlier. Returns 0
 * on success, negative on failure.
 */
int idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q)
{
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vport_config *vport_config;
	u16 tx_itr[] = {2, 8, 64, 128, 256};
	u16 rx_itr[] = {2, 8, 32, 96, 128};
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;
	int err = 0;

	vport_config = adapter->vport_config[idx];
	rss_data = &vport_config->user_config.rss_data;
	vport_msg = (struct virtchnl2_create_vport *)
				adapter->vport_params_recvd[idx];

	vport->max_mtu = le16_to_cpu(vport_msg->max_mtu) - IDPF_PACKET_HDR_PAD;
	if (vport->max_mtu < ETH_MIN_MTU) {
		pr_err("Invalid value for maximum MTU: %d\n", vport->max_mtu);
		return -EINVAL;
	}

	if (le16_to_cpu(vport_msg->vport_flags) & VIRTCHNL2_VPORT_UPLINK_PORT) {
		set_bit(IDPF_VPORT_UPLINK_PORT, vport_config->flags);
		err = idpf_uplink_port_stats_alloc(vport);
		if (err)
			return err;
	}

	vport_config->max_q.max_txq = max_q->max_txq;
	vport_config->max_q.max_rxq = max_q->max_rxq;
	vport_config->max_q.max_complq = max_q->max_complq;
	vport_config->max_q.max_bufq = max_q->max_bufq;

	q_grp->txq_model = le16_to_cpu(vport_msg->txq_model);
	q_grp->rxq_model = le16_to_cpu(vport_msg->rxq_model);
	vport->vport_type = le16_to_cpu(vport_msg->vport_type);
	vport->vport_id = le32_to_cpu(vport_msg->vport_id);

	rss_data->rss_key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
				       le16_to_cpu(vport_msg->rss_key_size));
	rss_data->rss_lut_size = le16_to_cpu(vport_msg->rss_lut_size);

	ether_addr_copy(vport->default_mac_addr, vport_msg->default_mac_addr);

	/* Initialize Tx and Rx profiles for Dynamic Interrupt Moderation */
	memcpy(vport->rx_itr_profile, rx_itr, IDPF_DIM_PROFILE_SLOTS);
	memcpy(vport->tx_itr_profile, tx_itr, IDPF_DIM_PROFILE_SLOTS);

#ifdef HAVE_XDP_SUPPORT
	idpf_vport_set_xdp_tx_desc_handler(vport);

	if (idpf_xdp_is_prog_ena(vport))
		idpf_vport_set_hsplit(vport, false);
	else
		idpf_vport_set_hsplit(vport, true);
#else
	idpf_vport_set_hsplit(vport, true);
#endif /* HAVE_XDP_SUPPORT */

	idpf_vport_init_num_qs(vport, vport_msg, q_grp);
	idpf_vport_calc_num_q_desc(vport, q_grp);
	idpf_vport_alloc_vec_indexes(vport, &vport->dflt_grp);

	vport->crc_enable = adapter->crc_enable;

	idpf_vport_edt_init(vport);

	if (le16_to_cpu(vport_msg->vport_flags) & VIRTCHNL2_VPORT_PORT2PORT_PORT)
		set_bit(IDPF_VPORT_PORT2PORT_ENABLED, vport->flags);

	if (le16_to_cpu(vport_msg->vport_flags) & VIRTCHNL2_VPORT_UPLINK_PORT) {
		err = idpf_ptp_get_vport_tstamps_caps(vport);
		switch (err) {
		case 0:
			break;
		/* -EOPNOTSUPP is returned when the Tx timestamping is
		 * not enabled by the CP policy - there is no need
		 * to break the init flow, when the Tx timestamp caps
		 * are not negotiated.
		 */
		case -EOPNOTSUPP:
			dev_dbg(idpf_adapter_to_dev(vport->adapter),
				"Tx timestamping not supported\n");
			return 0;
		default:
			return err;
		};

		INIT_WORK(&vport->tstamp_task, idpf_tstamp_task);
	}
	return err;
}

/**
 * idpf_get_vec_ids - Initialize vector id from Mailbox parameters
 * @adapter: adapter structure to get the mailbox vector id
 * @vecids: Array of vector ids
 * @num_vecids: number of vector ids
 * @chunks: vector ids received over mailbox
 *
 * Will initialize the mailbox vector id which is received from the
 * get capabilities and data queue vector ids with ids received as
 * mailbox parameters.
 * Returns number of ids filled
 */
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_vchunks);
	int num_vecid_filled = 0;
	int i, j;

	vecids[num_vecid_filled] = adapter->mb_vector.v_idx;
	num_vecid_filled++;

	for (j = 0; j < num_chunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u16 start_vecid, num_vec;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		start_vecid = le16_to_cpu(chunk->start_vector_id);
		for (i = 0; i < num_vec; i++) {
			if ((num_vecid_filled + i) < num_vecids) {
				vecids[num_vecid_filled + i] = start_vecid;
				start_vecid++;
			} else {
				break;
			}
		}
		num_vecid_filled = num_vecid_filled + i;
	}

	return num_vecid_filled;
}

/**
 * idpf_vport_get_queue_ids - Initialize queue id from Mailbox parameters
 * @qids: Array of queue ids
 * @num_qids: number of queue ids
 * @q_type: queue model
 * @chunks: queue ids received over mailbox
 *
 * Will initialize all queue ids with ids received as mailbox parameters
 * Returns number of ids filled
 */
static int idpf_vport_get_queue_ids(u32 *qids, int num_qids, u16 q_type,
				    struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	u32 num_q_id_filled = 0, i;
	u32 start_q_id, num_q;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		start_q_id = le32_to_cpu(chunk->start_queue_id);

		for (i = 0; i < num_q; i++) {
			if ((num_q_id_filled + i) < num_qids) {
				qids[num_q_id_filled + i] = start_q_id;
				start_q_id++;
			} else {
				break;
			}
		}
		num_q_id_filled = num_q_id_filled + i;
	}

	return num_q_id_filled;
}

/**
 * idpf_rx_map_bufq_qids - Map buffer queue q_ids to RX queues
 * @q_grp: Queue resources
 *
 * RX queues may need to know what buffer queue they're actually assigned to in
 * HW. This relationship is determined by q_id. Returns 0 on success, negative
 * on failure.
 */
static int idpf_rx_map_bufq_qids(struct idpf_q_grp *q_grp)
{
	int i, j;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];

		for (j = 0; j < q_grp->bufq_per_rxq; j++) {
			int offset = idpf_rx_bufq_offset(q_grp, i, j);

			rxq->rx.bufq_qids[j] = q_grp->bufqs[offset].q_id;
		}
	}

	return 0;
}

/**
 * __idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @q_grp: Queue resources
 * @qids: queue ids
 * @num_qids: number of queue ids
 * @q_type: type of queue
 *
 * Will initialize all queue ids with ids received as mailbox
 * parameters.
 */
static void __idpf_vport_queue_ids_init(struct idpf_q_grp *q_grp,
					const u32 *qids,
					int num_qids,
					u32 q_type)
{
	struct idpf_queue *q;
	u16 i, numq;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		numq = q_grp->num_txq;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		numq = q_grp->num_rxq;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		numq = q_grp->num_complq;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		numq = q_grp->num_bufq;
		break;
	default:
		return;
	}

	for (i = 0; i < numq; i++) {
		switch (q_type) {
		case VIRTCHNL2_QUEUE_TYPE_TX:
			q = q_grp->txqs[i];
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX:
			q = q_grp->rxqs[i];
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
			q = &q_grp->complqs[i];
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			q = &q_grp->bufqs[i];
			break;
		}

		q->q_id = qids[i];
		q->q_type = q_type;
	}
}

/**
 * idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @q_grp: Queue resources
 * @chunks: Queue register info
 *
 * Will initialize all queue ids with ids received as mailbox parameters.
 * Returns 0 on success, negative if all the queues are not initialized.
 */
int idpf_vport_queue_ids_init(struct idpf_q_grp *q_grp,
			      struct virtchnl2_queue_reg_chunks *chunks)
{
	/* We may never deal with more than 256 same type of queues */
#define IDPF_MAX_QIDS	256
	int num_ids, ret = 0;
	u16 q_type;
	u32 *qids;

	qids = kcalloc(IDPF_MAX_QIDS, sizeof(u32), GFP_KERNEL);
	if (!qids)
		return -ENOMEM;

	q_type = VIRTCHNL2_QUEUE_TYPE_TX;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < q_grp->num_txq) {
		ret = -EINVAL;
		goto out;
	}

	__idpf_vport_queue_ids_init(q_grp, qids, num_ids, q_type);

	q_type = VIRTCHNL2_QUEUE_TYPE_RX;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < q_grp->num_rxq) {
		ret = -EINVAL;
		goto out;
	}

	__idpf_vport_queue_ids_init(q_grp, qids, num_ids, q_type);

	if (!idpf_is_queue_model_split(q_grp->txq_model))
		goto check_rx;

	q_type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < q_grp->num_complq) {
		ret = -EINVAL;
		goto out;
	}

	__idpf_vport_queue_ids_init(q_grp, qids, num_ids, q_type);

check_rx:
	if (!idpf_is_queue_model_split(q_grp->rxq_model))
		goto out;

	q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < q_grp->num_bufq) {
		ret = -EINVAL;
		goto out;
	}

	__idpf_vport_queue_ids_init(q_grp, qids, num_ids, q_type);

	if (idpf_rx_map_bufq_qids(q_grp))
		ret = -ENOMEM;

out:
	kfree(qids);

	return ret;
}

/**
 * idpf_vport_adjust_qs - Adjust to new requested queues
 * @vport: virtual port data struct
 */
void idpf_vport_adjust_qs(struct idpf_vport *vport)
{
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct virtchnl2_create_vport vport_msg;

	vport_msg.txq_model = cpu_to_le16(q_grp->txq_model);
	vport_msg.rxq_model = cpu_to_le16(q_grp->rxq_model);
	idpf_vport_calc_total_qs(vport->adapter, vport->idx, &vport_msg, NULL);

	idpf_vport_init_num_qs(vport, &vport_msg, q_grp);
}

/**
 * idpf_is_capability_ena - Default implementation of capability checking
 * @adapter: Private data struct
 * @all: all or one flag
 * @field: caps field to check for flags
 * @flag: flag to check
 *
 * Return true if all capabilities are supported, false otherwise
 */
bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag)
{
	u8 *caps = (u8 *)&adapter->caps;
	u64 *cap_field;

	if (!caps)
		return false;

	if (field == IDPF_BASE_CAPS)
		return false;

	cap_field = (u64 *)(caps + field);

	if (all)
		return (*cap_field & flag) == flag;
	else
		return !!(*cap_field & flag);
}

/**
 * idpf_set_mac_type: Set the mac address type
 * @vport: virtual port structure
 * @mac_addr: mac address pointer
 */
static void idpf_set_mac_type(struct idpf_vport *vport,
			      struct virtchnl2_mac_addr *mac_addr)
{
	if (ether_addr_equal(vport->default_mac_addr, mac_addr->addr))
		mac_addr->type = VIRTCHNL2_MAC_ADDR_PRIMARY;
	else
		mac_addr->type = VIRTCHNL2_MAC_ADDR_EXTRA;
}

/**
 * idpf_mac_filter_async_handler - Async callback for mac filters
 * @adapter: private data struct
 * @xn: transaction for message
 * @ctlq_msg: received message
 *
 * In some scenarios driver can't sleep and wait for a reply (e.g.: stack is
 * holding rtnl_lock) when adding a new mac filter. It puts us in a difficult
 * situation to deal with errors returned on the reply. The best we can
 * ultimately do is remove it from our list of mac filters and report the
 * error.
 */
static int idpf_mac_filter_async_handler(struct idpf_adapter *adapter,
					 struct idpf_vc_xn *xn,
					 const struct idpf_ctlq_msg *ctlq_msg)
{
	struct virtchnl2_mac_addr_list *ma_list;
	struct idpf_vport_config *vport_config;
	struct virtchnl2_mac_addr *mac_addr;
	struct idpf_mac_filter *f, *tmp;
	struct list_head *ma_list_head;
	struct idpf_vport *vport;
	u16 num_entries;
	int i;

	/* if success we're done, we're only here if something bad happened */
	if (!ctlq_msg->cookie.mbx.chnl_retval)
		return 0;

	/* make sure at least struct is there */
	if (xn->reply_sz < sizeof(*ma_list))
		goto invalid_payload;

	ma_list = (struct virtchnl2_mac_addr_list *)
		  ctlq_msg->ctx.indirect.payload->va;
	mac_addr = ma_list->mac_addr_list;
	num_entries = le16_to_cpu(ma_list->num_mac_addr);
	/* we should have received a buffer at least this big */
	if (xn->reply_sz < (sizeof(*ma_list) +
			   ((sizeof(*mac_addr) * num_entries))))
		goto invalid_payload;

	vport = idpf_vid_to_vport(adapter, le32_to_cpu(ma_list->vport_id));
	if (!vport)
		goto invalid_payload;

	vport_config = adapter->vport_config[le32_to_cpu(ma_list->vport_id)];
	ma_list_head = &vport_config->user_config.mac_filter_list;

	/* We can't do much to reconcile bad filters at this point, however we
	 * should at least remove them from our list one way or the other so we
	 * have some idea what good filters we have.
	 */
	spin_lock_bh(&vport_config->mac_filter_list_lock);
	list_for_each_entry_safe(f, tmp, ma_list_head, list)
		for (i = 0; i < num_entries; i++)
			if (ether_addr_equal(mac_addr[i].addr, f->macaddr))
				list_del(&f->list);
	spin_unlock_bh(&vport_config->mac_filter_list_lock);
	dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Received error sending mac filter request (op %d)\n",
			    xn->vc_op);

	return 0;

invalid_payload:
	dev_err_ratelimited(idpf_adapter_to_dev(adapter), "Received invalid mac filter payload (op %d) (len %ld)\n",
			    xn->vc_op, xn->reply_sz);
	return -EINVAL;
}

/**
 * idpf_add_del_mac_filters - Add/del mac filters
 * @vport: Virtual port data structure
 * @np: Netdev private structure
 * @add: Add or delete flag
 * @async: Don't wait for return message
 *
 * Returns 0 on success, error on failure.
 **/
int idpf_add_del_mac_filters(struct idpf_vport *vport,
			     struct idpf_netdev_priv *np,
			     bool add, bool async)
{
	struct virtchnl2_mac_addr_list *ma_list = NULL;
	struct idpf_adapter *adapter = np->adapter;
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_vport_config *vport_config;
	struct virtchnl2_mac_addr *mac_addr;
	u32 num_msgs, total_filters = 0;
	struct idpf_mac_filter *f, *tmp;
	int i = 0, k = 0, err = 0;
	ssize_t reply_sz;

	xn_params.vc_op = add ? VIRTCHNL2_OP_ADD_MAC_ADDR :
				VIRTCHNL2_OP_DEL_MAC_ADDR;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.async = async;
	xn_params.async_handler = idpf_mac_filter_async_handler;

	vport_config = adapter->vport_config[np->vport_idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	/* Find the number of newly added filters */
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list,
			    list) {
		if (add && f->add)
			total_filters++;
		else if (!add && f->remove)
			total_filters++;
	}
	if (!total_filters) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return 0;
	}

	/* Fill all the new filters into virtchannel message */
	mac_addr = kcalloc(total_filters, sizeof(*mac_addr), GFP_ATOMIC);
	if (!mac_addr) {
		err = -ENOMEM;
		spin_unlock_bh(&vport_config->mac_filter_list_lock);
		goto error;
	}

	list_for_each_entry_safe(f, tmp, &vport_config->user_config.mac_filter_list,
				 list) {
		if (add && f->add) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			idpf_set_mac_type(vport, &mac_addr[i]);
			i++;
			f->add = false;
			if (i == total_filters)
				break;
		}
		if (!add && f->remove) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			idpf_set_mac_type(vport, &mac_addr[i]);
			i++;
			f->remove = false;
			if (i == total_filters)
				break;
		}
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	/* Chunk up the filters into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	num_msgs = DIV_ROUND_UP(total_filters, IDPF_NUM_FILTERS_PER_MSG);

	for (i = 0, k = 0; i < num_msgs; i++) {
		u32 entries_size, buf_size, num_entries;

		num_entries = min_t(u32, total_filters, IDPF_NUM_FILTERS_PER_MSG);
		entries_size = sizeof(struct virtchnl2_mac_addr) * num_entries;
		buf_size = struct_size(ma_list, mac_addr_list, num_entries);

		if (!ma_list || num_entries != IDPF_NUM_FILTERS_PER_MSG) {
			kfree(ma_list);
			ma_list = kzalloc(buf_size, GFP_ATOMIC);
			if (!ma_list) {
				err = -ENOMEM;
				goto list_prep_error;
			}
		} else {
			memset(ma_list, 0, buf_size);
		}

		ma_list->vport_id = cpu_to_le32(np->vport_id);
		ma_list->num_mac_addr = cpu_to_le16(num_entries);
		memcpy(ma_list->mac_addr_list, &mac_addr[k], entries_size);

		xn_params.send_buf.iov_base = ma_list;
		xn_params.send_buf.iov_len = buf_size;
		reply_sz = idpf_vc_xn_exec(adapter, xn_params);
		if (reply_sz < 0) {
			err = reply_sz;
			goto mbx_error;
		}

		k += num_entries;
		total_filters -= num_entries;
	}

mbx_error:
	kfree(ma_list);
list_prep_error:
	kfree(mac_addr);
error:
	if (err)
		dev_err(idpf_adapter_to_dev(adapter), "Failed to add or del mac filters %d", err);

	return 0;
}

/**
 * idpf_set_promiscuous - set promiscuous and send message to mailbox
 * @adapter: Driver specific private structure
 * @config_data: Vport specific config data
 * @vport_id: Vport identifier
 *
 * Request to enable promiscuous mode for the vport. Message is sent
 * asynchronously and won't wait for response.  Returns 0 on success, negative
 * on failure;
 */
int idpf_set_promiscuous(struct idpf_adapter *adapter,
			 struct idpf_vport_user_config_data *config_data,
			 u32 vport_id)
{
	struct idpf_vc_xn_params xn_params = { };
	struct virtchnl2_promisc_info vpi;
	ssize_t reply_sz;
	u16 flags = 0;

	if (test_bit(__IDPF_PROMISC_UC, config_data->user_flags))
		flags |= VIRTCHNL2_UNICAST_PROMISC;
	if (test_bit(__IDPF_PROMISC_MC, config_data->user_flags))
		flags |= VIRTCHNL2_MULTICAST_PROMISC;

	vpi.vport_id = cpu_to_le32(vport_id);
	vpi.flags = cpu_to_le16(flags);

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &vpi;
	xn_params.send_buf.iov_len = sizeof(vpi);
	/* setting promiscuous is only ever done asynchronously */
	xn_params.async = true;
	reply_sz = idpf_vc_xn_exec(adapter, xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}
