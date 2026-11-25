/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only

#include "idpf_psp.h"
#include "idpf_psp_virtchnl.h"

#include <linux/debugfs.h>
#include <net/psp.h>

/* Delay before the PSP work sends again a request that couldn't be sent */
#define IDPF_PSP_RETRY_MSEC		100

/* Maximum number of TX keys queued for insertion */
#define IDPF_PSP_INS_QUEUE_MAX		1024

/* Maximum number of packets queued per TX key until its SA index is known */
#define IDPF_PSP_TX_QUEUE_MAX		64

/* Bits of 26 bit SA indexes in the split-DMA fields of the context
 * descriptor, see idpf_psp_tx_ctx_desc()
 */
#define IDPF_PSP_SAIDX_PFNUM_S		21	/* bits 21-24 in PFNUM */
#define IDPF_PSP_SAIDX_HOST_S		25	/* bit 25 in HOST bit 0 */

/**
 * idpf_queue_psp_work - Queue the PSP work
 * @adapter: private data struct
 */
void idpf_queue_psp_work(struct idpf_adapter *adapter)
{
	if (adapter->psp.wq)
		mod_delayed_work(adapter->psp.wq, &adapter->psp.work, 0);
}

/**
 * idpf_retry_psp_work - Queue the PSP work after a request couldn't be sent
 * @adapter: private data struct
 *
 * The request is sent again after IDPF_PSP_RETRY_MSEC, unless the PSP work is
 * queued earlier.
 */
void idpf_retry_psp_work(struct idpf_adapter *adapter)
{
	if (adapter->psp.wq)
		queue_delayed_work(adapter->psp.wq, &adapter->psp.work,
				   msecs_to_jiffies(IDPF_PSP_RETRY_MSEC));
}

/**
 * idpf_cancel_psp_work - Cancel the PSP work and wait for it to finish
 * @adapter: private data struct
 */
void idpf_cancel_psp_work(struct idpf_adapter *adapter)
{
	if (adapter->psp.wq)
		cancel_delayed_work_sync(&adapter->psp.work);
}

static void idpf_psp_tx_drain(struct idpf_adapter *adapter);

/**
 * idpf_psp_work - Send the PSP key insertion and deletion requests
 * @work: work of struct idpf_adapter_psp
 *
 * Transmit the packets of the TX keys whose SA index became known, time out
 * the insert request in flight, then send at most one request of each kind.
 * The work is queued again when there is more to do, or after a delay when a
 * request couldn't be sent.
 */
static void idpf_psp_work(struct work_struct *work)
{
	struct idpf_adapter *adapter = container_of(to_delayed_work(work),
						    struct idpf_adapter,
						    psp.work);

	/* The mailbox is initialized again on reset, and released on remove
	 * and shutdown, see idpf_psp_quiesce()
	 */
	if (idpf_is_reset_in_prog(adapter) ||
	    test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return;

	idpf_psp_tx_drain(adapter);
	idpf_psp_insert_check_timeout(adapter);
	idpf_send_insert_psp_keys(adapter);
	if (idpf_send_delete_psp_keys(adapter))
		idpf_queue_psp_work(adapter);
}

/**
 * idpf_psp_insert_timeout - Insert request timer
 * @t: insert_timer of struct idpf_adapter_psp
 *
 * The mailbox transactions don't time out asynchronous requests: the PSP work
 * times out the insert request in flight, see
 * idpf_psp_insert_check_timeout(). The transaction lock can't be taken here.
 */
static void idpf_psp_insert_timeout(struct timer_list *t)
{
	struct idpf_adapter_psp *psp = timer_container_of(psp, t, insert_timer);
	struct idpf_adapter *adapter = container_of(psp, struct idpf_adapter,
						    psp);

	idpf_queue_psp_work(adapter);
}

/**
 * idpf_psp_insert_timer_arm - Start the insert request timer
 * @adapter: private data struct
 * @expires: timeout of the insert request in jiffies
 */
void idpf_psp_insert_timer_arm(struct idpf_adapter *adapter,
			       unsigned long expires)
{
	mod_timer(&adapter->psp.insert_timer, expires);
}

/**
 * idpf_psp_negotiate_caps - Negotiate the crypto and PSP capabilities
 * @adapter: private data struct
 *
 * Query the crypto and PSP capabilities granted by the CP, check that they
 * cover what the driver implements and apply the negotiated values. Must only
 * be called if VIRTCHNL2_CAP_CRYPTO was negotiated.
 *
 * Return: 0 if PSP offload can be used, negative error code otherwise.
 */
static int idpf_psp_negotiate_caps(struct idpf_adapter *adapter)
{
	struct virtchnl2_crypto_get_caps crypto_caps = { };
	struct virtchnl2_psp_get_caps psp_caps = { };
	struct device *dev = &adapter->pdev->dev;
	u32 caps, sadb_entries;
	int err;

	err = idpf_send_get_crypto_caps(adapter, &crypto_caps);
	if (err)
		return err;

	if (!(le32_to_cpu(crypto_caps.crypto_caps) & VIRTCHNL2_CAP_CRYPTO_PSP)) {
		dev_notice(dev, "PSP crypto offload not granted by CP\n");
		return -EOPNOTSUPP;
	}

	if (crypto_caps.saidx_width != IDPF_PSP_SAIDX_WIDTH_21 &&
	    crypto_caps.saidx_width != IDPF_PSP_SAIDX_WIDTH_26) {
		dev_err(dev, "Unsupported PSP SA index width %u\n",
			crypto_caps.saidx_width);
		return -EOPNOTSUPP;
	}

	sadb_entries = le32_to_cpu(crypto_caps.num_sadb_entries);
	if (!sadb_entries) {
		dev_notice(dev, "No PSP SADB entries granted by CP\n");
		return -EOPNOTSUPP;
	}

	/* The SA indexes of all the SADB entries must fit in the width */
	if (sadb_entries > BIT(crypto_caps.saidx_width)) {
		dev_err(dev, "%u PSP SADB entries don't fit in %u bit SA indexes\n",
			sadb_entries, crypto_caps.saidx_width);
		return -EOPNOTSUPP;
	}

	err = idpf_send_get_psp_caps(adapter, &psp_caps);
	if (err)
		return err;

	/* The driver only allocates and inserts PSP version 0 keys */
	caps = le32_to_cpu(psp_caps.psp_caps);
	if (!(caps & VIRTCHNL2_CAP_PSP_PROTO_V0)) {
		dev_notice(dev, "PSP version 0 keys not granted by CP\n");
		return -EOPNOTSUPP;
	}

	adapter->psp.psp_caps = caps;
	adapter->psp.sadb_entries = sadb_entries;
	adapter->psp.saidx_width = crypto_caps.saidx_width;

	return 0;
}

/**
 * idpf_psp_debugfs_init - Expose the PSP counters in debugfs
 * @adapter: private data struct
 *
 * The counters are in /sys/kernel/debug/idpf/<PCI device>/psp/. They are reset
 * on each core init, see idpf_psp_init().
 */
static void idpf_psp_debugfs_init(struct idpf_adapter *adapter)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct dentry *dir;

	dir = debugfs_create_dir(pci_name(adapter->pdev), idpf_debugfs_root);
	psp->debugfs = dir;
	dir = debugfs_create_dir("psp", dir);

	debugfs_create_u32("sadb_entries", 0444, dir, &psp->sadb_entries);
	debugfs_create_atomic_t("sadb_used", 0444, dir, &psp->sadb_used);
	debugfs_create_atomic_t("keys_allocated", 0444, dir,
				&psp->keys_allocated);
	debugfs_create_atomic_t("keys_inserted", 0444, dir,
				&psp->keys_inserted);
	debugfs_create_atomic_t("keys_removed", 0444, dir, &psp->keys_removed);
	debugfs_create_atomic_t("keys_lost", 0444, dir, &psp->keys_lost);
	debugfs_create_atomic_t("keys_refused", 0444, dir,
				&psp->keys_refused);
	debugfs_create_atomic_t("insert_errors", 0444, dir,
				&psp->insert_errors);
	debugfs_create_atomic_t("insert_late", 0444, dir, &psp->insert_late);
	debugfs_create_atomic_t("delete_retries", 0444, dir,
				&psp->del_retries);
	debugfs_create_atomic_t("tx_drops", 0444, dir, &psp->tx_drops);
	debugfs_create_atomic_t("rx_drops", 0444, dir, &psp->rx_drops);
}

/**
 * idpf_psp_init - Initialize PSP offload
 * @adapter: private data struct
 *
 * Called on each core init, including after a hard reset: PSP offload is
 * negotiated again, the CP may grant different capabilities. PSP offload uses
 * the virtchnl2 crypto offload API: if VIRTCHNL2_CAP_CRYPTO was not granted,
 * the negotiation fails or the CP didn't report the PSP RX ptype, PSP stays
 * disabled for the adapter instead of failing the core init, see
 * idpf_is_psp_ena(). The RX ptypes must be queried before, see
 * idpf_psp_set_rx_ptype().
 */
void idpf_psp_init(struct idpf_adapter *adapter)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct device *dev = &adapter->pdev->dev;
	int err;

	WRITE_ONCE(psp->enabled, false);

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_CRYPTO)) {
		dev_notice(dev, "PSP disabled, crypto capability not granted\n");
		return;
	}

	err = idpf_psp_negotiate_caps(adapter);
	if (err) {
		dev_warn(dev, "PSP disabled, capability negotiation failed: %d\n",
			 err);
		return;
	}

	/* Decrypted packets would otherwise reach the stack as plain UDP */
	if (psp->rx_ptype == IDPF_INVALID_PTYPE_ID) {
		dev_warn(dev, "PSP disabled, PSP RX ptype not reported by CP\n");
		return;
	}

	/* The FIPS compliance status is informational only */
	err = idpf_send_get_fips_compliance_status(adapter);
	if (err)
		dev_warn(dev, "Failed to get PSP FIPS compliance status: %d\n",
			 err);

	/* Initialized the first time PSP is negotiated */
	if (!psp->initialized) {
		spin_lock_init(&psp->del_lock);
		INIT_LIST_HEAD(&psp->del_list);
		INIT_DELAYED_WORK(&psp->work, idpf_psp_work);
		spin_lock_init(&psp->insert_lock);
		timer_setup(&psp->insert_timer, idpf_psp_insert_timeout, 0);
		INIT_LIST_HEAD(&psp->ins_list);
		spin_lock_init(&psp->drain_lock);
		INIT_LIST_HEAD(&psp->drain_list);
		/* Not in the idpf_test and DFT builds */
		idpf_psp_debugfs_init(adapter);
		psp->initialized = true;
	}

	if (!psp->wq) {
		psp->wq = alloc_workqueue("%s-%s-psp",
					  WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS,
					  0, dev_driver_string(dev),
					  dev_name(dev));
		if (!psp->wq) {
			dev_warn(dev, "PSP disabled, failed to allocate the workqueue\n");
			return;
		}
	}

	/* The master keys are tracked again for the new PSP device */
	psp->generation = 0;
	psp->rx_gen[0].gen = IDPF_PSP_GEN_UNKNOWN;
	psp->rx_gen[1].gen = IDPF_PSP_GEN_UNKNOWN;

	spin_lock_bh(&psp->del_lock);
	psp->del_stopped = false;
	psp->del_in_flight = false;
	psp->del_late = 0;
	/* Under del_lock: a late deletion reply may be handled meanwhile */
	atomic_set(&psp->keys_removed, 0);
	atomic_set(&psp->keys_lost, 0);
	atomic_set(&psp->sadb_used, 0);
	spin_unlock_bh(&psp->del_lock);

	/* The counters cover the time since the core init */
	atomic_set(&psp->keys_allocated, 0);
	atomic_set(&psp->del_retries, 0);
	atomic_set(&psp->keys_inserted, 0);
	atomic_set(&psp->insert_errors, 0);
	atomic_set(&psp->insert_late, 0);
	atomic_set(&psp->keys_refused, 0);
	atomic_set(&psp->tx_drops, 0);
	atomic_set(&psp->rx_drops, 0);

	WRITE_ONCE(psp->enabled, true);
}

/**
 * idpf_psp_quiesce - Stop the PSP work and drop the pending requests
 * @adapter: private data struct
 *
 * Called after idpf_vc_xn_shutdown(), which discards the asynchronous
 * transactions without calling their response callback: the keys of the
 * insert request in flight are failed here. The SA indexes queued for deletion
 * are dropped, as the SADB is flushed by the reset or remove that follows, see
 * idpf_psp_queue_delete().
 */
void idpf_psp_quiesce(struct idpf_adapter *adapter)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct idpf_psp_tx_key *key, *tmp;
	struct idpf_psp_insert_req *req;
	LIST_HEAD(keys);
	u32 i;

	if (!psp->wq)
		return;

	cancel_delayed_work_sync(&psp->work);
	timer_delete_sync(&psp->insert_timer);

	spin_lock_bh(&psp->insert_lock);
	req = psp->insert_req;
	psp->insert_req = NULL;
	list_splice_init(&psp->ins_list, &keys);
	WRITE_ONCE(psp->ins_queued, 0);
	spin_unlock_bh(&psp->insert_lock);

	if (req) {
		for (i = 0; i < req->num_keys; i++) {
			idpf_psp_tx_key_failed(adapter, req->keys[i]);
			idpf_psp_tx_key_put(req->keys[i]);
		}
		kfree(req);
	}

	list_for_each_entry_safe(key, tmp, &keys, ins_node) {
		list_del_init(&key->ins_node);
		idpf_psp_tx_key_failed(adapter, key);
		idpf_psp_tx_key_put(key);
	}

	/* The mailbox task can still queue deletions, e.g. of late insertions */
	spin_lock_bh(&psp->del_lock);
	psp->del_stopped = true;
	list_splice_init(&psp->del_list, &keys);
	spin_unlock_bh(&psp->del_lock);

	list_for_each_entry_safe(key, tmp, &keys, del_node) {
		list_del_init(&key->del_node);
		idpf_psp_tx_key_put(key);
	}

	/* The keys are deleted when the PSP device is unregistered, which
	 * happens first, see idpf_init_hard_reset()
	 */
	spin_lock_bh(&psp->drain_lock);
	list_splice_init(&psp->drain_list, &keys);
	spin_unlock_bh(&psp->drain_lock);

	list_for_each_entry_safe(key, tmp, &keys, drain_node) {
		list_del_init(&key->drain_node);
		idpf_psp_tx_key_put(key);
	}
}

/**
 * idpf_psp_free - Release the PSP offload resources
 * @adapter: private data struct
 *
 * Called on remove, after idpf_vc_core_deinit().
 */
void idpf_psp_free(struct idpf_adapter *adapter)
{
	idpf_psp_unregister(adapter);
	/* Created even if the workqueue couldn't be allocated */
	debugfs_remove_recursive(adapter->psp.debugfs);
	adapter->psp.debugfs = NULL;

	if (!adapter->psp.wq)
		return;

	idpf_psp_quiesce(adapter);
	destroy_workqueue(adapter->psp.wq);
	adapter->psp.wq = NULL;
}

/**
 * idpf_psp_tx_key_alloc - Allocate the state of a PSP TX key
 *
 * Return: the TX key with a reference, NULL if it couldn't be allocated.
 */
struct idpf_psp_tx_key *idpf_psp_tx_key_alloc(void)
{
	struct idpf_psp_tx_key *key;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return NULL;

	kref_init(&key->ref);
	spin_lock_init(&key->lock);
	key->idx = IDPF_PSP_IDX_IN_PROG;
	key->hw_idx = IDPF_PSP_IDX_NONE;
	INIT_LIST_HEAD(&key->del_node);
	INIT_LIST_HEAD(&key->ins_node);
	__skb_queue_head_init(&key->tx_queue);
	INIT_LIST_HEAD(&key->drain_node);

	return key;
}

/**
 * idpf_psp_tx_key_free - Free the state of a PSP TX key
 * @ref: reference count of the TX key
 */
static void idpf_psp_tx_key_free(struct kref *ref)
{
	struct idpf_psp_tx_key *key = container_of(ref, struct idpf_psp_tx_key,
						   ref);

	/* In case the key was never copied into an insert request */
	memzero_explicit(key->key, sizeof(key->key));
	/* The TX path may still read the SA index of the key */
	kfree_rcu(key, rcu);
}

/**
 * idpf_psp_tx_key_get - Get a reference on a PSP TX key
 * @key: the TX key
 */
void idpf_psp_tx_key_get(struct idpf_psp_tx_key *key)
{
	kref_get(&key->ref);
}

/**
 * idpf_psp_tx_key_put - Release a reference on a PSP TX key
 * @key: the TX key
 */
void idpf_psp_tx_key_put(struct idpf_psp_tx_key *key)
{
	kref_put(&key->ref, idpf_psp_tx_key_free);
}

/**
 * idpf_psp_queue_delete - Queue the deletion of the SA index of a TX key
 * @adapter: private data struct
 * @key: the TX key, whose hw_idx is the SA index to delete
 *
 * The deletion requests are sent by the PSP work, which releases the
 * reference taken on @key once the SA index was deleted, see
 * idpf_send_delete_psp_keys(). No deletion is queued during a reset or
 * remove, nor once idpf_psp_quiesce() dropped the queued ones: the SADB is
 * flushed by the reset, and by the function reset on remove.
 */
void idpf_psp_queue_delete(struct idpf_adapter *adapter,
			   struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	bool queued;

	if (idpf_is_reset_in_prog(adapter) ||
	    test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return;

	spin_lock_bh(&psp->del_lock);
	queued = !psp->del_stopped;
	if (queued) {
		idpf_psp_tx_key_get(key);
		list_add_tail(&key->del_node, &psp->del_list);
	}
	spin_unlock_bh(&psp->del_lock);

	if (queued)
		idpf_queue_psp_work(adapter);
}

/**
 * idpf_psp_tx_purge - Drop the PSP packets of a list
 * @adapter: private data struct
 * @list: the packets
 */
static void idpf_psp_tx_purge(struct idpf_adapter *adapter,
			      struct sk_buff_head *list)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(list))) {
		atomic_inc(&adapter->psp.tx_drops);
		kfree_skb_reason(skb, SKB_DROP_REASON_PSP_OUTPUT);
	}
}

/**
 * idpf_psp_tx_drain_queue - Schedule the transmission of queued packets
 * @adapter: private data struct
 * @key: TX key whose SA index is known, with packets queued
 *
 * Called with @key->lock held. The SA index is published to the TX path once
 * the queued packets are transmitted, see idpf_psp_tx_drain_key(), so that
 * they aren't overtaken by later packets.
 */
static void idpf_psp_tx_drain_queue(struct idpf_adapter *adapter,
				    struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;

	spin_lock_bh(&psp->drain_lock);
	if (list_empty(&key->drain_node)) {
		idpf_psp_tx_key_get(key);
		list_add_tail(&key->drain_node, &psp->drain_list);
	}
	spin_unlock_bh(&psp->drain_lock);

	idpf_queue_psp_work(adapter);
}

/**
 * idpf_psp_tx_drain_cancel - Take a deleted TX key off the drain list
 * @adapter: private data struct
 * @key: the TX key
 */
static void idpf_psp_tx_drain_cancel(struct idpf_adapter *adapter,
				     struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	bool queued;

	spin_lock_bh(&psp->drain_lock);
	queued = !list_empty(&key->drain_node);
	list_del_init(&key->drain_node);
	spin_unlock_bh(&psp->drain_lock);

	if (queued)
		idpf_psp_tx_key_put(key);
}

/**
 * idpf_psp_tx_drain_key - Transmit the queued packets of a TX key
 * @adapter: private data struct
 * @key: TX key taken off the drain list
 *
 * Transmit the packets queued until the SA index of the key was known, then
 * publish the SA index when the queue is empty: the packets transmitted
 * meanwhile are queued behind the drained ones.
 */
static void idpf_psp_tx_drain_key(struct idpf_adapter *adapter,
				  struct idpf_psp_tx_key *key)
{
	struct idpf_psp_tx psp = {
		.spi		= key->spi,
		.version	= key->version,
	};
	struct sk_buff_head batch;
	struct sk_buff *skb;

	__skb_queue_head_init(&batch);

	for (;;) {
		spin_lock_bh(&key->lock);
		/* Unless the key was deleted meanwhile, which purged the queue */
		if (key->idx != IDPF_PSP_IDX_IN_PROG) {
			spin_unlock_bh(&key->lock);
			return;
		}

		if (skb_queue_empty(&key->tx_queue)) {
			WRITE_ONCE(key->idx, key->hw_idx);
			spin_unlock_bh(&key->lock);
			return;
		}

		skb_queue_splice_init(&key->tx_queue, &batch);
		psp.saidx = key->hw_idx;
		spin_unlock_bh(&key->lock);

		while ((skb = __skb_dequeue(&batch))) {
			if (!idpf_tx_psp_xmit(skb, &psp))
				atomic_inc(&adapter->psp.tx_drops);
		}
	}
}

/**
 * idpf_psp_tx_drain - Transmit the packets of the TX keys of the drain list
 * @adapter: private data struct
 *
 * Called from the PSP work.
 */
static void idpf_psp_tx_drain(struct idpf_adapter *adapter)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct idpf_psp_tx_key *key;

	for (;;) {
		spin_lock_bh(&psp->drain_lock);
		key = list_first_entry_or_null(&psp->drain_list,
					       struct idpf_psp_tx_key,
					       drain_node);
		if (key)
			list_del_init(&key->drain_node);
		spin_unlock_bh(&psp->drain_lock);

		if (!key)
			return;

		idpf_psp_tx_drain_key(adapter, key);
		idpf_psp_tx_key_put(key);
	}
}

/**
 * idpf_psp_tx_key_inserted - Complete the insertion of a TX key
 * @adapter: private data struct
 * @key: TX key of an insert request
 * @saidx: SA index the key was inserted at, see idpf_psp_saidx_ok()
 *
 * Called from the insert response callback, must not sleep.
 */
void idpf_psp_tx_key_inserted(struct idpf_adapter *adapter,
			      struct idpf_psp_tx_key *key, u32 saidx)
{
	bool deleted;

	atomic_inc(&adapter->psp.keys_inserted);

	spin_lock_bh(&key->lock);
	key->hw_idx = saidx;
	deleted = key->idx == IDPF_PSP_IDX_DELETED;
	if (!deleted) {
		/* Packets were queued: use the SA index once they are sent */
		if (skb_queue_empty(&key->tx_queue))
			WRITE_ONCE(key->idx, saidx);
		else
			idpf_psp_tx_drain_queue(adapter, key);
	}
	spin_unlock_bh(&key->lock);

	/* The key was deleted while its insertion was pending */
	if (deleted)
		idpf_psp_queue_delete(adapter, key);
}

/**
 * idpf_psp_tx_key_failed - Fail the insertion of a TX key
 * @adapter: private data struct
 * @key: TX key of an insert request
 *
 * Called from the insert response callback, must not sleep.
 */
void idpf_psp_tx_key_failed(struct idpf_adapter *adapter,
			    struct idpf_psp_tx_key *key)
{
	struct sk_buff_head drop;

	__skb_queue_head_init(&drop);
	atomic_inc(&adapter->psp.insert_errors);
	/* The SADB entry reserved for the key wasn't used */
	atomic_dec(&adapter->psp.sadb_used);

	spin_lock_bh(&key->lock);
	if (key->idx == IDPF_PSP_IDX_IN_PROG)
		WRITE_ONCE(key->idx, IDPF_PSP_IDX_ERROR);
	skb_queue_splice_init(&key->tx_queue, &drop);
	spin_unlock_bh(&key->lock);

	idpf_psp_tx_purge(adapter, &drop);
}

/**
 * idpf_psp_sadb_full - Check if new PSP keys must be refused
 * @adapter: private data struct
 *
 * Return: true if the SADB or the insertion queue is full, false otherwise.
 */
static bool idpf_psp_sadb_full(struct idpf_adapter *adapter)
{
	/* sadb_entries fits in 26 bits, see idpf_psp_negotiate_caps() */
	return atomic_read(&adapter->psp.sadb_used) >=
	       (int)adapter->psp.sadb_entries ||
	       READ_ONCE(adapter->psp.ins_queued) >= IDPF_PSP_INS_QUEUE_MAX;
}

/**
 * idpf_psp_queue_insert - Queue a TX key for insertion into the SADB
 * @adapter: private data struct
 * @key: the TX key, with its SPI and key set
 *
 * Reserve a SADB entry for the key and queue it for insertion. The PSP work
 * inserts the queued keys, see idpf_send_insert_psp_keys(), and releases the
 * reference taken on @key once the insertion completed.
 *
 * Return: 0 on success, -ENOSPC if the SADB or the insertion queue is full.
 */
int idpf_psp_queue_insert(struct idpf_adapter *adapter,
			  struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;

	spin_lock_bh(&psp->insert_lock);
	if (idpf_psp_sadb_full(adapter)) {
		spin_unlock_bh(&psp->insert_lock);
		atomic_inc(&psp->keys_refused);
		return -ENOSPC;
	}

	atomic_inc(&psp->sadb_used);
	idpf_psp_tx_key_get(key);
	list_add_tail(&key->ins_node, &psp->ins_list);
	WRITE_ONCE(psp->ins_queued, psp->ins_queued + 1);
	spin_unlock_bh(&psp->insert_lock);

	idpf_queue_psp_work(adapter);

	return 0;
}

/**
 * idpf_psp_assoc_key - Get the location of the TX key of a PSP association
 * @pas: the PSP association
 *
 * Return: the driver data of @pas, which holds a pointer to its TX key, see
 * idpf_psp_register().
 */
static struct idpf_psp_tx_key __rcu **idpf_psp_assoc_key(struct psp_assoc *pas)
{
	return (struct idpf_psp_tx_key __rcu **)pas->drv_data;
}

/**
 * idpf_psp_tx_key_delete - Delete a TX key
 * @adapter: private data struct
 * @key: the TX key
 *
 * Mark the key deleted, so that the TX path drops its packets, and delete its
 * SA index from the SADB, or cancel its insertion.
 */
static void idpf_psp_tx_key_delete(struct idpf_adapter *adapter,
				   struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct sk_buff_head drop;
	bool queued, inserted;

	__skb_queue_head_init(&drop);
	spin_lock_bh(&key->lock);
	WRITE_ONCE(key->idx, IDPF_PSP_IDX_DELETED);
	/* If the insertion is pending, its SA index is deleted once it
	 * completes, see idpf_psp_tx_key_inserted()
	 */
	inserted = idpf_psp_idx_valid(key->hw_idx);
	skb_queue_splice_init(&key->tx_queue, &drop);
	spin_unlock_bh(&key->lock);

	/* Cancel the insertion if the key is still queued for it. Marked
	 * deleted first: idpf_psp_insert_requeue() doesn't queue it again.
	 */
	spin_lock_bh(&psp->insert_lock);
	queued = !list_empty(&key->ins_node);
	if (queued) {
		list_del_init(&key->ins_node);
		WRITE_ONCE(psp->ins_queued, psp->ins_queued - 1);
	}
	spin_unlock_bh(&psp->insert_lock);

	if (queued) {
		atomic_dec(&psp->sadb_used);
		idpf_psp_tx_key_put(key);
	}

	idpf_psp_tx_drain_cancel(adapter, key);
	idpf_psp_tx_purge(adapter, &drop);

	if (inserted)
		idpf_psp_queue_delete(adapter, key);
}

/**
 * idpf_psp_tx_key_add - Add a PSP TX key
 * @psd: PSP device
 * @pas: PSP association of the key
 * @extack: netlink extended ack for error reporting
 *
 * Queue the TX key for insertion into the SADB and store its state in the
 * driver data of @pas. The SA index is used by the TX path once the insertion
 * completed, see idpf_psp_tx_key_inserted(), the packets transmitted before
 * are queued until then.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int idpf_psp_tx_key_add(struct psp_dev *psd, struct psp_assoc *pas,
			       struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	struct idpf_psp_tx_key *key;
	int err;

	/* Only version 0 keys are inserted, see idpf_psp_register() */
	if (psp_key_size(pas->version) != sizeof(key->key)) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported PSP version");
		return -EOPNOTSUPP;
	}

	key = idpf_psp_tx_key_alloc();
	if (!key)
		return -ENOMEM;

	key->spi = pas->tx.spi;
	key->version = pas->version;
	memcpy(key->key, pas->tx.key, sizeof(key->key));

	err = idpf_psp_queue_insert(adapter, key);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "PSP SADB full");
		idpf_psp_tx_key_put(key);
		return err;
	}

	/* The reference of the association */
	rcu_assign_pointer(*idpf_psp_assoc_key(pas), key);

	return 0;
}

/**
 * idpf_psp_tx_key_del - Delete a PSP TX key
 * @psd: PSP device
 * @pas: PSP association of the key
 */
static void idpf_psp_tx_key_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	struct idpf_psp_tx_key __rcu **slot = idpf_psp_assoc_key(pas);
	struct idpf_psp_tx_key *key;

	key = rcu_dereference_protected(*slot, lockdep_is_held(&psd->lock));
	if (!key)
		return;

	/* The TX path may still see the key, it is freed after an RCU grace
	 * period, see idpf_psp_tx_key_free()
	 */
	RCU_INIT_POINTER(*slot, NULL);

	idpf_psp_tx_key_delete(adapter, key);
	idpf_psp_tx_key_put(key);
}

/**
 * idpf_psp_tx_queue_skb - Queue a PSP packet until its SA index is known
 * @adapter: private data struct
 * @tx_q: TX queue of the packet
 * @key: TX key of the packet
 * @skb: the packet
 * @psp: PSP parameters of the packet
 *
 * Return: IDPF_PSP_TX_SEND with the SA index in @psp if it was published
 * meanwhile, IDPF_PSP_TX_CONSUMED if the packet was queued or dropped.
 */
static enum idpf_psp_tx_verdict
idpf_psp_tx_queue_skb(struct idpf_adapter *adapter, struct idpf_queue *tx_q,
		      struct idpf_psp_tx_key *key, struct sk_buff *skb,
		      struct idpf_psp_tx *psp)
{
	u32 idx;

	spin_lock_bh(&key->lock);
	idx = key->idx;
	if (idpf_psp_idx_valid(idx)) {
		spin_unlock_bh(&key->lock);
		psp->saidx = idx;

		return IDPF_PSP_TX_SEND;
	}

	if (idx == IDPF_PSP_IDX_IN_PROG &&
	    skb_queue_len(&key->tx_queue) < IDPF_PSP_TX_QUEUE_MAX) {
		__skb_queue_tail(&key->tx_queue, skb);
		spin_unlock_bh(&key->lock);

		return IDPF_PSP_TX_CONSUMED;
	}
	spin_unlock_bh(&key->lock);

	/* The queue is full, the insertion failed or the key was deleted */
	atomic_inc(&adapter->psp.tx_drops);
	idpf_tx_drop_skb(tx_q, skb);

	return IDPF_PSP_TX_CONSUMED;
}

/**
 * __idpf_psp_tx_prep - Get the PSP parameters of a TX packet
 * @vport: vport the packet is transmitted on
 * @tx_q: TX queue of the packet
 * @skb: the packet
 * @pas: PSP association of the packet
 * @psp: filled with the PSP parameters of the packet
 *
 * Called from the TX path with the RCU read lock held, see
 * idpf_psp_tx_prep().
 *
 * Return: IDPF_PSP_TX_SEND if the packet can be transmitted with @psp,
 * IDPF_PSP_TX_CONSUMED if it was queued until the SA index of its TX key is
 * known, or dropped.
 */
enum idpf_psp_tx_verdict
__idpf_psp_tx_prep(const struct idpf_vport *vport, struct idpf_queue *tx_q,
		   struct sk_buff *skb, struct psp_assoc *pas,
		   struct idpf_psp_tx *psp)
{
	struct idpf_psp_tx_key *key;
	u32 idx;

	/* Only the splitq TX path encrypts, see idpf_psp_register() */
	if (unlikely(!idpf_is_queue_model_split(vport->dflt_qv_rsrc.txq_model)))
		goto drop;

	psp->spi = pas->tx.spi;
	psp->version = pas->version;

	key = rcu_dereference(*idpf_psp_assoc_key(pas));
	if (unlikely(!key))
		goto drop;

	/* Read the SA index once, it can be published concurrently */
	idx = READ_ONCE(key->idx);
	if (likely(idpf_psp_idx_valid(idx))) {
		psp->saidx = idx;

		return IDPF_PSP_TX_SEND;
	}

	return idpf_psp_tx_queue_skb(vport->adapter, tx_q, key, skb, psp);

drop:
	atomic_inc(&vport->adapter->psp.tx_drops);
	idpf_tx_drop_skb(tx_q, skb);

	return IDPF_PSP_TX_CONSUMED;
}

/**
 * idpf_psp_tx_ctx_desc - Build the context descriptor of a PSP packet
 * @desc: the context descriptor
 * @off: offload parameters of the packet, see idpf_tso()
 * @tso: whether the packet uses TSO
 * @saidx: SA index of the TX key of the packet
 *
 * PSP packets use the TX native "with SA with Host offload" TSO context
 * descriptor (DTYPE 9), with or without TSO. Its split-DMA fields (FTYPE,
 * FNUM, PFNUM and HOST) are 0, a 0 FTYPE is FTYPE_VF, except for the bits of 26
 * bit SA indexes: SA index bits 21 to 24 are in the PFNUM field and bit 25 in
 * bit 0 of the HOST field.
 */
void idpf_psp_tx_ctx_desc(union idpf_flex_tx_ctx_desc *desc,
			  const struct idpf_tx_offload_params *off, bool tso,
			  u32 saidx)
{
	u64 qw1 = IDPF_TX_DESC_DTYPE_FLEX_HOSTSPLIT_SA_TSO_CTX;
	struct idpf_flex_tx_hs_ctx_desc *ctx =
		(struct idpf_flex_tx_hs_ctx_desc *)desc;
	u32 host_fnum_tlen = 0;

	memset(ctx, 0, sizeof(*ctx));

	if (tso) {
		qw1 |= IDPF_TX_FLEX_CTX_DESC_CMD_TSO;
		host_fnum_tlen = off->tso_len & IDPF_TXD_FLEX_CTX_TLEN_M;
		ctx->qw0.tso.ftype_mss_rt =
			cpu_to_le16(off->mss & IDPF_TXD_FLEX_CTX_MSS_RT_M);
		ctx->qw0.tso.hdr_len = off->tso_hdr_len;
	}

	/* Parser tag 1, for the benefit of the FXP */
	ctx->qw0.tso.ptag = 1;

	host_fnum_tlen |= ((saidx >> IDPF_PSP_SAIDX_HOST_S) & 1) <<
			  IDPF_TXD_FLEX_CTX_HOST_S;
	ctx->qw0.tso.host_fnum_tlen = cpu_to_le32(host_fnum_tlen);

	qw1 |= ((u64)(saidx & IDPF_TXD_FLEX_CTX_QW1_SAIDX_M) <<
		IDPF_TXD_FLEX_CTX_QW1_SAIDX_S) |
	       ((u64)((saidx >> IDPF_PSP_SAIDX_PFNUM_S) &
		      IDPF_TXD_FLEX_CTX_QW1_PFNUM_M) <<
		IDPF_TXD_FLEX_CTX_QW1_PFNUM_S) |
	       IDPF_TXD_FLEX_CTX_QW1_SAIDX_VALID;
	ctx->qw1_cmd_dtype = cpu_to_le64(qw1);
}

/**
 * idpf_psp_tx_encap - Add the UDP and PSP headers to a PSP packet
 * @tx_q: TX queue of the packet
 * @skb: the packet
 * @psp: PSP parameters of the packet
 *
 * Called once the TX resources of the packet are reserved, so that a packet
 * that is requeued after NETDEV_TX_BUSY isn't encapsulated twice. The HW
 * encrypts the packet and appends the ICV.
 *
 * Return: true on success, false if the packet must be dropped.
 */
bool idpf_psp_tx_encap(struct idpf_queue *tx_q, struct sk_buff *skb,
		       const struct idpf_psp_tx *psp)
{
	if (likely(psp_dev_encapsulate(sock_net(skb->sk), skb, psp->spi,
				       psp->version, 0)))
		return true;

	atomic_inc(&idpf_netdev_to_adapter(tx_q->netdev)->psp.tx_drops);

	return false;
}

/**
 * idpf_psp_set_config - Set the PSP device configuration
 * @psd: PSP device
 * @conf: new configuration
 * @extack: netlink extended ack for error reporting
 *
 * The configuration is applied by the PSP core. The HW decrypts the PSP
 * packets in any case: the decrypted packets are dropped while no PSP version
 * is enabled, see idpf_psp_rx_process_skb().
 *
 * Return: 0.
 */
static int idpf_psp_set_config(struct psp_dev *psd, struct psp_dev_config *conf,
			       struct netlink_ext_ack *extack)
{
	return 0;
}

/**
 * idpf_psp_rx_gen_update - Track the master key of an allocated SPI
 * @adapter: private data struct
 * @psd: PSP device, locked
 * @spi: SPI allocated by the CP
 * @cp_gen: CP master key generation of @spi
 *
 * Bit 31 of an SPI selects one of the two master keys of the CP, a rotation
 * replaces the older one. The HW doesn't tell which master key decrypted a
 * packet: report the PSP device generation that was current when the first
 * SPI of the master key was allocated, which is the generation of the
 * associations using it, see idpf_psp_rx_process_skb(). The CP master key
 * generation tells when a master key was replaced, including by a rotation
 * the PSP core didn't request, see idpf_psp_rotation_event().
 *
 * Return: 0 on success, -EAGAIN if @spi has the master key of the last SPI of
 * its phase but the PSP device generation changed: the CP didn't apply the
 * rotation assumed by idpf_psp_key_rotate(), the generation is restored. The
 * CP processes the mailbox requests in order, so it won't apply a timed-out
 * rotation after answering this later allocation.
 */
static int idpf_psp_rx_gen_update(struct idpf_adapter *adapter,
				  struct psp_dev *psd, __be32 spi, u32 cp_gen)
{
	struct idpf_psp_rx_gen *rx_gen;

	lockdep_assert_held(&psd->lock);

	rx_gen = &adapter->psp.rx_gen[be32_to_cpu(spi) >> 31];
	if (rx_gen->gen != IDPF_PSP_GEN_UNKNOWN && rx_gen->cp_gen == cp_gen) {
		if (rx_gen->gen == psd->generation)
			return 0;

		netdev_warn(psd->main_netdev,
			    "PSP key rotation not applied by CP, generation restored to %u\n",
			    rx_gen->gen);
		psd->generation = rx_gen->gen;
		adapter->psp.generation = rx_gen->gen;

		return -EAGAIN;
	}

	rx_gen->cp_gen = cp_gen;
	WRITE_ONCE(rx_gen->gen, psd->generation);

	return 0;
}

/**
 * idpf_psp_rx_spi_alloc - Allocate a PSP RX SPI and key
 * @psd: PSP device
 * @version: PSP version
 * @key: filled with the allocated SPI and key
 * @extack: netlink extended ack for error reporting
 *
 * Allocate one RX key with a synchronous VIRTCHNL2_OP_PSP_ALLOCATE_KEYS
 * request.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int idpf_psp_rx_spi_alloc(struct psp_dev *psd, u32 version,
				 struct psp_key_parsed *key,
				 struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	struct idpf_psp_rx_key rx_key;
	int err;

	/* Only version 0 keys are allocated, see idpf_psp_register() */
	if (psp_key_size(version) != sizeof(rx_key.key)) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported PSP version");
		return -EOPNOTSUPP;
	}

	/* Refuse new connections whose TX key couldn't be inserted */
	if (idpf_psp_sadb_full(adapter)) {
		atomic_inc(&adapter->psp.keys_refused);
		NL_SET_ERR_MSG_MOD(extack, "PSP SADB full");
		return -ENOSPC;
	}

	err = idpf_send_allocate_psp_key(adapter, &rx_key);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to allocate RX SPI and key");
		return err;
	}

	err = idpf_psp_rx_gen_update(adapter, psd, rx_key.spi, rx_key.generation);
	if (err) {
		memzero_explicit(&rx_key, sizeof(rx_key));
		NL_SET_ERR_MSG_MOD(extack,
				   "PSP key rotation not applied by CP, generation restored");
		return err;
	}

	key->spi = rx_key.spi;
	memcpy(key->key, rx_key.key, sizeof(rx_key.key));
	memzero_explicit(&rx_key, sizeof(rx_key));

	return 0;
}

/**
 * idpf_psp_key_rotate - Rotate the PSP master keys
 * @psd: PSP device
 * @extack: netlink extended ack for error reporting
 *
 * The PSP core increments the PSP device generation before calling this op
 * and doesn't restore it if the op fails, see psp_nl_key_rotate_doit(): restore
 * it then, the master keys didn't change. If the request timed out, the CP may
 * have rotated: report the rotation, as an association reported stale too
 * early is better than one that can no longer decrypt without being reported
 * stale. If the CP didn't rotate, the next RX SPI allocation restores the
 * generation, see idpf_psp_rx_gen_update(). -ENXIO is a failure: the mailbox
 * was shut down, before the request was sent or for a reset that unregisters
 * the PSP device.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int idpf_psp_key_rotate(struct psp_dev *psd,
			       struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	int err;

	err = idpf_psp_rotation_request(adapter);
	if (err == -ETIME) {
		netdev_warn(psd->main_netdev,
			    "PSP key rotation outcome unknown (%d), assuming rotated\n",
			    err);
		err = 0;
	}
	if (err) {
		psd->generation = adapter->psp.generation;

		if (err == -EOPNOTSUPP)
			NL_SET_ERR_MSG_MOD(extack, "PSP key rotation request not granted by CP");
		else
			NL_SET_ERR_MSG_MOD(extack, "PSP key rotation request failed");

		return err;
	}

	adapter->psp.generation = psd->generation;

	return 0;
}

/**
 * idpf_psp_get_stats - Get the PSP device statistics
 * @psd: PSP device
 * @stats: statistics to fill in
 *
 * Read the PSP statistics with VIRTCHNL2_OP_GET_PSP_STATS. The last
 * statistics read are reported if they can't be read, e.g. during reset.
 */
static void idpf_psp_get_stats(struct psp_dev *psd, struct psp_dev_stats *stats)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	struct idpf_psp_dev_stats *cur = &adapter->psp.stats;
	struct virtchnl2_psp_stats_response resp;
	u32 supported;

	if (!idpf_send_get_psp_stats(adapter, &resp)) {
		supported = le32_to_cpu(resp.supported_stats);

		if (supported & VIRTCHNL2_PSP_STAT_COMMON) {
			const struct virtchnl2_psp_common_stats *cs =
				&resp.common_stats;

			cur->rx_packets = le64_to_cpu(cs->rx_decrypted_packets);
			cur->rx_bytes = le64_to_cpu(cs->rx_decrypted_bytes);
			cur->rx_auth_fail = le32_to_cpu(cs->rx_auth_failures);
			/* PSP spec: rx_error counts length/framing errors,
			 * rx_bad miscellaneous errors.
			 */
			cur->rx_error = le32_to_cpu(cs->rx_bad_packets);
			cur->rx_bad = le32_to_cpu(cs->rx_misc_errors);
			cur->tx_packets = le64_to_cpu(cs->tx_encrypted_packets);
			cur->tx_bytes = le64_to_cpu(cs->tx_encrypted_bytes);
			cur->tx_error = (u64)le32_to_cpu(cs->tx_misc_errors) +
					le32_to_cpu(cs->tx_bad_packets);
			if (supported & VIRTCHNL2_PSP_STAT_ADDON)
				cur->tx_error +=
					le32_to_cpu(resp.addon_stats.tx_inv_sa_packets);
		}
	}

	stats->rx_packets = cur->rx_packets;
	stats->rx_bytes = cur->rx_bytes;
	stats->rx_auth_fail = cur->rx_auth_fail;
	stats->rx_error = cur->rx_error;
	stats->rx_bad = cur->rx_bad;
	stats->tx_packets = cur->tx_packets;
	stats->tx_bytes = cur->tx_bytes;
	stats->tx_error = cur->tx_error;
}

/* PSP device operations, see idpf_psp_register() */
static struct psp_dev_ops idpf_psp_ops = {
	.set_config	= idpf_psp_set_config,
	.rx_spi_alloc	= idpf_psp_rx_spi_alloc,
	.tx_key_add	= idpf_psp_tx_key_add,
	.tx_key_del	= idpf_psp_tx_key_del,
	.key_rotate	= idpf_psp_key_rotate,
	.get_stats	= idpf_psp_get_stats,
};

/**
 * idpf_psp_register - Register the PSP device
 * @adapter: private data struct
 *
 * Register the PSP device of the first netdev if PSP offload was negotiated
 * and the netdev is registered.
 * Only the splitq TX path encrypts PSP packets: the PSP device is only
 * registered if vport 0 uses the splitq queue model.
 * Called from the virtchnl event task, see idpf_init_hard_reset().
 */
void idpf_psp_register(struct idpf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct idpf_vport *vport;
	struct psp_dev *psd;

	if (!idpf_is_psp_ena(adapter))
		return;

	/* idpf_decfg_netdev() clears IDPF_VPORT_REG_NETDEV, then waits for the
	 * lock in idpf_psp_unregister() before freeing the netdev and vports
	 */
	mutex_lock(&adapter->psp.psp_dev_lock);
	if (adapter->psp.psp_dev || adapter->psp.reg_blocked)
		goto unlock;

	if (!adapter->netdevs || !adapter->netdevs[0] ||
	    !test_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config[0]->flags))
		goto unlock;

	vport = adapter->vports ? adapter->vports[0] : NULL;
	if (!vport) {
		dev_notice(dev, "PSP disabled, vport 0 not created\n");
		goto unlock;
	}

	if (!idpf_is_queue_model_split(vport->dflt_qv_rsrc.txq_model) ||
	    !idpf_is_queue_model_split(vport->dflt_qv_rsrc.rxq_model)) {
		dev_notice(dev, "PSP disabled, vport 0 doesn't use the splitq queue model\n");
		goto unlock;
	}

	/* The driver data of an association holds a pointer to its TX key */
	adapter->psp.caps.assoc_drv_spc = sizeof(struct idpf_psp_tx_key *);
	/* The driver only allocates and inserts PSP version 0 keys */
	adapter->psp.caps.versions = BIT(PSP_VERSION_HDR0_AES_GCM_128);

	psd = psp_dev_create(adapter->netdevs[0], &idpf_psp_ops,
			     &adapter->psp.caps, NULL);
	if (IS_ERR(psd)) {
		dev_err(dev, "PSP failed to register: %pe\n", psd);
		goto unlock;
	}

	adapter->psp.psp_dev = psd;
	dev_info(dev, "PSP Netlink device registered successfully: id=%u\n",
		 psd->id);
unlock:
	mutex_unlock(&adapter->psp.psp_dev_lock);
}

/**
 * idpf_psp_block_register - Block or allow the registration of the PSP device
 * @adapter: private data struct
 * @block: true from idpf_reset_prepare(), false once the PCI reset is done
 *
 * A hard reset racing with idpf_reset_prepare() would register the PSP device
 * again while the mailbox its ops use is torn down.
 */
void idpf_psp_block_register(struct idpf_adapter *adapter, bool block)
{
	mutex_lock(&adapter->psp.psp_dev_lock);
	adapter->psp.reg_blocked = block;
	mutex_unlock(&adapter->psp.psp_dev_lock);
}

/**
 * idpf_psp_unregister - Unregister the PSP device
 * @adapter: private data struct
 *
 * The PSP core deletes the TX keys of all the associations, see
 * idpf_psp_tx_key_del(). Called before the netdev of the PSP device is
 * unregistered. A concurrent caller, e.g. a hard reset racing with
 * idpf_reset_prepare(), returns once the PSP device ops are done.
 */
void idpf_psp_unregister(struct idpf_adapter *adapter)
{
	struct psp_dev *psd;

	mutex_lock(&adapter->psp.psp_dev_lock);
	psd = adapter->psp.psp_dev;
	if (!psd)
		goto unlock;

	adapter->psp.psp_dev = NULL;
	psp_dev_unregister(psd);

	/* The PSP work may still transmit the packets it took off a TX key
	 * before the key was deleted: wait for it, as the netdev may be freed
	 * next
	 */
	idpf_cancel_psp_work(adapter);
unlock:
	mutex_unlock(&adapter->psp.psp_dev_lock);
}

/**
 * idpf_psp_rx_process_skb - Decapsulate a decrypted PSP packet
 * @rxq: RX queue the packet was received on
 * @skb: received packet, skb->data points to the network header
 * @rx_ptype: splitq ptype of the packet
 *
 * Remove the UDP and PSP headers of a packet decrypted by the HW with
 * psp_dev_rcv(), which also attaches the PSP extension of the PSP device of
 * the netdev. The packet is dropped while no PSP version is enabled: the HW
 * decrypts it anyway, it must not be delivered as plain UDP.
 *
 * Return: 0 on success or if the packet isn't a decrypted PSP packet,
 * negative error code if the packet must be dropped.
 */
int idpf_psp_rx_process_skb(struct idpf_queue *rxq, struct sk_buff *skb,
			    u16 rx_ptype)
{
	struct idpf_adapter_psp *psp = &rxq->vport->adapter->psp;
	struct idpf_vport *vport = rxq->vport;
	struct psp_skb_ext *pse;
	struct psp_dev *psd;
	u16 dev_id;
	int err;
	u8 gen;

	/* Only decapsulate the decrypted PSP packets (MAC, IPV6, UDP, PSP, TCP,
	 * PAY). psp_rx_ptype is IDPF_INVALID_PTYPE_ID if PSP offload is
	 * disabled or the CP didn't report the PSP RX ptype.
	 */
	if (rx_ptype != rxq->psp_rx_ptype)
		return 0;

	rcu_read_lock();
	psd = rcu_dereference(vport->netdev->psp_dev);
	if (!psd || !READ_ONCE(psd->config.versions)) {
		rcu_read_unlock();
		goto drop;
	}
	dev_id = psd->id;
	rcu_read_unlock();

	/* psp_dev_rcv() expects skb->data at the MAC header, which
	 * eth_type_trans() already pulled. The ICV was removed by the HW.
	 */
	skb_push(skb, ETH_HLEN);
	skb->mac_len = ETH_HLEN;
	err = psp_dev_rcv(skb, dev_id, IDPF_PSP_GEN_UNKNOWN, false);
	if (!err) {
		/* psp_dev_rcv() moved the MAC header over the removed headers */
		skb_reset_mac_header(skb);
		skb->decrypted = 1;

		/* The generation of the master key of the SPI */
		pse = (struct psp_skb_ext *)skb_ext_find(skb, SKB_EXT_PSP);
		gen = READ_ONCE(psp->rx_gen[be32_to_cpu(pse->spi) >> 31].gen);
		if (gen == IDPF_PSP_GEN_UNKNOWN)
			err = -EINVAL;
		pse->generation = gen;
	}
	skb_pull(skb, ETH_HLEN);

	if (!err)
		return 0;

drop:
	atomic_inc(&psp->rx_drops);

	return -EINVAL;
}
