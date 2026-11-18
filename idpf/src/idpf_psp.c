/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only

#include "idpf_psp.h"
#include "idpf_psp_virtchnl.h"

#include <net/psp.h>

/* Delay before the PSP work sends again a request that couldn't be sent */
#define IDPF_PSP_RETRY_MSEC		100

/* Maximum number of TX keys queued for insertion */
#define IDPF_PSP_INS_QUEUE_MAX		1024

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

/**
 * idpf_psp_work - Send the PSP key insertion and deletion requests
 * @work: work of struct idpf_adapter_psp
 *
 * Time out the insert request in flight, then send at most one request of
 * each kind. The work is queued again when there is more to do, or after a
 * delay when a request couldn't be sent.
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
 * idpf_psp_init - Initialize PSP offload
 * @adapter: private data struct
 *
 * Called on each core init, including after a hard reset: PSP offload is
 * negotiated again, the CP may grant different capabilities. PSP offload uses
 * the virtchnl2 crypto offload API: if VIRTCHNL2_CAP_CRYPTO was not granted or
 * the negotiation fails, PSP stays disabled for the adapter instead of failing
 * the core init, see idpf_is_psp_ena().
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

	/* The counters cover the time since the core init */
	atomic_set(&psp->keys_allocated, 0);
	atomic_set(&psp->keys_removed, 0);
	atomic_set(&psp->keys_lost, 0);
	atomic_set(&psp->del_retries, 0);
	atomic_set(&psp->keys_inserted, 0);
	atomic_set(&psp->insert_errors, 0);
	atomic_set(&psp->insert_late, 0);
	atomic_set(&psp->sadb_used, 0);
	atomic_set(&psp->keys_refused, 0);

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

	spin_lock_bh(&psp->del_lock);
	list_splice_init(&psp->del_list, &keys);
	spin_unlock_bh(&psp->del_lock);

	list_for_each_entry_safe(key, tmp, &keys, del_node) {
		list_del_init(&key->del_node);
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
 * remove: the SADB is flushed by the reset, and by the function reset on
 * remove.
 */
void idpf_psp_queue_delete(struct idpf_adapter *adapter,
			   struct idpf_psp_tx_key *key)
{
	struct idpf_adapter_psp *psp = &adapter->psp;

	if (idpf_is_reset_in_prog(adapter) ||
	    test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return;

	idpf_psp_tx_key_get(key);
	spin_lock_bh(&psp->del_lock);
	list_add_tail(&key->del_node, &psp->del_list);
	spin_unlock_bh(&psp->del_lock);

	idpf_queue_psp_work(adapter);
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
	if (!deleted)
		WRITE_ONCE(key->idx, saidx);
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
	atomic_inc(&adapter->psp.insert_errors);
	/* The SADB entry reserved for the key wasn't used */
	atomic_dec(&adapter->psp.sadb_used);

	spin_lock_bh(&key->lock);
	if (key->idx == IDPF_PSP_IDX_IN_PROG)
		WRITE_ONCE(key->idx, IDPF_PSP_IDX_ERROR);
	spin_unlock_bh(&key->lock);
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
	bool queued, inserted;

	/* Cancel the insertion if the key is still queued for it */
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

	spin_lock_bh(&key->lock);
	WRITE_ONCE(key->idx, IDPF_PSP_IDX_DELETED);
	/* If the insertion is pending, its SA index is deleted once it
	 * completes, see idpf_psp_tx_key_inserted()
	 */
	inserted = idpf_psp_idx_valid(key->hw_idx);
	spin_unlock_bh(&key->lock);

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
 * idpf_psp_set_config - Set the PSP device configuration
 * @psd: PSP device
 * @conf: new configuration
 * @extack: netlink extended ack for error reporting
 *
 * The configuration is applied by the PSP core.
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
 */
static void idpf_psp_rx_gen_update(struct idpf_adapter *adapter,
				   struct psp_dev *psd, __be32 spi, u32 cp_gen)
{
	struct idpf_psp_rx_gen *rx_gen;

	lockdep_assert_held(&psd->lock);

	rx_gen = &adapter->psp.rx_gen[be32_to_cpu(spi) >> 31];
	if (rx_gen->gen != IDPF_PSP_GEN_UNKNOWN && rx_gen->cp_gen == cp_gen)
		return;

	rx_gen->cp_gen = cp_gen;
	WRITE_ONCE(rx_gen->gen, psd->generation);
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

	idpf_psp_rx_gen_update(adapter, psd, rx_key.spi, rx_key.generation);

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
 * it then, the master keys didn't change.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int idpf_psp_key_rotate(struct psp_dev *psd,
			       struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(psd->main_netdev);
	int err;

	err = idpf_psp_rotation_request(adapter);
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
 */
void idpf_psp_register(struct idpf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct psp_dev *psd;

	if (!idpf_is_psp_ena(adapter) || adapter->psp.psp_dev)
		return;

	if (!adapter->netdevs || !adapter->netdevs[0] ||
	    !test_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config[0]->flags))
		return;

	/* The driver data of an association holds a pointer to its TX key */
	adapter->psp.caps.assoc_drv_spc = sizeof(struct idpf_psp_tx_key *);
	/* The driver only allocates and inserts PSP version 0 keys */
	adapter->psp.caps.versions = BIT(PSP_VERSION_HDR0_AES_GCM_128);

	psd = psp_dev_create(adapter->netdevs[0], &idpf_psp_ops,
			     &adapter->psp.caps, NULL);
	if (IS_ERR(psd)) {
		dev_err(dev, "PSP failed to register: %pe\n", psd);
		return;
	}

	adapter->psp.psp_dev = psd;
	dev_info(dev, "PSP Netlink device registered successfully: id=%u\n",
		 psd->id);
}

/**
 * idpf_psp_unregister - Unregister the PSP device
 * @adapter: private data struct
 *
 * The PSP core deletes the TX keys of all the associations, see
 * idpf_psp_tx_key_del(). Called before the netdev of the PSP device is
 * unregistered.
 */
void idpf_psp_unregister(struct idpf_adapter *adapter)
{
	struct psp_dev *psd = adapter->psp.psp_dev;

	if (!psd)
		return;

	psp_dev_unregister(psd);
	adapter->psp.psp_dev = NULL;
}
