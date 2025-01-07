/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#include "idpf.h"

static const struct net_device_ops idpf_netdev_ops_splitq;
static const struct net_device_ops idpf_netdev_ops_singleq;

/**
 * idpf_init_vector_stack - Fill the MSIX vector stack with vector index
 * @adapter: private data struct
 *
 * Return 0 on success, error on failure
 */
static int idpf_init_vector_stack(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack;
	u16 min_vec;
	u32 i;

	mutex_lock(&adapter->vector_lock);
	min_vec = adapter->num_msix_entries - adapter->num_avail_msix;
	stack = &adapter->vector_stack;
	stack->size = adapter->num_msix_entries;
	/* set the base and top to point at start of the 'free pool' to
	 * distribute the unused vectors on-demand basis
	 */
	stack->base = min_vec;
	stack->top = min_vec;

	stack->vec_idx = kcalloc(stack->size, sizeof(u16), GFP_KERNEL);
	if (!stack->vec_idx) {
		mutex_unlock(&adapter->vector_lock);

		return -ENOMEM;
	}

	for (i = 0; i < stack->size; i++)
		stack->vec_idx[i] = i;

	mutex_unlock(&adapter->vector_lock);

	return 0;
}

/**
 * idpf_deinit_vector_stack - zero out the MSIX vector stack
 * @adapter: private data struct
 */
void idpf_deinit_vector_stack(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack;

	mutex_lock(&adapter->vector_lock);
	stack = &adapter->vector_stack;
	kfree(stack->vec_idx);
	stack->vec_idx = NULL;
	mutex_unlock(&adapter->vector_lock);
}

/**
 * idpf_mb_intr_rel_irq - Free the IRQ association with the OS
 * @adapter: adapter structure
 *
 * This will also disable interrupt mode and queue up mailbox task. Mailbox
 * task will reschedule itself if not in interrupt mode.
 */
static void idpf_mb_intr_rel_irq(struct idpf_adapter *adapter)
{
	clear_bit(IDPF_MB_INTR_MODE, adapter->flags);
	free_irq(adapter->msix_entries[0].vector, adapter);
	queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task, 0);
	kfree(adapter->mb_vector.name);
	adapter->mb_vector.name = NULL;
}

/**
 * idpf_intr_rel - Release interrupt capabilities and free memory
 * @adapter: adapter to disable interrupts on
 */
void idpf_intr_rel(struct idpf_adapter *adapter)
{
	int err;

	if (!adapter->msix_entries)
		return;

	idpf_mb_intr_rel_irq(adapter);
	pci_free_irq_vectors(adapter->pdev);

	err = idpf_send_dealloc_vectors_msg(adapter);
	if (err && err != -EBUSY)
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to deallocate vectors: %d\n", err);

	idpf_deinit_vector_stack(adapter);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	kfree(adapter->rdma_data.msix_entries);
	adapter->rdma_data.msix_entries = NULL;
}

/**
 * idpf_mb_intr_clean - Interrupt handler for the mailbox
 * @irq: interrupt number
 * @data: pointer to the adapter structure
 */
static irqreturn_t idpf_mb_intr_clean(int __always_unused irq, void *data)
{
	struct idpf_adapter *adapter = data;

	/* MBX while in CORER signals its completion */
	if (test_and_clear_bit(IDPF_CORER_IN_PROG, adapter->flags)) {
		complete(&adapter->corer_done);

		return IRQ_HANDLED;
	}

	/* ASQ may not be set */
	if (adapter->hw.asq) {
		if (!(readl(idpf_get_reg_addr(adapter, adapter->hw.asq->reg.len)) &
		 adapter->hw.asq->reg.len_ena_mask)) {
			set_bit(IDPF_CORER_IN_PROG, adapter->flags);
			reinit_completion(&adapter->corer_done);
		}
	}

	queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task, 0);
	mod_delayed_work(adapter->serv_wq, &adapter->serv_task,
			 msecs_to_jiffies(0));

	return IRQ_HANDLED;
}

/**
 * idpf_mb_irq_enable - Enable MSIX interrupt for the mailbox
 * @adapter: adapter to get the hardware address for register write
 */
static void idpf_mb_irq_enable(struct idpf_adapter *adapter)
{
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m | intr->dyn_ctl_itridx_m;
	writel(val, intr->dyn_ctl);
	writel(intr->icr_ena_ctlq_m, intr->icr_ena);
}

/**
 * idpf_mb_intr_req_irq - Request irq for the mailbox interrupt
 * @adapter: adapter structure to pass to the mailbox irq handler
 */
static int idpf_mb_intr_req_irq(struct idpf_adapter *adapter)
{
	struct idpf_q_vector *mb_vector = &adapter->mb_vector;
	int irq_num, mb_vidx = 0, err;

	irq_num = adapter->msix_entries[mb_vidx].vector;
	mb_vector->name = kasprintf(GFP_KERNEL, "%s-%s-%d",
				    dev_driver_string(&adapter->pdev->dev),
				    "Mailbox", mb_vidx);
	err = request_irq(irq_num, adapter->irq_mb_handler, 0,
			  mb_vector->name, adapter);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"IRQ request for mailbox failed, error: %d\n", err);
		return err;
	}
	set_bit(IDPF_MB_INTR_MODE, adapter->flags);
	return 0;
}

/**
 * idpf_set_mb_vec_id - Set vector index for mailbox
 * @adapter: adapter structure to access the vector chunks
 *
 * The first vector id in the requested vector chunks from the CP is for
 * the mailbox
 */
static void idpf_set_mb_vec_id(struct idpf_adapter *adapter)
{
	if (adapter->req_vec_chunks)
		adapter->mb_vector.v_idx =
			le16_to_cpu(adapter->caps.mailbox_vector_id);
	else
		adapter->mb_vector.v_idx = 0;
}

/**
 * idpf_mb_intr_init - Initialize the mailbox interrupt
 * @adapter: adapter structure to store the mailbox vector
 */
static int idpf_mb_intr_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.reg_ops.mb_intr_reg_init(adapter);
	adapter->irq_mb_handler = idpf_mb_intr_clean;
	return idpf_mb_intr_req_irq(adapter);
}

/**
 * idpf_vector_lifo_push - push MSIX vector index onto stack
 * @adapter: private data struct
 * @vec_idx: vector index to store
 */
static int idpf_vector_lifo_push(struct idpf_adapter *adapter, u16 vec_idx)
{
	struct idpf_vector_lifo *stack = &adapter->vector_stack;

	lockdep_assert_held(&adapter->vector_lock);

	if (stack->top == stack->base) {
		dev_err(idpf_adapter_to_dev(adapter), "Exceeded the vector stack limit: %d\n",
			stack->top);
		return -EINVAL;
	}

	stack->vec_idx[--stack->top] = vec_idx;
	return 0;
}

/**
 * idpf_vector_lifo_pop - pop MSIX vector index from stack
 * @adapter: private data struct
 */
static int idpf_vector_lifo_pop(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack = &adapter->vector_stack;

	lockdep_assert_held(&adapter->vector_lock);

	if (stack->top == stack->size) {
		dev_err(idpf_adapter_to_dev(adapter), "No interrupt vectors are available to distribute!\n");
		return -EINVAL;
	}

	return stack->vec_idx[stack->top++];
}

/**
 * idpf_vector_stash - Store the vector indexes onto the stack
 * @adapter: private data struct
 * @q_vector_idxs: vector index array
 * @vec_info: info related to the number of vectors
 *
 * This function is a no-op if there are no vectors indexes to be stashed
 */
static void idpf_vector_stash(struct idpf_adapter *adapter, u16 *q_vector_idxs,
			      struct idpf_vector_info *vec_info)
{
	int i, base = 0;
	u16 vec_idx;

	lockdep_assert_held(&adapter->vector_lock);

	if (!vec_info->num_curr_vecs)
		return;

	/* For default vports, no need to stash vector allocated from the
	 * default pool onto the stack
	 */
	if (vec_info->default_vport)
		base = IDPF_MIN_Q_VEC;

	for (i = vec_info->num_curr_vecs - 1; i >= base ; i--) {
		vec_idx = q_vector_idxs[i];
		idpf_vector_lifo_push(adapter, vec_idx);
		adapter->num_avail_msix++;
	}
}

/**
 * idpf_req_rel_vector_indexes - Request or release MSIX vector indexes
 * @adapter: driver specific private structure
 * @q_vector_idxs: vector index array
 * @vec_info: info related to the number of vectors
 *
 * This is the core function to distribute the MSIX vectors acquired from the
 * OS. It expectes the caller to pass the number of vectors required and
 * also previously allocated. First, it stashes previously allocated vector
 * indexes on to the stack and then figures out if it can allocate requested
 * vectors. It can wait on acquiring the mutex lock. If the caller passes 0 as
 * requested vectors, then this function just stashes the already allocated
 * vectors and returns 0.
 *
 * Returns actual number of vectors allocated on success, error value on failure
 * If 0 is returned, implies the stack has no vectors to allocate which is also
 * a failure case for the caller
 */
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter, u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info)
{
	u16 num_req_vecs, num_alloc_vecs = 0, max_vecs;
	struct idpf_vector_lifo *stack;
	int i, j, vecid;

	mutex_lock(&adapter->vector_lock);
	stack = &adapter->vector_stack;
	num_req_vecs = vec_info->num_req_vecs;

	/* Stash interrupt vector indexes onto the stack if required */
	idpf_vector_stash(adapter, q_vector_idxs, vec_info);

	if (!num_req_vecs)
		goto rel_lock;

	if (vec_info->default_vport) {
		/* As IDPF_MIN_Q_VEC per default vport is put aside in the
		 * default pool of the stack, use them for default vports
		 */
		j = vec_info->index * IDPF_MIN_Q_VEC + IDPF_MBX_Q_VEC;
		for (i = 0; i < IDPF_MIN_Q_VEC; i++) {
			q_vector_idxs[num_alloc_vecs++] = stack->vec_idx[j++];
			num_req_vecs--;
		}
	}

	/* Find if stack has enough vector to allocate */
	max_vecs = min(adapter->num_avail_msix, num_req_vecs);

	for (j = 0; j < max_vecs; j++) {
		vecid = idpf_vector_lifo_pop(adapter);
		q_vector_idxs[num_alloc_vecs++] = vecid;
	}
	adapter->num_avail_msix -= max_vecs;

rel_lock:
	mutex_unlock(&adapter->vector_lock);
	return num_alloc_vecs;
}

/**
 * idpf_intr_req - Request interrupt capabilities
 * @adapter: adapter to enable interrupts on
 *
 * Returns 0 on success, negative on failure
 */
int idpf_intr_req(struct idpf_adapter *adapter)
{
	u16 num_lan_vecs, min_lan_vecs, num_rdma_vecs = 0, min_rdma_vecs = 0;
	u16 default_vports = idpf_get_default_vports(adapter);
	int num_q_vecs, total_vecs, num_vec_ids;
	int min_vectors, v_actual, err;
	unsigned int vector;
	u16 *vecids;
	int i;

	total_vecs = idpf_get_reserved_vecs(adapter);
	num_lan_vecs = total_vecs;
	if (idpf_is_rdma_cap_ena(adapter)) {
		num_rdma_vecs = idpf_get_reserved_rdma_vecs(adapter);
		min_rdma_vecs = IDPF_MIN_RDMA_VEC;

		if (!num_rdma_vecs) {
			/* If idpf_get_reserved_rdma_vecs is 0, vectors are
			 * pulled from the LAN pool.
			 */
			num_rdma_vecs = min_rdma_vecs;
		} else if (num_rdma_vecs < min_rdma_vecs) {
			dev_err(idpf_adapter_to_dev(adapter),
				"Not enough vectors reserved for rdma (min: %u, current: %u)\n",
				min_rdma_vecs, num_rdma_vecs);
			return -EINVAL;
		}
	}

	num_q_vecs = total_vecs - IDPF_MBX_Q_VEC;

	err = idpf_send_alloc_vectors_msg(adapter, num_q_vecs);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to allocate %d vectors: %d\n", num_q_vecs, err);

		return -EAGAIN;
	}

	min_lan_vecs = IDPF_MBX_Q_VEC + IDPF_MIN_Q_VEC * default_vports;
	min_vectors = min_lan_vecs + min_rdma_vecs;
	v_actual = pci_alloc_irq_vectors(adapter->pdev, min_vectors,
					 total_vecs, PCI_IRQ_MSIX);
	if (v_actual < min_vectors) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to allocate minimum MSIX vectors required: %d\n",
			v_actual);
		err = -EAGAIN;
		goto send_dealloc_vecs;
	}

	num_lan_vecs = v_actual - num_rdma_vecs;

	if (idpf_is_rdma_cap_ena(adapter)) {
		if (v_actual < total_vecs) {
			dev_warn(idpf_adapter_to_dev(adapter),
				 "Warning: not enough vectors available. Defaulting to minimum for RDMA and remaining for LAN.\n");
			num_rdma_vecs = min_rdma_vecs;
			/* Reset num_lan_vecs to account for updated
			 * num_rdma_vecs
			 */
			num_lan_vecs = v_actual - min_rdma_vecs;
		}

		adapter->rdma_data.msix_entries = kcalloc(num_rdma_vecs,
							  sizeof(struct msix_entry),
							  GFP_KERNEL);
		if (!adapter->rdma_data.msix_entries) {
			err = -ENOMEM;
			goto free_irq;
		}
	}

	adapter->msix_entries = kcalloc(num_lan_vecs,
					sizeof(struct msix_entry), GFP_KERNEL);

	if (!adapter->msix_entries) {
		err = -ENOMEM;
		goto free_rdma_msix;
	}

	idpf_set_mb_vec_id(adapter);

	vecids = kcalloc(v_actual, sizeof(u16), GFP_KERNEL);
	if (!vecids) {
		err = -ENOMEM;
		goto free_msix;
	}

	num_vec_ids = idpf_get_vec_ids(adapter, vecids, v_actual,
				       &adapter->req_vec_chunks->vchunks);
	if (num_vec_ids < v_actual) {
		err = -EINVAL;
		goto free_vecids;
	}

	for (i = 0, vector = 0; vector < num_lan_vecs; vector++) {
		adapter->msix_entries[vector].entry = vecids[vector];
		adapter->msix_entries[vector].vector =
			pci_irq_vector(adapter->pdev, vector);
	}
	for (i = 0; i < num_rdma_vecs; vector++, i++) {
		adapter->rdma_data.msix_entries[i].entry = vecids[vector];
		adapter->rdma_data.msix_entries[i].vector =
			pci_irq_vector(adapter->pdev, vector);
	}

	adapter->rdma_data.num_vecs = num_rdma_vecs;
	/* 'num_avail_msix' is used to distribute excess vectors to the vports
	 * after considering the minimum vectors required per each default
	 * vport
	 */
	adapter->num_avail_msix = num_lan_vecs - min_lan_vecs;
	adapter->num_msix_entries = num_lan_vecs;

	/* Fill MSIX vector lifo stack with vector indexes */
	err = idpf_init_vector_stack(adapter);
	if (err)
		goto free_vecids;

	err = idpf_mb_intr_init(adapter);
	if (err)
		goto deinit_vec_stack;
	idpf_mb_irq_enable(adapter);
	kfree(vecids);

	return 0;

deinit_vec_stack:
	idpf_deinit_vector_stack(adapter);
free_vecids:
	kfree(vecids);
free_msix:
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
free_rdma_msix:
	kfree(adapter->rdma_data.msix_entries);
	adapter->rdma_data.msix_entries = NULL;
free_irq:
	pci_free_irq_vectors(adapter->pdev);
send_dealloc_vecs:
	idpf_send_dealloc_vectors_msg(adapter);

	return err;
}

/**
 * idpf_find_mac_filter - Search filter list for specific mac filter
 * @vconfig: Vport config structure
 * @macaddr: The MAC address
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_filter_list_lock.
 **/
static struct idpf_mac_filter *idpf_find_mac_filter(struct idpf_vport_config *vconfig,
						    const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	if (!macaddr)
		return NULL;

	list_for_each_entry(f, &vconfig->user_config.mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}

	return NULL;
}

/**
 * __idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport_config: Vport config structure
 * @macaddr: The MAC address
 *
 * Returns 0 on success, error value on failure
 **/
static int __idpf_del_mac_filter(struct idpf_vport_config *vport_config,
				 const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	spin_lock_bh(&vport_config->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	return 0;
}

/**
 * idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: Main vport structure
 * @np: Netdev private structure
 * @macaddr: The MAC address
 * @async: Don't wait for return message
 *
 * Removes filter from list and if interface is up, tells hardware about the
 * removed filter.
 **/
static int idpf_del_mac_filter(struct idpf_vport *vport,
			       struct idpf_netdev_priv *np,
			       const u8 *macaddr, bool async)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = np->adapter->vport_config[np->vport_idx];

	spin_lock_bh(&vport_config->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		f->remove = true;
	} else {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return -EINVAL;
	}
	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	if (np->active) {
		int err;

		err = idpf_add_del_mac_filters(vport, np, false, async);
		if (err)
			return err;
	}

	return  __idpf_del_mac_filter(vport_config, macaddr);
}

/**
 * __idpf_add_mac_filter - Add mac filter helper function
 * @vport_config: Vport config structure
 * @macaddr: Address to add
 *
 * Takes mac_filter_list_lock spinlock to add new filter to list.
 */
static int __idpf_add_mac_filter(struct idpf_vport_config *vport_config,
				 const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	spin_lock_bh(&vport_config->mac_filter_list_lock);

	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		f->remove = false;
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return 0;
	}

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return -ENOMEM;
	}

	ether_addr_copy(f->macaddr, macaddr);
	list_add_tail(&f->list, &vport_config->user_config.mac_filter_list);
	f->add = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	return 0;
}

/**
 * idpf_add_mac_filter - Add a mac filter to the filter list
 * @vport: Main vport structure
 * @np: Netdev private structure
 * @macaddr: The MAC address
 * @async: Don't wait for return message
 *
 * Returns 0 on success or error on failure. If interface is up, we'll also
 * send the virtchnl message to tell hardware about the filter.
 **/
static int idpf_add_mac_filter(struct idpf_vport *vport,
			       struct idpf_netdev_priv *np,
			       const u8 *macaddr, bool async)
{
	struct idpf_vport_config *vport_config;
	int err;

	vport_config = np->adapter->vport_config[np->vport_idx];
	err = __idpf_add_mac_filter(vport_config, macaddr);
	if (err)
		return err;

	if (np->active)
		err = idpf_add_del_mac_filters(vport, np, true, async);

	return err;
}

/**
 * idpf_del_all_mac_filters - Delete all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Deletes all filters
 */
static void idpf_del_all_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f, *ftmp;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry_safe(f, ftmp, &vport_config->user_config.mac_filter_list,
				 list) {
		list_del(&f->list);
		kfree(f);
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);
}

/**
 * idpf_restore_mac_filters - Re-add all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets add field to true for filters to
 * resync filters back to HW.
 */
static void idpf_restore_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->add = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, netdev_priv(vport->netdev),
				 true, false);
}

/**
 * idpf_remove_mac_filters - Remove all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock. Sets remove field to true for filters
 * to remove filters in HW.
 */
static void idpf_remove_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->remove = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, netdev_priv(vport->netdev),
				 false, false);
}

/**
 * idpf_deinit_mac_addr - deinitialize mac address for vport
 * @vport: main vport structure
 */
static void idpf_deinit_mac_addr(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];

	spin_lock_bh(&vport_config->mac_filter_list_lock);

	f = idpf_find_mac_filter(vport_config, vport->default_mac_addr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);
}

/**
 * idpf_init_mac_addr - initialize mac address for vport
 * @vport: main vport structure
 * @netdev: pointer to netdev struct associated with this vport
 */
static int idpf_init_mac_addr(struct idpf_vport *vport,
			      struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_adapter *adapter = vport->adapter;
	int err;

	if (is_valid_ether_addr(vport->default_mac_addr)) {
		eth_hw_addr_set(netdev, vport->default_mac_addr);
		ether_addr_copy(netdev->perm_addr, vport->default_mac_addr);

		return idpf_add_mac_filter(vport, np, vport->default_mac_addr,
					   false);
	}

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_err(idpf_adapter_to_dev(adapter),
			"MAC address is not provided and capability is not set\n");
		return -EINVAL;
	}

	eth_hw_addr_random(netdev);
	err = idpf_add_mac_filter(vport, np, netdev->dev_addr, false);
	if (err)
		return err;

	dev_info(idpf_adapter_to_dev(adapter), "Invalid MAC address %pM, using random %pM\n",
		 vport->default_mac_addr, netdev->dev_addr);
	ether_addr_copy(vport->default_mac_addr, netdev->dev_addr);

	return 0;
}

/**
 * idpf_device_detach - Mark device as removed on reset. This will help reduce
 * noise from kernel callbacks.
 * @adapter: private data struct
 */
void idpf_device_detach(struct idpf_adapter *adapter)
{
	int i;

	rtnl_lock();
	for (i = 0; i < adapter->max_vports; i++) {
		if (adapter->netdevs[i])
			netif_device_detach(adapter->netdevs[i]);
	}
	rtnl_unlock();
}

/**
 * idpf_cfg_netdev - Allocate, configure and register a netdev
 * @vport: main vport structure
 *
 * Returns 0 on success, negative value on failure.
 */
static int idpf_cfg_netdev(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	netdev_features_t dflt_features;
	netdev_features_t offloads = 0;
	struct idpf_netdev_priv *np;
	struct net_device *netdev;
	u16 idx = vport->idx;
	int err;

	vport_config = adapter->vport_config[idx];

	/* It's possible we already have a netdev allocated and registered for
	 * this vport
	 */
	if (test_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags)) {
		netdev = adapter->netdevs[idx];
		np = netdev_priv(netdev);
		np->vport = vport;
		np->vport_idx = vport->idx;
		np->vport_id = vport->vport_id;
#ifdef HAVE_NDO_FEATURES_CHECK
		np->max_tx_hdr_size = idpf_get_max_tx_hdr_size(adapter);
#endif /* HAVE_NDO_FEATURES_CHECK */
		vport->netdev = netdev;

		return idpf_init_mac_addr(vport, netdev);
	}

	netdev = alloc_etherdev_mqs(sizeof(struct idpf_netdev_priv),
				    vport_config->max_q.max_txq,
				    vport_config->max_q.max_rxq);
	if (!netdev)
		return -ENOMEM;

	vport->netdev = netdev;
	np = netdev_priv(netdev);
	np->vport = vport;
	np->adapter = adapter;
	np->vport_idx = vport->idx;
	np->vport_id = vport->vport_id;
#ifdef HAVE_NDO_FEATURES_CHECK
	np->max_tx_hdr_size = idpf_get_max_tx_hdr_size(adapter);
#endif /* HAVE_NDO_FEATURES_CHECK */

	spin_lock_init(&np->stats_lock);

	err = idpf_init_mac_addr(vport, netdev);
	if (err) {
		free_netdev(vport->netdev);
		vport->netdev = NULL;

		return err;
	}

	/* assign netdev_ops */
	if (idpf_is_queue_model_split(vport->dflt_grp.q_grp.txq_model))
		netdev->netdev_ops = &idpf_netdev_ops_splitq;
	else
		netdev->netdev_ops = &idpf_netdev_ops_singleq;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

	/* Update dev_port field to provide an unique id which is
	 * understood by both CP config file and user scripts
	 */
	netdev->dev_port = idx;

	/* Max MTU value from CP may be lower than default */
	netdev->mtu = min_t(unsigned int, netdev->mtu, vport->max_mtu);
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
	/* configure default MTU size */
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = ETH_MIN_MTU;
	netdev->extended->max_mtu = vport->max_mtu;
#else /* HAVE_REHL7_EXTENDED_MIN_MAX_MTU */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = vport->max_mtu;
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */

#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */
	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA;

	if (idpf_is_cap_ena_all(adapter, IDPF_RSS_CAPS, IDPF_CAP_RSS))
		dflt_features |= NETIF_F_RXHASH;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM_L4V4))
		dflt_features |= NETIF_F_IP_CSUM;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM_L4V6))
		dflt_features |= NETIF_F_IPV6_CSUM;
	if (idpf_is_cap_ena(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM))
		dflt_features |= NETIF_F_RXCSUM;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_SCTP_CSUM))
		dflt_features |= NETIF_F_SCTP_CRC;
	if (idpf_is_cap_ena(adapter, IDPF_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV4_TCP))
		dflt_features |= NETIF_F_TSO;
	if (idpf_is_cap_ena(adapter, IDPF_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV6_TCP))
		dflt_features |= NETIF_F_TSO6;
	if (idpf_is_cap_ena_all(adapter, IDPF_SEG_CAPS,
				VIRTCHNL2_CAP_SEG_IPV4_UDP |
				VIRTCHNL2_CAP_SEG_IPV6_UDP))
		dflt_features |= NETIF_F_GSO_UDP_L4;
	if (idpf_is_cap_ena_all(adapter, IDPF_RSC_CAPS, IDPF_CAP_RSC))
		offloads |= NETIF_F_GRO_HW;
#ifdef HAVE_ENCAP_CSUM_OFFLOAD
	/* advertise to stack only if offloads for encapsulated packets is
	 * supported
	 */
	if (idpf_is_cap_ena(vport->adapter, IDPF_SEG_CAPS,
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL)) {
#ifdef HAVE_ENCAP_TSO_OFFLOAD
		offloads |= NETIF_F_GSO_UDP_TUNNEL	|
#ifdef HAVE_GRE_ENCAP_OFFLOAD
			    NETIF_F_GSO_GRE		|
#ifdef NETIF_F_GSO_PARTIAL
			    NETIF_F_GSO_GRE_CSUM	|
			    NETIF_F_GSO_PARTIAL		|
#endif
			    NETIF_F_GSO_UDP_TUNNEL_CSUM	|
#ifdef NETIF_F_GSO_IPXIP4
			    NETIF_F_GSO_IPXIP4		|
#ifdef NETIF_F_GSO_IPXIP6
			    NETIF_F_GSO_IPXIP6		|
#endif
#else /* NETIF_F_GSO_IPXIP4 */
#ifdef NETIF_F_GSO_IPIP
			    NETIF_F_GSO_IPIP		|
#endif
#ifdef NETIF_F_GSO_SIT
			    NETIF_F_GSO_SIT		|
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
#endif /* NETIF_F_GRE_ENCAP_OFFLOAD */
			    0;

		if (!idpf_is_cap_ena_all(vport->adapter, IDPF_CSUM_CAPS,
					 IDPF_CAP_TUNNEL_TX_CSUM))
#ifndef NETIF_F_GSO_PARTIAL
			offloads ^= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#else
			netdev->gso_partial_features |=
				NETIF_F_GSO_UDP_TUNNEL_CSUM;

		netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
		offloads |= NETIF_F_TSO_MANGLEID;
#endif /* !NETIF_F_GSO_PARTIAL */
#endif /* HAVE_ENCAP_TSO_OFFLOAD */
	}
#endif /* HAVE_ENCAP_CSUM_OFFLOAD */
	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_LOOPBACK))
		offloads |= NETIF_F_LOOPBACK;
	netdev->features |= dflt_features;
	netdev->hw_features |= dflt_features | offloads;
	netdev->hw_enc_features |= dflt_features | offloads;
#ifdef HAVE_XDP_SUPPORT

	xdp_set_features_flag(netdev, NETDEV_XDP_ACT_BASIC              |
#ifdef HAVE_NETDEV_BPF_XSK_POOL
				      NETDEV_XDP_ACT_XSK_ZEROCOPY       |
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
				      NETDEV_XDP_ACT_REDIRECT);
#endif /* HAVE_XDP_SUPPORT */

	idpf_set_ethtool_ops(netdev);
	SET_NETDEV_DEV(netdev, idpf_adapter_to_dev(adapter));

	/* carrier off on init to avoid Tx hangs */
	netif_carrier_off(netdev);

	/* make sure transmit queues start off as stopped */
	netif_tx_stop_all_queues(netdev);

	/* The vport can be arbitrarily released so we need to also track
	 * netdevs in the adapter struct
	 */
	adapter->netdevs[idx] = netdev;

	return 0;
}

/**
 * idpf_get_free_slot - get the next non-NULL location index in array
 * @adapter: adapter in which to look for a free vport slot
 */
static int idpf_get_free_slot(struct idpf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->max_vports; i++) {
		if (!adapter->vports[i])
			return i;
	}

	return IDPF_NO_FREE_SLOT;
}

/**
 * idpf_remove_features - Turn off feature configs
 * @vport: virtual port structure
 */
static void idpf_remove_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_remove_mac_filters(vport);
}

/**
 * idpf_netdev_stop - Stop traffic from getting queued up
 * @netdev: stack net device
 */
static void idpf_netdev_stop(struct net_device *netdev)
{
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
}

/**
 * idpf_netdev_stop_all - Stop all traffic on all netdevs
 * @adapter: private data struct
 *
 * In the case of PFR, we have a small window to stop queueing up
 * traffic before we start triggering tx timeouts on queues that got
 * yanked out from under us. We can't afford to timeout on all the
 * virtchnl messages or wait for cancelling delayed work before
 * stopping traffic. Stop traffic on all vports first, then try to
 * clean up any dangling resources.
 */
void idpf_netdev_stop_all(struct idpf_adapter *adapter)
{
	int i;

	if (!adapter->vports)
		return;

	for (i = 0; i < adapter->max_vports; i++)
		if (adapter->vports[i])
			idpf_netdev_stop(adapter->vports[i]->netdev);
}

/**
 * idpf_vport_stop - Disable a vport
 * @vport: vport to disable
 */
static void idpf_vport_stop(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct idpf_vgrp *vgrp = &vport->dflt_grp;

	if (!np->active)
		return;

	idpf_netdev_stop(vport->netdev);

	if (!test_bit(IDPF_CORER_IN_PROG, vport->adapter->flags)) {
		idpf_send_disable_vport_msg(vport);
		idpf_send_disable_queues_msg(vport, vgrp,
					     idpf_get_queue_reg_chunks(vport));
	}
	idpf_send_map_unmap_queue_vector_msg(vport, vgrp, false);
	/* Normally we ask for queues in create_vport, but if the number of
	 * initially requested queues have changed, for example via ethtool
	 * set channels, we do delete queues and then add the queues back
	 * instead of deleting and reallocating the vport.
	 */
	if (test_and_clear_bit(IDPF_VPORT_DEL_QUEUES, vport->flags))
		idpf_send_delete_queues_msg(vport);

	idpf_remove_features(vport);

	idpf_vport_intr_deinit(vport, &vgrp->intr_grp);
	idpf_vport_intr_rel(vgrp);
	idpf_vport_queue_rel_all(vport, &vgrp->q_grp);
	np->active = false;
}

/**
 * idpf_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state.  The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int idpf_stop(struct net_device *netdev)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
	struct idpf_vport *vport;

	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	idpf_vport_stop(vport);

	idpf_vport_ctrl_unlock(adapter);

	return 0;
}

/**
 * idpf_decfg_netdev - Unregister the netdev
 * @vport: vport for which netdev to be unregistered
 */
static void idpf_decfg_netdev(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	unregister_netdev(vport->netdev);
	clear_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config[vport->idx]->flags);
	free_netdev(vport->netdev);
	vport->netdev = NULL;

	adapter->netdevs[vport->idx] = NULL;
}

/**
 * idpf_vport_rel - Delete a vport and free its resources
 * @vport: the vport being removed
 */
static void idpf_vport_rel(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_rss_data *rss_data;
	struct idpf_vport_max_q max_q;
	u16 idx = vport->idx;

	vport_config = adapter->vport_config[vport->idx];
	rss_data = &vport_config->user_config.rss_data;
	idpf_deinit_rss(rss_data);
	kfree(rss_data->rss_key);
	rss_data->rss_key = NULL;

	idpf_send_destroy_vport_msg(vport);

	/* Release all max queues allocated to the adapter's pool */
	max_q.max_rxq = vport_config->max_q.max_rxq;
	max_q.max_txq = vport_config->max_q.max_txq;
	max_q.max_bufq = vport_config->max_q.max_bufq;
	max_q.max_complq = vport_config->max_q.max_complq;
	idpf_vport_dealloc_max_qs(adapter, &max_q);

	/* Release all the allocated vectors on the stack */
	idpf_vport_dealloc_vec_indexes(vport, &vport->dflt_grp);

	kfree(vport->port_stats.phy_port_stats);

	kfree(adapter->vport_params_recvd[idx]);
	adapter->vport_params_recvd[idx] = NULL;
	kfree(adapter->vport_params_reqd[idx]);
	adapter->vport_params_reqd[idx] = NULL;
	if (adapter->vport_config[idx]) {
		kfree(adapter->vport_config[idx]->req_qs_chunks);
		adapter->vport_config[idx]->req_qs_chunks = NULL;
	}
	kfree(vport);
	adapter->num_alloc_vports--;
}

/**
 * idpf_del_user_cfg_data - delete all user configuration data
 * @vport: virtual port private structure
 */
static void idpf_del_user_cfg_data(struct idpf_vport *vport)
{
	idpf_del_all_mac_filters(vport);
}

/**
 * idpf_rx_init_buf_tail - Write initial buffer ring tail value
 * @q_grp: Queue resources
 */
static void idpf_rx_init_buf_tail(struct idpf_q_grp *q_grp)
{
	bool is_splitq = idpf_is_queue_model_split(q_grp->rxq_model);
	int i, numq;

	numq = is_splitq ? q_grp->num_bufq : q_grp->num_rxq;

	for (i = 0; i < numq; i++) {
		struct idpf_queue *q = is_splitq ?
			&q_grp->bufqs[i] :
			q_grp->rxqs[i];

		writel(q->next_to_alloc, q->tail);
	}
}

/**
 * idpf_vport_p2p_del_queues - Delete P2P queues
 * @vport: virtual port
 * @q_grp: Queue resources
 *
 * Delete the P2P queues by sening a mailbox message
 * and free the memory
 */
static void idpf_vport_p2p_del_queues(struct idpf_vport *vport,
				      struct idpf_q_grp *q_grp)
{
	if (!q_grp->req_qs_chunks)
		return;

	idpf_send_del_queue_grp_msg(vport, q_grp->req_qs_chunks);
	kfree(q_grp->req_qs_chunks);
	q_grp->req_qs_chunks = NULL;
}

/**
 * idpf_vport_p2p_vgrp_deinit - Deinitialize P2P virtual group
 * @vport: Virtual port
 * @p2p_vgrp: Virtual group
 * @vgrp_idx: Virtual group index
 */
static void idpf_vport_p2p_vgrp_deinit(struct idpf_vport *vport,
				       struct idpf_vgrp *p2p_vgrp,
				       int vgrp_idx)
{
	struct idpf_vport_config *vport_config;
	struct idpf_rss_data *rss_data;

	vport_config = vport->adapter->vport_config[vport->idx];
	rss_data = &vport_config->user_config.p2p_rss_data[vgrp_idx];
	kfree(rss_data->rss_key);
	rss_data->rss_key = NULL;

	idpf_vport_dealloc_vec_indexes(vport, p2p_vgrp);
}

/**
 * idpf_vport_p2p_deinit - Uninitialize P2P
 * @vport: virtual port data
 */
static void idpf_vport_p2p_deinit(struct idpf_vport *vport)
{
	int vgrp_idx = 0;

	for (vgrp_idx = 0; vgrp_idx < IDPF_P2P_NUM_OF_VGRPS; vgrp_idx++) {
		struct idpf_vgrp *p2p_vgrp = &vport->p2p_vgrps[vgrp_idx];

		idpf_vport_p2p_del_queues(vport, &p2p_vgrp->q_grp);
		idpf_vport_p2p_vgrp_deinit(vport, p2p_vgrp, vgrp_idx);
	}
}

/**
 * idpf_vport_p2p_add_queue_grp - Add P2P queues
 * @vport: Virtual port
 * @q_grp: Queue resources
 * @qgrp_id: Unique identifier for queue group
 *
 * Add the P2P queues by sening a mailbox message and store the data.
 */
static int idpf_vport_p2p_add_queue_grp(struct idpf_vport *vport,
					struct idpf_q_grp *q_grp,
					int qgrp_id)
{
	int err;

	q_grp->req_qs_chunks = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!q_grp->req_qs_chunks)
		return -ENOMEM;

	err = idpf_send_add_queue_grp_msg(vport, IDPF_P2P_TXQ_PER_VGRP,
					  IDPF_P2P_COMPLQ_PER_VGRP,
					  IDPF_P2P_RXQ_PER_VGRP,
					  IDPF_P2P_BUFQ_PER_VGRP,
					  q_grp->req_qs_chunks,
					  qgrp_id);
	if (err) {
		kfree(q_grp->req_qs_chunks);
		q_grp->req_qs_chunks = NULL;

		return err;
	}

	return 0;
}

/**
 * idpf_vport_p2p_vgrp_init - Initialize P2P virtual group
 * @vport: Virtual port
 * @p2p_vgrp: Virtual group
 * @vgrp_idx: Virtual group index
 *
 * Initialize P2P virtual group with queue and interrupt specific defaults.
 */
static int idpf_vport_p2p_vgrp_init(struct idpf_vport *vport,
				    struct idpf_vgrp *p2p_vgrp,
				    int vgrp_idx)
{
	struct idpf_intr_grp *intr_grp = &p2p_vgrp->intr_grp;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_q_grp *q_grp = &p2p_vgrp->q_grp;
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vport_config *vport_config;
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;
	u16 num_max_q;
	int err;

	vport_config = adapter->vport_config[idx];
	vport_msg = (struct virtchnl2_create_vport *)
			adapter->vport_params_recvd[idx];

	q_grp->txq_model = le16_to_cpu(vport_msg->txq_model);
	q_grp->rxq_model = le16_to_cpu(vport_msg->rxq_model);

	/* Initialize RSS sizes */
	rss_data = &vport_config->user_config.p2p_rss_data[vgrp_idx];
	rss_data->rss_key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
				       le16_to_cpu(vport_msg->rss_key_size));
	rss_data->rss_lut_size = le16_to_cpu(vport_msg->rss_lut_size);
	rss_data->rss_key = kzalloc(rss_data->rss_key_size, GFP_KERNEL);
	if (!rss_data->rss_key)
		return -ENOMEM;

	idpf_vport_vgrp_init_num_qs(vport, q_grp);
	num_max_q = max(q_grp->num_txq, q_grp->num_rxq);
	intr_grp->q_vector_idxs = kcalloc(num_max_q, sizeof(u16), GFP_KERNEL);
	if (!intr_grp->q_vector_idxs) {
		err = -ENOMEM;
		goto free_rss_key;
	}

	idpf_vport_calc_num_q_desc(vport, q_grp);
	idpf_vport_alloc_vec_indexes(vport, p2p_vgrp);

	return 0;

free_rss_key:
	kfree(rss_data->rss_key);

	return err;
}

/**
 * idpf_vport_p2p_init - Initialize port 2 port
 * @vport: virtual port data
 *
 * P2P init will request for additional queue groups and initialize the
 * vport P2P data with the response received on mailbox.
 */
static int idpf_vport_p2p_init(struct idpf_vport *vport)
{
	int vgrp_idx = 0;
	int err;

	for (vgrp_idx = 0; vgrp_idx < IDPF_P2P_NUM_OF_VGRPS; vgrp_idx++) {
		struct idpf_vgrp *p2p_vgrp = &vport->p2p_vgrps[vgrp_idx];

		/* Apart from virtual group structure, initialize P2P type in
		 * queue and interrupt group as well to avoid passing
		 * virtual group pointer where ever possible
		 */
		p2p_vgrp->type = IDPF_GRP_TYPE_P2P;
		p2p_vgrp->q_grp.type = IDPF_GRP_TYPE_P2P;
		p2p_vgrp->intr_grp.type = IDPF_GRP_TYPE_P2P;

		err = idpf_vport_p2p_add_queue_grp(vport, &p2p_vgrp->q_grp,
						   vport->vport_id * (vgrp_idx + 1));
		if (err)
			goto init_err;

		err = idpf_vport_p2p_vgrp_init(vport, p2p_vgrp, vgrp_idx);
		if (err)
			goto del_queues;
	}

	return 0;

del_queues:
	idpf_vport_p2p_del_queues(vport, &vport->p2p_vgrps[vgrp_idx].q_grp);
init_err:
	while (vgrp_idx > 0) {
		struct idpf_vgrp *p2p_vgrp = &vport->p2p_vgrps[--vgrp_idx];

		idpf_vport_p2p_del_queues(vport, &p2p_vgrp->q_grp);
		idpf_vport_p2p_vgrp_deinit(vport, p2p_vgrp, vgrp_idx);
	}

	return err;
}

/**
 * idpf_vport_vgrp_stop - Disable virtual group queues
 * @vport: Virtual port
 * @rss_data: Associated RSS data
 * @vgrp: Queue and interrupt resource group
 *
 * Disables queues and interrupts of a virtual group.
 */
static void idpf_vport_vgrp_stop(struct idpf_vport *vport,
				 struct idpf_rss_data *rss_data,
				 struct idpf_vgrp *vgrp)
{
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct virtchnl2_queue_group_info *qg_info;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;

	qg_info = idpf_get_queue_group_info(q_grp->req_qs_chunks);

	idpf_send_disable_queues_msg(vport, vgrp, &qg_info->chunks);
	idpf_send_map_unmap_queue_vector_msg(vport, vgrp, false);
	idpf_vport_intr_deinit(vport, intr_grp);
	idpf_vport_intr_rel(vgrp);
	idpf_vport_queue_rel_all(vport, q_grp);
}

/**
 * idpf_vport_p2p_vgrp_stop - Disable p2p queues
 * @vport: virtual port
 *
 * Disables queues and interrupts and free memory
 * for both resources
 */
static void idpf_vport_p2p_vgrp_stop(struct idpf_vport *vport)
{
	int vgrp_idx;

	if (!test_bit(IDPF_VPORT_PORT2PORT_OPENED, vport->flags))
		return;

	for (vgrp_idx = 0; vgrp_idx < IDPF_P2P_NUM_OF_VGRPS; vgrp_idx++) {
		struct idpf_vgrp *vgrp = &vport->p2p_vgrps[vgrp_idx];
		struct idpf_vport_config *vport_config;
		struct idpf_rss_data *rss_data;

		vport_config = vport->adapter->vport_config[vport->idx];
		rss_data = &vport_config->user_config.p2p_rss_data[vgrp_idx];

		idpf_vport_vgrp_stop(vport, rss_data, vgrp);
	}

	clear_bit(IDPF_VPORT_PORT2PORT_OPENED, vport->flags);
}

/**
 * idpf_vport_vgrp_open - Enable virtual group queues
 * @vport: Virtual port
 * @rss_data: Associated RSS data
 * @vgrp: Queue and interrupt resource group
 *
 * Enables queues and interrupts of a virtual group.
 */
static int idpf_vport_vgrp_open(struct idpf_vport *vport,
				struct idpf_rss_data *rss_data,
				struct idpf_vgrp *vgrp)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_queue_group_info *qg_info;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_intr_grp *intr_grp = &vgrp->intr_grp;
	struct idpf_q_grp *q_grp = &vgrp->q_grp;
	int err;

	err = idpf_vport_queue_alloc_all(vport, q_grp);
	if (err)
		return err;

	err = idpf_vport_intr_alloc(vport, vgrp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to allocate non-default queue type interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto queues_rel;
	}

	qg_info = idpf_get_queue_group_info(q_grp->req_qs_chunks);
	chunks = &qg_info->chunks;
	err = idpf_vport_queue_ids_init(q_grp, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to initialize non-default queue type queue ids for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	err = idpf_queue_reg_init(vport, q_grp, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to initialize non-default queue type queue registers for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	idpf_rx_init_buf_tail(q_grp);

	err = idpf_vport_intr_init(vport, vgrp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to initialize non-default queue type interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	idpf_vport_intr_ena(vport, vgrp);

	err = idpf_send_config_queues_msg(vport, q_grp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to configure non-default queue type queues for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_map_unmap_queue_vector_msg(vport, vgrp, true);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to map non-default queue type queue vectors for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_enable_queues_msg(vport, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to enable non-default queue type queues for vport %u: %d\n",
			vport->vport_id, err);
		goto unmap_queue_vectors;
	}

	return 0;

unmap_queue_vectors:
	idpf_send_map_unmap_queue_vector_msg(vport, vgrp, false);
intr_deinit:
	idpf_vport_intr_deinit(vport, intr_grp);
intr_rel:
	idpf_vport_intr_rel(vgrp);
queues_rel:
	idpf_vport_queue_rel_all(vport, q_grp);

	return err;
}

/**
 * idpf_vport_p2p_vgrp_open - Config P2P queues
 * @vport: Virtual port
 *
 * Configure and enable queues and interrupts for P2P support
 */
static int idpf_vport_p2p_vgrp_open(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_rss_data *rss_data;
	int vgrp_idx, err = 0;

	for (vgrp_idx = 0; vgrp_idx < IDPF_P2P_NUM_OF_VGRPS; vgrp_idx++) {
		struct idpf_vgrp *vgrp = &vport->p2p_vgrps[vgrp_idx];

		vport_config = adapter->vport_config[vport->idx];
		rss_data = &vport_config->user_config.p2p_rss_data[vgrp_idx];
		err = idpf_vport_vgrp_open(vport, rss_data, vgrp);
		if (err) {
			dev_err(idpf_adapter_to_dev(adapter),
				"Failed to open P2P virtual group %d for vport %u: %d\n",
				vgrp_idx, vport->vport_id, err);
			goto vgrp_open_err;
		}
	}

	set_bit(IDPF_VPORT_PORT2PORT_OPENED, vport->flags);

	return 0;

vgrp_open_err:
	while (vgrp_idx > 0) {
		struct idpf_vgrp *vgrp = &vport->p2p_vgrps[--vgrp_idx];

		vport_config = adapter->vport_config[vport->idx];
		rss_data = &vport_config->user_config.p2p_rss_data[vgrp_idx];

		idpf_vport_vgrp_stop(vport, rss_data, vgrp);
	}

	return err;
}

/**
 * idpf_vport_dealloc - cleanup and release a given vport
 * @vport: pointer to idpf vport structure
 *
 * returns nothing
 */
#ifdef DEVLINK_ENABLED
void idpf_vport_dealloc(struct idpf_vport *vport)
#else
static void idpf_vport_dealloc(struct idpf_vport *vport)
#endif /* DEVLINK_ENABLED */
{
	struct idpf_adapter *adapter = vport->adapter;
	unsigned int i = vport->idx;

	idpf_deinit_mac_addr(vport);

	idpf_vport_ctrl_lock(adapter);
	idpf_vport_stop(vport);
	idpf_vport_ctrl_unlock(adapter);

	if (idpf_is_p2p_enabled(vport)) {
		idpf_vport_p2p_vgrp_stop(vport);
		idpf_vport_p2p_deinit(vport);
	}

	if (!vport->idx)
		idpf_idc_deinit(adapter);

	if (!test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags))
		idpf_decfg_netdev(vport);
	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		idpf_del_user_cfg_data(vport);

	if (adapter->netdevs[i]) {
		struct idpf_netdev_priv *np = netdev_priv(adapter->netdevs[i]);

		np->vport = NULL;
	}

	idpf_vport_rel(vport);

	adapter->vports[i] = NULL;
	adapter->next_vport = idpf_get_free_slot(adapter);
}

/**
 * idpf_vport_set_hsplit - enable or disable header split on a given vport
 * @vport: virtual port
 * @ena: flag controlling header split, On (true) or Off (false)
 */
void idpf_vport_set_hsplit(struct idpf_vport *vport, bool ena)
{
	struct idpf_vport_user_config_data *config_data;

	config_data = &vport->adapter->vport_config[vport->idx]->user_config;
#ifdef HAVE_XDP_SUPPORT
	if (!ena) {
		clear_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags);
		return;
	}

#endif /* HAVE_XDP_SUPPORT */
	if (idpf_is_cap_ena_all(vport->adapter, IDPF_HSPLIT_CAPS,
				IDPF_CAP_HSPLIT) &&
	    idpf_is_queue_model_split(vport->dflt_grp.q_grp.rxq_model))
		set_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags);
}

/**
 * idpf_vport_alloc - Allocates the next available struct vport in the adapter
 * @adapter: board private structure
 * @max_q: vport max queue info
 *
 * returns a pointer to a vport on success, NULL on failure.
 */
static struct idpf_vport *idpf_vport_alloc(struct idpf_adapter *adapter,
					   struct idpf_vport_max_q *max_q)
{
	struct idpf_rss_data *rss_data;
	struct idpf_intr_grp *intr_grp;
	u16 idx = adapter->next_vport;
	struct idpf_vport *vport;
	u16 num_max_q;

	if (idx == IDPF_NO_FREE_SLOT)
		return NULL;

	vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!vport)
		return vport;

	if (!adapter->vport_config[idx]) {
		struct idpf_vport_config *vport_config;

		vport_config = kzalloc(sizeof(*vport_config), GFP_KERNEL);
		if (!vport_config) {
			kfree(vport);

			return NULL;
		}

		adapter->vport_config[idx] = vport_config;
	}

	vport->idx = idx;
	vport->adapter = adapter;
	vport->compln_clean_budget = IDPF_TX_COMPLQ_CLEAN_BUDGET;
	vport->default_vport = adapter->num_alloc_vports <
			       idpf_get_default_vports(adapter);

	num_max_q = max(max_q->max_txq, max_q->max_rxq);
	intr_grp = &vport->dflt_grp.intr_grp;
	intr_grp->q_vector_idxs = kcalloc(num_max_q, sizeof(u16), GFP_KERNEL);
	if (!intr_grp->q_vector_idxs)
		goto free_vport;

	if (idpf_vport_init(vport, max_q))
		goto free_qvec_idxs;

	/* This alloc is done separate from the LUT because it's not strictly
	 * dependent on how many queues we have. If we change number of queues
	 * and soft reset we'll need a new LUT but the key can remain the same
	 * for as long as the vport exists.
	 */
	rss_data = &adapter->vport_config[idx]->user_config.rss_data;
	rss_data->rss_key = kzalloc(rss_data->rss_key_size, GFP_KERNEL);
	if (!rss_data->rss_key)
		goto free_qvec_idxs;

	/* Initialize default rss key */
	netdev_rss_key_fill((void *)rss_data->rss_key, rss_data->rss_key_size);

	/* fill vport slot in the adapter struct */
	adapter->vports[idx] = vport;
	adapter->vport_ids[idx] = vport->vport_id;

	adapter->num_alloc_vports++;
	/* prepare adapter->next_vport for next use */
	adapter->next_vport = idpf_get_free_slot(adapter);

	if (idpf_is_p2p_enabled(vport))
		idpf_vport_p2p_init(vport);

	return vport;

free_qvec_idxs:
	kfree(intr_grp->q_vector_idxs);
	intr_grp->q_vector_idxs = NULL;
free_vport:
	kfree(vport);
	return NULL;
}

/**
 * idpf_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
#ifdef HAVE_VOID_NDO_GET_STATS64
static void idpf_get_stats64(struct net_device *netdev,
			     struct rtnl_link_stats64 *stats)
#else /* HAVE_VOID_NDO_GET_STATS64 */
static struct rtnl_link_stats64 *idpf_get_stats64(struct net_device *netdev,
						  struct rtnl_link_stats64 *stats)
#endif /* !HAVE_VOID_NDO_GET_STATS64 */
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_adapter *adapter = np->adapter;

	spin_lock_bh(&np->stats_lock);
	*stats = np->netstats;
	spin_unlock_bh(&np->stats_lock);

	if (!idpf_is_resource_rel_in_prog(adapter) && np->active)
		mod_delayed_work(adapter->stats_wq, &adapter->stats_task,
				 msecs_to_jiffies(300));
#ifndef HAVE_VOID_NDO_GET_STATS64

	return stats;
#else /* !HAVE_VOID_NDO_GET_STATS64 */

	return;
#endif /* HAVE_VOID_NDO_GET_STATS64 */
}

/**
 * idpf_statistics_task - Delayed task to get statistics over mailbox
 * @work: work_struct handle to our data
 */
void idpf_statistics_task(struct work_struct *work)
{
	struct idpf_adapter *adapter;
	int i;

	adapter = container_of(work, struct idpf_adapter, stats_task.work);

	for (i = 0; i < adapter->max_vports; i++) {
		struct idpf_vport *vport = adapter->vports[i];

		if (!vport)
			continue;

		if (test_bit(IDPF_VPORT_UPLINK_PORT,
			     adapter->vport_config[i]->flags))
			idpf_send_get_port_stats_msg(vport);
		else
		idpf_send_get_stats_msg(vport);
	}

	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10000));
}

/**
 * init_tstamp_task - Delayed task to handle Tx tstamps
 * @work: work_struct handle
 */
void idpf_tstamp_task(struct work_struct *work)
{
	struct idpf_vport *vport;

	vport = container_of(work, struct idpf_vport, tstamp_task);

	idpf_ptp_get_tx_tstamp_mb(vport);
}

/**
 * idpf_mbx_task - Delayed task to handle mailbox responses
 * @work: work_struct handle
 */
void idpf_mbx_task(struct work_struct *work)
{
	struct idpf_adapter *adapter;

	adapter = container_of(work, struct idpf_adapter, mbx_task.work);

	if (test_bit(IDPF_MB_INTR_MODE, adapter->flags))
		idpf_mb_irq_enable(adapter);
	else
		queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task,
				   msecs_to_jiffies(300));

	idpf_recv_mb_msg(adapter);
}

/**
 * idpf_service_task - Delayed task for handling reset detection
 * @work: work_struct handle to our data
 *
 */
void idpf_service_task(struct work_struct *work)
{
	struct idpf_adapter *adapter;

	adapter = container_of(work, struct idpf_adapter, serv_task.work);

	if (idpf_is_reset_detected(adapter) &&
	    !idpf_is_reset_in_prog(adapter) &&
	    !test_bit(IDPF_REMOVE_IN_PROG, adapter->flags)) {
		dev_info(idpf_adapter_to_dev(adapter), "%s reset detected\n",
			 test_bit(IDPF_CORER_IN_PROG, adapter->flags) ? "CORER" : "HW");
		set_bit(IDPF_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));

		return;
	}

	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(300));
}

/**
 * idpf_restore_features - Restore feature configs
 * @vport: virtual port structure
 */
static void idpf_restore_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_restore_mac_filters(vport);
}

/**
 * idpf_set_real_num_queues - set number of queues for netdev
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_set_real_num_queues(struct idpf_vport *vport)
{
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	int err;

	err = netif_set_real_num_rx_queues(vport->netdev, q_grp->num_rxq);
	if (err)
		return err;
#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(vport))
		return netif_set_real_num_tx_queues(vport->netdev,
						    q_grp->num_txq - vport->num_xdp_txq);
	else
#endif /* HAVE_XDP_SUPPORT */
	return netif_set_real_num_tx_queues(vport->netdev, q_grp->num_txq);
}

/**
 * idpf_up_complete - Complete interface up sequence
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_up_complete(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	if (vport->link_up && !netif_carrier_ok(vport->netdev)) {
		netif_carrier_on(vport->netdev);
		netif_tx_start_all_queues(vport->netdev);
	}

	np->active = true;
	return 0;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_vport_xdp_init - Prepare and configure XDP structures
 * @vport: vport where XDP should be initialized
 * @q_grp: Queue resources
 *
 * returns 0 on success or error code in case of any failure
 */
static int idpf_vport_xdp_init(struct idpf_vport *vport,
			       struct idpf_q_grp *q_grp)
{
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter;
	u16 idx = vport->idx;
	int i, err;

	adapter = vport->adapter;
	config_data = &adapter->vport_config[idx]->user_config;

	for (i = 0; i < q_grp->num_rxq; i++) {
		struct idpf_queue *rxq = q_grp->rxqs[i];

		WRITE_ONCE(rxq->xdp_prog, config_data->xdp_prog);
		err = idpf_xdp_rxq_init(rxq);
		if (err)
			goto exit_xdp_init;
#ifdef HAVE_NETDEV_BPF_XSK_POOL

		if (rxq->xsk_pool)
			idpf_rx_buf_hw_alloc_zc_all(vport, q_grp, rxq);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (!idpf_xdp_is_prog_ena(vport))
		goto exit_xdp_init;

	for (i = vport->xdp_txq_offset; i < q_grp->num_txq; i++) {
		set_bit(__IDPF_Q_XDP, q_grp->txqs[i]->flags);

		/* For AF_XDP we are assuming that the queue id received from
		 * the user space is mapped to the pair of queues:
		 *  - Rx queue where queue id is mapped to the queue index
		 *    (q->idx)
		 *  - XDP Tx queue where queue id is mapped to the queue index,
		 *    considering the XDP offset (q->idx + vport->xdp_txq_offset).
		 */
		idpf_get_xsk_pool(q_grp->txqs[i], true);
	}

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
exit_xdp_init:
	return err;
}

#endif /* HAVE_XDP_SUPPORT */
/**
 * idpf_vport_open - Bring up a vport
 * @vport: vport to bring up
 * @alloc_res: allocate queue resources
 */
static int idpf_vport_open(struct idpf_vport *vport, bool alloc_res)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vgrp *vgrp = &vport->dflt_grp;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_rss_data *rss_data;
	int err;

	if (np->active)
		return -EBUSY;

	/* we do not allow interface up just yet */
	netif_carrier_off(vport->netdev);

	if (alloc_res) {
		err = idpf_vport_queue_alloc_all(vport, q_grp);
		if (err)
			return err;
	}

	err = idpf_vport_intr_alloc(vport, vgrp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to allocate interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto queues_rel;
	}

	chunks = idpf_get_queue_reg_chunks(vport);
	err = idpf_vport_queue_ids_init(q_grp, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to initialize queue ids for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	err = idpf_queue_reg_init(vport, q_grp, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to initialize queue registers for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	idpf_rx_init_buf_tail(q_grp);

	err = idpf_vport_intr_init(vport, vgrp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to initialize interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

#ifdef HAVE_XDP_SUPPORT
	idpf_vport_xdp_init(vport, q_grp);

#endif /* HAVE_XDP_SUPPORT */
	idpf_vport_intr_ena(vport, vgrp);
	err = idpf_send_config_queues_msg(vport, q_grp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to configure queues for vport %u, %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_map_unmap_queue_vector_msg(vport, vgrp, true);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to map queue vectors for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_enable_queues_msg(vport, chunks);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to enable queues for vport %u: %d\n",
			vport->vport_id, err);
		goto unmap_queue_vectors;
	}

	/* The PORT2PORT queues should never be stopped or reconfigured, so do
	 * not call open again after the first link up.
	 */
	if (idpf_is_p2p_enabled(vport) &&
	    !test_bit(IDPF_VPORT_PORT2PORT_OPENED, vport->flags)) {
		err = idpf_vport_p2p_vgrp_open(vport);
		if (err) {
			err = -EAGAIN;
			goto disable_queues;
		}
	}

	err = idpf_send_enable_vport_msg(vport);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to enable vport %u: %d\n",
			vport->vport_id, err);
		err = -EAGAIN;
		goto disable_queues;
	}

	idpf_restore_features(vport);

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	if (rss_data->rss_lut)
		err = idpf_config_rss(vport, rss_data);
	else
		err = idpf_init_rss(vport, rss_data, q_grp);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to initialize RSS for vport %u: %d\n",
			vport->vport_id, err);
		goto disable_vport;
	}

	err = idpf_up_complete(vport);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to complete interface up for vport %u: %d\n",
			vport->vport_id, err);
		goto deinit_rss;
	}

	return 0;

deinit_rss:
	idpf_deinit_rss(rss_data);
disable_vport:
	idpf_send_disable_vport_msg(vport);
disable_queues:
	idpf_send_disable_queues_msg(vport, vgrp,
				     idpf_get_queue_reg_chunks(vport));
unmap_queue_vectors:
	idpf_send_map_unmap_queue_vector_msg(vport, vgrp, false);
intr_deinit:
	idpf_vport_intr_deinit(vport, &vgrp->intr_grp);
intr_rel:
	idpf_vport_intr_rel(vgrp);
queues_rel:
	if (alloc_res)
		idpf_vport_queue_rel_all(vport, q_grp);

	return err;
}

/**
 * idpf_init_task - Delayed initialization task
 * @work: work_struct handle to our data
 *
 * Init task finishes up pending work started in probe. Due to the asynchronous
 * nature in which the device communicates with hardware, we may have to wait
 * several milliseconds to get a response.  Instead of busy polling in probe,
 * pulling it out into a delayed work task prevents us from bogging down the
 * whole system waiting for a response from hardware.
 */
void idpf_init_task(struct work_struct *work)
{
	struct idpf_vport_config *vport_config;
	struct idpf_vport_max_q max_q;
	struct idpf_adapter *adapter;
	struct idpf_vport *vport;
	u16 num_default_vports;
	struct pci_dev *pdev;
	bool default_vport;
	int index, err;

	adapter = container_of(work, struct idpf_adapter, init_task.work);

	num_default_vports = idpf_get_default_vports(adapter);
	if (adapter->num_alloc_vports < num_default_vports)
		default_vport = true;
	else
		default_vport = false;

	err = idpf_vport_alloc_max_qs(adapter, &max_q);
	if (err)
		goto unwind_vports;

	err = idpf_send_create_vport_msg(adapter, &max_q);
	if (err) {
		idpf_vport_dealloc_max_qs(adapter, &max_q);
		goto unwind_vports;
	}

	pdev = adapter->pdev;
	vport = idpf_vport_alloc(adapter, &max_q);
	if (!vport) {
		err = -EFAULT;
		dev_err(&pdev->dev, "failed to allocate vport: %d\n",
			err);
		idpf_vport_dealloc_max_qs(adapter, &max_q);
		goto unwind_vports;
	}

	index = vport->idx;
	vport_config = adapter->vport_config[index];
	init_waitqueue_head(&vport->sw_marker_wq);

	spin_lock_init(&vport_config->mac_filter_list_lock);
	INIT_LIST_HEAD(&vport_config->user_config.mac_filter_list);

	err = idpf_check_supported_desc_ids(vport);
	if (err) {
		dev_err(&pdev->dev, "failed to get required descriptor ids\n");
		goto cfg_netdev_err;
	}

	if (idpf_cfg_netdev(vport))
		goto cfg_netdev_err;

	err = idpf_send_get_rx_ptype_msg(vport);
	if (err)
		goto handle_err;

	if (!vport->idx) {
		err = idpf_idc_init(adapter);
		if (err)
			goto handle_err;
	}

	if (test_and_clear_bit(IDPF_VPORT_UP_REQUESTED, vport_config->flags)) {
		idpf_vport_ctrl_lock(adapter);
		idpf_vport_open(vport, true);
		idpf_vport_ctrl_unlock(adapter);
	}

	/* Spawn and return 'idpf_init_task' work queue until all the
	 * default vports are created
	 */
	if (adapter->num_alloc_vports < num_default_vports) {
		queue_delayed_work(adapter->init_wq, &adapter->init_task,
				   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

		return;
	}

	for (index = 0; index < adapter->max_vports; index++) {
		if (adapter->netdevs[index]) {
			if (!test_and_set_bit(IDPF_VPORT_REG_NETDEV,
					      adapter->vport_config[index]->flags))
				register_netdev(adapter->netdevs[index]);
			else
				netif_device_attach(adapter->netdevs[index]);
		}
	}

	/* As all the required vports are created, clear the reset flag
	 * unconditionally here in case we were in reset and the link was down.
	 */
	clear_bit(IDPF_HR_RESET_IN_PROG, adapter->flags);
	/* Start the statistics task now */
	queue_delayed_work(adapter->stats_wq, &adapter->stats_task, 0);

	return;

handle_err:
	idpf_decfg_netdev(vport);
cfg_netdev_err:
	idpf_vport_rel(vport);
	adapter->vports[index] = NULL;
unwind_vports:
	if (default_vport) {
		for (index = 0; index < adapter->max_vports; index++) {
			if (adapter->vports[index])
				idpf_vport_dealloc(adapter->vports[index]);
		}
	}
	clear_bit(IDPF_HR_RESET_IN_PROG, adapter->flags);
}

/**
 * idpf_sriov_ena - Enable or change number of VFs
 * @adapter: private data struct
 * @num_vfs: number of VFs to allocate
 */
static int idpf_sriov_ena(struct idpf_adapter *adapter, int num_vfs)
{
	struct device *dev = idpf_adapter_to_dev(adapter);
	int err;

	err = idpf_send_set_sriov_vfs_msg(adapter, num_vfs);
	if (err) {
		dev_err(dev, "Failed to allocate VFs: %d\n", err);
		return err;
	}

	err = pci_enable_sriov(adapter->pdev, num_vfs);
	if (err) {
		idpf_send_set_sriov_vfs_msg(adapter, 0);
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	adapter->num_vfs = num_vfs;
	return num_vfs;
}

/**
 * idpf_sriov_config_vfs - Configure the requested VFs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of vfs to allocate
 *
 * Enable or change the number of VFs. Called when the user updates the number
 * of VFs in sysfs.
 *
 * Returns 0 on success or error code in case of any failure
 **/
int idpf_sriov_config_vfs(struct pci_dev *pdev, int num_vfs)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	lockdep_assert_held(&adapter->init_ctrl_lock);

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_SRIOV)) {
		dev_info(&pdev->dev, "SR-IOV is not supported on this device\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs)
		return idpf_sriov_ena(adapter, num_vfs);

	if (pci_vfs_assigned(pdev)) {
		dev_warn(&pdev->dev, "Unable to free VFs because some are assigned to VMs\n");

		return -EBUSY;
	}

	pci_disable_sriov(adapter->pdev);
	idpf_send_set_sriov_vfs_msg(adapter, 0);
	adapter->num_vfs = 0;

	return 0;
}

/**
 * idpf_sriov_configure - Calls idpf_sriov_config_vfs to configure
 * the requested VFs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of vfs to allocate
 *
 * Returns 0 on success or error code in case of any failure
 **/
int idpf_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
	int ret;

	idpf_init_ctrl_lock(adapter);
	ret = idpf_sriov_config_vfs(pdev, num_vfs);
	idpf_init_ctrl_unlock(adapter);

	return ret;
}

/**
 * idpf_deinit_task - Device deinit routine
 * @adapter: Driver specific private structue
 *
 * Extended remove logic which will be used for
 * hard reset as well
 */
void idpf_deinit_task(struct idpf_adapter *adapter)
{
	unsigned int i;

	idpf_netdev_stop_all(adapter);

	/* Wait until the init_task is done else this thread might release
	 * the resources first and the other thread might end up in a bad state
	 */
	cancel_delayed_work_sync(&adapter->init_task);

	/* Once the stats_task is cancelled here, dont schedule it in
	 * .ndo_get_stats64 or .get_ethtool_stats callbacks.
	 */
	cancel_delayed_work_sync(&adapter->stats_task);

	if (!adapter->vports)
		return;

	for (i = 0; i < adapter->max_vports; i++) {
		if (adapter->vports[i])
			idpf_vport_dealloc(adapter->vports[i]);
	}
}

/**
 * idpf_check_reset_complete - check that reset is complete
 * @adapter: Driver specific private structure
 *
 * Returns 0 if device is ready to use, or -EBUSY if it's in reset.
 **/
int idpf_check_reset_complete(struct idpf_adapter *adapter)
{
	int i;

	/* Must wait for CORER to complete, fail on timeout. */
	if (test_bit(IDPF_CORER_IN_PROG, adapter->flags)) {
		unsigned long timeout = msecs_to_jiffies(IDPF_CORER_TIMEOUT_MSEC);

		timeout = wait_for_completion_interruptible_timeout(&adapter->corer_done,
								    timeout);
		/* Fail gracefully on timeout or if wait is interrupted since either way
		 * we did not get a signal for the completion of CORER.
		 */
		if (timeout == 0 || timeout == -ERESTARTSYS) {
			clear_bit(IDPF_CORER_IN_PROG, adapter->flags);
			dev_err(idpf_adapter_to_dev(adapter), "Waiting for CORER timed out\n");

			return -EBUSY;
		}
		dev_dbg(idpf_adapter_to_dev(adapter), "CORER completed in %d ms\n",
			IDPF_CORER_TIMEOUT_MSEC - jiffies_to_msecs(timeout));
	}

	for (i = 0; i < IDPF_RESET_POLL_COUNT; i++) {
		u32 reg_val = readl(adapter->reset_reg.rstat);

		/* Bail if driver is removed while waiting for reset to complete
		 * to avoid needless delays in the removal of the driver.
		 */
		if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
			return -EBUSY;

		/* 0xFFFFFFFF might be read if other side hasn't cleared the
		 * register for us yet and 0xFFFFFFFF is not a valid value for
		 * the register, so treat that as invalid.
		 */
		if (reg_val != 0xFFFFFFFF &&
		    (reg_val & adapter->reset_reg.rstat_m) == IDPF_RSTAT_COMPLETE)
			return 0;

		usleep_range(5000, 10000);
	}

	dev_warn(idpf_adapter_to_dev(adapter), "Device reset timeout!\n");
	/* Clear the reset flag unconditionally here since the reset
	 * technically isn't in progress anymore from the driver's perspective
	 */
	clear_bit(IDPF_HR_RESET_IN_PROG, adapter->flags);

	return -EBUSY;
}

/**
 * idpf_set_vport_state - Set the vport state to be after the reset
 * @adapter: Driver specific private structure
 */
void idpf_set_vport_state(struct idpf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < adapter->max_vports; i++) {
		struct idpf_netdev_priv *np;

		if (!adapter->netdevs[i])
			continue;

		np = netdev_priv(adapter->netdevs[i]);
		if (np->active)
			set_bit(IDPF_VPORT_UP_REQUESTED,
				adapter->vport_config[i]->flags);
	}
}

/**
 * idpf_wait_on_reset_detection - Wait until reset has been detected
 * @adapter: Driver specific private structure
 *
 * Check on mailbox context set to 0
 * Returns 0 if reset is complete, -EBUSY otherwise.
 */
static int idpf_wait_on_reset_detection(struct idpf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < IDPF_RESET_POLL_COUNT; i++) {
		if (idpf_is_reset_detected(adapter))
			return 0;

		usleep_range(5000, 10000);
	}

	return -EBUSY;
}

/**
 * idpf_init_hard_reset - Initiate a hardware reset
 * @adapter: Driver specific private structure
 *
 * Deallocate the vports and all the resources associated with them and
 * reallocate. Also reinitialize the mailbox. Return 0 on success,
 * negative on failure.
 */
int idpf_init_hard_reset(struct idpf_adapter *adapter)
{
	struct idpf_reg_ops *reg_ops = &adapter->dev_ops.reg_ops;
	struct device *dev = idpf_adapter_to_dev(adapter);
	int err;

	idpf_netdev_stop_all(adapter);
	idpf_device_detach(adapter);

	idpf_init_ctrl_lock(adapter);

	dev_info(dev, "Device HW Reset initiated\n");
	/* Prepare for reset */
	if (test_and_clear_bit(IDPF_HR_DRV_LOAD, adapter->flags)) {
		reg_ops->trigger_reset(adapter, IDPF_HR_DRV_LOAD);
	} else if (test_bit(IDPF_HR_FUNC_RESET, adapter->flags)) {
		idpf_idc_event(&adapter->rdma_data, IDPF_HR_WARN_RESET, true);

		if (!idpf_is_reset_detected(adapter)) {
			reg_ops->trigger_reset(adapter, IDPF_HR_FUNC_RESET);
			err = idpf_wait_on_reset_detection(adapter);
			if (err) {
				dev_err(dev, "Device failed to reset\n");
				goto unlock_mutex;
			}
		}
		idpf_set_vport_state(adapter);
	} else {
		dev_err(dev, "Unhandled hard reset cause\n");
		err = -EBADRQC;
		goto unlock_mutex;
	}

	/* Wait for reset to complete */
	err = idpf_check_reset_complete(adapter);
	if (err) {
		dev_err(dev, "The driver was unable to contact the device's firmware. Check that the FW is running. Driver state=0x%x\n",
			adapter->state);
		goto unlock_mutex;
	}

	if (test_bit(IDPF_HR_FUNC_RESET, adapter->flags)) {
		/* We must wait until reset is complete to clean up IRQs
		 * because we need to touch some registers.
		 */
		idpf_vc_core_deinit(adapter);
		idpf_deinit_dflt_mbx(adapter);
	}

	clear_bit(IDPF_HR_FUNC_RESET, adapter->flags);

	/* Reset is complete and so start building the driver resources again */
	idpf_reset_recover(adapter);

unlock_mutex:
	idpf_init_ctrl_unlock(adapter);

	return err;
}

/**
 * idpf_vc_event_task - Handle virtchannel event logic
 * @work: work queue struct
 */
void idpf_vc_event_task(struct work_struct *work)
{
	struct idpf_adapter *adapter;

	adapter = container_of(work, struct idpf_adapter, vc_event_task.work);

	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return;

	if (test_bit(IDPF_HR_FUNC_RESET, adapter->flags))
		goto func_reset;
	if (test_bit(IDPF_HR_DRV_LOAD, adapter->flags))
		goto drv_load;

	return;

func_reset:
	idpf_vc_xn_shutdown(&adapter->vcxn_mngr);
drv_load:
	set_bit(IDPF_HR_RESET_IN_PROG, adapter->flags);
	idpf_init_hard_reset(adapter);
}

/**
 * idpf_initiate_soft_reset - Initiate a software reset
 * @vport: virtual port data struct
 * @reset_cause: reason for the soft reset
 *
 * Soft reset only reallocs vport queue resources. Returns 0 on success,
 * negative on failure.
 */
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_reset_cause reset_cause)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_rss_data *rss_data;
	bool alloc_vec_indexes = false;
	struct idpf_vport *new_vport;
	struct idpf_q_grp *new_q_grp;
	struct idpf_q_grp *q_grp;
	bool vport_is_up;
	int err, i;

	vport_is_up = np->active;

	/* If the system is low on memory, we can end up in bad state if we
	 * free all the memory for queue resources and try to allocate them
	 * again. Instead, we can pre-allocate the new resources before doing
	 * anything and bailing if the alloc fails.
	 *
	 * Make a clone of the existing vport to mimic its current
	 * configuration, then modify the new structure with any requested
	 * changes. Once the allocation of the new resources is done, stop the
	 * existing vport and copy the configuration to the main vport. If an
	 * error occurred, the existing vport will be untouched.
	 */
	new_vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!new_vport)
		return -ENOMEM;

	/* This purposely avoids copying the end of the struct because it
	 * contains wait_queues and mutexes and other stuff we don't want to
	 * mess with. Nothing below should use those variables from new_vport
	 * and should instead always refer to them in vport if they need to.
	 */
	memcpy(new_vport, vport, offsetof(struct idpf_vport, sw_marker_wq));

	new_q_grp = &new_vport->dflt_grp.q_grp;
	/* Adjust resource parameters prior to reallocating resources */
	switch (reset_cause) {
	case IDPF_SR_Q_CHANGE:
		idpf_vport_adjust_qs(new_vport);
		alloc_vec_indexes = true;
		break;
	case IDPF_SR_Q_DESC_CHANGE:
		/* Update queue parameters before allocating resources */
		idpf_vport_calc_num_q_desc(new_vport, new_q_grp);
		break;
	case IDPF_SR_Q_SCH_CHANGE:
	case IDPF_SR_MTU_CHANGE:
	case IDPF_SR_RSC_CHANGE:
	case IDPF_SR_HSPLIT_CHANGE:
#ifdef HAVE_XDP_SUPPORT
	case IDPF_SR_XDP_CHANGE:
#endif /* HAVE_XDP_SUPPORT */
		break;
	default:
		dev_err(idpf_adapter_to_dev(adapter), "Unhandled soft reset cause\n");
		err = -EINVAL;
		goto free_vport;
	}

	err = idpf_vport_queue_alloc_all(new_vport, new_q_grp);
	if (err)
		goto free_vport;
	if (!new_vport->idx) {
		idpf_idc_event(&adapter->rdma_data, reset_cause, true);
	}

	if (!vport_is_up) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (reset_cause == IDPF_SR_XDP_CHANGE) {
		err = idpf_xsk_handle_pool_change(new_vport);
		if (err)
			goto free_vport;
	}

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	switch (reset_cause) {
	case IDPF_SR_Q_CHANGE:
		vport_config = adapter->vport_config[vport->idx];
		rss_data = &vport_config->user_config.rss_data;

		idpf_deinit_rss(rss_data);
		break;
	default:
		break;
	}

	/* We're passing in vport here because we need it's wait_queue
	 * to send a message and it should be getting all the vport
	 * config data out of the adapter but we need to be careful not
	 * to add code to add_queues to change the vport config within
	 * vport itself as it will be wiped with a memcpy later.
	 */
	err = idpf_send_add_queues_msg(vport, new_q_grp->num_txq,
				       new_q_grp->num_complq,
				       new_q_grp->num_rxq,
				       new_q_grp->num_bufq);
	if (err)
		goto err_reset;

	/* Same comment as above regarding avoiding copying the wait_queues and
	 * mutexes applies here. We do not want to mess with those if possible.
	 */
	memcpy(vport, new_vport, offsetof(struct idpf_vport, sw_marker_wq));

	/* Since idpf_vport_queue_alloc_all was called with new_port, the queue
	 * back pointers are currently pointing to the local new_vport. Reset
	 * the backpointers to the original vport here
	 */
	q_grp = &vport->dflt_grp.q_grp;
	for (i = 0; i < q_grp->num_txq; i++)
		q_grp->txqs[i]->vport = vport;
	if (idpf_is_queue_model_split(q_grp->txq_model))
		for (i = 0; i < q_grp->num_complq; i++)
			q_grp->complqs[i].vport = vport;

	for (i = 0; i < q_grp->num_rxq; i++)
		q_grp->rxqs[i]->vport = vport;
	if (idpf_is_queue_model_split(q_grp->rxq_model))
		for (i = 0; i < q_grp->num_bufq; i++)
			q_grp->bufqs[i].vport = vport;

	if (alloc_vec_indexes)
		idpf_vport_alloc_vec_indexes(vport, &vport->dflt_grp);

	err = idpf_set_real_num_queues(vport);
	if (err)
		goto err_reset;

	if (vport_is_up)
		err = idpf_vport_open(vport, false);
	else
		/* When the vport is down it shouldn't have allocated queues,
		 * so release the queues allocated during the soft_reset for
		 * configuration reasons.
		 * Queues will be allocated in 'idpf_vport_open()' after
		 * .ndo_open() callback will be called.
		 */
		idpf_vport_queue_rel_all(vport, q_grp);
	if (!new_vport->idx) {
		idpf_idc_event(&adapter->rdma_data, reset_cause, false);
	}

	kfree(new_vport);

	return err;

err_reset:
	idpf_vport_queue_rel_all(vport, new_q_grp);
free_vport:
	kfree(new_vport);
	return err;
}

/**
 * idpf_addr_sync - Callback for dev_(mc|uc)_sync to add address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this, we have to add the
 * filter and send the virtchnl message asynchronously without waiting for the
 * response from the other side. We won't know whether or not the operation
 * actually succeeded until we get the message back.  Returns 0 on success,
 * negative on failure.
 */
static int idpf_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return idpf_add_mac_filter(np->vport, np, addr, true);
}

/**
 * idpf_addr_unsync - Callback for dev_(mc|uc)_sync to remove address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this we have to delete the
 * filter and send the virtchnl message asynchronously without waiting for the
 * return from the other side.  We won't know whether or not the operation
 * actually succeeded until we get the message back. Returns 0 on success,
 * negative on failure.
 */
static int idpf_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	/* Under some circumstances, we might receive a request to delete
	 * our own device address from our uc list. Because we store the
	 * device address in the VSI's MAC filter list, we need to ignore
	 * such requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	idpf_del_mac_filter(np->vport, np, addr, true);

	return 0;
}

/**
 * idpf_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 *
 * Stack takes addr_list_lock spinlock before calling our .set_rx_mode.  We
 * cannot sleep in this context.
 */
static void idpf_set_rx_mode(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter;
	bool changed = false;
	struct device *dev;
	int err;

	adapter = np->adapter;
	dev = idpf_adapter_to_dev(adapter);

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER)) {
		__dev_uc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
		__dev_mc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
	}

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_PROMISC))
		return;

	config_data = &adapter->vport_config[np->vport_idx]->user_config;
	/* IFF_PROMISC enables both unicast and multicast promiscuous,
	 * while IFF_ALLMULTI only enables multicast such that:
	 *
	 * promisc  + allmulti		= unicast | multicast
	 * promisc  + !allmulti		= unicast | multicast
	 * !promisc + allmulti		= multicast
	 */
	if ((netdev->flags & IFF_PROMISC) &&
	    !test_and_set_bit(__IDPF_PROMISC_UC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Entering promiscuous mode\n");
		if (!test_and_set_bit(__IDPF_PROMISC_MC, adapter->flags))
			dev_info(dev, "Entering multicast promiscuous mode\n");
	}

	if (!(netdev->flags & IFF_PROMISC) &&
	    test_and_clear_bit(__IDPF_PROMISC_UC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Leaving promiscuous mode\n");
	}

	if (netdev->flags & IFF_ALLMULTI &&
	    !test_and_set_bit(__IDPF_PROMISC_MC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Entering multicast promiscuous mode\n");
	}

	if (!(netdev->flags & (IFF_ALLMULTI | IFF_PROMISC)) &&
	    test_and_clear_bit(__IDPF_PROMISC_MC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Leaving multicast promiscuous mode\n");
	}

	if (!changed)
		return;

	err = idpf_set_promiscuous(adapter, config_data, np->vport_id);
	if (err)
		dev_info(dev, "Failed to set promiscuous mode: %d\n", err);
}

/**
 * idpf_vport_manage_rss_lut - disable/enable RSS
 * @vport: the vport being changed
 *
 * In the event of disable request for RSS, this function will zero out RSS
 * LUT, while in the event of enable request for RSS, it will reconfigure RSS
 * LUT with the default LUT configuration.
 */
static int idpf_vport_manage_rss_lut(struct idpf_vport *vport)
{
	bool ena = idpf_is_feature_ena(vport, NETIF_F_RXHASH);
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;
	int lut_size;

	rss_data = &vport->adapter->vport_config[idx]->user_config.rss_data;
	lut_size = rss_data->rss_lut_size * sizeof(u32);

	if (ena) {
		/* This will contain the default or user configured LUT */
		memcpy(rss_data->rss_lut, rss_data->cached_lut, lut_size);
	} else {
		/* Save a copy of the current LUT to be restored later if
		 * requested.
		 */
		memcpy(rss_data->cached_lut, rss_data->rss_lut, lut_size);

		/* Zero out the current LUT to disable */
		memset(rss_data->rss_lut, 0, lut_size);
	}

	return idpf_config_rss(vport, rss_data);
}

/**
 * idpf_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int idpf_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
	netdev_features_t changed = netdev->features ^ features;
	struct idpf_vport *vport;
	int err = 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	if (idpf_is_reset_in_prog(adapter)) {
		dev_err(idpf_adapter_to_dev(adapter), "Device is resetting, changing netdev features temporarily unavailable.\n");

		err = -EBUSY;
		goto unlock_mutex;
	}

	if (changed & NETIF_F_RXHASH) {
		netdev->features ^= NETIF_F_RXHASH;
		err = idpf_vport_manage_rss_lut(vport);
		if (err)
			goto unlock_mutex;
	}

#ifdef NETIF_F_GRO_HW
	if (changed & NETIF_F_GRO_HW) {
		netdev->features ^= NETIF_F_GRO_HW;
		err = idpf_initiate_soft_reset(vport, IDPF_SR_RSC_CHANGE);
		if (err)
			goto unlock_mutex;
	}

#endif /* NETIF_F_GRO_HW */
	if (changed & NETIF_F_LOOPBACK) {
		netdev->features ^= NETIF_F_LOOPBACK;
		err = idpf_send_ena_dis_loopback_msg(vport);
	}

unlock_mutex:
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

/**
 * idpf_fix_features - fix up the netdev feature bits
 * @netdev: our net device
 * @features: desired feature bits
 *
 * Returns fixed-up features bits
 */
static netdev_features_t idpf_fix_features(struct net_device *netdev,
					   netdev_features_t features)
{
	return features;
}

/**
 * idpf_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
static int idpf_open(struct net_device *netdev)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
	struct idpf_vport *vport;
	int err;

	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	err = idpf_vport_open(vport, true);
	if (err)
		goto unlock;

	err = idpf_set_real_num_queues(vport);

unlock:
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

/**
 * idpf_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
	struct idpf_vport *vport;
	int err = 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	if (new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->extended->min_mtu);
		err = -EINVAL;
		goto unlock_mutex;
	} else if (new_mtu > netdev->extended->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->extended->max_mtu);
		err = -EINVAL;
		goto unlock_mutex;
	}
#else /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
	if (new_mtu < netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		err = -EINVAL;
		goto unlock_mutex;
	} else if (new_mtu > netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->max_mtu);
		err = -EINVAL;
		goto unlock_mutex;
	}
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
#else /* HAVE_NETDEVICE_MIN_MAX_MTU */
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		err = -EINVAL;
		goto unlock_mutex;
	} else if (new_mtu > vport->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   vport->max_mtu);
		err = -EINVAL;
		goto unlock_mutex;
	}
#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */
#ifdef HAVE_XDP_SUPPORT

	if (idpf_xdp_is_prog_ena(vport) && new_mtu > IDPF_XDP_MAX_MTU) {
		netdev_err(netdev, "New MTU value is not valid. The maximum MTU value is %d.\n",
			   IDPF_XDP_MAX_MTU);
		err = -EINVAL;
		goto unlock_mutex;
	}
#endif /* HAVE_XDP_SUPPORT */
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		err = idpf_initiate_soft_reset(vport, IDPF_SR_MTU_CHANGE);

unlock_mutex:
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

#ifdef HAVE_NDO_FEATURES_CHECK
/**
 * idpf_features_check - Validate packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t idpf_features_check(struct sk_buff *skb,
					     struct net_device *netdev,
					     netdev_features_t features)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	u16 max_tx_hdr_size = np->max_tx_hdr_size;
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame.  We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 88 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) &&
	    (skb_shinfo(skb)->gso_size < IDPF_TX_TSO_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	/* Ensure MACLEN is <= 126 bytes (63 words) and not an odd size */
	len = skb_network_offset(skb);
	if (unlikely(len & ~(126)))
		goto unsupported;

	len = skb_network_header_len(skb);
	if (unlikely(len > max_tx_hdr_size))
		goto unsupported;

	if (!skb->encapsulation)
		return features;

	/* L4TUNLEN can support 127 words */
	len = skb_inner_network_header(skb) - skb_transport_header(skb);
	if (unlikely(len & ~(127 * 2)))
		goto unsupported;

	/* IPLEN can support at most 127 dwords */
	len = skb_inner_network_header_len(skb);
	if (unlikely(len > max_tx_hdr_size))
		goto unsupported;

	/* No need to validate L4LEN as TCP is the only protocol with a
	 * a flexible value and we support all possible values supported
	 * by TCP, which is at most 15 dwords
	 */

	return features;

unsupported:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

#endif /* HAVE_NDO_FEATURES_CHECK */
#ifdef HAVE_ETF_SUPPORT
/**
 * idpf_change_tx_sch_mode - reset queue context with appropriate
 * tx scheduling mode
 * @vport: virtual port data structure
 * @txq: queue to reset
 * @flow_sched: true if flow scheduling requested, false otherwise
 */
static int idpf_change_tx_sch_mode(struct idpf_vport *vport,
				   struct idpf_queue *txq,
				   bool flow_sched)
{
	if (flow_sched ^ test_bit(__IDPF_Q_FLOW_SCH_EN, txq->flags))
		return idpf_initiate_soft_reset(vport, IDPF_SR_Q_SCH_CHANGE);

	return 0;
}

/**
 * idpf_offload_txtime - Enable ETF offload
 * @vport: virtual port data structure
 * @qopt: input parameters for ETF offload
 *
 * Caller is expected to hold vport_ctrl_lock.
 *
 * Return 0 on success, error on failure.
 */
static int idpf_offload_txtime(struct idpf_vport *vport,
			       struct tc_etf_qopt_offload *qopt)
{
	struct idpf_q_grp *q_grp = &vport->dflt_grp.q_grp;
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_queue *tx_q;

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_EDT))
		return -EOPNOTSUPP;

	if (qopt->queue < 0 || qopt->queue > q_grp->num_txq)
		return -EINVAL;

	config_data = &adapter->vport_config[vport->idx]->user_config;
	/* Set config data to enable in future when queues are allocated */
	if (qopt->enable)
		set_bit(qopt->queue, config_data->etf_qenable);
	else
		clear_bit(qopt->queue, config_data->etf_qenable);

	tx_q = q_grp->txqs[qopt->queue];

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
			    VIRTCHNL2_CAP_SPLITQ_QSCHED))
		return idpf_change_tx_sch_mode(vport, tx_q, qopt->enable);

	/* Set bit in queue itself if queues are already allocated */
	if (qopt->enable)
		set_bit(__IDPF_Q_ETF_EN, tx_q->flags);
	else
		clear_bit(__IDPF_Q_ETF_EN, tx_q->flags);

	return 0;
}
#endif /* HAVE_ETF_SUPPORT */

/**
 * idpf_setup_tc - ndo callback to setup up TC schedulers
 * @netdev: pointer to net_device struct
 * @type: TC type
 * @type_data: TC type specific data
 */
static int idpf_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			 void *type_data)
{
	struct idpf_adapter *adapter = idpf_netdev_to_adapter(netdev);
	struct idpf_vport *vport;
	int err = 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	switch (type) {
#ifdef HAVE_ETF_SUPPORT
	case TC_SETUP_QDISC_ETF:
		if (!idpf_is_queue_model_split(vport->dflt_grp.q_grp.txq_model)) {
			err = -EOPNOTSUPP;
			goto vport_ctrl_unlock;
		}
		err = idpf_offload_txtime(vport, type_data);
		break;
#endif /* HAVE_ETF_SUPPORT */
	default:
		err = -EOPNOTSUPP;
		break;
	}

#ifdef HAVE_ETF_SUPPORT
vport_ctrl_unlock:
#endif /* HAVE_ETF_SUPPORT */
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

#ifdef HAVE_XDP_SUPPORT

/**
 * idpf_copy_xdp_prog_to_qs - set pointers to xdp program for each Rx queue
 * @vport: vport to setup XDP for
 * @xdp_prog: XDP program that should be copied to all Rx queues
 * @q_grp: Queue resources
 */
static void idpf_copy_xdp_prog_to_qs(struct idpf_vport *vport,
				     struct bpf_prog *xdp_prog,
				     struct idpf_q_grp *q_grp)
{
	int i;

	for (i = 0; i < q_grp->num_rxq; i++)
		WRITE_ONCE(q_grp->rxqs[i]->xdp_prog, xdp_prog);
}

/**
 * idpf_xdp_setup_prog - Add or remove XDP eBPF program
 * @np: netdev private data of the netdev where XDP will be configured
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
idpf_xdp_setup_prog(struct idpf_netdev_priv *np, struct bpf_prog *prog,
		    struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter = np->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_vport *vport = np->vport;
	bool needs_reconfig, vport_is_up;
	struct bpf_prog **current_prog;
	struct idpf_rss_data *rss_data;
	struct bpf_prog *old_prog;
	struct idpf_q_grp *q_grp;
	int err;

	q_grp = vport ? &vport->dflt_grp.q_grp : NULL;

	if (q_grp) {
		int frame_size = vport->netdev->mtu;

		if (frame_size > IDPF_XDP_MAX_MTU ||
		    frame_size > q_grp->bufq_size[0]) {
			NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
			return -EOPNOTSUPP;
		}
	}

	/* Do not allow for loading new programs while reseting */
	if (prog && test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags))
		return -EBUSY;

	vport_is_up = np->active;

	vport_config = adapter->vport_config[np->vport_idx];
	current_prog = &vport_config->user_config.xdp_prog;
	needs_reconfig = vport && (!!(*current_prog) != !!prog);

	if (!needs_reconfig) {
		if (q_grp && vport_is_up)
			idpf_copy_xdp_prog_to_qs(vport, prog, q_grp);

		old_prog = xchg(current_prog, prog);
		if (old_prog)
			bpf_prog_put(old_prog);

		return 0;
	}

	if (!vport_is_up) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

	rss_data = &vport_config->user_config.rss_data;
	idpf_deinit_rss(rss_data);

	if (!*current_prog && prog) {
		netdev_warn(vport->netdev,
			    "Setting up XDP disables header split\n");
		idpf_vport_set_hsplit(vport, false);
		xdp_features_set_redirect_target(vport->netdev, false);
	} else {
		idpf_vport_set_hsplit(vport, true);
		xdp_features_clear_redirect_target(vport->netdev);
	}

	old_prog = xchg(current_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	idpf_vport_adjust_qs(vport);
	idpf_vport_calc_num_q_desc(vport, q_grp);

	err = idpf_vport_queue_alloc_all(vport, q_grp);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not allocate queues for XDP\n");
		goto release_vport_queues;
	}

	err = idpf_send_add_queues_msg(vport, q_grp->num_txq,
				       q_grp->num_complq,
				       q_grp->num_rxq, q_grp->num_bufq);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not add queues for XDP, VC message sent failed\n");
		goto release_vport_queues;
	}

	idpf_vport_alloc_vec_indexes(vport, &vport->dflt_grp);

	if (vport_is_up) {
		err = idpf_vport_open(vport, false);
		if (err) {
			netdev_err(vport->netdev,
				   "Could not re-open the vport after XDP setup\n");
			goto release_vport_queues;
		}
	} else {
		idpf_vport_queue_rel_all(vport, q_grp);
	}

	return err;

release_vport_queues:
	idpf_vport_queue_rel_all(vport, q_grp);

	return err;
}

/**
 * idpf_xdp - implements XDP handler
 * @netdev: netdevice
 * @xdp: XDP command
 */
#ifdef HAVE_NDO_BPF
static int idpf_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
#else
static int idpf_xdp(struct net_device *netdev, struct netdev_xdp *xdp)
#endif /* HAVE_NDO_BPF */
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_adapter *adapter = np->adapter;
#ifdef HAVE_XDP_QUERY_PROG
	struct bpf_prog *current_prog;
	u16 vidx = np->vport_idx;
#endif /* HAVE_XDP_QUERY_PROG */
	int err = 0;

	idpf_vport_ctrl_lock(adapter);

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		err = idpf_xdp_setup_prog(np, xdp->prog, xdp->extack);
		break;
#ifdef HAVE_XDP_QUERY_PROG
	case XDP_QUERY_PROG:
		current_prog =
			np->adapter->vport_config[vidx]->user_config.xdp_prog;
		xdp->prog_id = current_prog ? current_prog->aux->id : 0;

#ifndef NO_NETDEV_BPF_PROG_ATTACHED
		xdp->prog_attached =
			np->adapter->vport_config[vidx]->user_config.xdp_prog;
#endif /* !NO_NETDEV_BPF_PROG_ATTACHED */
		break;
#endif /* HAVE_XDP_QUERY_PROG */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	case XDP_SETUP_XSK_POOL:
		err = idpf_xsk_pool_setup(netdev, xdp->xsk.pool,
					  xdp->xsk.queue_id);
		break;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	default:
		err = -EINVAL;
		break;
	}

	idpf_vport_ctrl_unlock(adapter);

	return err;
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * idpf_set_mac - NDO callback to set port mac address
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int idpf_set_mac(struct net_device *netdev, void *p)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct sockaddr *addr = p;
	struct idpf_adapter *adapter = np->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_vport *vport;
	int err = 0;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	if (!idpf_is_cap_ena(vport->adapter, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_info(idpf_adapter_to_dev(vport->adapter), "Setting MAC address is not supported\n");
		err = -EOPNOTSUPP;
		goto unlock_mutex;
	}

	if (!is_valid_ether_addr(addr->sa_data)) {
		dev_info(idpf_adapter_to_dev(vport->adapter), "Invalid MAC address: %pM\n",
			 addr->sa_data);
		err = -EADDRNOTAVAIL;
		goto unlock_mutex;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data))
		goto unlock_mutex;

	vport_config = vport->adapter->vport_config[vport->idx];
	err = idpf_add_mac_filter(vport, np, addr->sa_data, false);
	if (err) {
		__idpf_del_mac_filter(vport_config, addr->sa_data);
		goto unlock_mutex;
	}

	if (is_valid_ether_addr(vport->default_mac_addr))
		idpf_del_mac_filter(vport, np, vport->default_mac_addr, false);

	ether_addr_copy(vport->default_mac_addr, addr->sa_data);
	eth_hw_addr_set(netdev, addr->sa_data);

unlock_mutex:
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

/**
 * idpf_eth_ioctl - Access the hwtstamp interface
 * @netdev: network interface device structure
 * @ifr: interface request data
 * @cmd: ioctl command
 */
static int idpf_eth_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_adapter *adapter = np->adapter;
	enum idpf_ptp_access access;
	struct idpf_vport *vport;
	int err;

	idpf_vport_ctrl_lock(adapter);
	vport = idpf_netdev_to_vport(netdev);

	access = vport->adapter->ptp.tx_tstamp_access;
	if (access == IDPF_PTP_NONE || !vport->tx_tstamp_caps || !np->active) {
		err = -EOPNOTSUPP;
		goto free_vport;
	}

	switch (cmd) {
#ifdef SIOCGHWTSTAMP
	case SIOCGHWTSTAMP:
		err = idpf_ptp_get_ts_config(vport, ifr);
		break;
#endif /* SIOCGHWTSTAMP */
	case SIOCSHWTSTAMP:
		err = idpf_ptp_set_ts_config(vport, ifr);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

free_vport:
	idpf_vport_ctrl_unlock(adapter);

	return err;
}

/**
 * idpf_alloc_dma_mem - Allocate dma memory
 * @hw: pointer to hw struct
 * @mem: pointer to dma_mem struct
 * @size: size of the memory to allocate
 */
void *idpf_alloc_dma_mem(struct idpf_hw *hw, struct idpf_dma_mem *mem, u64 size)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;
	size_t sz = ALIGN(size, 4096);

	mem->va = dma_alloc_coherent(idpf_adapter_to_dev(adapter), sz,
				     &mem->pa, GFP_KERNEL);
	mem->size = sz;

	return mem->va;
}

/**
 * idpf_free_dma_mem - Free the allocated dma memory
 * @hw: pointer to hw struct
 * @mem: pointer to dma_mem struct
 */
void idpf_free_dma_mem(struct idpf_hw *hw, struct idpf_dma_mem *mem)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;

	dma_free_coherent(idpf_adapter_to_dev(adapter), mem->size,
			  mem->va, mem->pa);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = 0;
}

static const struct net_device_ops idpf_netdev_ops_splitq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_splitq_start,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = idpf_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
#ifdef HAVE_NDO_ETH_IOCTL
	.ndo_eth_ioctl = idpf_eth_ioctl,
#else
	.ndo_do_ioctl = idpf_eth_ioctl,
#endif /* HAVE_NDO_ETH_IOCTL */
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = idpf_change_mtu,
#else
	.ndo_change_mtu = idpf_change_mtu,
#endif
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_fix_features = idpf_fix_features,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = idpf_setup_tc,
#else
	.ndo_setup_tc = idpf_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NDO_BPF
	.ndo_bpf = idpf_xdp,
#else
	.ndo_xdp = idpf_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = idpf_xdp_xmit,
#ifndef NO_NDO_XDP_FLUSH
	.ndo_xdp_flush = idpf_xdp_flush,
#endif /* !NO_NDO_XDP_FLUSH */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#ifdef HAVE_NDO_XSK_WAKEUP
	.ndo_xsk_wakeup = idpf_xsk_splitq_wakeup,
#else
	.ndo_xsk_async_xmit = idpf_xsk_splitq_async_xmit,
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
};

static const struct net_device_ops idpf_netdev_ops_singleq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_singleq_start,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = idpf_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
#ifdef HAVE_NDO_ETH_IOCTL
	.ndo_eth_ioctl = idpf_eth_ioctl,
#else
	.ndo_do_ioctl = idpf_eth_ioctl,
#endif /* HAVE_NDO_ETH_IOCTL */
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = idpf_change_mtu,
#else
	.ndo_change_mtu = idpf_change_mtu,
#endif
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_fix_features = idpf_fix_features,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = idpf_setup_tc,
#else
	.ndo_setup_tc = idpf_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NDO_BPF
	.ndo_bpf = idpf_xdp,
#else
	.ndo_xdp = idpf_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = idpf_xdp_xmit,
#ifndef NO_NDO_XDP_FLUSH
	.ndo_xdp_flush = idpf_xdp_flush,
#endif /* !NO_NDO_XDP_FLUSH */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#ifdef HAVE_NDO_XSK_WAKEUP
	.ndo_xsk_wakeup = idpf_xsk_singleq_wakeup,
#else
	.ndo_xsk_async_xmit = idpf_xsk_singleq_async_xmit,
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
};
