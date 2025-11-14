/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"
#define DEVLINK_DEFER_TIME (4)  /* 4 milliseconds */

#ifdef HAVE_DEVLINK_PORT_OPS
static const struct devlink_port_ops idpf_devlink_port_ops;

#endif /* HAVE_DEVLINK_PORT_OPS */
/**
 * idpf_sf_by_sfnum - Search for a given subfn number in the subfn list
 * stored inside the adapter structure.
 * @adapter: pointer to idpf adapter structure
 * @sfnum: sub function number to be searched
 *
 * Returns pointer to subfn structure entry or NULL if not found.
 */
static struct idpf_sf *idpf_sf_by_sfnum(struct idpf_adapter *adapter, u32 sfnum)
{
	struct idpf_sf *sf;

	mutex_lock(&adapter->sf_mutex);
	list_for_each_entry(sf, &adapter->sf_list, list) {
		if (!sf->deleted && sf->sfnum == sfnum)
			goto found_entry;
	}
	sf = NULL;
found_entry:
	mutex_unlock(&adapter->sf_mutex);
	return sf;
}

/**
 * idpf_devlink_create_sf_port - Create and register a devlink_port for this SF.
 * @sf: the subfunction to create a devlink port for
 * Return: 0 on success or an error code on failure.
 */
static int idpf_devlink_create_sf_port(struct idpf_sf *sf)
{
	struct devlink_port_attrs attrs = { };
	struct devlink_port *devlink_port;
	struct idpf_adapter *adapter;
	struct devlink *devlink;
	struct device *dev;
	int err;

	adapter = sf->adapter;
	dev = idpf_adapter_to_dev(adapter);
	devlink_port = &sf->devl_port;
	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_SF;
	attrs.pci_sf.pf = 0;
	attrs.pci_sf.sf = sf->sfnum;
	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(adapter);
#ifdef HAVE_DEVLINK_PORT_OPS
#ifdef HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG
	err = devl_port_register_with_ops(devlink, devlink_port, sf->sf_id,
					  &idpf_devlink_port_ops);
#else
	err = devlink_port_register_with_ops(devlink, devlink_port, sf->sf_id,
					     &idpf_devlink_port_ops);
#endif /* HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG */
#else
#ifdef HAVE_DEVL_PORT_REGISTER
	err = devl_port_register(devlink, devlink_port, sf->sf_id);
#else
	err = devlink_port_register(devlink, devlink_port, sf->sf_id);
#endif /* HAVE_DEVL_PORT_REGISTER */
#endif /* HAVE_DEVLINK_PORT_OPS */
	if (err) {
		dev_err(dev, "Failed to create devlink port: sfnum %d, err %d",
			sf->sfnum, err);
		return err;
	}
	dev_dbg(dev, "%s: sfnum %d sf_id %d successful\n",
		__func__, sf->sfnum, sf->sf_id);
	return 0;
}

/**
 * idpf_dl_port_new - Add a new port function of a specified flavor
 * @devlink: Devlink instance pointer
 * @new_attr: attributes of the new port
 * @extack: extack for reporting error messages
#ifdef HAVE_DEVLINK_PORT_OPS
 * @devlink_port: pointer to pointer to new devlink_port instance.
 * value filled by function.
#else
 * @new_port_index: pointer to index of the new port. Value filled by func.
#endif
 *
 * Fills the 4th parameter with the index for the new sub function.
 * Returns 0 on success, negative value otherwise.
 */
#ifdef HAVE_DEVLINK_PORT_OPS
static int idpf_dl_port_new(struct devlink *devlink,
			    const struct devlink_port_new_attrs *new_attr,
			    struct netlink_ext_ack *extack,
			    struct devlink_port **devlink_port)
#else
static int idpf_dl_port_new(struct devlink *devlink,
			    const struct devlink_port_new_attrs *new_attr,
			    struct netlink_ext_ack *extack,
			    unsigned int *new_port_index)
#endif /* HAVE_DEVLINK_PORT_OPS */
{
	struct idpf_adapter *adapter = devlink_priv(devlink);
	struct device *dev = idpf_adapter_to_dev(adapter);
	u16 num_default_vports;
	struct idpf_sf *sf;
	int err;

	dev_dbg(dev, "%s: flavour:%d index:%d pfnum:%d\n", __func__,
		new_attr->flavour, new_attr->port_index, new_attr->pfnum);
	if (!new_attr->sfnum_valid) {
		NL_SET_ERR_MSG_MOD(extack, "sfnum autogeneration is not supported");
		return -EINVAL;
	}
	if (idpf_sf_by_sfnum(adapter, new_attr->sfnum)) {
		NL_SET_ERR_MSG_MOD(extack, "sfnum already exists");
		return -EEXIST;
	}
	if (adapter->sf_cnt >= IDPF_MAX_DYNAMIC_VPORT) {
		NL_SET_ERR_MSG_MOD(extack, "Cannot create more vports");
		return -EINVAL;
	}

	num_default_vports = idpf_get_default_vports(adapter);
	/* We came here too early. Let the default vports be allocated
	 * and initialized first. Only then we will proceed with dynamic
	 * ones
	 */
	if (!num_default_vports ||
	    adapter->num_alloc_vports < num_default_vports)
		return -EAGAIN;

	sf = kzalloc(sizeof(*sf), GFP_KERNEL);
	if (!sf)
		return -ENOMEM;
	sf->vport = NULL;
	sf->adapter = adapter;
	sf->state = DEVLINK_PORT_FN_STATE_INACTIVE;
	sf->sf_id = ++adapter->sf_id;
	sf->sfnum = new_attr->sfnum;
	eth_random_addr(sf->hw_addr);
	err = idpf_devlink_create_sf_port(sf);
	if (err)
		goto unroll_sf_alloc;
	mutex_lock(&adapter->sf_mutex);
	list_add(&sf->list, &adapter->sf_list);
#ifdef HAVE_DEVLINK_PORT_OPS
	*devlink_port = &sf->devl_port;
	dev_dbg(dev, "New devlink port addr %p\n", *devlink_port);
#else
	*new_port_index = sf->sf_id;
	dev_dbg(dev, "New devlink port index %d\n", *new_port_index);
#endif /* HAVE_DEVLINK_PORT_OPS */
	adapter->sf_cnt++;
	mutex_unlock(&adapter->sf_mutex);
	return 0;

unroll_sf_alloc:
	kfree(sf);
	return err;
}

/**
 * idpf_destroy_sf - Free the vport and the associated subfunc structure.
 * the corresponding devlink port is also unregistered.
 * @sf: pointer to subfunction structure
 */
static void idpf_destroy_sf(struct idpf_sf *sf)
{
	struct idpf_adapter *adapter;
	struct device *dev;

	adapter = sf->adapter;
	dev = idpf_adapter_to_dev(adapter);
	dev_dbg(dev, "%s: sfnum %d vport %p\n", __func__, sf->sfnum, sf->vport);
	if (sf->vport) {
		u16 idx = sf->vport->idx;

		/*
		 * The vport dealloc function does not free the vport config
		 * because it saves some information across resets. However
		 * this is a dynamic vport and when freeing the vport, its
		 * associated config can also be freed.
		 */
		idpf_vport_dealloc(sf->vport);
		kfree(adapter->vport_config[idx]);
		adapter->vport_config[idx] = NULL;
	}

#ifdef HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG
	devl_port_unregister(&sf->devl_port);
#else
	devlink_port_unregister(&sf->devl_port);
#endif /* HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG */
	mutex_lock(&adapter->sf_mutex);
	sf->vport = NULL;
	kfree(sf);
	adapter->sf_cnt--;
	mutex_unlock(&adapter->sf_mutex);
}

/**
 * idpf_destroy_sfs - delete all the associated subfunctions
 * marked for deletion.
 * @adapter: pointer to idpf adapter structure
 */
static void idpf_destroy_sfs(struct idpf_adapter *adapter)
{
	struct idpf_sf *sf, *temp_sf;

	mutex_lock(&adapter->sf_mutex);
	list_for_each_entry_safe(sf, temp_sf, &adapter->sf_list, list) {
		if (!sf->deleted)
			continue;

		/* remove this entry first */
		list_del(&sf->list);
		mutex_unlock(&adapter->sf_mutex);
		idpf_destroy_sf(sf);
		mutex_lock(&adapter->sf_mutex);
	}
	mutex_unlock(&adapter->sf_mutex);
}

/**
 * idpf_cleanup_task - task to delete associated vport and sf
 * @work: pointer to work_struct structure
 */
static void idpf_cleanup_task(struct work_struct *work)
{
	struct idpf_adapter *adapter;

	adapter = container_of(work, struct idpf_adapter, cleanup_task.work);
	idpf_destroy_sfs(adapter);
}

/**
 * idpf_dl_port_del - delete a port function that is referenced via port_index
 * @devlink: Devlink instance pointer
 * @port_index: index of the subfunction to be deleted
 * @extack: extack for reporting error messages
 *
 * Return: 0 on success, negative value otherwise.
 */
#ifdef HAVE_DEVLINK_PORT_OPS
static int idpf_dl_port_del(struct devlink *devlink,
			    struct devlink_port *port,
			    struct netlink_ext_ack *extack)
#else
static int idpf_dl_port_del(struct devlink *devlink,
			    unsigned int port_index,
			    struct netlink_ext_ack *extack)
#endif /* HAVE_DEVLINK_PORT_OPS */
{
	struct idpf_adapter *adapter = devlink_priv(devlink);
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_sf *sf = NULL, *sf_tmp;

#ifdef HAVE_DEVLINK_PORT_OPS
	dev_dbg(dev, "%s devlink_port :%p\n", __func__, port);
#else
	dev_dbg(dev, "%s: index:%d\n", __func__, port_index);
#endif /* HAVE_DEVLINK_PORT_OPS */
	mutex_lock(&adapter->sf_mutex);
	list_for_each_entry(sf_tmp, &adapter->sf_list, list) {
		if (sf_tmp->deleted)
			continue;
#ifdef HAVE_DEVLINK_PORT_OPS
		if (&sf_tmp->devl_port == port) {
#else
		if (sf_tmp->sf_id == port_index) {
#endif /* HAVE_DEVLINK_PORT_OPS */
			sf = sf_tmp;
			break;
		}
	}
	if (!sf) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to find a SF port with a given index");
		mutex_unlock(&adapter->sf_mutex);
		return -EINVAL;
	}

	sf->deleted = true;
#ifdef HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG
	list_del(&sf->list);
	mutex_unlock(&adapter->sf_mutex);
	idpf_destroy_sf(sf);
#else
	mutex_unlock(&adapter->sf_mutex);
	schedule_delayed_work(&adapter->cleanup_task,
			      msecs_to_jiffies(DEVLINK_DEFER_TIME));
#endif /* HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG */

	return 0;
}

/**
 * idpf_dl_port_fn_state_set - Set the admin state of a port function
 * This function uses the idpf_init_task task to spawn a new vport and
 * create a netdev and associated infrastructure.
 * @port: The devlink port
 * @state: Admin state
 * @extack: extack for reporting error messages
 *
 * Return: 0 on success, negative value otherwise.
 */
#ifdef HAVE_DEVLINK_SET_STATE_3_PARAM
static int idpf_dl_port_fn_state_set(struct devlink_port *port,
				     enum devlink_port_fn_state state,
				     struct netlink_ext_ack *extack)
#else
static int idpf_dl_port_fn_state_set(struct devlink *unused,
				     struct devlink_port *port,
				     enum devlink_port_fn_state state,
				     struct netlink_ext_ack *extack)
#endif
{
	struct idpf_sf *sf = container_of(port, struct idpf_sf, devl_port);
	struct idpf_adapter *adapter = sf->adapter;
	struct device *dev;
	u16 next_vport;

	dev = idpf_adapter_to_dev(adapter);
	dev_dbg(dev, "%s: sfnum %d input_state %d curr_state %d\n",
		__func__, sf->sfnum, state, sf->state);
	if (port->attrs.flavour != DEVLINK_PORT_FLAVOUR_PCI_SF) {
		NL_SET_ERR_MSG_MOD(extack, "Port is not a SF");
		return -EOPNOTSUPP;
	}
	if (state == sf->state)
		return 0;
	next_vport = adapter->next_vport;
	if (next_vport == IDPF_NO_FREE_SLOT) {
		NL_SET_ERR_MSG_MOD(extack, "No more free vport slot");
		return -ENOMEM;
	}
	INIT_WORK(&adapter->init_task.work, idpf_init_task);
	schedule_work(&adapter->init_task.work);
	flush_work(&adapter->init_task.work);
	if (!adapter->vports[next_vport]) {
		NL_SET_ERR_MSG_MOD(extack, "vport allocation failed");
		return -ENOMEM;
	}
	sf->vport = adapter->vports[next_vport];
#ifdef HAVE_DEVLINK_PORT_TYPE_ETH_HAS_NETDEV
	devlink_port_type_eth_set(&sf->devl_port, adapter->netdevs[next_vport]);
#else
#ifndef HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG
	devlink_port_type_eth_set(&sf->devl_port);
#endif /* HAVE_DEVL_PORT_REG_WITH_OPS_AND_UNREG */
#endif /* HAVE_DEVLINK_PORT_TYPE_ETH_HAS_NETDEV */
	sf->state = DEVLINK_PORT_FN_STATE_ACTIVE;
	return 0;
}

/**
 * idpf_destroy_sf_list - For a given input adapter, free all the associated
 * subfunctions.
 * @adapter: pointer to idpf adapter structure
 */
static void idpf_destroy_sf_list(struct idpf_adapter *adapter)
{
	struct idpf_sf *sf, *temp_sf;

	cancel_delayed_work_sync(&adapter->cleanup_task);
	/* Mark all the subfunctions as deleted and call destroy handler */
	mutex_lock(&adapter->sf_mutex);
	list_for_each_entry_safe(sf, temp_sf, &adapter->sf_list, list)
		sf->deleted = true;

	mutex_unlock(&adapter->sf_mutex);
	idpf_destroy_sfs(adapter);
}

#ifdef HAVE_DEVLINK_PORT_OPS
const struct devlink_ops idpf_devlink_ops = {
	.port_new = idpf_dl_port_new
};

static const struct devlink_port_ops idpf_devlink_port_ops = {
	.port_del = idpf_dl_port_del,
	.port_fn_state_set = idpf_dl_port_fn_state_set
};
#else
const struct devlink_ops idpf_devlink_ops = {
	.port_new = idpf_dl_port_new,
	.port_del = idpf_dl_port_del,
	.port_fn_state_set = idpf_dl_port_fn_state_set,
};
#endif /* HAVE_DEVLINK_PORT_OPS */

/**
 * idpf_devlink_deinit - Unregister and deallocate all devlink related
 * content and data structures for a given idpf adapter.
 * @adapter: pointer to idpf adapter structure
 */
void idpf_devlink_deinit(struct idpf_adapter *adapter)
{
	idpf_destroy_sf_list(adapter);
	flush_delayed_work(&adapter->cleanup_task);
	devlink_unregister(priv_to_devlink(adapter));
	mutex_destroy(&adapter->sf_mutex);
}

/**
 * idpf_devlink_init - Register driver resource flags, parameters and
 * the devlink port corresponding to the idpf adapter.
 * @adapter: pointer to idpf adapter structure to be associated with devlink
 * @dev: pointer to device structure for backward compatibiity. Older kernels
 * expected an additional parameter in register API
 */
void idpf_devlink_init(struct idpf_adapter *adapter, struct device *dev)
{
#ifdef HAVE_DEVLINK_REGISTER_SETS_DEV
	devlink_register(priv_to_devlink(adapter), dev);
#else
	devlink_register(priv_to_devlink(adapter));
#endif
	INIT_LIST_HEAD(&adapter->sf_list);
	mutex_init(&adapter->sf_mutex);
	INIT_DELAYED_WORK(&adapter->cleanup_task, idpf_cleanup_task);
	adapter->sf_id = 0;
}
