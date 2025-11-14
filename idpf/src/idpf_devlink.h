/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#ifndef _IDPF_DEVLINK_H_
#define _IDPF_DEVLINK_H_
#include <net/devlink.h>

struct idpf_sf {
	struct list_head list;
	u8 hw_addr[ETH_ALEN];
	s16 sf_id;
	bool deleted;
	u32 sfnum;
	enum devlink_port_fn_state state;
	struct devlink_port devl_port;
	struct idpf_adapter *adapter;
	struct idpf_vport *vport;
};

extern const struct devlink_ops idpf_devlink_ops;
void idpf_devlink_deinit(struct idpf_adapter *adapter);
void idpf_devlink_init(struct idpf_adapter *adapter, struct device *dev);

#endif /* _IDPF_DEVLINK_H_ */
