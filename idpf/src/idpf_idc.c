/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"
#include "idpf_virtchnl.h"

static DEFINE_IDA(idpf_idc_ida);

/**
 * idpf_idc_init - Called to initialize IDC
 * @adapter: driver private data structure
 */
int idpf_idc_init(struct idpf_adapter *adapter)
{
	int err;

	if (!idpf_is_rdma_cap_ena(adapter) ||
	    !adapter->dev_ops.idc_ops.idc_init)
		return 0;

	err = adapter->dev_ops.idc_ops.idc_init(adapter);
	if (err)
		dev_err(idpf_adapter_to_dev(adapter), "failed to initialize idc: %d\n",
			err);

	return err;
}

/**
 * idpf_idc_deinit - Called to de-initialize IDC
 * @adapter: driver private data structure
 */
void idpf_idc_deinit(struct idpf_adapter *adapter)
{
	if (idpf_is_rdma_cap_ena(adapter) &&
	    adapter->dev_ops.idc_ops.idc_deinit)
		adapter->dev_ops.idc_ops.idc_deinit(adapter);
}

/**
 * idpf_get_auxiliary_drv - retrieve iidc_auxiliary_drv structure
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions.
 */
static struct iidc_auxiliary_drv *
idpf_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;

	if (!cdev_info)
		return NULL;

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;

	return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
			    adrv.driver);
}

/**
 * idpf_idc_event - Function to handle IDC event
 * @rdma_data: pointer to rdma data struct
 * @event_type: IDC event type
 */
void idpf_idc_event(struct idpf_rdma_data *rdma_data,
		    enum iidc_event_type event_type)
{
	struct iidc_core_dev_info *cdev_info = rdma_data->cdev_info;
	struct iidc_auxiliary_drv *iadrv;
	struct iidc_event *event;

	if (!cdev_info)
		/* RDMA is not enabled */
		return;

	/* We do not care about other events */
	if (event_type != IIDC_EVENT_WARN_RESET &&
	    event_type != IIDC_EVENT_AFTER_MTU_CHANGE)
		return;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return;
	set_bit(event_type, event->type);

	device_lock(&cdev_info->adev->dev);
	iadrv = idpf_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev_info, event);
	device_unlock(&cdev_info->adev->dev);
	kfree(event);
}

/**
 * idpf_idc_vc_receive - Used to pass the received msg over IDC
 * @rdma_data: pointer to rdma data struct
 * @f_id: function source id
 * @msg: payload received on mailbox
 * @msg_size: size of the payload
 *
 * This function is used by the Auxiliary Device to pass the receive mailbox
 * message an Auxiliary Driver cell
 */
int idpf_idc_vc_receive(struct idpf_rdma_data *rdma_data, u32 f_id, const u8 *msg,
			u16 msg_size)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_drv *iadrv;
	int err = 0;

	if (!rdma_data->cdev_info || !rdma_data->cdev_info->adev)
		return -ENODEV;

	cdev_info = rdma_data->cdev_info;

	device_lock(&cdev_info->adev->dev);
	iadrv = idpf_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->vc_receive)
		err = iadrv->vc_receive(cdev_info, f_id, (u8 *)msg, msg_size);
	device_unlock(&cdev_info->adev->dev);
	if (err)
		pr_err("Failed to pass receive idc msg, err %d\n", err);

	return err;
}

/**
 * idpf_idc_request_reset - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @reset_type: function, core or other
 *
 * This callback function is accessed by an Auxiliary Driver to request a reset
 * on the Auxiliary Device
 */
static int
idpf_idc_request_reset(struct iidc_core_dev_info *cdev_info,
		       enum iidc_reset_type __always_unused reset_type)
{
	struct idpf_adapter *adapter = pci_get_drvdata(cdev_info->pdev);

	if (!idpf_is_reset_in_prog(adapter)) {
		set_bit(IDPF_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}

	return 0;
}

/**
 * idpf_idc_vc_async_handler - Handle async RDMA messages
 * @adapter: private data struct
 * @xn: transaction for message
 * @ctlq_msg: message received
 *
 * Returns 0 on success, negative on failure.
 */
static int
idpf_idc_vc_async_handler(struct idpf_adapter *adapter, struct idpf_vc_xn *xn,
			  const struct idpf_ctlq_msg *ctlq_msg)
{
	if (ctlq_msg->cookie.mbx.chnl_opcode != VIRTCHNL2_OP_RDMA)
		return -EINVAL;

	return idpf_idc_vc_receive(&adapter->rdma_data, 0,
				   (u8 *)ctlq_msg->ctx.indirect.payload->va,
				   ctlq_msg->ctx.indirect.payload->size);
}

/**
 * idpf_idc_vc_send - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @vf_id: always unused
 * @msg: payload to be sent
 * @msg_size: size of the payload
 *
 * This callback function is accessed by an Auxiliary Driver to request a send
 * on the mailbox queue
 */
static int
idpf_idc_vc_send(struct iidc_core_dev_info *cdev_info,
		 u32 __always_unused vf_id, u8 *msg, u16 msg_size)
{
	struct idpf_vc_xn_params xn_params = { };
	struct idpf_adapter *adapter;
	ssize_t reply_sz;

	if (cdev_info->cdev_info_id != IIDC_RDMA_ID)
		return -EINVAL;

	if (msg_size > IDPF_CTLQ_MAX_BUF_LEN)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);

	xn_params.vc_op = VIRTCHNL2_OP_RDMA;
	xn_params.timeout_ms = idpf_get_vc_xn_default_timeout(adapter);
	xn_params.send_buf.iov_base = msg;
	xn_params.send_buf.iov_len = msg_size;
	xn_params.async = true;
	xn_params.async_handler = idpf_idc_vc_async_handler;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0) {
		pr_err("Failed to pass send IDC msg, err %ld\n", reply_sz);
		return reply_sz;
	}

	return 0;
}

/**
 * idpf_idc_vc_send_sync - synchronous version of vc_send
 * @cdev_info: core device info pointer
 * @send_msg: message to send
 * @msg_size: size of message to send
 * @recv_msg: message to populate on reception of response
 * @recv_len: length of message copied into recv_msg or 0 on error
 */
static int
idpf_idc_vc_send_sync(struct iidc_core_dev_info *cdev_info, u8 *send_msg,
		      u16 msg_size, u8 *recv_msg, u16 *recv_len)
{
	struct idpf_adapter *adapter = pci_get_drvdata(cdev_info->pdev);
	struct idpf_vc_xn_params xn_params = { };
	ssize_t reply_sz;
	u16 recv_size;

	if (!recv_msg || !recv_len || msg_size > IDPF_CTLQ_MAX_BUF_LEN)
		return -EINVAL;

	recv_size = min_t(u16, *recv_len, IDPF_CTLQ_MAX_BUF_LEN);
	*recv_len = 0;
	xn_params.vc_op = VIRTCHNL2_OP_RDMA;
	xn_params.timeout_ms = idpf_get_vc_xn_default_timeout(adapter);
	xn_params.send_buf.iov_base = send_msg;
	xn_params.send_buf.iov_len = msg_size;
	xn_params.recv_buf.iov_base = recv_msg;
	xn_params.recv_buf.iov_len = recv_size;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	*recv_len = reply_sz;

	return 0;
}

/**
 * idpf_idc_vc_qv_map_unmap - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @qvl_info: payload to be sent on mailbox
 * @map: map or unmap
 *
 * Deprecated, use generic auxiliary driver messaging interface instead.
 */
static int
idpf_idc_vc_qv_map_unmap(struct iidc_core_dev_info *cdev_info,
			 struct iidc_qvlist_info *qvl_info, bool map)
{
	return -EOPNOTSUPP;
}

/* Implemented by the Auxiliary Device and called by the Auxiliary Driver */
static const struct iidc_core_ops idc_ops = {
	.request_reset                  = idpf_idc_request_reset,
	.vc_send                        = idpf_idc_vc_send,
	.vc_send_sync			= idpf_idc_vc_send_sync,
	.vc_queue_vec_map_unmap         = idpf_idc_vc_qv_map_unmap,
};

/**
 * idpf_adev_release - function to be mapped to aux dev's release op
 * @dev: pointer to device to free
 */
static void idpf_adev_release(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
	iadev = NULL;
}

/* idpf_plug_aux_dev - allocate and register an Auxiliary device
 * @rdma_data: pointer to rdma data struct
 */
static int idpf_plug_aux_dev(struct idpf_rdma_data *rdma_data)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_dev *iadev;
	struct auxiliary_device *adev;
	int err;

	cdev_info = rdma_data->cdev_info;
	if (!cdev_info)
		return -ENODEV;

	rdma_data->aux_idx = ida_alloc(&idpf_idc_ida, GFP_KERNEL);
	if (rdma_data->aux_idx < 0) {
		pr_err("failed to allocate unique device ID for Auxiliary driver\n");
		return -ENOMEM;
	}

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		err = -ENOMEM;
		goto err_iadev_alloc;
	}

	adev = &iadev->adev;
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;

	if (cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_IWARP)
		adev->name = IIDC_RDMA_IWARP_NAME;
	else
		adev->name = IIDC_RDMA_ROCE_NAME;

	adev->id = rdma_data->aux_idx;
	adev->dev.release = idpf_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;

	err = auxiliary_device_init(adev);
	if (err)
		goto err_aux_dev_init;

	err = auxiliary_device_add(adev);
	if (err)
		goto err_aux_dev_add;

	return 0;

err_aux_dev_add:
	cdev_info->adev = NULL;
	auxiliary_device_uninit(adev);
err_aux_dev_init:
	kfree(iadev);
err_iadev_alloc:
	ida_free(&idpf_idc_ida, rdma_data->aux_idx);

	return err;
}

/* idpf_unplug_aux_dev - unregister and free an Auxiliary device
 * @rdma_data: pointer to rdma data struct
 */
static void idpf_unplug_aux_dev(struct idpf_rdma_data *rdma_data)
{
	struct auxiliary_device *adev;

	if (!rdma_data->cdev_info)
		return;

	ida_free(&idpf_idc_ida, rdma_data->aux_idx);

	adev = rdma_data->cdev_info->adev;
	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);
	adev = NULL;

}

/**
 * idpf_idc_init_msix_data - initialize MSIX data for the cdev_info structure
 * @rdma_data: pointer to rdma data struct
 */
static void
idpf_idc_init_msix_data(struct idpf_rdma_data *rdma_data)
{
	struct iidc_core_dev_info *cdev_info;

	if (!rdma_data->msix_entries)
		return;

	cdev_info = rdma_data->cdev_info;

	cdev_info->msix_entries = rdma_data->msix_entries;
	cdev_info->msix_count = rdma_data->num_vecs;
}

/**
 * idpf_idc_init_qos_info - initialialize default QoS information
 * @qos_info: QoS information structure to populate
 */
static void
idpf_idc_init_qos_info(struct iidc_qos_params *qos_info)
{
	int i;

	qos_info->num_apps = 0;
	qos_info->num_tc = 1;

	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		qos_info->up2tc[i] = 0;

	qos_info->tc_info[0].rel_bw = 100;
	for (i = 1; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->tc_info[i].rel_bw = 0;
}

/**
 * idpf_idc_init_aux_device - initialize Auxiliary Device(s)
 * @rdma_data: pointer to rdma data struct
 * @ftype: function type
 */
int
idpf_idc_init_aux_device(struct idpf_rdma_data *rdma_data,
			 enum iidc_function_type ftype)
{
	struct iidc_core_dev_info *cdev_info;
	struct idpf_adapter *adapter;
	int err;

	/* structure layout needed for container_of's looks like:
	 * iidc_auxiliary_dev (container_of super-struct for adev)
	 * |--> auxiliary_device
	 * |--> *iidc_core_dev_info (pointer from cdev_info struct)
	 *
	 * The iidc_auxiliary_device has a lifespan as long as it
	 * is on the bus.  Once removed it will be freed and a new
	 * one allocated if needed to re-add.
	 */
	rdma_data->cdev_info = kzalloc(sizeof(struct iidc_core_dev_info),
				       GFP_KERNEL);
	if (!rdma_data->cdev_info) {
		err = -ENOMEM;
		goto err_cdev_info_alloc;
	}

	adapter = container_of(rdma_data, struct idpf_adapter, rdma_data);

	cdev_info = rdma_data->cdev_info;
	cdev_info->hw_addr = (u8 __iomem *)adapter->hw.hw_addr;
	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->ftype = ftype;
	cdev_info->vport_id = adapter->vports[0]->vport_id;
	cdev_info->netdev = adapter->vports[0]->netdev;
	cdev_info->pdev = adapter->pdev;
	cdev_info->ops = &idc_ops;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_IWARP;
	cdev_info->cdev_info_id = IIDC_RDMA_ID;

	idpf_idc_init_qos_info(&cdev_info->qos_info);
	idpf_idc_init_msix_data(rdma_data);

	err = idpf_plug_aux_dev(rdma_data);
	if (err)
		goto err_plug_aux_dev;

	return 0;

err_plug_aux_dev:
	kfree(rdma_data->cdev_info);
	rdma_data->cdev_info = NULL;
err_cdev_info_alloc:
	memset(rdma_data, 0, sizeof(*rdma_data));

	return err;
}

/**
 * idpf_idc_deinit_aux_device - de-initialize Auxiliary Device(s)
 * @adapter: driver private data structure
 */
void idpf_idc_deinit_aux_device(struct idpf_adapter *adapter)
{
	struct idpf_rdma_data *rdma_data = &adapter->rdma_data;

	idpf_unplug_aux_dev(rdma_data);
	kfree(rdma_data->cdev_info);
	memset(rdma_data, 0, sizeof(*rdma_data));
}
