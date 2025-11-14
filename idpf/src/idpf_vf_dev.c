/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"
#include "idpf_lan_vf_regs.h"
#include "idpf_virtchnl.h"

/* LAN driver does not own all the BAR0 address space. This results in 2 BAR0
 * regions for VF device and the driver should map each region separately.
 *
 * Rest of BAR0 is owned by RDMA and it maps the pages on its own as it needs
 * to map some of the pages for write combing (WC) instead of the default
 * non-cached (NC) mapping that LAN driver does. In the VF BAR space,
 * RDMA BAR0 memory lies between 64KB to 128KB.
 *
 * Also driver should map 1 page of RDMA from its space.
 */
#define IDPF_VF_BAR0_REGION1_END	0x11000		/* 64KB + 4KB */
#define IDPF_VF_BAR0_REGION2_START	0x20000		/* 128KB */

#define IDPF_VF_ITR_IDX_SPACING		0x40

#define IDPF_VDEV_BAR0_REGION2_START	(SIOV_REG_BAR_SIZE + 0x1000)

static const struct idpf_ctlq_reg idpf_vdev_tx_regs = {
		.head = VDEV_MBX_ATQH,
		.tail = VDEV_MBX_ATQT,
		.len = VDEV_MBX_ATQLEN,
		.bah = VDEV_MBX_ATQBAH,
		.bal = VDEV_MBX_ATQBAL
};

static const struct idpf_ctlq_reg idpf_vdev_rx_regs = {
		.head = VDEV_MBX_ARQH,
		.tail = VDEV_MBX_ARQT,
		.len = VDEV_MBX_ARQLEN,
		.bah = VDEV_MBX_ARQBAH,
		.bal = VDEV_MBX_ARQBAL
};

/**
 * idpf_vf_ctlq_reg_init - initialize default mailbox registers
 * @hw: pointer to hw struct
 * @cq: pointer to the array of create control queues
 */
static void idpf_vf_ctlq_reg_init(struct idpf_hw *hw,
				  struct idpf_ctlq_create_info *cq)
{
	int i;

	for (i = 0; i < IDPF_NUM_DFLT_MBX_Q; i++) {
		struct idpf_ctlq_create_info *ccq = cq + i;

		switch (ccq->type) {
		case IDPF_CTLQ_TYPE_MAILBOX_TX:
			/* set head and tail registers in our local struct */
			if (hw->device_id == IDPF_DEV_ID_VF_SIOV) {
				ccq->reg = idpf_vdev_tx_regs;
			} else {
				ccq->reg.head = VF_ATQH;
				ccq->reg.tail = VF_ATQT;
				ccq->reg.len = VF_ATQLEN;
				ccq->reg.bah = VF_ATQBAH;
				ccq->reg.bal = VF_ATQBAL;
			}
			ccq->reg.len_mask = VF_ATQLEN_ATQLEN_M;
			ccq->reg.len_ena_mask = VF_ATQLEN_ATQENABLE_M;
			ccq->reg.head_mask = VF_ATQH_ATQH_M;
			break;
		case IDPF_CTLQ_TYPE_MAILBOX_RX:
			/* set head and tail registers in our local struct */
			if (hw->device_id == IDPF_DEV_ID_VF_SIOV) {
				ccq->reg = idpf_vdev_rx_regs;
			} else {
				ccq->reg.head = VF_ARQH;
				ccq->reg.tail = VF_ARQT;
				ccq->reg.len = VF_ARQLEN;
				ccq->reg.bah = VF_ARQBAH;
				ccq->reg.bal = VF_ARQBAL;
			}
			ccq->reg.len_mask = VF_ARQLEN_ARQLEN_M;
			ccq->reg.len_ena_mask = VF_ARQLEN_ARQENABLE_M;
			ccq->reg.head_mask = VF_ARQH_ARQH_M;
			break;
		default:
			break;
		}
	}
}

/**
 * idpf_vf_mb_intr_reg_init - Initialize the mailbox register
 * @adapter: adapter structure
 */
static void idpf_vf_mb_intr_reg_init(struct idpf_adapter *adapter)
{
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 dyn_ctl = le32_to_cpu(adapter->caps.mailbox_dyn_ctl);

	intr->dyn_ctl = idpf_get_reg_addr(adapter, dyn_ctl);
	intr->dyn_ctl_intena_m = VF_INT_DYN_CTL0_INTENA_M;
	intr->dyn_ctl_itridx_m = VF_INT_DYN_CTL0_ITR_INDX_M;
	intr->icr_ena = idpf_get_reg_addr(adapter, VF_INT_ICR0_ENA1);
	intr->icr_ena_ctlq_m = VF_INT_ICR0_ENA1_ADMINQ_M;
}

/**
 * idpf_vf_intr_reg_init - Initialize interrupt registers
 * @vport: virtual port structure
 * @intr_grp: Interrupt resources
 */
static int idpf_vf_intr_reg_init(struct idpf_vport *vport,
				 struct idpf_intr_grp *intr_grp)
{
	struct idpf_adapter *adapter = vport->adapter;
	int num_vecs = intr_grp->num_q_vectors;
	struct idpf_vec_regs *reg_vals;
	int num_regs, i, err = 0;
	u32 rx_itr, tx_itr;
	u16 total_vecs;

	total_vecs = idpf_get_reserved_vecs(vport->adapter);
	reg_vals = kcalloc(total_vecs, sizeof(struct idpf_vec_regs),
			   GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	num_regs = idpf_get_reg_intr_vecs(vport, reg_vals);
	if (num_regs < num_vecs) {
		err = -EINVAL;
		goto free_reg_vals;
	}

	for (i = 0; i < num_vecs; i++) {
		struct idpf_q_vector *q_vector = &intr_grp->q_vectors[i];
		struct idpf_intr_reg *intr = &q_vector->intr_reg;
		u16 vec_id = intr_grp->q_vector_idxs[i] - IDPF_MBX_Q_VEC;
		u32 spacing;

		intr->dyn_ctl = idpf_get_reg_addr(adapter,
						  reg_vals[vec_id].dyn_ctl_reg);
		intr->dyn_ctl_intena_m = VF_INT_DYN_CTLN_INTENA_M;
		intr->dyn_ctl_intena_msk_m = VF_INT_DYN_CTLN_INTENA_MSK_M;
		intr->dyn_ctl_itridx_s = VF_INT_DYN_CTLN_ITR_INDX_S;
		intr->dyn_ctl_intrvl_s = VF_INT_DYN_CTLN_INTERVAL_S;
		intr->dyn_ctl_wb_on_itr_m = VF_INT_DYN_CTLN_WB_ON_ITR_M;
		intr->dyn_ctl_itridx_m = VF_INT_DYN_CTLN_ITR_INDX_M;
		intr->dyn_ctl_swint_trig_m = VF_INT_DYN_CTLN_SWINT_TRIG_M;
		intr->dyn_ctl_sw_itridx_ena_m =
			VF_INT_DYN_CTLN_SW_ITR_INDX_ENA_M;

		spacing = IDPF_ITR_IDX_SPACING(reg_vals[vec_id].itrn_index_spacing,
					       IDPF_VF_ITR_IDX_SPACING);
		rx_itr = VF_INT_ITRN_ADDR(VIRTCHNL2_ITR_IDX_0,
					  reg_vals[vec_id].itrn_reg,
					  spacing);
		tx_itr = VF_INT_ITRN_ADDR(VIRTCHNL2_ITR_IDX_1,
					  reg_vals[vec_id].itrn_reg,
					  spacing);
		intr->rx_itr = idpf_get_reg_addr(adapter, rx_itr);
		intr->tx_itr = idpf_get_reg_addr(adapter, tx_itr);
	}

free_reg_vals:
	kfree(reg_vals);
	return err;
}

/**
 * idpf_vf_reset_reg_init - Initialize reset registers
 * @adapter: Driver specific private structure
 */
static void idpf_vf_reset_reg_init(struct idpf_adapter *adapter)
{
	adapter->reset_reg.rstat = idpf_get_reg_addr(adapter, VFGEN_RSTAT);
	adapter->reset_reg.rstat_m = VFGEN_RSTAT_VFR_STATE_M;
}

/**
 * idpf_vf_trigger_reset - trigger reset
 * @adapter: Driver specific private structure
 * @trig_cause: Reason to trigger a reset
 */
static void idpf_vf_trigger_reset(struct idpf_adapter *adapter,
				  enum idpf_flags trig_cause)
{
	int err;

	if (trig_cause == IDPF_HR_FUNC_RESET) {
		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_RESET_VF, 0, NULL, 0);
		if (err)
			dev_err(idpf_adapter_to_dev(adapter),
				"Failed to send Reset VF\n");
	}
}

/**
 * idpf_vf_idc_register - register for idc callbacks
 * @adapter: Driver specific private structure
 */
static int idpf_vf_idc_register(struct idpf_adapter *adapter)
{
	return idpf_idc_init_aux_device(&adapter->rdma_data, IIDC_FUNCTION_TYPE_VF);
}

/**
 * idpf_vf_idc_ops_init - Initialize IDC function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_vf_idc_ops_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.idc_ops.idc_init = idpf_vf_idc_register;
	adapter->dev_ops.idc_ops.idc_deinit = idpf_idc_deinit_aux_device;
}

/**
 * idpf_vf_reg_ops_init - Initialize register API function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_vf_reg_ops_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.reg_ops.ctlq_reg_init = idpf_vf_ctlq_reg_init;
	adapter->dev_ops.reg_ops.intr_reg_init = idpf_vf_intr_reg_init;
	adapter->dev_ops.reg_ops.mb_intr_reg_init = idpf_vf_mb_intr_reg_init;
	adapter->dev_ops.reg_ops.reset_reg_init = idpf_vf_reset_reg_init;
	adapter->dev_ops.reg_ops.trigger_reset = idpf_vf_trigger_reset;
}

/**
 * idpf_vf_dev_ops_init - Initialize device API function pointers
 * @adapter: Driver specific private structure
 */
void idpf_vf_dev_ops_init(struct idpf_adapter *adapter)
{
	idpf_vf_reg_ops_init(adapter);
	idpf_vf_idc_ops_init(adapter);

	if (adapter->pdev->device == IDPF_DEV_ID_VF_SIOV) {
		adapter->dev_ops.bar0_region1_size = SIOV_REG_BAR_SIZE;
		adapter->dev_ops.bar0_region2_start =
						IDPF_VDEV_BAR0_REGION2_START;
		return;
	}
	adapter->dev_ops.bar0_region1_size = IDPF_VF_BAR0_REGION1_END;
	adapter->dev_ops.bar0_region2_start = IDPF_VF_BAR0_REGION2_START;
}
