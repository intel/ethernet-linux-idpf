/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"
#include "idpf_lan_pf_regs.h"
#include "idpf_virtchnl.h"
#include "idpf_ptp.h"

/* LAN driver does not own all the BAR0 address space. This results in 2 BAR0
 * regions for PF device and the driver should map each region separately.
 *
 * Rest of BAR0 is owned by RDMA and it maps the pages on its own as it needs
 * to map some of the pages for write combing (WC) instead of the default
 * non-cached (NC) mapping that LAN driver does. In the PF BAR space,
 * RDMA BAR0 memory lies between 192MB to 256MB.
 *
 * Also driver should map 1 page of RDMA from its space.
 */
#define IDPF_PF_BAR0_REGION1_END	0xC001000	/* 192MB + 4KB */
#define IDPF_PF_BAR0_REGION2_START	0x10000000	/* 256MB */

#define IDPF_PF_ITR_IDX_SPACING		0x4

/**
 * idpf_ctlq_reg_init - initialize default mailbox registers
 * @hw: pointer to the hardware structure
 * @cq: pointer to the array of create control queues
 */
static void idpf_ctlq_reg_init(struct idpf_hw *hw,
			       struct idpf_ctlq_create_info *cq)
{
	int i;

	for (i = 0; i < IDPF_NUM_DFLT_MBX_Q; i++) {
		struct idpf_ctlq_create_info *ccq = cq + i;

		switch (ccq->type) {
		case IDPF_CTLQ_TYPE_MAILBOX_TX:
			/* set head and tail registers in our local struct */
			ccq->reg.head = PF_FW_ATQH;
			ccq->reg.tail = PF_FW_ATQT;
			ccq->reg.len = PF_FW_ATQLEN;
			ccq->reg.bah = PF_FW_ATQBAH;
			ccq->reg.bal = PF_FW_ATQBAL;
			ccq->reg.len_mask = PF_FW_ATQLEN_ATQLEN_M;
			ccq->reg.len_ena_mask = PF_FW_ATQLEN_ATQENABLE_M;
			ccq->reg.head_mask = PF_FW_ATQH_ATQH_M;
			break;
		case IDPF_CTLQ_TYPE_MAILBOX_RX:
			/* set head and tail registers in our local struct */
			ccq->reg.head = PF_FW_ARQH;
			ccq->reg.tail = PF_FW_ARQT;
			ccq->reg.len = PF_FW_ARQLEN;
			ccq->reg.bah = PF_FW_ARQBAH;
			ccq->reg.bal = PF_FW_ARQBAL;
			ccq->reg.len_mask = PF_FW_ARQLEN_ARQLEN_M;
			ccq->reg.len_ena_mask = PF_FW_ARQLEN_ARQENABLE_M;
			ccq->reg.head_mask = PF_FW_ARQH_ARQH_M;
			break;
		default:
			break;
		}
	}
}

/**
 * idpf_mb_intr_reg_init - Initialize mailbox interrupt register
 * @adapter: adapter structure
 */
static void idpf_mb_intr_reg_init(struct idpf_adapter *adapter)
{
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 dyn_ctl = le32_to_cpu(adapter->caps.mailbox_dyn_ctl);

	intr->dyn_ctl = idpf_get_reg_addr(adapter, dyn_ctl);
	intr->dyn_ctl_intena_m = PF_GLINT_DYN_CTL_INTENA_M;
	intr->dyn_ctl_itridx_m = PF_GLINT_DYN_CTL_ITR_INDX_M;
	intr->icr_ena = idpf_get_reg_addr(adapter, PF_INT_DIR_OICR_ENA);
	intr->icr_ena_ctlq_m = PF_INT_DIR_OICR_ENA_M;
}

/**
 * idpf_intr_reg_init - Initialize interrupt registers
 * @vport: virtual port structure
 * @intr_grp: Interrupt resources
 */
static int idpf_intr_reg_init(struct idpf_vport *vport,
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
		intr->dyn_ctl_intena_m = PF_GLINT_DYN_CTL_INTENA_M;
		intr->dyn_ctl_intena_msk_m = PF_GLINT_DYN_CTL_INTENA_MSK_M;
		intr->dyn_ctl_itridx_s = PF_GLINT_DYN_CTL_ITR_INDX_S;
		intr->dyn_ctl_intrvl_s = PF_GLINT_DYN_CTL_INTERVAL_S;
		intr->dyn_ctl_wb_on_itr_m = PF_GLINT_DYN_CTL_WB_ON_ITR_M;
		intr->dyn_ctl_itridx_m = PF_GLINT_DYN_CTL_ITR_INDX_M;
		intr->dyn_ctl_swint_trig_m = PF_GLINT_DYN_CTL_SWINT_TRIG_M;
		intr->dyn_ctl_sw_itridx_ena_m =
			PF_GLINT_DYN_CTL_SW_ITR_INDX_ENA_M;

		spacing = IDPF_ITR_IDX_SPACING(reg_vals[vec_id].itrn_index_spacing,
					       IDPF_PF_ITR_IDX_SPACING);
		rx_itr = PF_GLINT_ITR_ADDR(VIRTCHNL2_ITR_IDX_0,
					   reg_vals[vec_id].itrn_reg,
					   spacing);
		tx_itr = PF_GLINT_ITR_ADDR(VIRTCHNL2_ITR_IDX_1,
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
 * idpf_reset_reg_init - Initialize reset registers
 * @adapter: Driver specific private structure
 */
static void idpf_reset_reg_init(struct idpf_adapter *adapter)
{
	adapter->reset_reg.rstat = idpf_get_reg_addr(adapter, PFGEN_RSTAT);
	adapter->reset_reg.rstat_m = PFGEN_RSTAT_PFR_STATE_M;
	adapter->reset_reg.oicr_cause = idpf_get_reg_addr(adapter, PF_INT_DIR_OICR_CAUSE);
	adapter->reset_reg.oicr_cause_m = PF_INT_DIR_OICR_CAUSE_CAUSE_M;
}

/**
 * idpf_trigger_reset - trigger reset
 * @adapter: Driver specific private structure
 * @trig_cause: Reason to trigger a reset
 */
static void idpf_trigger_reset(struct idpf_adapter *adapter,
			       enum idpf_flags __always_unused trig_cause)
{
	u32 reset_reg;

	reset_reg = readl(idpf_get_reg_addr(adapter, PFGEN_CTRL));
	writel(reset_reg | PFGEN_CTRL_PFSWR,
	       idpf_get_reg_addr(adapter, PFGEN_CTRL));
}

/**
 * idpf_read_master_time_ns - Gets Master time in nanoseconds
 * @hw: pointer to hw struct
 */
static u64 idpf_read_master_time_ns(const struct idpf_hw *hw)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;
	u32 ts_lo, ts_hi;
	u64 ns_time;

	/* Must be performed in 2 separate steps according to HAS */
	writel(PF_GLTSYN_CMD_SYNC_SHTIME_EN_M,
	       idpf_get_reg_addr(adapter, PF_GLTSYN_CMD_SYNC));
	writel(PF_GLTSYN_CMD_SYNC_EXEC_CMD_M | PF_GLTSYN_CMD_SYNC_SHTIME_EN_M,
	       idpf_get_reg_addr(adapter, PF_GLTSYN_CMD_SYNC));

	ts_lo = readl(idpf_get_reg_addr(adapter, PF_GLTSYN_SHTIME_L));
	ts_hi = readl(idpf_get_reg_addr(adapter, PF_GLTSYN_SHTIME_H));

	ns_time = (u64)ts_hi << 32;
	ns_time |= (u64)ts_lo;

	return ns_time;
}

/**
 * idpf_ptp_reg_init - Initialize required registers
 * @adapter: Driver specific private structure
 *
 * Set the bits required for enabling shtime and cmd execution
 */
static void idpf_ptp_reg_init(const struct idpf_adapter *adapter)
{
	adapter->ptp->cmd.shtime_enable_mask = PF_GLTSYN_CMD_SYNC_SHTIME_EN_M;
	adapter->ptp->cmd.exec_cmd_mask = PF_GLTSYN_CMD_SYNC_EXEC_CMD_M;
}

/**
 * idpf_idc_register - idc register function for idpf
 * @adapter: Driver specific private structure
 */
static int idpf_idc_register(struct idpf_adapter *adapter)
{
	return idpf_idc_init_aux_device(&adapter->rdma_data, IIDC_FUNCTION_TYPE_PF);
}

/**
 * idpf_idc_ops_init - Initialize IDC function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_idc_ops_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.idc_ops.idc_init = idpf_idc_register;
	adapter->dev_ops.idc_ops.idc_deinit = idpf_idc_deinit_aux_device;
}

/**
 * idpf_reg_ops_init - Initialize register API function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_reg_ops_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.reg_ops.ctlq_reg_init = idpf_ctlq_reg_init;
	adapter->dev_ops.reg_ops.intr_reg_init = idpf_intr_reg_init;
	adapter->dev_ops.reg_ops.mb_intr_reg_init = idpf_mb_intr_reg_init;
	adapter->dev_ops.reg_ops.reset_reg_init = idpf_reset_reg_init;
	adapter->dev_ops.reg_ops.trigger_reset = idpf_trigger_reset;
	adapter->dev_ops.reg_ops.read_master_time = idpf_read_master_time_ns;
	adapter->dev_ops.reg_ops.ptp_reg_init = idpf_ptp_reg_init;
}

/**
 * idpf_dev_ops_init - Initialize device API function pointers
 * @adapter: Driver specific private structure
 */
void idpf_dev_ops_init(struct idpf_adapter *adapter)
{
	idpf_reg_ops_init(adapter);
	idpf_idc_ops_init(adapter);
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	adapter->dev_ops.vdcm_init = idpf_vdcm_init;
	adapter->dev_ops.vdcm_deinit = idpf_vdcm_deinit;
	adapter->dev_ops.notify_adi_reset = idpf_notify_adi_reset;
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

	adapter->dev_ops.bar0_region1_size = IDPF_PF_BAR0_REGION1_END;
	adapter->dev_ops.bar0_region2_start = IDPF_PF_BAR0_REGION2_START;
}
