/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#ifndef _IDPF_VDCM_H_
#define _IDPF_VDCM_H_

#include <linux/uuid.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <linux/sched/mm.h>

#define IDPF_VDCM_BAR0_SIZE SZ_64M
#define IDPF_VDCM_BAR3_SIZE SZ_16K
#define IDPF_VDCM_CFG_SIZE 256
/* According to PCI Express Base Specification 4.0r1.0 section 7.5.1.2
 * Type 0 Configuration Space Header, the device specific capabilities
 * start at offset 0x40.
 */
#define IDPF_VDCM_MSIX_CTRL_OFFS (0x40 + PCI_MSIX_FLAGS)

#define VFIO_PCI_OFFSET_SHIFT		40
#define VFIO_PCI_OFFSET_TO_INDEX(off)	((off) >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index)	((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK		(BIT_ULL(VFIO_PCI_OFFSET_SHIFT) - 1)

/**
 * struct idpf_vdcm_irq_ctx - IRQ Context information for VDCM
 *
 * @trigger:		Eventfd context
 * @name:		Name for the IRQ context
 */
struct idpf_vdcm_irq_ctx {
	struct eventfd_ctx *trigger;
	char *name;
};

/**
 * struct idpf_vdcm - Abstraction for VDCM
 *
 * @dev:		Linux device for this VDCM
 * @parent_dev:		Linux parent device for this VDCM
 * @vfio_group:		VFIO group for this device
 * @pci_cfg_space:	PCI configuration space buffer
 * @ref_lock:		lock to protect refcnt
 * @refcnt:		device reference count
 * @ctx:		IRQ context
 * @num_ctx:		number of requested iRQ context
 * @irq_type:		IRQ type
 * @adi:		ADI attribute
 */
struct idpf_vdcm {
#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	/* Must put vfio_device as the 1st structure member to
	 * align with VFIO memory alloc/free model
	 */
	struct vfio_device vdev;
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */
	/* Common attribute */
	struct device *dev;
	struct device *parent_dev;
	struct vfio_group *vfio_group;
	u8 pci_cfg_space[IDPF_VDCM_CFG_SIZE];
	struct mutex igate;		/* protects access to interrupt */

	struct mutex ref_lock; /* lock to protect refcnt */
	int refcnt;

	/* IRQ context */
	struct idpf_vdcm_irq_ctx *ctx;
	unsigned int num_ctx;
	unsigned int irq_type;

	/* Device Specific */
	struct idpf_adi *adi;
};

/**
 * struct idpf_adi - Assignable Device Interface attribute
 * This structure defines the device specific resource and callbacks
 * @config:
 *     This function is called when VDCM want to config ADI's pasid
 * @reset: This function is called when VDCM wants to reset ADI
 * @read_reg32: This function is called when VDCM wants to read ADI register
 * @write_reg32: This function is called when VDCM wants to write ADI register
 * @get_num_of_vectors: get number of vectors assigned to this ADI
 * @set_num_of_vectors: set number of vectors assigned to this ADI
 * @get_irq_num: get OS IRQ number per vector
 * @get_sparse_mmap_hpa: This function is called when VDCM wants to get ADI HPA
 * @get_sparse_mmap_num: This function is called when VDCM wants to get
 *                       the number of sparse memory areas
 * @get_sparse_mmap_area: This function is called when VDCM wants to get
 *                        layout of sparse memory
 * @get_adi_index: get ADI index (policy ID) assigned to this ADI
 * @set_adi_index: set ADI index (policy ID) assigned to this ADI
 */
struct idpf_adi {
	int (*config)(struct idpf_adi *adi, u32 pasid, bool ena);
	int (*reset)(struct idpf_adi *adi);
	u32 (*read_reg32)(struct idpf_adi *adi, size_t offs);
	void (*write_reg32)(struct idpf_adi *adi, size_t offs, u32 val);
	int (*get_num_of_vectors)(struct idpf_adi *adi);
	int (*set_num_of_vectors)(struct idpf_adi *adi, u16 num_of_vectors);
	int (*get_irq_num)(struct idpf_adi *adi, u32 vector);
	int (*get_sparse_mmap_num)(struct idpf_adi *adi);
	int (*get_sparse_mmap_area)(struct idpf_adi *adi, u64 index,
				    u64 *offset, u64 *size);
	int (*get_sparse_mmap_hpa)(struct idpf_adi *adi, u32 index, u64 pg_off,
				   u64 *addr);
	int (*get_adi_index)(struct idpf_adi *adi);
	int (*set_adi_index)(struct idpf_adi *adi, u16 adi_index);
};

struct idpf_adi *idpf_vdcm_alloc_adi(struct device *dev);
void idpf_vdcm_free_adi(struct idpf_adi *adi);
int idpf_vdcm_init(struct pci_dev *pdev);
void idpf_vdcm_deinit(struct pci_dev *pdev);
void idpf_notify_adi_reset(struct idpf_adapter *adapter, u16 adi_id,
			   bool reset);
int idpf_vdcm_dev_init(struct idpf_vdcm *ivdm, struct device *dev,
		       struct device *parent_dev);
void idpf_vdcm_dev_release(struct idpf_vdcm *ivdm);
int idpf_vdcm_dev_open(struct idpf_vdcm *ivdm);
void idpf_vdcm_dev_close(struct idpf_vdcm *ivdm);
ssize_t idpf_vdcm_dev_read(struct idpf_vdcm *ivdm, char __user *buf,
			   size_t count, loff_t *ppos);
ssize_t idpf_vdcm_dev_write(struct idpf_vdcm *ivdm, const char __user *buf,
			    size_t count, loff_t *ppos);
long idpf_vdcm_dev_ioctl(struct idpf_vdcm *ivdm, unsigned int cmd,
			 unsigned long arg);
int idpf_vdcm_dev_mmap(struct idpf_vdcm *ivdm, struct vm_area_struct *vma);
ssize_t idpf_vdcm_dev_vector_count_show(struct idpf_vdcm *ivdm, char *buf);
ssize_t idpf_vdcm_dev_vector_count_store(struct idpf_vdcm *ivdm,
					 const char *buf, size_t count);
ssize_t idpf_vdcm_dev_policy_idx_show(struct idpf_vdcm *ivdm, char *buf);
ssize_t idpf_vdcm_dev_policy_idx_store(struct idpf_vdcm *ivdm, const char *buf,
				       size_t count);

/* Below definitions are used by idpf_adi.c */

/* ADI vectors */
#define IDPF_MAX_ADI_Q_COUNT		64
#define IDPF_MBX_VECS_PER_ADI		1
#define IDPF_PAGES_FOR_MBX_REGS		1
#define IDPF_DEFAULT_ADI_VEC		8
/* Max number of ADIs supported */
#define IDPF_MAX_ADI_NUM		30

/**
 * struct idpf_adi_vec_info - ADI vector information
 * @num_vectors: Number of vectors assigned to this ADI. Includes Data queue vectors and MBX vectors
 * @vec_indexes: Vector indexes includes MBX vector
 * @mbx_vec_id: MSIX entry from first value in array of vec_indexes
 */
struct idpf_adi_vec_info {
	u16	num_vectors;
	u16	*vec_indexes;
	int	mbx_vec_id;
	int	*data_q_vec_ids;
};

struct idpf_adi_q {
	int qid;
	u64 tail_reg;
};

struct idpf_adi_queue_info {
	int	num_txqs;
	int	num_complqs;
	int	num_rxqs;
	int	num_bufqs;
	struct idpf_adi_q *txq;
	struct idpf_adi_q *complq;
	struct idpf_adi_q *rxq;
	struct idpf_adi_q *bufq;
};

enum idpf_adi_reset_state {
	/* Specific Reset ADI states */
	IDPF_ADI_RESET_INPROGRESS,
	IDPF_ADI_RESET_COMPLETED
};

struct idpf_adi_priv {
	struct idpf_adi adi;
	struct idpf_adapter *adapter;
	struct idpf_adi_vec_info vec_info;
	struct idpf_adi_queue_info qinfo;
	int	mbx_id;
	/* ADI id used by HMA which is sent as part of destroy ADI */
	int	adi_id;
	u16     adi_index;
	enum idpf_adi_reset_state reset_state;
};

#endif /* !_IDPF_VDCM_H_ */
