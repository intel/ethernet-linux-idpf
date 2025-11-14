/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#ifndef _IDPF_ADI_H_
#define _IDPF_ADI_H_

#include "siov_regs.h"

#define VDEV_MBX_ARQBAL			(VDEV_MBX_START + 0x0000)
#define VDEV_MBX_ARQBAH			(VDEV_MBX_START + 0x0004)
#define VDEV_MBX_ARQLEN			(VDEV_MBX_START + 0x0008)
#define VDEV_MBX_ARQH			(VDEV_MBX_START + 0x000C)
#define VDEV_MBX_ARQT			(VDEV_MBX_START + 0x0010)
#define VDEV_MBX_ATQBAL			(VDEV_MBX_START + 0x0014)
#define VDEV_MBX_ATQBAH			(VDEV_MBX_START + 0x0018)
#define VDEV_MBX_ATQLEN			(VDEV_MBX_START + 0x001C)
#define VDEV_MBX_ATQH			(VDEV_MBX_START + 0x0020)
#define VDEV_MBX_ATQT			(VDEV_MBX_START + 0x0024)

#if IS_ENABLED(CONFIG_ARM64) && defined(ENABLE_ACC_PASID_WA)
/* override PASID for ARM, when compiling for SIOV on ACC and IMC */
#ifndef HAVE_PASID_SUPPORT
#define HAVE_PASID_SUPPORT
#endif /* !HAVE_PASID_SUPPORT */
#endif /* CONFIG_ARM64 && ENABLE_ACC_PASID_WA */
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
#include "idpf_vdcm.h"
int idpf_adi_core_init(struct idpf_adapter *adapter);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

struct idpf_adi_info {
	struct idpf_adi_priv **priv_info;
	u16 max_adi_cnt;
	u16 curr_adi_cnt;
	bool vdcm_init_ok;
};

#endif /* !_IDPF_ADI_H_ */
