/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_DEF_H_
#define _IDPF_PSP_DEF_H_

#if IS_ENABLED(CONFIG_INET_PSP)
#include <net/psp.h>
#endif

/* SA index widths supported by the driver, negotiated per adapter with
 * VIRTCHNL2_OP_CRYPTO_GET_CAPS, see idpf_psp_negotiate_caps().
 */
#define IDPF_PSP_SAIDX_WIDTH_21		21
#define IDPF_PSP_SAIDX_WIDTH_26		26

/**
 * struct idpf_psp_rx_key - PSP RX key allocated by the CP
 * @spi: SPI of the key
 * @generation: CP master key generation of the key
 * @key: the key
 */
struct idpf_psp_rx_key {
	__be32 spi;
	u32 generation;
	u8 key[VIRTCHNL2_PSP_KEY_SIZE_V0];
};

/**
 * struct idpf_adapter_psp - PSP offload state of an adapter
 * @enabled: PSP was negotiated with the CP in the last core init, see
 *	     idpf_is_psp_ena()
 * @sadb_entries: SADB size granted by VIRTCHNL2_OP_CRYPTO_GET_CAPS
 * @saidx_width: SA index width granted by VIRTCHNL2_OP_CRYPTO_GET_CAPS
 * @psp_caps: PSP capabilities granted by VIRTCHNL2_OP_PSP_GET_CAPS, see
 *	      enum virtchnl2_psp_caps
 * @vport_id: ID of adapter->vports[0] for the PSP requests. A copy, as the
 *	      PSP device stays registered while the vports are freed and
 *	      allocated again during a soft reset. Set in idpf_vport_alloc().
 * @keys_allocated: RX keys allocated
 * @psp_dev: the PSP device, see idpf_psp_register()
 * @caps: capabilities of @psp_dev
 */
struct idpf_adapter_psp {
	bool enabled;
	u32 sadb_entries;
	u8 saidx_width;
	u32 psp_caps;
	u32 vport_id;
	atomic_t keys_allocated;
	struct psp_dev *psp_dev;
#if IS_ENABLED(CONFIG_INET_PSP)
	struct psp_dev_caps caps;
#endif
};

#endif /* !_IDPF_PSP_DEF_H_ */
