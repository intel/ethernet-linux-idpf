/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_DEF_H_
#define _IDPF_PSP_DEF_H_

#include <linux/kref.h>
#include <linux/spinlock.h>
#if IS_ENABLED(CONFIG_INET_PSP)
#include <net/psp.h>
#endif

/* SA index widths supported by the driver, negotiated per adapter with
 * VIRTCHNL2_OP_CRYPTO_GET_CAPS, see idpf_psp_negotiate_caps().
 */
#define IDPF_PSP_SAIDX_WIDTH_21		21
#define IDPF_PSP_SAIDX_WIDTH_26		26

/* Largest SA index the driver supports. The SA indexes the CP returns are
 * checked against the width negotiated for the adapter before they are used,
 * see idpf_psp_saidx_ok().
 */
#define IDPF_PSP_IDX_MAX		(BIT(IDPF_PSP_SAIDX_WIDTH_26) - 1)
/* States of a TX key without a usable SA index, see struct idpf_psp_tx_key */
#define IDPF_PSP_IDX_NONE		(U32_MAX - 3)	/* no SA index */
#define IDPF_PSP_IDX_IN_PROG		(U32_MAX - 2)	/* insertion pending */
#define IDPF_PSP_IDX_ERROR		(U32_MAX - 1)	/* insertion failed */
#define IDPF_PSP_IDX_DELETED		U32_MAX		/* key deleted */

/**
 * struct idpf_psp_tx_key - State of a PSP TX key
 * @ref: reference count, held by the PSP association, see
 *	 idpf_psp_tx_key_add(), and by the lists and the insert request the
 *	 key is on
 * @lock: protects @idx and @hw_idx updates, and @tx_queue
 * @idx: SA index the TX path uses, or IDPF_PSP_IDX_IN_PROG,
 *	 IDPF_PSP_IDX_ERROR or IDPF_PSP_IDX_DELETED. Read without @lock.
 * @rcu: for freeing the key after the RCU readers of the TX path
 */
struct idpf_psp_tx_key {
	struct kref ref;
	spinlock_t lock;		/* protects the SA indexes and tx_queue */
	u32 idx;
	struct rcu_head rcu;
};

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

/* PSP device generation of an SPI phase whose master key isn't known */
#define IDPF_PSP_GEN_UNKNOWN		0xff

/**
 * struct idpf_psp_rx_gen - Generation of the master key of an SPI phase
 * @cp_gen: CP master key generation of the SPIs allocated in the phase
 * @gen: PSP device generation reported for the packets of the phase,
 *	 IDPF_PSP_GEN_UNKNOWN if no SPI was allocated in the phase
 *
 * Bit 31 of an SPI selects one of the two master keys of the CP, see
 * idpf_psp_rx_gen_update().
 */
struct idpf_psp_rx_gen {
	u32 cp_gen;
	u8 gen;
};

/* Last PSP device statistics read, see idpf_psp_get_stats() */
struct idpf_psp_dev_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_auth_fail;
	u64 rx_error;
	u64 rx_bad;
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_error;
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
 * @generation: PSP device generation after the last key rotation, protected
 *		by the PSP device lock, see idpf_psp_key_rotate()
 * @rx_gen: generation of the master key of each SPI phase, protected by the
 *	    PSP device lock, see idpf_psp_rx_gen_update()
 * @stats: last PSP device statistics read with VIRTCHNL2_OP_GET_PSP_STATS,
 *	   protected by the PSP device lock, see idpf_psp_get_stats()
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
	u8 generation;
	struct idpf_psp_rx_gen rx_gen[2];
	struct idpf_psp_dev_stats stats;
	atomic_t keys_allocated;
	struct psp_dev *psp_dev;
#if IS_ENABLED(CONFIG_INET_PSP)
	struct psp_dev_caps caps;
#endif
};

#endif /* !_IDPF_PSP_DEF_H_ */
