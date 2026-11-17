/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only

#include "idpf_psp.h"

#include <net/psp.h>

/**
 * idpf_psp_init - Initialize PSP offload
 * @adapter: private data struct
 *
 * Called on each core init, including after a hard reset: PSP offload is
 * negotiated again, the CP may grant different capabilities. PSP offload uses
 * the virtchnl2 crypto offload API: if VIRTCHNL2_CAP_CRYPTO was not granted or
 * the negotiation fails, PSP stays disabled for the adapter instead of failing
 * the core init, see idpf_is_psp_ena().
 */
void idpf_psp_init(struct idpf_adapter *adapter)
{
	struct idpf_adapter_psp *psp = &adapter->psp;
	struct device *dev = &adapter->pdev->dev;

	WRITE_ONCE(psp->enabled, false);

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_CRYPTO)) {
		dev_notice(dev, "PSP disabled, crypto capability not granted\n");
		return;
	}

	WRITE_ONCE(psp->enabled, true);
}

/**
 * idpf_psp_free - Release the PSP offload resources
 * @adapter: private data struct
 *
 * Called on remove, after idpf_vc_core_deinit().
 */
void idpf_psp_free(struct idpf_adapter *adapter)
{
	idpf_psp_unregister(adapter);
}

/**
 * idpf_psp_set_config - Set the PSP device configuration
 * @psd: PSP device
 * @conf: new configuration
 * @extack: netlink extended ack for error reporting
 *
 * The configuration is applied by the PSP core.
 *
 * Return: 0.
 */
static int idpf_psp_set_config(struct psp_dev *psd, struct psp_dev_config *conf,
			       struct netlink_ext_ack *extack)
{
	return 0;
}

/* PSP device operations, see idpf_psp_register() */
static struct psp_dev_ops idpf_psp_ops = {
	.set_config	= idpf_psp_set_config,
};

/**
 * idpf_psp_register - Register the PSP device
 * @adapter: private data struct
 *
 * Register the PSP device of the first netdev if PSP offload was negotiated
 * and the netdev is registered.
 */
void idpf_psp_register(struct idpf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct psp_dev *psd;

	if (!idpf_is_psp_ena(adapter) || adapter->psp.psp_dev)
		return;

	if (!adapter->netdevs || !adapter->netdevs[0] ||
	    !test_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config[0]->flags))
		return;

	/* The driver only allocates and inserts PSP version 0 keys */
	adapter->psp.caps.versions = BIT(PSP_VERSION_HDR0_AES_GCM_128);

	psd = psp_dev_create(adapter->netdevs[0], &idpf_psp_ops,
			     &adapter->psp.caps, NULL);
	if (IS_ERR(psd)) {
		dev_err(dev, "PSP failed to register: %pe\n", psd);
		return;
	}

	adapter->psp.psp_dev = psd;
	dev_info(dev, "PSP Netlink device registered successfully: id=%u\n",
		 psd->id);
}

/**
 * idpf_psp_unregister - Unregister the PSP device
 * @adapter: private data struct
 *
 * The PSP core deletes the TX keys of all the associations, see
 * idpf_psp_tx_key_del(). Called before the netdev of the PSP device is
 * unregistered.
 */
void idpf_psp_unregister(struct idpf_adapter *adapter)
{
	struct psp_dev *psd = adapter->psp.psp_dev;

	if (!psd)
		return;

	psp_dev_unregister(psd);
	adapter->psp.psp_dev = NULL;
}
