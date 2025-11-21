/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "kcompat.h"
#include <linux/aer.h>
#include "idpf.h"
#include "idpf_virtchnl.h"

#define DRV_SUMMARY    "Intel(R) Infrastructure Data Path Function Linux Driver"
MODULE_VERSION(IDPF_DRV_VER);
static const char idpf_driver_string[] = DRV_SUMMARY;
static const char idpf_copyright[] = "Copyright (C) 2019-2025 Intel Corporation";
MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL");

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
static int iommu_bypass;
module_param(iommu_bypass, int, 0644);
MODULE_PARM_DESC(iommu_bypass, " iommu bypass");

/**
 * idpf_deinit_iommu_bypass
 * @adapter: pointer to adapter struct
 */
static void idpf_deinit_iommu_bypass(struct idpf_adapter *adapter)
{
	if (adapter->iommu_byp.iodom)
		iommu_unmap(adapter->iommu_byp.iodom,
			    adapter->iommu_byp.bypass_iova_addr,
			    adapter->iommu_byp.bypass_size);
	if (adapter->iommu_byp.ddev) {
		struct platform_device *ldev =
			adapter->iommu_byp.ddev->platform_data;
		platform_device_unregister(ldev);
	}
}

/**
 * idpf_init_iommu_bypass - configure IDPF in IOMMU bypass mode
 * @adapter: pointer to adapter struct
 * @pdev: PCI device information struct
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_init_iommu_bypass(struct idpf_adapter *adapter,
				  struct pci_dev *pdev)
{
	struct platform_device *ldev = NULL;
	struct iommu_domain *iodom = NULL;
	struct sysinfo inf;
	int err = 0;

	ldev = platform_device_alloc("iommu_bypass", PLATFORM_DEVID_NONE);
	if (!ldev)
		goto iommu_bypass_fail;

	err = platform_device_add(ldev);
	if (err)
		goto iommu_bypass_fail;

	adapter->iommu_byp.ddev = &ldev->dev;
	adapter->iommu_byp.ddev->platform_data = ldev;
	adapter->iommu_byp.ddev->cma_area = pdev->dev.cma_area;
	adapter->iommu_byp.ddev->dma_coherent = true;

	err = dma_set_mask_and_coherent(adapter->iommu_byp.ddev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(adapter->iommu_byp.ddev,
						DMA_BIT_MASK(32));
	if (err)
		goto iommu_bypass_fail;

	si_meminfo(&inf);
	adapter->iommu_byp.bypass_size = inf.totalram << (PAGE_SHIFT + 1);
	adapter->iommu_byp.bypass_phys_addr = memstart_addr;
	adapter->iommu_byp.bypass_iova_addr = adapter->iommu_byp.bypass_phys_addr;
	iodom = iommu_get_domain_for_dev(&pdev->dev);
	if (iodom) {
		err = iommu_map(iodom, adapter->iommu_byp.bypass_iova_addr,
				adapter->iommu_byp.bypass_phys_addr,
				adapter->iommu_byp.bypass_size,
				IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
		if (err)
			goto iommu_bypass_fail;
		dev_info(&pdev->dev,
			 "IOMMU bypass enabled. WARNING: driver reload may be unstable\n");
		adapter->iommu_byp.iodom = iodom;
	} else {
		dev_info(&pdev->dev, "IOMMU disabled\n");
	}

	return err;

iommu_bypass_fail:
	idpf_deinit_iommu_bypass(adapter);

	return err;
}

#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
/**
 * idpf_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void idpf_remove(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
	int i;

	set_bit(IDPF_REMOVE_IN_PROG, adapter->flags);

	/* Wait until vc_event_task is done to consider if any hard reset is
	 * in progress else we may go ahead and release the resources but the
	 * thread doing the hard reset might continue the init path and
	 * end up in bad state.
	 */
	cancel_delayed_work_sync(&adapter->vc_event_task);

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	if (adapter->dev_ops.vdcm_deinit)
		adapter->dev_ops.vdcm_deinit(pdev);

#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
#ifdef DEVLINK_ENABLED
	idpf_devlink_deinit(adapter);
#endif /* DEVLINK_ENABLED */

	idpf_vport_init_lock(adapter);
	if (adapter->num_vfs)
		idpf_sriov_config_vfs(pdev, 0);
	idpf_vc_core_deinit(adapter);
	idpf_vport_init_unlock(adapter);

	/* Shut down the per-adapter virtchnl transactions */
	idpf_vc_xn_shutdown(adapter->vcxn_mngr);

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	xa_destroy(&adapter->adi_info.priv_info);

#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	/* Be a good citizen and leave the device clean on exit */
	adapter->dev_ops.reg_ops.trigger_reset(adapter, IDPF_HR_FUNC_RESET);
	idpf_deinit_dflt_mbx(adapter);

	if (!adapter->netdevs)
		goto destroy_wqs;

	/* There are some cases where it's possible to still have netdevs
	 * registered with the stack at this point, e.g. if the driver detected
	 * a HW reset and rmmod is called before it fully recovers. Unregister
	 * any stale netdevs here.
	 */
	for (i = 0; i < adapter->max_vports; i++) {
		if (!adapter->netdevs[i])
			continue;
		if (adapter->netdevs[i]->reg_state != NETREG_UNINITIALIZED)
			unregister_netdev(adapter->netdevs[i]);
		free_netdev(adapter->netdevs[i]);
		adapter->netdevs[i] = NULL;
	}

destroy_wqs:
	destroy_workqueue(adapter->init_wq);
	destroy_workqueue(adapter->serv_wq);
	destroy_workqueue(adapter->mbx_wq);
	if (IS_SILICON_DEVICE(adapter->hw.subsystem_device_id))
		destroy_workqueue(adapter->stats_wq);
	destroy_workqueue(adapter->vc_event_wq);

	for (i = 0; i < adapter->max_vports; i++) {
		if (!adapter->vport_config[i])
			continue;
		kfree(adapter->vport_config[i]->user_config.q_coalesce);
#ifndef HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS
		kfree(adapter->vport_config[i]->affinity_config);
#endif /* !HAVE_NETDEV_IRQ_AFFINITY_AND_ARFS */
		kfree(adapter->vport_config[i]);
		adapter->vport_config[i] = NULL;
	}
	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
	kfree(adapter->netdevs);
	adapter->netdevs = NULL;
	kfree(adapter->vcxn_mngr);
	adapter->vcxn_mngr = NULL;

	mutex_destroy(&adapter->vport_init_lock);
	mutex_destroy(&adapter->vport_cfg_lock);
	mutex_destroy(&adapter->vector_lock);
	mutex_destroy(&adapter->queue_lock);

#if IS_ENABLED(CONFIG_PCIE_PTM)
	pci_disable_ptm(pdev);
#endif /* CONFIG_PCIE_PTM */
#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_disable_pcie_error_reporting(pdev);
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
	iounmap(adapter->hw.hw_addr);
	if (adapter->hw.hw_addr_region2)
		iounmap(adapter->hw.hw_addr_region2);
	pci_release_mem_regions(pdev);

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
	idpf_deinit_iommu_bypass(adapter);
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
	pci_set_drvdata(pdev, NULL);
#ifdef DEVLINK_ENABLED
	devlink_free(priv_to_devlink(adapter));
#else
	kfree(adapter);
#endif /* DEVLINK_ENABLED */
}

/**
 * idpf_shutdown - PCI callback for shutting down device
 * @pdev: PCI device information struct
 */
static void idpf_shutdown(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->vc_event_task);
	idpf_vc_core_deinit(adapter);
	idpf_deinit_dflt_mbx(adapter);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

/**
 * idpf_cfg_hw - Initialize HW struct
 * @adapter: adapter to setup hw struct for
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_cfg_hw(struct idpf_adapter *adapter)
{
	u64 region2_start = adapter->dev_ops.bar0_region2_start;
	struct pci_dev *pdev = adapter->pdev;
	struct idpf_hw *hw = &adapter->hw;
	resource_size_t res_start;
	long len;

	res_start = pci_resource_start(pdev, 0);
	len = adapter->dev_ops.bar0_region1_size;
	hw->hw_addr = ioremap(res_start, len);
	if (!hw->hw_addr) {
		dev_info(&pdev->dev, "ioremap(0x%04llx) region1 failed:\n",
			 res_start);
		return -EIO;
	}
	hw->hw_addr_len = len;

	len = pci_resource_len(pdev, 0) - region2_start;
	if (len <= 0)
		goto store_hw_info;

	hw->hw_addr_region2 = ioremap(res_start + region2_start, len);
	if (!hw->hw_addr_region2) {
		dev_info(&pdev->dev, "ioremap(0x%04llx) region2 failed:\n",
			 res_start + region2_start);
		return -EIO;
	}
	hw->hw_addr_region2_len = len;
store_hw_info:
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->back = adapter;

	return 0;
}

static struct lock_class_key idpf_pf_vport_init_lock_key;
static struct lock_class_key idpf_pf_work_lock_key;

/**
 * idpf_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in idpf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct idpf_adapter *adapter;
#ifdef DEVLINK_ENABLED
	struct devlink *devlink;
#endif /* DEVLINK_ENABLED */
	int err;

#ifdef DEVLINK_ENABLED
	devlink = devlink_alloc(&idpf_devlink_ops, sizeof(struct idpf_adapter),
				dev);
	if (!devlink)
		return -ENOMEM;
	adapter = devlink_priv(devlink);
#else
	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
#endif /* DEVLINK_ENABLED */
	if (!adapter)
		return -ENOMEM;

	pr_info("%s - version %s\n", idpf_driver_string, IDPF_DRV_VER);
	pr_info("%s\n", idpf_copyright);

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
	if (iommu_bypass) {
		if (idpf_init_iommu_bypass(adapter, pdev)) {
			kfree(adapter);
			return -EINVAL;
		}
	}

#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
	adapter->pdev = pdev;
	adapter->drv_name = IDPF_DRV_NAME;
	adapter->drv_ver = IDPF_DRV_VER;

	adapter->req_tx_splitq = true;
	adapter->req_rx_splitq = true;

	mutex_init(&adapter->vport_init_lock);
	mutex_init(&adapter->vport_cfg_lock);
	mutex_init(&adapter->vector_lock);
	mutex_init(&adapter->queue_lock);

	INIT_DELAYED_WORK(&adapter->init_task, idpf_init_task);
	INIT_DELAYED_WORK(&adapter->serv_task, idpf_service_task);
	INIT_DELAYED_WORK(&adapter->mbx_task, idpf_mbx_task);
	if (IS_SILICON_DEVICE(adapter->hw.subsystem_device_id))
		INIT_DELAYED_WORK(&adapter->stats_task, idpf_statistics_task);
	INIT_DELAYED_WORK(&adapter->vc_event_task, idpf_vc_event_task);

	switch (ent->device) {
	case IDPF_DEV_ID_PF:
		idpf_dev_ops_init(adapter);
		lockdep_set_class(&adapter->vport_init_lock,
				  &idpf_pf_vport_init_lock_key);
		lockdep_init_map(&adapter->vc_event_task.work.lockdep_map,
				 "idpf-PF-vc-work", &idpf_pf_work_lock_key, 0);
		break;
	case IDPF_DEV_ID_VF:
		idpf_vf_dev_ops_init(adapter);
		adapter->crc_enable = true;
		break;
	case IDPF_DEV_ID_VF_SIOV:
		idpf_vf_dev_ops_init(adapter);
		break;
	case IDPF_DEV_ID_PF_SIMICS:
		idpf_dev_ops_init(adapter);
		lockdep_set_class(&adapter->vport_init_lock,
				  &idpf_pf_vport_init_lock_key);
		lockdep_init_map(&adapter->vc_event_task.work.lockdep_map,
				 "idpf-PF-simics-vc-work", &idpf_pf_work_lock_key, 0);
		break;
	case IDPF_DEV_ID_VF_SIMICS:
		idpf_vf_dev_ops_init(adapter);
		break;
	default:
		err = -ENODEV;
		dev_err(&pdev->dev, "Unexpected dev ID 0x%x in idpf probe\n",
			ent->device);
		goto err_free;
	}

	if (!adapter->drv_name) {
		dev_err(dev, "Invalid configuration, no drv_name given\n");
		err = -EINVAL;
		goto err_free;
	}
	if (!adapter->drv_ver) {
		dev_err(dev, "Invalid configuration, no drv_ver given\n");
		err = -EINVAL;
		goto err_free;
	}

	err = pcim_enable_device(pdev);
	if (err)
		goto err_free;

	err = pci_request_mem_regions(pdev, pci_name(pdev));
	if (err) {
		dev_err(dev,
			"pci_request_selected_regions failed %d\n", err);
		goto err_free;
	}

#if IS_ENABLED(CONFIG_PCIE_PTM)
	err = pci_enable_ptm(pdev, NULL);
	if (err)
		dev_info(dev, "PCIe PTM not supported by PCIe bus/controller\n");

#endif /* CONFIG_PCIE_PTM */
	/* set up for high or low dma */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		pci_err(pdev, "DMA configuration failed: %pe\n", ERR_PTR(err));
		goto err_free;
	}

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_enable_pcie_error_reporting(pdev);
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
	pci_set_master(pdev);
	pci_set_drvdata(pdev, adapter);

	if (!adapter->vcxn_mngr) {
		adapter->vcxn_mngr = kzalloc(sizeof(*adapter->vcxn_mngr),
					     GFP_KERNEL);
		if (!adapter->vcxn_mngr) {
			err = -ENOMEM;
			goto err_free;
		}
	}

	/* Initialize the per-adapter virtchnl transactions. */
	idpf_init_vc_xn_completion(adapter->vcxn_mngr);
	idpf_vc_xn_init(adapter->vcxn_mngr);
	init_completion(&adapter->corer_done);

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	xa_init(&adapter->adi_info.priv_info);

#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	adapter->init_wq = alloc_workqueue("%s-%s-init",
					   WQ_UNBOUND | WQ_MEM_RECLAIM, 0,
					   dev_driver_string(dev),
					   dev_name(dev));
	if (!adapter->init_wq) {
		dev_err(dev, "Failed to allocate init workqueue\n");
		err = -ENOMEM;
#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
		goto err_wq_alloc;
#else
		goto err_free;
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
	}

	adapter->serv_wq = alloc_workqueue("%s-%s-service",
					   WQ_UNBOUND | WQ_MEM_RECLAIM, 0,
					   dev_driver_string(dev),
					   dev_name(dev));
	if (!adapter->serv_wq) {
		dev_err(dev, "Failed to allocate service workqueue\n");
		err = -ENOMEM;
		goto err_serv_wq_alloc;
	}

	adapter->mbx_wq = alloc_workqueue("%s-%s-mbx",
					  WQ_UNBOUND | WQ_HIGHPRI,
					  0, dev_driver_string(dev),
					  dev_name(dev));
	if (!adapter->mbx_wq) {
		dev_err(dev, "Failed to allocate mailbox workqueue\n");
		err = -ENOMEM;
		goto err_mbx_wq_alloc;
	}

	if (IS_SILICON_DEVICE(adapter->hw.subsystem_device_id)) {
		adapter->stats_wq = alloc_workqueue("%s-%s-stats",
						    WQ_UNBOUND | WQ_MEM_RECLAIM,
						    0, dev_driver_string(dev),
						    dev_name(dev));
		if (!adapter->stats_wq) {
			dev_err(dev, "Failed to allocate statistics workqueue\n");
			err = -ENOMEM;
			goto err_stats_wq_alloc;
		}
	}

	adapter->vc_event_wq = alloc_workqueue("%s-%s-vc_event",
					       WQ_UNBOUND | WQ_MEM_RECLAIM, 0,
					       dev_driver_string(dev),
					       dev_name(dev));
	if (!adapter->vc_event_wq) {
		dev_err(dev, "Failed to allocate virtchnl event workqueue\n");
		err = -ENOMEM;
		goto err_vc_event_wq_alloc;
	}

	/* setup msglvl */
	adapter->msg_enable = netif_msg_init(-1, IDPF_AVAIL_NETIF_M);

	err = idpf_cfg_hw(adapter);
	if (err) {
		dev_err(dev, "Failed to configure HW structure for adapter: %d\n",
			err);
		goto err_cfg_hw;
	}

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	adapter->adi_info.vdcm_init_ok = (adapter->dev_ops.vdcm_init &&
			adapter->dev_ops.vdcm_init(adapter->pdev) == 0);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

	adapter->dev_ops.reg_ops.reset_reg_init(adapter);
	set_bit(IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));

#ifdef DEVLINK_ENABLED
	idpf_devlink_init(adapter, dev);

#endif /* DEVLINK_ENABLED */
	return 0;

err_cfg_hw:
	destroy_workqueue(adapter->vc_event_wq);
err_vc_event_wq_alloc:
	if (IS_SILICON_DEVICE(adapter->hw.subsystem_device_id))
		destroy_workqueue(adapter->stats_wq);
err_stats_wq_alloc:
	destroy_workqueue(adapter->mbx_wq);
err_mbx_wq_alloc:
	destroy_workqueue(adapter->serv_wq);
err_serv_wq_alloc:
	destroy_workqueue(adapter->init_wq);
#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
err_wq_alloc:
	pci_disable_pcie_error_reporting(pdev);
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
#if IS_ENABLED(CONFIG_PCIE_PTM)
	pci_disable_ptm(pdev);
#endif /* CONFIG_PCIE_PTM */
err_free:
#ifdef DEVLINK_ENABLED
	devlink_free(priv_to_devlink(adapter));
#else
	kfree(adapter);
#endif /* DEVLINK_ENABLED */

	return err;
}

/** idpf_reset_recover - Restore the driver after a reset
 * @adapter: driver specific private structure
 *
 * Returns 0 on success, negative on failure
 */
int idpf_reset_recover(struct idpf_adapter *adapter)
{
	int err;

	/* Reset is complete and so start building the driver resources again */
	err = idpf_init_dflt_mbx(adapter);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to initialize default mailbox: %d\n", err);

		return err;
	}

	if (!adapter->vcxn_mngr->active)
		idpf_vc_xn_init(adapter->vcxn_mngr);

	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));
	queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task, 0);

	/* Initialize the state machine, also allocate memory and request
	 * resources
	 */
	err = idpf_vc_core_init(adapter);
	if (err)
		goto init_err;

	/* Wait till all the vports are initialized to release the reset lock,
	 * else user space callbacks may access uninitialized vports
	 */
	while (test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags))
		msleep(100);

	return 0;

init_err:
	cancel_delayed_work_sync(&adapter->mbx_task);
	cancel_delayed_work_sync(&adapter->serv_task);
	idpf_deinit_dflt_mbx(adapter);

	return err;
}

/**
 * idpf_is_reset_detected - check if we were reset at some point
 * @adapter: driver specific private structure
 *
 * Returns true if we are either in reset currently or were previously reset.
 */
bool idpf_is_reset_detected(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_reg reg;
	u32 arqlen;
	/* No need to check reset state in CORER */
	if (test_bit(IDPF_CORER_IN_PROG, adapter->flags))
		return true;

	if (!adapter->hw.arq)
		return true;

	reg = adapter->hw.arq->reg;
	arqlen = readl(idpf_get_reg_addr(adapter, reg.len));

	/* We are in reset if either LEN or ENA bits are cleared. */
	return (!(arqlen & reg.len_mask) || !(arqlen & reg.len_ena_mask));
}

/**
 * idpf_reset_prepare - Prepare to go down for reset
 * @adapter: private data struct
 */
static void idpf_reset_prepare(struct idpf_adapter *adapter)
{
	idpf_vport_init_lock(adapter);
	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->vc_event_task);
	set_bit(IDPF_HR_RESET_IN_PROG, adapter->flags);
	dev_info(idpf_adapter_to_dev(adapter), "Device FLR Reset initiated\n");

	idpf_device_detach(adapter);

	idpf_netdev_stop_all(adapter);
	idpf_vc_xn_shutdown(adapter->vcxn_mngr);

	idpf_idc_event(&adapter->rdma_data, IIDC_EVENT_WARN_RESET);
	idpf_set_vport_state(adapter);
	idpf_vc_core_deinit(adapter);
	idpf_deinit_dflt_mbx(adapter);

	idpf_vport_init_unlock(adapter);
}

/**
 * idpf_pci_err_detected - PCI error detected, about to attempt recovery
 * @pdev: PCI device struct
 * @err: err detected
 *
 * Return PCI_ERS_RESULT_DISCONNECT if we can't recover,
 * PCI_ERS_RESULT_NEED_RESET otherwise.
 */
static pci_ers_result_t
idpf_pci_err_detected(struct pci_dev *pdev, pci_channel_state_t err)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter) {
		dev_err(&pdev->dev, "%s: unrecoverable device error %d\n",
			__func__, err);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	idpf_reset_prepare(adapter);

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * idpf_pci_err_slot_reset - PCI undergoing reset
 * @pdev: PCI device struct
 *
 * Reset PCI state and use a register read to see if we're good.
 */
static pci_ers_result_t
idpf_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
	pci_ers_result_t res;
	int err;

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to re-enable PCI device after reset %d\n",
			err);
		res = PCI_ERS_RESULT_DISCONNECT;
		goto clear_status;
	}
	pci_set_master(pdev);
	if (readl(adapter->reset_reg.rstat) != 0xFFFFFFFF)
		res = PCI_ERS_RESULT_RECOVERED;
	else
		res = PCI_ERS_RESULT_DISCONNECT;

clear_status:
	err = pci_aer_clear_nonfatal_status(pdev);
	if (err)
		dev_err(&pdev->dev, "Failed to clear pci aer status %d\n", err);

	return res;
}

/**
 * idpf_pci_err_resume - Resume operations after PCI error recovery
 * @pdev: PCI device struct
 */
static void idpf_pci_err_resume(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
	int err;

	if (!adapter) {
		dev_err(&pdev->dev, "Failed to resume after PCI reset\n");
		return;
	}

	idpf_vport_init_lock(adapter);

	err = idpf_check_reset_complete(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "The driver was unable to contact the device's firmware.  Check that the FW is running. Driver state=%u\n",
			adapter->state);
		idpf_vport_init_unlock(adapter);
		return;
	}

	err = idpf_reset_recover(adapter);

	if (err)
		dev_err(&adapter->pdev->dev, "Failed to recover after PCI reset\n");

	idpf_vport_init_unlock(adapter);

	/* Wait for all init_task WQs to complete */
	flush_delayed_work(&adapter->init_task);
}

#ifdef HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
/**
 * idpf_pci_err_reset_prepare - Prepare driver for PCI reset
 * @pdev: PCI device struct
 */
static void idpf_pci_err_reset_prepare(struct pci_dev *pdev)
{
	idpf_reset_prepare(pci_get_drvdata(pdev));
}

/**
 * idpf_pci_err_reset_done - PCI err reset recovery complete
 * @pdev: PCI device struct
 */
static void idpf_pci_err_reset_done(struct pci_dev *pdev)
{
	idpf_pci_err_resume(pdev);
}

#endif /* HAVE_PCI_ERROR_HANDLER_RESET_PREPARE */
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY
/**
 * idpf_pci_err_reset_notify - Either prepare and handle a reset
 * @pdev: PCI device struct
 * @prepare: true if prepare, false if reset done
 */
static void idpf_pci_err_reset_notify(struct pci_dev *pdev, bool prepare)
{
	if (prepare)
		idpf_reset_prepare(pci_get_drvdata(pdev));
	else
		idpf_pci_err_resume(pdev);
}

#endif /* HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY */
#ifdef HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS
static const struct pci_error_handlers idpf_pci_err_handler = {
#else
static struct pci_error_handlers idpf_pci_err_handler = {
#endif /* HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS */
	.error_detected = idpf_pci_err_detected,
	.slot_reset = idpf_pci_err_slot_reset,
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY
	.reset_notify = idpf_pci_err_reset_notify,
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY */
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
	.reset_prepare = idpf_pci_err_reset_prepare,
	.reset_done = idpf_pci_err_reset_done,
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_PREPARE */
	.resume = idpf_pci_err_resume,
};

/* idpf_pci_tbl - PCI Dev idpf ID Table
 */
static const struct pci_device_id idpf_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF) },
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_VF) },
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_VF_SIOV) },
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF_SIMICS) },
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_VF_SIMICS) },
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(pci, idpf_pci_tbl);

static struct pci_driver idpf_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= idpf_pci_tbl,
	.probe			= idpf_probe,
	.sriov_configure	= idpf_sriov_configure,
	.remove			= idpf_remove,
	.shutdown		= idpf_shutdown,
	.err_handler		= &idpf_pci_err_handler,
};

module_pci_driver(idpf_driver);
