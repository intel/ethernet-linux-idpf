/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#include "idpf.h"

#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
/**
 * idpf_vdcm_vdev_read - read function entry
 * @vdev: vfio device instance pointer
 * @buf: buf stores read content
 * @count: read length
 * @ppos: read offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to read
 * vfio device with any device specific information for register access
 * Return the number of read bytes.
 */
static ssize_t
idpf_vdcm_vdev_read(struct vfio_device *vdev, char __user *buf, size_t count,
		    loff_t *ppos)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	return idpf_vdcm_dev_read(ivdm, buf, count, ppos);
}

/**
 * idpf_vdcm_vdev_write - write function entry
 * @vdev: vfio device instance pointer
 * @buf: buf stores content to be written
 * @count: write length
 * @ppos: write offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to write
 * vfio device with any device specific information like register access
 * Return the number of written bytes.
 */
static ssize_t
idpf_vdcm_vdev_write(struct vfio_device *vdev, const char __user *buf, size_t count,
		     loff_t *ppos)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	return idpf_vdcm_dev_write(ivdm, buf, count, ppos);
}

/**
 * idpf_vdcm_vdev_ioctl - IOCTL function entry
 * @vdev: vfio device instance pointer
 * @cmd: pre defined ioctls
 * @arg: cmd arguments
 *
 * This function is called when VFIO consumer (like QEMU) wants to config
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_vdev_ioctl(struct vfio_device *vdev, unsigned int cmd, unsigned long arg)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	return idpf_vdcm_dev_ioctl(ivdm, cmd, arg);
}

/**
 * idpf_vdcm_vdev_open - open vfio device
 * @vdev: vfio device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to open
 * vfio device.
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_vdev_open(struct vfio_device *vdev)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	return idpf_vdcm_dev_open(ivdm);
}

/**
 * idpf_vdcm_vdev_close - close a vfio device
 * @vdev: vfio device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to close
 * vfio device.
 */
static void idpf_vdcm_vdev_close(struct vfio_device *vdev)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	idpf_vdcm_dev_close(ivdm);
}

/**
 * idpf_vdcm_vdev_release - release a vfio device
 * @vdev: vfio device instance pointer
 *
 * This function is called when vfio device is going to be released.
 * The corresponding allocated driver data should be freed as well.
 */
static void idpf_vdcm_vdev_release(struct vfio_device *vdev)
{
#ifdef HAVE_VFIO_FREE_DEV
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	vfio_free_device(&ivdm->vdev);
#endif
}

/**
 * idpf_vdcm_vdev_mmap - map device memory to user space
 * @vdev: vfio device instance pointer
 * @vma: pointer to the vm where device memory will be mapped
 *
 * Return 0 if succeed, negative for failure.
 */
static int
idpf_vdcm_vdev_mmap(struct vfio_device *vdev, struct vm_area_struct *vma)
{
	struct idpf_vdcm *ivdm = container_of(vdev, struct idpf_vdcm, vdev);

	return idpf_vdcm_dev_mmap(ivdm, vma);
}

static const struct vfio_device_ops idpf_vdcm_vdev_ops = {
	.open_device		= idpf_vdcm_vdev_open,
	.close_device		= idpf_vdcm_vdev_close,
	.release		= idpf_vdcm_vdev_release,
	.read			= idpf_vdcm_vdev_read,
	.write			= idpf_vdcm_vdev_write,
	.ioctl			= idpf_vdcm_vdev_ioctl,
	.mmap			= idpf_vdcm_vdev_mmap,
#if IS_ENABLED(CONFIG_IOMMUFD)
	.bind_iommufd           = vfio_iommufd_emulated_bind,
	.unbind_iommufd         = vfio_iommufd_emulated_unbind,
	.attach_ioas            = vfio_iommufd_emulated_attach_ioas,
	.detach_ioas            = vfio_iommufd_emulated_detach_ioas,
#endif /* CONFIG_IOMMUFD */
};

/**
 * idpf_vdcm_mdev_probe - Device initialization routine
 * @mdev: emulated device instance pointer
 *
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_mdev_probe(struct mdev_device *mdev)
{
	struct device *parent_dev = mdev->dev.parent;
	struct iommu_group *group;
	struct idpf_vdcm *ivdm;
	int err;

	/* Customized way for DMA passthrough in kernel v6.1 w/ mdev patches */
	group = iommu_group_alloc();
	if (IS_ERR(group))
		return PTR_ERR(group);

	err = iommu_group_add_device(group, &mdev->dev);
	if (!err)
		dev_info(&mdev->dev, "MDEV: group_id = %d", iommu_group_id(group));

	iommu_group_put(group);

	ivdm = vfio_alloc_device(idpf_vdcm, vdev, &mdev->dev, &idpf_vdcm_vdev_ops);
	if (!ivdm)
		return -ENOMEM;

	err = idpf_vdcm_dev_init(ivdm, mdev_dev(mdev), parent_dev);
	if (err)
		goto vdcm_adi_init_err;

	/* register vfio device */
	err = vfio_register_group_dev(&ivdm->vdev);
	if (err)
		goto vdcm_register_dev_err;

	mdev_set_iommu_device(mdev, parent_dev);
	dev_set_drvdata(&mdev->dev, ivdm);

	return 0;

vdcm_register_dev_err:
	idpf_vdcm_dev_release(ivdm);
vdcm_adi_init_err:
	vfio_put_device(&ivdm->vdev);

	return err;
}

/**
 * idpf_vdcm_mdev_remove - Device removal routine
 * @mdev: pointer to the mdev device
 */
static void idpf_vdcm_mdev_remove(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = dev_get_drvdata(&mdev->dev);

	vfio_unregister_group_dev(&ivdm->vdev);
	idpf_vdcm_dev_release(ivdm);
	vfio_put_device(&ivdm->vdev);
}

/**
 * idpf_vdcm_show_description - show mdev type description
 * @mtype: mdev type
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t idpf_vdcm_show_description(struct mdev_type *mtype, char *buf)
{
	return sprintf(buf, "Intel IDPF ADI: %s\n", mtype->sysfs_name);
}

/**
 * idpf_vdcm_get_available_instances - get available instances
 * @mtype: mdev type
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of available instances.
 */
static unsigned int idpf_vdcm_get_available_instances(struct mdev_type *mtype)
{
	return 0;
}

/**
 * vector_count_show - SYSFS show function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of bytes used to store the current value in string buffer
 */
static ssize_t vector_count_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct idpf_vdcm *ivdm = dev_get_drvdata(dev);

	return idpf_vdcm_dev_vector_count_show(ivdm, buf);
}

/**
 * vector_count_store - SYSFS store function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: buffer containing new value
 * @datalen: length of data
 *
 * This function is called when SYSFS file entry is modified/written by user
 * Return number of bytes written
 */
static ssize_t vector_count_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t datalen)
{
	struct idpf_vdcm *ivdm = dev_get_drvdata(dev);

	return idpf_vdcm_dev_vector_count_store(ivdm, buf, datalen);
}
static DEVICE_ATTR_RW(vector_count);

/**
 * policy_idx_show - SYSFS show function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of bytes used to store the current value in string buffer
 */
static ssize_t policy_idx_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct idpf_vdcm *ivdm = dev_get_drvdata(dev);

	return idpf_vdcm_dev_policy_idx_show(ivdm, buf);
}

/**
 * policy_idx_store - SYSFS store function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: buffer containing new value
 * @datalen: length of data
 *
 * This function is called when SYSFS file entry is modified/written by user
 * Return number of bytes written
 */
static ssize_t policy_idx_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t datalen)
{
	struct idpf_vdcm *ivdm = dev_get_drvdata(dev);

	return idpf_vdcm_dev_policy_idx_store(ivdm, buf, datalen);
}
static DEVICE_ATTR_RW(policy_idx);

static struct attribute *idpf_vdcm_mdev_dev_attrs[] = {
	&dev_attr_vector_count.attr,
	&dev_attr_policy_idx.attr,
	NULL,
};

static const struct attribute_group idpf_vdcm_mdev_dev_group = {
	.name  = "vdcm",
	.attrs = idpf_vdcm_mdev_dev_attrs,
};

static const struct attribute_group *idpf_vdcm_mdev_dev_groups[] = {
	&idpf_vdcm_mdev_dev_group,
	NULL
};

static struct mdev_driver idpf_vdcm_driver = {
	.device_api = VFIO_DEVICE_API_PCI_STRING,
	.driver = {
		.name = "idpf_vdcm",
		.owner = THIS_MODULE,
		.mod_name = KBUILD_MODNAME,
		.dev_groups = idpf_vdcm_mdev_dev_groups,
	},
	.probe = idpf_vdcm_mdev_probe,
	.remove = idpf_vdcm_mdev_remove,
	.show_description = idpf_vdcm_show_description,
	.get_available = idpf_vdcm_get_available_instances,
};

static struct idpf_vdcm_type {
	struct mdev_type type;
} idpf_vdcm_types[] = {
	{
		.type.sysfs_name	= "vdcm",
		.type.pretty_name	= "vdcm",
	},
};

static struct mdev_type *idpf_vdcm_mdev_types[] = {
	&idpf_vdcm_types[0].type,
};

#else
/**
 * idpf_vdcm_mdev_mmap - map device memory to user space
 * @mdev: pointer to the mdev device
 * @vma: pointer to the vm where device memory will be mapped
 *
 * Return 0 if succeed, negative for failure.
 */
static int
idpf_vdcm_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_mmap(ivdm, vma);
}

/**
 * idpf_vdcm_mdev_create - create an emulated device
 * @kobj: kernel object
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to create a
 * emulated device, typically by echo some uuid to the SYSFS.
 * Return 0 for success, non 0 for failure.
 */
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
static int idpf_vdcm_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
#else
static int idpf_vdcm_mdev_create(struct mdev_device *mdev)
#endif
{
	struct device *parent_dev = mdev_parent_dev(mdev);
	struct idpf_vdcm *ivdm;
	int err;

	ivdm = kzalloc(sizeof(*ivdm), GFP_KERNEL);
	if (!ivdm)
		return -ENOMEM;

	err = idpf_vdcm_dev_init(ivdm, mdev_dev(mdev), parent_dev);
	if (err) {
		kfree(ivdm);

		return err;
	}

	mdev_set_drvdata(mdev, ivdm);

#ifdef HAVE_DEV_IN_MDEV_API
	mdev_set_iommu_device(mdev_dev(mdev), parent_dev);
#else
	mdev_set_iommu_device(mdev, parent_dev);
#endif /* HAVE_DEV_IN_MDEV_API */

	return 0;
}

/**
 * idpf_vdcm_mdev_destroy - delete an emulated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer(like QEMU) wants to delete
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_mdev_destroy(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	idpf_vdcm_dev_release(ivdm);
	kfree(ivdm);

	return 0;
}

/**
 * idpf_vdcm_mdev_read - read function entry
 * @mdev: emulated device instance pointer
 * @buf: buf stores read content
 * @count: read length
 * @ppos: read offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to read
 * emulated device with any device specific information for register access
 * Return the number of read bytes.
 */
static ssize_t
idpf_vdcm_mdev_read(struct mdev_device *mdev, char __user *buf, size_t count,
		    loff_t *ppos)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_read(ivdm, buf, count, ppos);
}

/**
 * idpf_vdcm_mdev_write - write function entry
 * @mdev: emulated device instance pointer
 * @buf: buf stores content to be written
 * @count: write length
 * @ppos: write offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to write
 * emulated device with any device specific information like register access
 * Return the number of written bytes.
 */
static ssize_t
idpf_vdcm_mdev_write(struct mdev_device *mdev, const char __user *buf, size_t count,
		     loff_t *ppos)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_write(ivdm, buf, count, ppos);
}

/**
 * idpf_vdcm_mdev_ioctl - IOCTL function entry
 * @mdev: emulated device instance pointer
 * @cmd: pre defined ioctls
 * @arg: cmd arguments
 *
 * This function is called when VFIO consumer (like QEMU) wants to config
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd, unsigned long arg)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_ioctl(ivdm, cmd, arg);
}

/**
 * idpf_vdcm_mdev_open - open emulated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to open
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_mdev_open(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_open(ivdm);
}

/**
 * idpf_vdcm_mdev_close - close a mediated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to close
 * emulated device.
 */
static void idpf_vdcm_mdev_close(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	idpf_vdcm_dev_close(ivdm);
}

/**
 * name_show - SYSFS show function
 * @kobj: kernel object
 * @dev: linux device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
name_show(struct kobject *kobj, struct device *dev, char *buf)
#else
name_show(struct mdev_type *mtype,
	  struct mdev_type_attribute *attr, char *buf)
#endif
{
#ifndef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
	struct device *dev = mtype_get_parent_dev(mtype);
#endif /* !HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE */
	return sprintf(buf, "%s\n", dev_name(dev));
}
static MDEV_TYPE_ATTR_RO(name);

/**
 * available_instances_show - SYSFS show function
 * @kobj: kernel object
 * @dev: device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
#else
available_instances_show(struct mdev_type *mtype,
			 struct mdev_type_attribute *attr, char *buf)
#endif
{
	return sprintf(buf, "ivdcm\n");
}
static MDEV_TYPE_ATTR_RO(available_instances);

/**
 * device_api_show - SYSFS show function
 * @kobj: kernel object
 * @dev: device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
device_api_show(struct kobject *kobj, struct device *dev, char *buf)
#else
device_api_show(struct mdev_type *mtype,
		struct mdev_type_attribute *attr, char *buf)
#endif
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

/**
 * vector_count_show - SYSFS show function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of bytes used to store the current value in string buffer
 */
static ssize_t vector_count_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct idpf_vdcm *ivdm =
			mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_vector_count_show(ivdm, buf);
}

/**
 * vector_count_store - SYSFS store function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: buffer containing new value
 * @datalen: length of data
 *
 * This function is called when SYSFS file entry is modified/written by user
 * Return number of bytes written
 */
static ssize_t vector_count_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t datalen)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct idpf_vdcm *ivdm =
			mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_vector_count_store(ivdm, buf, datalen);
}
static DEVICE_ATTR_RW(vector_count);

/**
 * policy_idx_show - SYSFS show function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of bytes used to store the current value in string buffer
 */
static ssize_t policy_idx_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct idpf_vdcm *ivdm =
			mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_policy_idx_show(ivdm, buf);
}

/**
 * policy_idx_store - SYSFS store function
 * @dev: device pointer
 * @attr: device attribute pointer
 * @buf: buffer containing new value
 * @datalen: length of data
 *
 * This function is called when SYSFS file entry is modified/written by user
 * Return number of bytes written
 */
static ssize_t policy_idx_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t datalen)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct idpf_vdcm *ivdm =
			mdev_get_drvdata(mdev);

	return idpf_vdcm_dev_policy_idx_store(ivdm, buf, datalen);
}
static DEVICE_ATTR_RW(policy_idx);

static struct attribute *idpf_vdcm_mdev_attrs[] = {
	&dev_attr_vector_count.attr,
	&dev_attr_policy_idx.attr,
	NULL,
};

static struct attribute_group idpf_vdcm_mdev_group0 = {
	.name  = "vdcm",
	.attrs = idpf_vdcm_mdev_attrs,
};

static const struct attribute_group *idpf_vdcm_mdev_attr_groups[] = {
	&idpf_vdcm_mdev_group0,
	NULL,
};
static struct attribute *idpf_vdcm_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group idpf_vdcm_type_group0 = {
	.name  = "vdcm",
	.attrs = idpf_vdcm_types_attrs,
};

static struct attribute_group *idpf_vdcm_mdev_type_groups[] = {
	&idpf_vdcm_type_group0,
	NULL,
};

static const struct mdev_parent_ops idpf_vdcm_parent_ops = {
	.mdev_attr_groups	= idpf_vdcm_mdev_attr_groups,
	.supported_type_groups	= idpf_vdcm_mdev_type_groups,
	.create			= idpf_vdcm_mdev_create,
	.remove			= idpf_vdcm_mdev_destroy,
#ifdef HAVE_DEVICE_IN_MDEV_PARENT_OPS
	.open_device		= idpf_vdcm_mdev_open,
	.close_device		= idpf_vdcm_mdev_close,
#else
	.open			= idpf_vdcm_mdev_open,
	.release		= idpf_vdcm_mdev_close,
#endif /* HAVE_DEVICE_IN_MDEV_PARENT_OPS */
	.read			= idpf_vdcm_mdev_read,
	.write			= idpf_vdcm_mdev_write,
	.ioctl			= idpf_vdcm_mdev_ioctl,
	.mmap			= idpf_vdcm_mdev_mmap,
};
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */

/*
 * idpf_vdcm_init - VDCM initialization routine
 * @pdev: the parent pci device
 *
 * Return 0 for success, negative for failure.
 */
int idpf_vdcm_init(struct pci_dev *pdev)
{
#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */
	int err;

	err = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable aux-domain: %d", err);
		return err;
	}

#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	err = mdev_register_driver(&idpf_vdcm_driver);
	if (err) {
		dev_err(&pdev->dev, "Failed to register mdev driver: %d", err);
		iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
		return err;
	}

	err = mdev_register_parent(&adapter->parent, &pdev->dev,
				   &idpf_vdcm_driver, idpf_vdcm_mdev_types,
				   ARRAY_SIZE(idpf_vdcm_mdev_types));
	if (err) {
		dev_err(&pdev->dev, "Failed to register mdev parent: %d", err);
		mdev_unregister_driver(&idpf_vdcm_driver);
		iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
		return err;
	}
#else
	err = mdev_register_device(&pdev->dev, &idpf_vdcm_parent_ops);
	if (err) {
		dev_err(&pdev->dev, "S-IOV device register failed, err %d",
			err);
		iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
		return err;
	}
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */

	return 0;
}

/*
 * idpf_vdcm_deinit - VDCM deinitialization routine
 * @pdev: the parent pci device
 */
void idpf_vdcm_deinit(struct pci_dev *pdev)
{
#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */

	if (!(iommu_dev_feature_enabled(&pdev->dev, IOMMU_DEV_FEAT_AUX)))
		return;

#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	mdev_unregister_parent(&adapter->parent);
	mdev_unregister_driver(&idpf_vdcm_driver);
#else
	mdev_unregister_device(&pdev->dev);
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
}
