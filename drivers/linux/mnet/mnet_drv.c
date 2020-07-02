#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/of.h>
#include <linux/ioctl.h>
#include <linux/of_platform.h>
#include "mnet_drv.h"

#define DEVINFO_SIZE            0x1000

#define DRVCFG_SIZE             0x80

#define MSIXCFG_SIZE            0x40

#define DOORBELL_PG_SIZE        0x8

#define MNET_NODE_NAME_LEN      0x8

struct mnet_dev_t {
	struct device_node *of_node;
	uint32_t busy;
	struct platform_device *mnic_pdev;
	struct list_head node;
};

LIST_HEAD(mnet_list);

static struct class *mnet_class;
static dev_t mnet_dev;
struct device *mnet_device;
static unsigned int mnet_major;
static struct cdev mnet_cdev;
extern int ionic_probe(struct platform_device *pfdev);
extern int mnet_uio_pdrv_genirq_probe(struct platform_device *pfdev);
extern int ionic_remove(struct platform_device *pfdev);
extern int mnet_uio_pdrv_genirq_remove(struct platform_device *pfdev);

static int mnet_open(struct inode *inode, struct file *filep)
{
	return 0;
}

static int mnet_close(struct inode *i, struct file *f)
{
	return 0;
}

struct platform_device *mnet_get_platform_device(struct mnet_dev_t *mnet,
		struct mnet_dev_create_req_t *req)
{
	int ret = 0;
	struct platform_device *pdev;
	char *mnic_name = NULL;

	struct resource mnic_resource[] = {
		{ /*devinfo*/
			.flags    = IORESOURCE_MEM,
			.start    = req->regs_pa,
			.end      = req->regs_pa + DEVINFO_SIZE - 1
		}, {/*drvcfg/intr_ctrl*/
			.flags    = IORESOURCE_MEM,
			.start    = req->drvcfg_pa,
			.end      = req->drvcfg_pa + DRVCFG_SIZE - 1
		}, {/*msixcfg*/
			.flags    = IORESOURCE_MEM,
			.start    = req->msixcfg_pa,
			.end      = req->msixcfg_pa + MSIXCFG_SIZE - 1
		}, {/*doorbell*/
			.flags    = IORESOURCE_MEM,
			.start    = req->doorbell_pa,
			.end      = req->doorbell_pa + DOORBELL_PG_SIZE - 1
		}
	};

	pdev = of_find_device_by_node(mnet->of_node);

	if (pdev == NULL) {
		dev_err(mnet_device, "Can't find platform_device for of_node %s\n",
				mnet->of_node->name);
		return NULL;
	}

	/* add resource info */
	ret = platform_device_add_resources(pdev, mnic_resource,
			ARRAY_SIZE(mnic_resource));
	if (ret) {
		dev_err(mnet_device, "Can't add mem resource to platform_device"
				"for %s device\n", req->iface_name);
		return NULL;
	}

	mnic_name = devm_kzalloc(mnet_device, MNIC_NAME_LEN, GFP_KERNEL);
	if (!pdev->name) {
		dev_err(mnet_device, "Can't allocate memory for mnic_name\n");
		return NULL;
	}

	strcpy(mnic_name, req->iface_name);
	pdev->name = mnic_name;

	return pdev;
}

static long mnet_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct mnet_dev_t *mnet;
	uint8_t found_dev_node = 0, cpu_mnic_dev = 0;
	struct mnet_dev_create_req_t req;
	char iface_name[MNIC_NAME_LEN] = {0};
	void __user *argp = (void __user *)arg;

	switch (cmd) {

	case MNET_CREATE_DEV:

		list_for_each_entry(mnet, &mnet_list, node) {
			/* find the first free mnet instance to create mnic device */
			if (!mnet->busy) {
				found_dev_node = 1;
				break;
			}
		}

		if (!found_dev_node) {
			dev_err(mnet_device, "Dev node not found \n");
			return -EDQUOT;
		}

		if (copy_from_user(&req, argp, sizeof(req))) {
			dev_err(mnet_device, "copy from user failed\n");
			return -EFAULT;
		}

		mnet->mnic_pdev = mnet_get_platform_device(mnet, &req);

		if (!mnet->mnic_pdev) {
			dev_err(mnet_device, "Can't get platform_device \n");
			ret = -ENXIO;
			break;
		}

		/*
		 * No probe for device names of cpu_mnic, better way to do this
		 * would be pass on a flag called no-probe in mnet_dev_create_req_t struct
		 */
		if (!strncmp(req.iface_name, "cpu_mnic", 8))
			cpu_mnic_dev = 1;
		dev_info(mnet_device, "MNET_CREATE_DEV called iface name %s (is cpu mnic: %d)\n", req.iface_name, cpu_mnic_dev);

		/* call probe with this platform_device */
		if (cpu_mnic_dev) {
			ret = mnet_uio_pdrv_genirq_probe(mnet->mnic_pdev);
		} else {
			ret = ionic_probe(mnet->mnic_pdev);
		}
		if (ret) {
			dev_err(mnet_device, "mnic probe for %s failed with err: %d\n",
					mnet->mnic_pdev->name, ret);

			break;
		}

		/* mark the mnet device as busy once mnic probe is successful */
		mnet->busy = 1;

		dev_info(mnet_device, "mnic device :%s created successfully!\n",
				mnet->mnic_pdev->name);

		break;

	case MNET_DESTROY_DEV:

		ret = copy_from_user(iface_name, argp, MNIC_NAME_LEN) ?
				-EFAULT : 0;
		if (ret)
			break;

		dev_info(mnet_device, "Removing mnic device: %s \n", iface_name);

		list_for_each_entry(mnet, &mnet_list, node) {
			/* find the mnet device which is bound to this interface */
			if (!strcmp(mnet->mnic_pdev->name, iface_name)) {
				found_dev_node = 1;
				/* For CPU MNIC devices, call a different remove */
				if (!strncmp(iface_name, "cpu_mnic", 8))
					cpu_mnic_dev = 1;
				break;
			}
		}

		if (!found_dev_node)
			return -EDQUOT;

		if (mnet->busy) {
			if (cpu_mnic_dev)
				ret = mnet_uio_pdrv_genirq_remove(mnet->mnic_pdev);
			else
				ret = ionic_remove(mnet->mnic_pdev);
			if (ret) {
				dev_err(mnet_device, "ionic_remove failed to remove %s "
						"interface\n", mnet->mnic_pdev->name);
				break;
			}

			/* Mark mnet as free since we are detached from mnic */
			mnet->busy = 0;

			dev_info(mnet_device, "mnic device :%s removed successfully!\n",
                    iface_name);
		}

		break;

	default:
		dev_dbg(mnet_device, "Invalid ioctl cmd\n");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int mnet_probe(struct platform_device *pfdev)
{
	return 0;
}

static int mnet_remove(struct platform_device *pfdev)
{
	struct mnet_dev_t *mnet, *tmp;
	int ret;

	list_for_each_entry_safe(mnet, tmp, &mnet_list, node) {
		if (mnet->mnic_pdev) {

			if (mnet->busy) {

				ret = ionic_remove(mnet->mnic_pdev);

				if (ret) {
					dev_err(mnet_device, "ionic_remove failed to remove %s "
							"interface\n", mnet->mnic_pdev->name);
					break;
				}

				dev_info(mnet_device, "Successfully Removed "
						"mnic interface %s\n", mnet->mnic_pdev->name);

				/* Mark mnet as free since we are detached from mnic */
				mnet->mnic_pdev = NULL;
			}
		}

		mnet->busy = 0;

		list_del(&mnet->node);
	}

	return ret;
}

static struct of_device_id mnet_of_match[] = {
	{.compatible = "pensando,mnet"},
	{/* end of table */}
};

static struct platform_driver mnet_driver = {
	.probe = mnet_probe,
	.remove = mnet_remove,
	.driver = {
		.name = "pensando-mnet",
		.owner = THIS_MODULE,
		.of_match_table = mnet_of_match,
	},
};

static const struct file_operations mnet_fops = {
	.owner = THIS_MODULE,
	.open = mnet_open,
	.release = mnet_close,
	.unlocked_ioctl = mnet_ioctl,
};

static int __init mnet_init(void)
{
	int ret, i;
	char of_node_name[MNET_NODE_NAME_LEN + 1] = {0, };
	struct mnet_dev_t *mnet_inst;

	mnet_class = class_create(THIS_MODULE, DRV_NAME);
	if (IS_ERR(mnet_class)) {
		ret = PTR_ERR(mnet_class);
		goto error_class;
	}

	ret = alloc_chrdev_region(&mnet_dev, 0, NUM_MNET_DEVICES, MNET_CHAR_DEV_NAME);
	if (ret < 0)
		goto error_chrdev;

	mnet_major = MAJOR(mnet_dev);

	pr_info("Pensando mnet driver: mnet_major = %d\n", mnet_major);

	mnet_device = device_create(mnet_class, NULL,
			MKDEV(mnet_major, 0), NULL, DRV_NAME);

	if (IS_ERR(mnet_device)) {
		pr_err("Failed to create device %s", DRV_NAME);
		ret = PTR_ERR(mnet_class);
		goto error_device_add;
	}

	dev_info(mnet_device, "device mnet created succussfully\n");

	cdev_init(&mnet_cdev, &mnet_fops);

	mnet_cdev.owner = THIS_MODULE;

	ret = cdev_add(&mnet_cdev, mnet_dev, 1);
	if (ret) {
		dev_err(mnet_device, "Error in adding character device %s. Exiting...\n", MNET_CHAR_DEV_NAME);
		goto error_device_add;
	}

	for (i = 0; i < MAX_MNET_DEVICES; i++) {

		mnet_inst = devm_kzalloc(mnet_device, sizeof(*mnet_inst), GFP_KERNEL);

		if (mnet_inst == NULL) {
			ret = PTR_ERR(mnet_class);
			goto error_device_add;
		}

		snprintf(of_node_name, sizeof(of_node_name), "mnet%d", i);
		mnet_inst->of_node = of_find_node_by_name(NULL, of_node_name);

		/* skip the mnet node not found in device tree */
		if (mnet_inst->of_node == NULL)
			continue;

		dev_info(mnet_device, "Found mnet node %s\n", mnet_inst->of_node->name);

		/* Add the mnet node in list */
		list_add_tail(&mnet_inst->node, &mnet_list);

		of_node_put(mnet_inst->of_node);
	}

	return platform_driver_register(&mnet_driver);;

error_device_add:
	device_destroy(mnet_class, mnet_major);
	unregister_chrdev_region(mnet_dev, NUM_MNET_DEVICES);
error_chrdev:
	class_destroy(mnet_class);

error_class:
	return ret;
}

static void __exit mnet_cleanup(void)
{
	platform_driver_unregister(&mnet_driver);
	device_destroy(mnet_class, MKDEV(mnet_major, 0));
	unregister_chrdev_region(mnet_dev, NUM_MNET_DEVICES);
	class_destroy(mnet_class);

	return;
}

module_init(mnet_init);
module_exit(mnet_cleanup);

MODULE_AUTHOR("Pensando Systems");
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
