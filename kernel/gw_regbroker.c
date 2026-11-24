// SPDX-License-Identifier: GPL-2.0
/*
 * gw_regbroker - narrow physical register access broker.
 *
 * This is an OPTIONAL template for vendor/field tools that need a few MMIO
 * registers. It is deliberately not /dev/mem:
 *
 *   - only addresses in the build-time regions[] table are accepted;
 *   - access width is limited to 1/2/4 bytes;
 *   - a region can be marked read-only;
 *   - the misc device is created root:root 0600 by default; use an udev rule
 *     and a dedicated group/service account if a non-root debugger needs it;
 *   - sign this .ko with the OEM module key exactly like any other module.
 *
 * Do not whitelist DDR, interrupt controllers, IOMMU, secure-controller, boot
 * configuration or DMA-control windows. Whitelist only the exact peripheral
 * register page required by the vendor tool.
 *
 * The ioctl ABI is native word size. Add compat_ioctl if supporting 32-bit
 * userspace on a 64-bit kernel.
 */

#include <linux/fs.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/uaccess.h>

#define GW_REGBROKER_MAGIC 'G'

struct gw_reg_op {
	__u64 phys;
	__u32 width;
	__u32 value;
};

#define GW_REGBROKER_READ _IOWR(GW_REGBROKER_MAGIC, 1, struct gw_reg_op)
#define GW_REGBROKER_WRITE _IOW(GW_REGBROKER_MAGIC, 2, struct gw_reg_op)

struct gw_region {
	phys_addr_t base;
	resource_size_t size;
	bool writable;
	void __iomem *va;
};

/*
 * TODO(board): replace the zero placeholder with exact register windows from
 * the SoC/vendor manual. Example:
 *
 *   { .base = 0x12340000, .size = 0x00001000, .writable = false },
 *   { .base = 0x12350000, .size = 0x00000100, .writable = true  },
 */
static struct gw_region regions[] = {
	{ .base = 0, .size = 0, .writable = false, .va = NULL },
};

static struct gw_region *gw_find_region(u64 phys, u32 width, bool write)
{
	size_t i;

	if (width != 1 && width != 2 && width != 4)
		return ERR_PTR(-EINVAL);
	if (phys > U64_MAX - width)
		return ERR_PTR(-EOVERFLOW);

	for (i = 0; i < ARRAY_SIZE(regions); i++) {
		struct gw_region *r = &regions[i];
		u64 end;

		if (r->size == 0)
			continue;
		if (phys < (u64)r->base)
			continue;
		if (check_add_overflow((u64)r->base, (u64)r->size, &end))
			continue;
		if (phys + width > end)
			continue;
		if (!IS_ALIGNED(phys, width))
			return ERR_PTR(-EINVAL);
		if (write && !r->writable)
			return ERR_PTR(-EPERM);

		return r;
	}

	return ERR_PTR(-ENXIO);
}

static long gw_regbroker_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct gw_reg_op __user *uarg = (void __user *)arg;
	struct gw_reg_op op;
	struct gw_region *r;
	u64 offset;
	u32 value = 0;

	(void)file;

	if (copy_from_user(&op, uarg, sizeof(op)))
		return -EFAULT;

	if (cmd != GW_REGBROKER_READ && cmd != GW_REGBROKER_WRITE)
		return -ENOTTY;

	r = gw_find_region(op.phys, op.width, cmd == GW_REGBROKER_WRITE);
	if (IS_ERR(r))
		return PTR_ERR(r);

	offset = op.phys - (u64)r->base;

	if (cmd == GW_REGBROKER_READ) {
		switch (op.width) {
		case 1:
			value = ioread8((u8 __iomem *)r->va + offset);
			break;
		case 2:
			value = ioread16((u8 __iomem *)r->va + offset);
			break;
		case 4:
			value = ioread32((u8 __iomem *)r->va + offset);
			break;
		}

		op.value = value;
		if (copy_to_user(uarg, &op, sizeof(op)))
			return -EFAULT;
		return 0;
	}

	switch (op.width) {
	case 1:
		iowrite8((u8)op.value, (u8 __iomem *)r->va + offset);
		break;
	case 2:
		iowrite16((u16)op.value, (u8 __iomem *)r->va + offset);
		break;
	case 4:
		iowrite32(op.value, (u8 __iomem *)r->va + offset);
		break;
	}

	/* Make the write reach the device before the ioctl returns. */
	mmiowb();
	return 0;
}

static const struct file_operations gw_regbroker_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = gw_regbroker_ioctl,
#ifdef CONFIG_COMPAT
	/* Add a translated compat_ioctl if the struct ABI differs. */
#endif
};

static struct miscdevice gw_regbroker_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "gw-regbroker",
	.fops = &gw_regbroker_fops,
	.mode = 0600,
};

static int __init gw_regbroker_init(void)
{
	int i, ret;

	for (i = 0; i < (int)ARRAY_SIZE(regions); i++) {
		struct gw_region *r = &regions[i];

		if (r->size == 0)
			continue;

		if (!request_mem_region(r->base, r->size, "gw-regbroker")) {
			pr_err("gw-regbroker: region %pa+%pa busy\n",
			       &r->base, &r->size);
			ret = -EBUSY;
			goto unwind_previous;
		}

		r->va = ioremap(r->base, r->size);
		if (!r->va) {
			pr_err("gw-regbroker: cannot map region %pa\n",
			       &r->base);
			release_mem_region(r->base, r->size);
			ret = -ENOMEM;
			goto unwind_previous;
		}
	}

	ret = misc_register(&gw_regbroker_dev);
	if (ret) {
		pr_err("gw-regbroker: misc_register failed: %d\n", ret);
		i = (int)ARRAY_SIZE(regions);
		goto unwind_all;
	}

	pr_info("gw-regbroker: registered narrow MMIO broker\n");
	return 0;

unwind_all:
unwind_previous:
	while (i-- > 0) {
		struct gw_region *r = &regions[i];

		if (r->va) {
			iounmap(r->va);
			r->va = NULL;
		}
		if (r->size)
			release_mem_region(r->base, r->size);
	}
	return ret;
}

static void __exit gw_regbroker_exit(void)
{
	int i;

	misc_deregister(&gw_regbroker_dev);

	for (i = 0; i < (int)ARRAY_SIZE(regions); i++) {
		struct gw_region *r = &regions[i];

		if (r->va)
			iounmap(r->va);
		if (r->size)
			release_mem_region(r->base, r->size);
	}
}

module_init(gw_regbroker_init);
module_exit(gw_regbroker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gateway Security Reference");
MODULE_DESCRIPTION("Allow-listed MMIO register broker");
MODULE_VERSION("0.1");
