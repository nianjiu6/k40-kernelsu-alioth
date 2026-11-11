#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

extern long do_mount(const char *dev_name, const char __user *dir_name, const char *type_page, unsigned long flags,
		     void *data_page);

int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page)
{
	char *buf, *dir;
	mm_segment_t old_fs;
	int ret;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	dir = d_path(path, buf, PATH_MAX);
	if (IS_ERR(dir)) {
		kfree(buf);
		return PTR_ERR(dir);
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = (int)do_mount(dev_name, (const char __user *)dir, type_page, flags, data_page);
	set_fs(old_fs);
	kfree(buf);
	return ret;
}

#endif
