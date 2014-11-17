/*below all the  functon locate in  mesh_route.c*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>
//#include "mesh.h"




extern void print_route(void);
struct dentry *my_debugfs_root;


static int mesh_route_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

static ssize_t mesh_route_read(struct file *filp, char __user *buffer,
		size_t count, loff_t *ppos)
{
//	if (*ppos >= 500)
//		return 0;
//	if (*ppos + count > 500)
//		count = 500 - *ppos;
	print_route();
	

//	if (copy_to_user(buffer,data_buf + *ppos, count))
//		return -EFAULT;

//	*ppos += count;

	return 0;
}

static ssize_t mesh_route_write(struct file *filp, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	/*int ret;
	if (*ppos >= 500)
		return 0;
	if (*ppos + count > 500)
		count = 500 - *ppos;

	if (copy_from_user(data_buf + *ppos, buffer, count))
		return -EFAULT;

	*ppos += count;
	printk("mesh_route_write complete\n");
//	para_written = true;

	return count;*/
	return 0;
}

struct file_operations c_fops = {
	.owner = THIS_MODULE,
	.open = mesh_route_open,
	.read = mesh_route_read,
	.write = mesh_route_write,
};


//this function called by ieee80211_init()
int __init debugfs_mesh_route_init(void)
{
	struct dentry  *s_c;
	int i;

    printk(KERN_INFO "mydebugfs_init\n");

//	para_written = false;
//	for(i =0; i<500; i++)	{
//		data_buf[i] = 0;
//	}
	
	my_debugfs_root = debugfs_create_dir("mesh_route", NULL);
	if (!my_debugfs_root)	{
		printk("debugfs_mesh_route_init:creat root_dir fail\n");
		return -ENOENT;
	}

	s_c = debugfs_create_file("route", S_IRUSR | S_IWUSR, my_debugfs_root, NULL, &c_fops);
	if (!s_c)	{
		printk("debugfs_mesh_route_init:creat file fail\n");
		goto Fail;
	}
	        
        return 0;

Fail:
	debugfs_remove_recursive(my_debugfs_root);
	my_debugfs_root = NULL;
	return -ENOENT;
}


////this function called by ieee80211s_stop()
void __exit debugfs_mesh_route_exit(void)
{
        printk(KERN_INFO "debugfs_mesh_route_exit\n");

	debugfs_remove_recursive(my_debugfs_root);

        return;
}




