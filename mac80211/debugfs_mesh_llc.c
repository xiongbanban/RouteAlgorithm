#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>


#include "mesh_llc.h"
#include "debugfs_mesh_llc.h"

struct dentry *my_debugfs_root;
char data_buf[500];
//char *pathname = "/sys/kernel/debug/mesh_llc_debug/mesh_llc";


extern struct config_para my_data;



int get_config_para(struct config_para *data)	{
		char *p = data_buf;
		int i, j, k;
		for(k=0;k<500;k++)	{
			printk("%d ",*(p+k));
		}
		printk("\n");
		int p_cnt = 0;
		
		while((*p != '\0') && (*p != '\n')) {
	
			while(*p == ' ')	{	
				p++;
				p_cnt++;
	
			}

			if((*p == 'e') || (*p == 'E'))	{
				 p++ ;
				p_cnt++;
				while(*p == ' ')	{	
					p++;
					p_cnt++;
	
				}
				if(*p == '1')	{
					printk("open order_enable\n");
					data->order_enable = true;
					p++;
					p_cnt++;
				}
				else if(*p == '0')	{
					printk("close order_enable\n");
					data->order_enable = false;
					p++;
					p_cnt++;
				}
			}
			else if((*p == 'i') || (*p == 'I'))	{
				p++;
				p_cnt++;
				while(*p == ' ')	{
					p++;
					p_cnt++;
				}
				data->scan_interval = 0;
				while((*p !=' ') && (*p != '\n')) {
					if((*p >= '0') && (*p <= '9'))	{
						
						data->scan_interval = (*p - '0') + 10 * (data->scan_interval) ;
						p++;
						p_cnt++;
					}
					else	{
						printk("i:input illegal\n");
						return -1;
	
					}
				}
				printk("get_para scan_interval:%d  ",data->scan_interval);
			}

			else if((*p == 't') || (*p == 'T'))	{
				p++;
				p_cnt++;
				while(*p == ' ')	{
					p++;
					p_cnt++;
				}
				data->wait_max_time = 0;
				while((*p !=' ') && (*p != '\n')) {
					if((*p >= '0') && (*p <= '9'))	{
						
						data->wait_max_time = (*p - '0') + 10 * (data->wait_max_time) ;
						p++;
						p_cnt++;
					}
					else	{
						printk("t:input illegal\n");
						return -1;
					}
				}
				printk("get_para wait_max_time:%d  ",data->wait_max_time);
			}
		
			else	{
				if(*p != '\n')	{
					printk("not i,not t,input illegal\n");
					return -1;
				}
			}
	
		}
		printk("p_cnt:%d\n",p_cnt);
		return 0;
	/*
		fail:
			printk("input illegal\n");
			return -1;
	*/	
}



static int mesh_llc_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

static ssize_t mesh_llc_read(struct file *filp, char __user *buffer,
		size_t count, loff_t *ppos)
{
	if (*ppos >= 500)
		return 0;
	if (*ppos + count > 500)
		count = 500 - *ppos;

	if (copy_to_user(buffer,data_buf + *ppos, count))
		return -EFAULT;

	*ppos += count;

	return count;
}

static ssize_t mesh_llc_write(struct file *filp, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	int ret;
	if (*ppos >= 500)
		return 0;
	if (*ppos + count > 500)
		count = 500 - *ppos;

	if (copy_from_user(data_buf + *ppos, buffer, count))
		return -EFAULT;

	*ppos += count;
	printk("mesh_llc_write complete\n");
//	para_written = true;
	if((ret = get_config_para(&my_data)) < 0)	{
		printk("mesh_llc_write:get para fail\n");
		return -EFAULT;
	}
	return count;
}

struct file_operations c_fops = {
	.owner = THIS_MODULE,
	.open = mesh_llc_open,
	.read = mesh_llc_read,
	.write = mesh_llc_write,
};

int __init debugfs_mesh_llc_init(void)
{
	struct dentry  *s_c;
	int i;

    printk(KERN_INFO "mydebugfs_init\n");

//	para_written = false;
	for(i =0; i<500; i++)	{
		data_buf[i] = 0;
	}
	
	my_debugfs_root = debugfs_create_dir("mesh_llc_debug", NULL);
	if (!my_debugfs_root)	{
		printk("debugfs_mesh_llc_init:creat root_dir fail\n");
		return -ENOENT;
	}

	s_c = debugfs_create_file("mesh_llc", S_IRUSR | S_IWUSR, my_debugfs_root, NULL, &c_fops);
	if (!s_c)	{
		printk("debugfs_mesh_llc_init:creat file fail\n");
		goto Fail;
	}
	        
        return 0;

Fail:
	debugfs_remove_recursive(my_debugfs_root);
	my_debugfs_root = NULL;
	return -ENOENT;
}

void __exit debugfs_mesh_llc_exit(void)
{
        printk(KERN_INFO "debugfs_mesh_llc_exit\n");

	debugfs_remove_recursive(my_debugfs_root);

        return;
}



//MODULE_LICENSE("GPL");

