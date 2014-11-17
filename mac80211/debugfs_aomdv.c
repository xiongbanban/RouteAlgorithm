#include "debugfs_aomdv.h"

extern struct list_head AOMDV_rtable;

struct dentry *ieee80211s_debugfs_dir;
struct file_operations aomdv_fops = { 
    .owner = THIS_MODULE, 
    .read = aomdv_fread, 
    .write = aomdv_fwrite, 
}; 

void debugfs_aomdv_init() 
{

	ieee80211s_debugfs_dir = debugfs_create_dir("mesh", NULL);

	debugfs_create_file("aomdv", S_IRUSR | S_IWUSR,
			    ieee80211s_debugfs_dir, NULL, &aomdv_fops);
	
}

unsigned char aomdv_hextodec(char *str){
	unsigned char tmp=0;
	
	if(str[0]>='A'  )
		tmp |= str[0]-'A'+10;
	else if(str[0]>='a')
		tmp |= |= str[0]-'a'+10;
	else
		tmp |= str[0]-'0';

	tmp <<=4;

	if(str[1]>='A'  )
		tmp |= str[1]-'A'+10;
	else if(str[1]>='a')
		tmp |= str[1]-'a'+10;
	else
		tmp |= str[1]-'0';

	return tmp;
}


ssize_t aomdv_fwrite(struct file *filp, const char __user *buffer, 
        size_t count, loff_t *ppos) 
{ 
	char temp[32];
	unsigned char mac_addr[12];
	int i;
	
	memset(temp,0,32);

    if (*ppos >= 32) 
        return 0; 
    if (*ppos + count > 32) 
        count = 32 - *ppos; 
  
    if (copy_from_user(temp + *ppos, buffer, count)) 
        return -EFAULT; 
  
    *ppos += count; 
	
	printk(KERN_ERR"aomdv debugfs write %s \n", temp);
	if(temp[0]=='r'))
	{
		for(i=0;i<12;i+=2)
			mac_addr[i/2] = aomdv_hextodec(temp[i+2]);
		AOMDV_display_rtable(mac_addr);
	}
	
	
    return count;
} 

ssize_t aomdv_fread(struct file *filp, char __user *buffer, 
         size_t count, loff_t *ppos) {
	return count;
}

void AOMDV_display_rtable() {
	struct list_head *lh, *lh1;
	struct mesh_path_aomdv *rt = NULL;
	struct AOMDV_Path *path = NULL;
	u8 i;
if(list_empty(&AOMDV_rtable)) {
	printk("rtable empty\n");
}
	list_for_each(lh,&AOMDV_rtable) {
		rt = list_entry(lh, struct mesh_path_aomdv, rt_link);
		printk(KERN_ERR"route table for %0x%0x%0x%0x%0x%0x",*(rt->dst + 5), *(rt->dst + 4), *(rt->dst + 3), *(rt->dst + 2),*(rt->dst + 1),*(rt->dst + 0));
		printk(KERN_ERR"SN = %d", rt->sn);
		printk(KERN_ERR"Ad hop_cnt = %d", rt->advertised_hops);
		
		i=0;
		list_for_each(lh1, &rt->path_list) {
			++i;
			path = list_entry(lh1, struct AOMDV_Path, path_link);
			printk(KERN_ERR"Path %d: ", i);
			printk(KERN_ERR"nexthop =  %0x%0x%0x%0x%0x%0x",*(path->nexthop + 5), *(path->nexthop + 4), *(path->nexthop + 3), *(path->nexthop + 2),*(path->nexthop + 1),*(path->nexthop + 0));
			printk(KERN_ERR"hopcount = %d", path->hopcount);
			printk(KERN_ERR"nexthop =  %0x%0x%0x%0x%0x%0x",*(path->lasthop + 5), *(path->lasthop + 4), *(path->lasthop + 3), *(path->lasthop + 2),*(path->lasthop + 1),*(path->lasthop + 0));
			printk(KERN_ERR"error = %d", path->error);
		}
	}
	
}
