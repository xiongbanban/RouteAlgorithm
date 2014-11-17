#ifndef DEBUGFS_AOMDV
#define DEBUGFS_AOMDV

#include <linux/list.h>
#include <linux/types.h>

void debugfs_aomdv_init(void);

ssize_t aomdv_fwrite(struct file *, const char __user *, size_t, loff_t *);

ssize_t aomdv_fread(struct file *, char __user *, size_t, loff_t *);

void AOMDV_display_rtable(void);

#endif