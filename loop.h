/*
 * loop.h
 *
 * Written by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 */
#ifndef _LINUX_LOOP_H
#define _LINUX_LOOP_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <uapi/linux/loop.h>

#include "igelsdk.h"
#include "igel.h"

/* Possible states of device */
enum {
	Lo_unbound,
	Lo_bound,
	Lo_rundown,
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	Lo_deleting,
#endif
};

struct igel_loop_private;

struct igel_loop_device {
	int		lo_number;
	atomic_t	lo_refcnt;
	size_t          lo_hdrlen;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	int		(*transfer)(struct igel_loop_device *, int cmd,
				    struct page *raw_page, unsigned raw_off,
				    struct page *loop_page, unsigned loop_off,
				    int size, sector_t real_block);
	char		lo_file_name[LO_NAME_SIZE];
	int		(*ioctl)(struct igel_loop_device *, int cmd, 
				 unsigned long arg); 

	struct file *	lo_backing_file, *lo_backing_virt_file;
	struct block_device *lo_device;
	void		*key_data; 

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	struct kthread_worker	worker;
	struct task_struct	*worker_task;
	bool			use_dio;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	struct mutex            lo_mutex;
#endif

	struct igel_partition_info lo_igel_info;
	struct igel_loop_private   *igel_private;
	int mount_order;
	int cmty_pkid;
};

struct igel_loop_cmd {
	struct kthread_work work;
	bool use_aio; /* use AIO interface to handle I/O */
	atomic_t ref; /* only for aio */
	long ret;
	struct kiocb iocb;
	struct bio_vec *bvec;
	struct cgroup_subsys_state *css;
};

#endif
