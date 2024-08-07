/*
 *  linux/drivers/block/loop.c
 *
 *  Written by Theodore Ts'o, 3/29/93
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 *
 * DES encryption plus some minor changes by Werner Almesberger, 30-MAY-1993
 * more DES encryption plus IDEA encryption by Nicholas J. Leon, June 20, 1996
 *
 * Modularized and updated for 1.1.16 kernel - Mitch Dsouza 28th May 1994
 * Adapted for 1.3.59 kernel - Andries Brouwer, 1 Feb 1996
 *
 * Fixed do_loop_request() re-entrancy - Vincent.Renardias@waw.com Mar 20, 1997
 *
 * Added devfs support - Richard Gooch <rgooch@atnf.csiro.au> 16-Jan-1998
 *
 * Handle sparse backing files correctly - Kenn Humborg, Jun 28, 1998
 *
 * Loadable modules and other fixes by AK, 1998
 *
 * Make real block number available to downstream transfer functions, enables
 * CBC (and relatives) mode encryption requiring unique IVs per data block.
 * Reed H. Petty, rhp@draper.net
 *
 * Maximum number of loop devices now dynamic via max_loop module parameter.
 * Russell Kroll <rkroll@exploits.org> 19990701
 *
 * Maximum number of loop devices when compiled-in now selectable by passing
 * max_loop=<1-255> to the kernel on boot.
 * Erik I. Bolsø, <eriki@himolde.no>, Oct 31, 1999
 *
 * Completely rewrite request handling to be make_request_fn style and
 * non blocking, pushing work to a helper thread. Lots of fixes from
 * Al Viro too.
 * Jens Axboe <axboe@suse.de>, Nov 2000
 *
 * Support up to 256 loop devices
 * Heinz Mauelshagen <mge@sistina.com>, Feb 2002
 *
 * Support for falling back on the write file operation when the address space
 * operations write_begin is not available on the backing filesystem.
 * Anton Altaparmakov, 16 Feb 2005
 *
 * Still To Fix:
 * - Advisory locking is ignored here.
 * - Should use an own CAP_* category instead of CAP_SYS_ADMIN
 *
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/crc32.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/bug.h>
#include <linux/math64.h>
#include <linux/version.h>
#include <linux/time.h>
#include <linux/string_helpers.h>

#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <linux/key.h>
#include <crypto/public_key.h>

#include "loop.h"
#include "util.h"

#include <linux/uaccess.h>

#include </usr/include/igel64/igel.h>
#include "section_allocation.h"
#include "igel.h"
#include "igel_keys.h"

#undef LOOP_MAJOR

#undef IGF_LOGIN_DEBUG

///* END of section */
//
//static const uint64_t END_SECTION = ~((uint64_t)0) >> ((8 - sizeof(((struct igf_sect_hdr *)0)->next_section)) * 8);
//
///* Modulo for section in minor */
//
//static const uint64_t MOD_SECT_IN_MINOR = (uint64_t) 1UL << (sizeof(((struct igf_sect_hdr *)0)->section_in_minor) * 8);

/* The following make the code a little bit mor flexible, so if the section header or directory headers
 * are changed there should no need to fix offsets or END values */

/* crc offsets for section and directory header */
static const u_int32_t crc_sh_offset = offsetof(struct igf_sect_hdr, crc) + sizeof(((struct igf_sect_hdr *)0) ->crc);
static const u_int32_t crc_dir_offset = offsetof(struct directory, crc) + sizeof(((struct directory *)0) ->crc);

/* One file can be opened at module insertion time */
/* insmod cloop file=/path/to/file */
static char *file=NULL;
module_param(file, charp, 0);
MODULE_PARM_DESC(file, "Initial igf image file (full path)");

static int crc_check = 0;
module_param(crc_check, int, 0);
MODULE_PARM_DESC(crc_check, "Enable crc check");

static int failsafe = 0;
module_param(failsafe, int, 0);
MODULE_PARM_DESC(failsafe, "Create a new directory");

static int max_devices = 10;
module_param(max_devices, int, 0);
MODULE_PARM_DESC(max_devices, "The maximum number of devices allowed to be handled");

static int sys_minor = 1;
module_param(sys_minor, int, 0);
MODULE_PARM_DESC(sys_check, "System minor to use (default is 1)");

const static int LOOP_MAJOR = 61;

static DEFINE_IDR(igel_loop_index_idr);
static DEFINE_MUTEX(igel_loop_ctl_mutex);

static int max_part;
static int part_shift;

#ifdef IGF_LOGIN_DEBUG
	#define MAX_LOGIN_EXTENT_SIZE 24
#else
	#define MAX_LOGIN_EXTENT_SIZE 128
#endif

uint8_t *login_info_health = NULL;
static struct igel_login_info *login_info_cache = NULL;
static struct igel_login_info_element *login_info_element_cache = NULL;

/* TODO: Move to .h file */
int build_directory(struct file *file, struct directory *dir, int crc_check, int sys_minor);
static int igel_loop_remove(struct igel_loop_device *lo, bool release);

//struct igel_loop_private *loop_private;
LIST_HEAD(loop_private);
static void destroy_igel_loop_device(struct igel_loop_private *private);
static void loop_remove(struct igel_loop_device *lo);
static int igel_loop_add_minor(struct igel_loop_private *private, size_t minor, int only_raw_ro);
static int read_dir(struct file *file, struct directory *dir);
static int write_dir(struct file *file, struct directory *dir);
void proc_igel_remove_part(struct igel_loop_device *lo);
void proc_igel_firmware_create_entry(struct igel_loop_device *lo);
void proc_igel_remove(struct igel_loop_private *private);
void proc_igel_create(struct igel_loop_private *private);

static inline void loop_update_dio(struct igel_loop_device *lo);
void proc_igel_cleanup(void);
int proc_igel_startup(void);

struct key *igf_keyring = NULL;

static int
read_igf_sect_header(struct igf_sect_hdr *hdr, size_t section, struct file *file)
{
	loff_t off = START_OF_SECTION(section);
	int ret;

	ret = kernel_read(file, (void __user *)hdr, sizeof(*hdr), &off);

	return ret != sizeof(*hdr);
}

static int
read_igf_part_header(struct igf_part_hdr *hdr, size_t section, struct file *file)
{
	loff_t off = START_OF_SECTION(section) + IGF_SECT_HDR_LEN;
	int ret;

	ret = kernel_read(file, (void __user *)hdr, sizeof(*hdr), &off);

	return ret != sizeof(*hdr);
}

/* IGEL-extension aware version of get_size.
 * This takes into account whether we are redirecting IO
 * to an extent or not */
static loff_t get_igel_size(struct igel_loop_device *lo)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	struct igf_partition_extent *extent;

	/* That's the normal case. Use partition header information */
	if (!lo->lo_igel_info.use_ext_instead) {
		return (info->phdr.n_blocks * 1024) >> 9;
	}

	/* Ok, we are in the extent case */
	extent = &info->part_exts.extent[info->use_ext_instead - 1];

	return extent->length >> 9;
}

/* IGEL-extension aware version of get_offset
 * This takes into account whether we redirect to an extent
 * and otherwise uses the partition offset from the header */
static int set_igel_offset(struct igel_loop_device *lo)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	struct igf_partition_extent *extent;

	if (!lo->lo_igel_info.use_ext_instead) {
		lo->lo_offset = lo->lo_igel_info.phdr.offset_blocks;
		return 0;
	}

	extent = &info->part_exts.extent[info->use_ext_instead - 1];
	lo->lo_offset = extent->offset;
	return 0;
}

/* Switch to an extent we export as block device to userspace.
 * This checks that we aren't used elsewhere and change data&size
 * of the block device.
 * This will also refuse if the extent isn't of type SQUASHFS */
static int
set_extent(struct igel_loop_device *lo, unsigned int extent_num)
{
	loff_t size;
	struct igel_partition_info *info = &lo->lo_igel_info;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	struct block_device *bdev = lo->lo_device;
#endif
	int error;

	if (extent_num > info->phdr.n_extents) {
		return -ENOENT;
	}

	/* do not switch if there is no need to switch */
	if (info->use_ext_instead == extent_num)
		return 0;

	if (extent_num) {
		struct igf_partition_extent *extent;
		extent = &info->part_exts.extent[extent_num - 1];
		if (extent->type != EXTENT_TYPE_SQUASHFS) {
			return -EINVAL;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	error = mutex_lock_killable(&igel_loop_ctl_mutex);
#else
	error = mutex_lock_killable(&lo->lo_mutex);
#endif
	if (error)
		return error;

	/* > 1, because we have a reference to it to call this IOCTL */
	if (atomic_read(&lo->lo_refcnt) > 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		mutex_unlock(&igel_loop_ctl_mutex);
#else
		mutex_unlock(&lo->lo_mutex);
#endif
		return -EBUSY;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	if (lo->lo_state != Lo_bound) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		mutex_unlock(&igel_loop_ctl_mutex);
#else
		mutex_unlock(&lo->lo_mutex);
#endif
		return -ENXIO;
	}
#endif

	blk_mq_freeze_queue(lo->lo_queue);
	info->use_ext_instead = extent_num;
	set_igel_offset(lo);
	size = get_igel_size(lo);
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	if (!set_capacity_and_notify(lo->lo_disk, size))
		kobject_uevent(&disk_to_dev(lo->lo_disk)->kobj, KOBJ_CHANGE);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	if (SECTOR_SHIFT != 9) {
		bd_set_nr_sectors(bdev, ((loff_t)size << 9) >> SECTOR_SHIFT);
	} else {
		bd_set_nr_sectors(bdev, size);
	}
#else
	bd_set_size(bdev, (loff_t)size << 9);
#endif /*  LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	/* let user-space know about the new size */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	set_capacity_revalidate_and_notify(lo->lo_disk, size, false);
#else
	if (!set_capacity_revalidate_and_notify(lo->lo_disk, size, false))
		kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
#endif
#else
	set_capacity(lo->lo_disk, (sector_t) size);
	/* let user-space know about the new size */
	kobject_uevent(&disk_to_dev(lo->lo_disk)->kobj, KOBJ_CHANGE);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0) */
#endif  /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) */

	loop_update_dio(lo);
	blk_mq_unfreeze_queue(lo->lo_queue);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	mutex_unlock(&igel_loop_ctl_mutex);
#else
	mutex_unlock(&lo->lo_mutex);
#endif

	return 0;
}

static loff_t get_size(loff_t offset, loff_t sizelimit, struct file *file)
{
	loff_t loopsize;

	/* Compute loopsize in bytes */
	loopsize = i_size_read(file->f_mapping->host);
	if (offset > 0)
		loopsize -= offset;
	/* offset is beyond i_size, weird but possible */
	if (loopsize < 0)
		return 0;

	if (sizelimit > 0 && sizelimit < loopsize)
		loopsize = sizelimit;
	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return loopsize >> 9;
}

static loff_t get_loop_size(struct igel_loop_device *lo, struct file *file)
{
	/* lo_number (aka minor) 0 is the kernel style loop device.
	 * Any other minor is an igel partition, so we have to do some
	 * tricks :/ */
	if (lo->lo_number) {
		return get_igel_size(lo);
	}
	return get_size(lo->lo_offset, lo->lo_sizelimit, file);
}

static void __loop_update_dio(struct igel_loop_device *lo, bool dio)
{
	struct file *file = lo->lo_backing_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned short sb_bsize = 0;
	unsigned dio_align = 0;
	bool use_dio;

	if (inode->i_sb->s_bdev) {
		sb_bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
		dio_align = sb_bsize - 1;
	}

	/*
	 * We support direct I/O only if lo_offset is aligned with the
	 * logical I/O size of backing device, and the logical block
	 * size of loop is bigger than the backing device's and the loop
	 * needn't transform transfer.
	 *
	 * TODO: the above condition may be loosed in the future, and
	 * direct I/O may be switched runtime at that time because most
	 * of requests in sane applications should be PAGE_SIZE aligned
	 */
	/* Never use direct IO on igel special parts (aka minor != 0) */
	if (!lo->lo_number && dio) {
		if (queue_logical_block_size(lo->lo_queue) >= sb_bsize &&
				!(lo->lo_offset & dio_align) &&
				mapping->a_ops->direct_IO &&
				!lo->transfer)
			use_dio = true;
		else
			use_dio = false;
	} else {
		use_dio = false;
	}

	if (lo->use_dio == use_dio)
		return;

	/* flush dirty pages before changing direct IO */
	vfs_fsync(file, 0);

	/*
	 * The flag of LO_FLAGS_DIRECT_IO is handled similarly with
	 * LO_FLAGS_READ_ONLY, both are set from kernel, and losetup
	 * will get updated by ioctl(LOOP_GET_STATUS)
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	if (lo->lo_state == Lo_bound)
#endif
		blk_mq_freeze_queue(lo->lo_queue);
	lo->use_dio = use_dio;
	if (use_dio) {
		blk_queue_flag_clear(QUEUE_FLAG_NOMERGES, lo->lo_queue);
		lo->lo_flags |= LO_FLAGS_DIRECT_IO;
	} else {
		blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->lo_queue);
		lo->lo_flags &= ~LO_FLAGS_DIRECT_IO;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	if (lo->lo_state == Lo_bound)
#endif
		blk_mq_unfreeze_queue(lo->lo_queue);
}

static int
figure_loop_size(struct igel_loop_device *lo, loff_t offset, loff_t sizelimit)
{
	loff_t size = get_loop_size(lo, lo->lo_backing_file);
	sector_t x = (sector_t)size;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	struct block_device *bdev = lo->lo_device;
#endif

	if (unlikely((loff_t)x != size))
		return -EFBIG;
	if (lo->lo_offset != offset)
		lo->lo_offset = offset;
	if (lo->lo_sizelimit != sizelimit)
		lo->lo_sizelimit = sizelimit;

#if  LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	if (!set_capacity_and_notify(lo->lo_disk, size))
		kobject_uevent(&disk_to_dev(lo->lo_disk)->kobj, KOBJ_CHANGE);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	if (SECTOR_SHIFT != 9) {
		bd_set_nr_sectors(bdev, ((loff_t)size << 9) >> SECTOR_SHIFT);
	} else {
		bd_set_nr_sectors(bdev, (loff_t)size);
	}
#else
	bd_set_size(bdev, (loff_t)size << 9);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	/* let user-space know about the new size */
	set_capacity_revalidate_and_notify(lo->lo_disk, size, false);
#else
	set_capacity(lo->lo_disk, x);
	/* let user-space know about the new size */
	kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0) */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) */
	return 0;
}

static inline int
lo_do_transfer(struct igel_loop_device *lo, int cmd,
	       struct page *rpage, unsigned roffs,
	       struct page *lpage, unsigned loffs,
	       int size, sector_t rblock)
{
	int ret;

	ret = lo->transfer(lo, cmd, rpage, roffs, lpage, loffs, size, rblock);
	if (likely(!ret))
		return 0;

	printk_ratelimited(KERN_ERR
		"loop: Transfer error at byte offset %llu, length %i.\n",
		(unsigned long long)rblock << 9, size);
	return ret;
}

static int lo_write_bvec(struct file *file, struct bio_vec *bvec, loff_t *ppos)
{
	struct iov_iter i;
	ssize_t bw;

	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);

	file_start_write(file);
	bw = vfs_iter_write(file, &i, ppos, 0);
	file_end_write(file);

	if (likely(bw ==  bvec->bv_len))
		return 0;

	printk_ratelimited(KERN_ERR
		"loop: Write error at byte offset %llu, length %i.\n",
		(unsigned long long)*ppos, bvec->bv_len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}

static int lo_write_simple(struct igel_loop_device *lo, struct request *rq,
		loff_t pos)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int ret = 0;

	if (lo->lo_number) {
		if (lo->lo_igel_info.is_locked) {
			return -EACCES;
		}
		rq_for_each_segment(bvec, rq, iter) {
			loff_t done = 0;
			struct iov_iter i;
			ssize_t bw = 0;

			iov_iter_bvec(&i, WRITE, &bvec, 1, bvec.bv_len);

			file_start_write(lo->lo_backing_file);

			while (done < bvec.bv_len) {
				size_t curr_sect;
				size_t phys_sect;
				loff_t offset;
				loff_t phys_offset;

				uint64_t total_pos = pos + done;
				size_t data_len = IGF_SECTION_SIZE - lo->lo_hdrlen;
				size_t max_len = bvec.bv_len - done;

				curr_sect = div64_u64_rem(total_pos, data_len, &offset);
				offset += lo->lo_hdrlen;
				phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number, curr_sect);
				phys_offset = START_OF_SECTION(phys_sect) + offset;
				if (max_len > IGF_SECTION_SIZE - offset) {
					max_len = IGF_SECTION_SIZE - offset;
				}

				iov_iter_bvec(&i, WRITE, &bvec, 1, max_len);
				i.iov_offset = done;
				bw = vfs_iter_write(lo->lo_backing_file, &i, &phys_offset, 0);
				if (bw < 0)
					break;
				done += bw;
			}
			if (bw > 0) {
				bw = done;
				pos += bw;
			}

			file_end_write(lo->lo_backing_file);

			if (unlikely(bw !=  bvec.bv_len)) {
				if (bw > 0) {
					ret = -EIO;
				} else {
					ret = bw;
				}
			}

			if (ret < 0)
				break;
			cond_resched();
		}
		return ret;
	}

	rq_for_each_segment(bvec, rq, iter) {
		ret = lo_write_bvec(lo->lo_backing_file, &bvec, &pos);
		if (ret < 0)
			break;
		cond_resched();
	}

	return ret;
}

/*
 * This is the slow, transforming version that needs to double buffer the
 * data as it cannot do the transformations in place without having direct
 * access to the destination pages of the backing file.
 */
static int lo_write_transfer(struct igel_loop_device *lo, struct request *rq,
		loff_t pos)
{
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct page *page;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		ret = lo_do_transfer(lo, WRITE, page, 0, bvec.bv_page,
			bvec.bv_offset, bvec.bv_len, pos >> 9);
		if (unlikely(ret))
			break;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;
		ret = lo_write_bvec(lo->lo_backing_file, &b, &pos);
		if (ret < 0)
			break;
	}

	__free_page(page);
	return ret;
}

int validate_slice(struct igel_loop_device *lo, size_t begin, size_t len);
static int lo_read_simple(struct igel_loop_device *lo, struct request *rq,
		loff_t pos)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct iov_iter i;
	ssize_t len;

	if (lo->lo_number) {
		if (lo->lo_igel_info.is_locked) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);
			return 0;
		}

		rq_for_each_segment(bvec, rq, iter) {
			loff_t done = 0;

			if(validate_slice(lo, pos, bvec.bv_len)) {
				//WARN(1, "failed to validate %d (%lld->%u)",
				//       lo->lo_number, pos, bvec.bv_len);
				if (!lo->lo_igel_info.has_wrong_hash) {
					wake_up_interruptible(&lo->igel_private->validate_wait);
				}
				lo->lo_igel_info.has_wrong_hash = 1;
				return -EIO;
			}

			while (done < bvec.bv_len) {
				size_t curr_sect;
				loff_t offset;
				size_t phys_sect;
				loff_t phys_offset;

				uint64_t total_pos = pos + done;
				size_t data_len = IGF_SECTION_SIZE - lo->lo_hdrlen;
				size_t max_len = bvec.bv_len - done;

				curr_sect = div64_u64_rem(total_pos, data_len, &offset);
				offset += lo->lo_hdrlen;
				phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number, curr_sect);
				phys_offset = START_OF_SECTION(phys_sect) + offset;


				if (max_len > IGF_SECTION_SIZE - offset) {
					max_len = IGF_SECTION_SIZE - offset;
				}

				iov_iter_bvec(&i, READ, &bvec, 1, max_len);
				i.iov_offset = done;
				len = vfs_iter_read(lo->lo_backing_file, &i, &phys_offset, 0);
				if (len < 0)
					return len;
				done += len;
			}
			len = done;
			pos += len;

			flush_dcache_page(bvec.bv_page);

			if (len != bvec.bv_len) {
				struct bio *bio;

				__rq_for_each_bio(bio, rq)
					zero_fill_bio(bio);
				break;
			}
			cond_resched();
		}

		return 0;
	}

	rq_for_each_segment(bvec, rq, iter) {
		iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(lo->lo_backing_file, &i, &pos, 0);
		if (len < 0)
			return len;

		flush_dcache_page(bvec.bv_page);

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);
			break;
		}
		cond_resched();
	}

	return 0;
}

static int lo_read_transfer(struct igel_loop_device *lo, struct request *rq,
		loff_t pos)
{
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct iov_iter i;
	struct page *page;
	ssize_t len;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		loff_t offset = pos;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;

		iov_iter_bvec(&i, READ, &b, 1, b.bv_len);
		len = vfs_iter_read(lo->lo_backing_file, &i, &pos, 0);
		if (len < 0) {
			ret = len;
			goto out_free_page;
		}

		ret = lo_do_transfer(lo, READ, page, 0, bvec.bv_page,
			bvec.bv_offset, len, offset >> 9);
		if (ret)
			goto out_free_page;

		flush_dcache_page(bvec.bv_page);

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);
			break;
		}
	}

	ret = 0;
out_free_page:
	__free_page(page);
	return ret;
}

static int lo_discard(struct igel_loop_device *lo, struct request *rq,
		loff_t pos)
{
	/*
	 * We use punch hole to reclaim the free space used by the
	 * image a.k.a. discard. However we do not support discard if
	 * encryption is enabled, because it may give an attacker
	 * useful information.
	 */
	struct file *file = lo->lo_backing_file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	if (!file->f_op->fallocate) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;
 out:
	return ret;
}

static int lo_req_flush(struct igel_loop_device *lo, struct request *rq)
{
	struct file *file = lo->lo_backing_file;
	int ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL))
		ret = -EIO;

	return ret;
}

static void lo_complete_rq(struct request *rq)
{
	struct igel_loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	blk_status_t ret = BLK_STS_OK;

	if (!cmd->use_aio || cmd->ret < 0 || cmd->ret == blk_rq_bytes(rq) ||
	    req_op(rq) != REQ_OP_READ) {
		if (cmd->ret < 0)
			ret = BLK_STS_IOERR;
		goto end_io;
	}

	/*
	 * Short READ - if we got some data, advance our request and
	 * retry it. If we got no data, end the rest with EIO.
	 */
	if (cmd->ret) {
		blk_update_request(rq, BLK_STS_OK, cmd->ret);
		cmd->ret = 0;
		blk_mq_requeue_request(rq, true);
	} else {
		if (cmd->use_aio) {
			struct bio *bio = rq->bio;

			while (bio) {
				zero_fill_bio(bio);
				bio = bio->bi_next;
			}
		}
		ret = BLK_STS_IOERR;
end_io:
		blk_mq_end_request(rq, ret);
	}
}

static void lo_rw_aio_do_completion(struct igel_loop_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);

	if (!atomic_dec_and_test(&cmd->ref))
		return;
	kfree(cmd->bvec);
	cmd->bvec = NULL;
	blk_mq_complete_request(rq);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)
static void lo_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
#else
static void lo_rw_aio_complete(struct kiocb *iocb, long ret)
#endif
{
	struct igel_loop_cmd *cmd = container_of(iocb, struct igel_loop_cmd, iocb);

	if (cmd->css)
		css_put(cmd->css);
	cmd->ret = ret;
	lo_rw_aio_do_completion(cmd);
}

static int lo_rw_aio(struct igel_loop_device *lo, struct igel_loop_cmd *cmd,
		     loff_t pos, bool rw)
{
	struct iov_iter iter;
	struct bio_vec *bvec;
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	struct bio *bio = rq->bio;
	struct file *file = lo->lo_backing_file;
	unsigned int offset;
	int segments = 0;
	int ret;

	if (rq->bio != rq->biotail) {
		struct req_iterator iter;
		struct bio_vec tmp;

		__rq_for_each_bio(bio, rq)
			segments += bio_segments(bio);
		bvec = kmalloc_array(segments, sizeof(struct bio_vec),
				     GFP_NOIO);
		if (!bvec)
			return -EIO;
		cmd->bvec = bvec;

		/*
		 * The bios of the request may be started from the middle of
		 * the 'bvec' because of bio splitting, so we can't directly
		 * copy bio->bi_iov_vec to new bvec. The rq_for_each_segment
		 * API will take care of all details for us.
		 */
		rq_for_each_segment(tmp, rq, iter) {
			*bvec = tmp;
			bvec++;
		}
		bvec = cmd->bvec;
		offset = 0;
	} else {
		/*
		 * Same here, this bio may be started from the middle of the
		 * 'bvec' because of bio splitting, so offset from the bvec
		 * must be passed to iov iterator
		 */
		offset = bio->bi_iter.bi_bvec_done;
		bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
		segments = bio_segments(bio);
	}
	atomic_set(&cmd->ref, 2);

	iov_iter_bvec(&iter, rw, bvec,
		      segments, blk_rq_bytes(rq));
	iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
	cmd->iocb.ki_complete = lo_rw_aio_complete;
	cmd->iocb.ki_flags = IOCB_DIRECT;
	cmd->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
	if (cmd->css)
		kthread_associate_blkcg(cmd->css);

	if (rw == WRITE)
		ret = call_write_iter(file, &cmd->iocb, &iter);
	else
		ret = call_read_iter(file, &cmd->iocb, &iter);

	lo_rw_aio_do_completion(cmd);
	kthread_associate_blkcg(NULL);

	if (ret != -EIOCBQUEUED)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)
		cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
#else
		cmd->iocb.ki_complete(&cmd->iocb, ret);
#endif

	return 0;
}

static int do_req_filebacked(struct igel_loop_device *lo, struct request *rq)
{
	struct igel_loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = ((loff_t) blk_rq_pos(rq) << 9) + lo->lo_offset;

	/*
	 * lo_write_simple and lo_read_simple should have been covered
	 * by io submit style function like lo_rw_aio(), one blocker
	 * is that lo_read_simple() need to call flush_dcache_page after
	 * the page is written from kernel, and it isn't easy to handle
	 * this in io submit style function which submits all segments
	 * of the req at one time. And direct read IO doesn't need to
	 * run flush_dcache_page().
	 */
	switch (req_op(rq)) {
	case REQ_OP_FLUSH:
		return lo_req_flush(lo, rq);
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		return lo_discard(lo, rq, pos);
	case REQ_OP_WRITE:
		if (lo->transfer)
			return lo_write_transfer(lo, rq, pos);
		else if (cmd->use_aio)
			return lo_rw_aio(lo, cmd, pos, WRITE);
		else
			return lo_write_simple(lo, rq, pos);
	case REQ_OP_READ:
		if (lo->transfer)
			return lo_read_transfer(lo, rq, pos);
		else if (cmd->use_aio)
			return lo_rw_aio(lo, cmd, pos, READ);
		else
			return lo_read_simple(lo, rq, pos);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
		break;
	}
}

static inline void loop_update_dio(struct igel_loop_device *lo)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	__loop_update_dio(lo, (lo->lo_backing_file->f_flags & O_DIRECT) |
#else
	__loop_update_dio(lo, io_is_direct(lo->lo_backing_file) |
#endif
				lo->use_dio);
}

static struct file *loop_real_file(struct file *file)
{
	struct file *f = NULL;

//	if (file->f_path.dentry->d_sb->s_op->real_loop)
//		f = file->f_path.dentry->d_sb->s_op->real_loop(file);
	return f;
}

static void loop_reread_partitions(struct igel_loop_device *lo,
				   struct block_device *bdev)
{
	int rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
	mutex_lock(&lo->lo_disk->open_mutex);
	rc = bdev_disk_changed(lo->lo_disk, false);
	mutex_unlock(&lo->lo_disk->open_mutex);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	mutex_lock(&bdev->bd_mutex);
	rc = bdev_disk_changed(bdev, false);
	mutex_unlock(&bdev->bd_mutex);
#else
	rc = blkdev_reread_part(bdev);
#endif
	if (rc)
		pr_warn("%s: partition scan of loop%d (%s) failed (rc=%d)\n",
			__func__, lo->lo_number, lo->lo_file_name, rc);
}

static inline int is_loop_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	return i && S_ISBLK(i->i_mode) && MAJOR(i->i_rdev) == LOOP_MAJOR;
#else
	return i && S_ISBLK(i->i_mode) && imajor(i) == LOOP_MAJOR;
#endif
}

static int loop_validate_file(struct file *file, struct block_device *bdev)
{
	struct inode	*inode = file->f_mapping->host;
	struct file	*f = file;

	/* Avoid recursion */
	while (is_loop_device(f)) {
		struct igel_loop_device *l;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		if (f->f_mapping->host->i_rdev == bdev->bd_dev)
			return -EBADF;

		l = I_BDEV(f->f_mapping->host)->bd_disk->private_data;
#else
		if (f->f_mapping->host->i_bdev == bdev)
			return -EBADF;

		l = f->f_mapping->host->i_bdev->bd_disk->private_data;
#endif
		if (l->lo_state == Lo_unbound) {
			return -EINVAL;
		}
		f = l->lo_backing_file;
	}
	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -EINVAL;
	return 0;
}

/*
 * loop_change_fd switched the backing store of a loopback device to
 * a new file. This is useful for operating system installers to free up
 * the original file and in High Availability environments to switch to
 * an alternative location for the content in case of server meltdown.
 * This can only work if the loop device is used read-only, and if the
 * new backing store is the same size and type as the old backing store.
 */
static int loop_change_fd(struct igel_loop_device *lo, struct block_device *bdev,
			  unsigned int arg)
{
	struct file	*file = NULL, *old_file;
	struct file	*f, *virt_file = NULL, *old_virt_file;
	int		error;
	bool		partscan;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	error = mutex_lock_killable(&igel_loop_ctl_mutex);
#else
	error = mutex_lock_killable(&lo->lo_mutex);
#endif
	if (error)
		return error;
	error = -ENXIO;
	if (lo->lo_state != Lo_bound)
		goto out_err;

	/* the loop device has to be read-only */
	error = -EINVAL;
	if (!(lo->lo_flags & LO_FLAGS_READ_ONLY))
		goto out_err;

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out_err;
	f = loop_real_file(file);
	if (f) {
		virt_file = file;
		file = f;
		get_file(file);
	}

	error = loop_validate_file(file, bdev);
	if (error)
		goto out_err;

	old_file = lo->lo_backing_file;
	old_virt_file = lo->lo_backing_virt_file;

	error = -EINVAL;

	/* size of the new backing store needs to be the same */
	if (get_loop_size(lo, file) != get_loop_size(lo, old_file))
		goto out_err;

	/* and ... switch */
	blk_mq_freeze_queue(lo->lo_queue);
	mapping_set_gfp_mask(old_file->f_mapping, lo->old_gfp_mask);
	lo->lo_backing_file = file;
	lo->lo_backing_virt_file = virt_file;
	lo->old_gfp_mask = mapping_gfp_mask(file->f_mapping);
	mapping_set_gfp_mask(file->f_mapping,
			     lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));
	loop_update_dio(lo);
	blk_mq_unfreeze_queue(lo->lo_queue);
	partscan = lo->lo_flags & LO_FLAGS_PARTSCAN;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	mutex_unlock(&igel_loop_ctl_mutex);
#else
	mutex_unlock(&lo->lo_mutex);
#endif

	/*
	 * We must drop file reference outside of loop_ctl_mutex as dropping
	 * the file ref can take bd_mutex which creates circular locking
	 * dependency.
	 */
	fput(old_file);
	if (old_virt_file)
		fput(old_virt_file);
	if (partscan)
		loop_reread_partitions(lo, bdev);
	return 0;

out_err:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	mutex_unlock(&igel_loop_ctl_mutex);
#else
	mutex_unlock(&lo->lo_mutex);
#endif
	if (file)
		fput(file);
	if (virt_file)
		fput(virt_file);
	return error;
}

// /*
//  * for AUFS
//  * no get/put for file.
//  */
// struct file *loop_backing_file(struct super_block *sb)
// {
// 	struct file *ret;
// 	struct loop_device *l;
//
// 	ret = NULL;
// 	if (MAJOR(sb->s_dev) == LOOP_MAJOR) {
// 		l = sb->s_bdev->bd_disk->private_data;
// 		ret = l->lo_backing_file;
// 	}
// 	return ret;
// }
// EXPORT_SYMBOL_GPL(loop_backing_file);

/* loop sysfs attributes */
static ssize_t loop_attr_signature_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%u\n", lo->cmty_pkid);
}
					  
static ssize_t loop_attr_mountorder_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%d\n", lo->mount_order);
}

static ssize_t loop_attr_show_extent(struct device *dev, int ext, char *page,
	      ssize_t (*callback)(struct igel_loop_device *, int ext, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct igel_loop_device *lo = disk->private_data;

	return callback(lo, ext, page);
}

static ssize_t loop_attr_show(struct device *dev, char *page,
	      ssize_t (*callback)(struct igel_loop_device *, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct igel_loop_device *lo = disk->private_data;

	return callback(lo, page);
}

static ssize_t loop_attr_store(struct device *dev, const char *page, size_t c,
	      ssize_t (*callback)(struct igel_loop_device *, const char *, size_t))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct igel_loop_device *lo = disk->private_data;

	return callback(lo, page, c);
}

#define LOOP_ATTR_RO(_name)						\
static ssize_t loop_attr_##_name##_show(struct igel_loop_device *,	\
		char *);						\
static ssize_t loop_attr_do_show_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return loop_attr_show(d, b, loop_attr_##_name##_show);		\
}									\
static struct device_attribute loop_attr_##_name =			\
	__ATTR(_name, 0444, loop_attr_do_show_##_name, NULL);

static ssize_t loop_attr_backing_file_show(struct igel_loop_device *lo,
		char *buf)
{
	ssize_t ret;
	char *p = NULL;

	spin_lock_irq(&lo->lo_lock);
	if (lo->lo_backing_file)
		p = file_path(lo->lo_backing_file, buf, PAGE_SIZE - 1);
	spin_unlock_irq(&lo->lo_lock);

	if (IS_ERR_OR_NULL(p))
		ret = PTR_ERR(p);
	else {
		ret = strlen(p);
		memmove(buf, p, ret);
		buf[ret++] = '\n';
		buf[ret] = 0;
	}

	return ret;
}

static ssize_t loop_attr_offset_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%llu\n", (unsigned long long)lo->lo_offset);
}

static ssize_t loop_attr_sizelimit_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%llu\n", (unsigned long long)lo->lo_sizelimit);
}

static int loop_clr_fd(struct igel_loop_device *lo, bool lock);
static ssize_t loop_attr_autoclear_show(struct igel_loop_device *lo, char *buf)
{
	int autoclear = (lo->lo_flags & LO_FLAGS_AUTOCLEAR);

	return sprintf(buf, "%s\n", autoclear ? "1" : "0");
}

static ssize_t loop_attr_partscan_show(struct igel_loop_device *lo, char *buf)
{
	int partscan = (lo->lo_flags & LO_FLAGS_PARTSCAN);

	return sprintf(buf, "%s\n", partscan ? "1" : "0");
}

static ssize_t loop_attr_dio_show(struct igel_loop_device *lo, char *buf)
{
	int dio = (lo->lo_flags & LO_FLAGS_DIRECT_IO);

	return sprintf(buf, "%s\n", dio ? "1" : "0");
}

#define IGEL_PHDR_ATTR(_name, _format) \
	static ssize_t loop_attr_##_name##_show(struct igel_loop_device *lo,\
	                                        char *buf)		    \
{ 									    \
	return sprintf(buf, _format "\n", lo->lo_igel_info.phdr._name);     \
}									    \
LOOP_ATTR_RO(_name);

static ssize_t loop_attr_num_extents_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%d\n", lo->lo_igel_info.phdr.n_extents);
}

static ssize_t loop_attr_flashsize_show(struct igel_loop_device *lo, char *buf);
static ssize_t loop_attr_size_show(struct igel_loop_device *lo, char *buf)
{
	if (lo->lo_number) {
		return sprintf(buf, "%llu\n", lo->lo_igel_info.phdr.n_blocks);
	}
	return loop_attr_flashsize_show(lo, buf);
}

static ssize_t loop_attr_hash_show(struct igel_loop_device *lo, char *buf)
{
	static const int hash_size = 64;
	size_t i;
	uint8_t *hash = lo->lo_igel_info.phdr.update_hash;
	for (i = 0; i < hash_size; ++i) {
		sprintf(buf + i * 2, "%02x", hash[i]);
	}
	buf[hash_size*2] = '\n';
	buf[hash_size*2 + 1] = '\0';

	return hash_size*2 + 2;
}

static ssize_t loop_attr_magic_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%u\n", lo->lo_igel_info.magic);
}

static ssize_t loop_attr_generation_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%u\n", lo->lo_igel_info.generation_number);
}

static ssize_t loop_attr_sectionsize_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%llu\n", 256llu * 1024llu);
}

static ssize_t loop_attr_flashsize_show(struct igel_loop_device *lo, char *buf)
{
	unsigned long long size = 0;
	struct directory *dir = &lo->igel_private->dir;
	if (lo->lo_number == 0) {
		size_t i;
		for (i = 0; i < dir->n_fragments; ++i) {
			struct fragment_descriptor *desc = &dir->fragment[i];
			if (desc->first_section + desc->length > size) {
				size = (desc->first_section + desc->length);
			}
		}
	} else {
		size = lo->lo_igel_info.num_sections;
	}
	return sprintf(buf, "%llu\n", size * IGF_SECTION_SIZE);
}

static ssize_t loop_attr_locked_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%s\n", lo->lo_igel_info.is_locked ? "1" : "0");
}

static ssize_t loop_attr_signed_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%s\n", lo->lo_igel_info.has_hash_info ? "1" : "0");
}

static ssize_t loop_attr_data_extent_in_use_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%u\n", lo->lo_igel_info.use_ext_instead);
}

static ssize_t loop_attr_data_extent_possible_show(struct igel_loop_device *lo, char *buf)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	ssize_t i;

	*buf = '\0';
	for (i = 0; i < info->phdr.n_extents; ++i) {
		char buffer[12];
		struct igf_partition_extent *extent =
			extent = &info->part_exts.extent[i];
		if (extent->type == EXTENT_TYPE_SQUASHFS) {
			snprintf(buffer, sizeof(buffer), "%zu ", i + 1);
			strcat(buf, buffer);
		}
	}

	strcat(buf, "\n");
	return strlen(buf) + 1;
}

static ssize_t loop_attr_extent_type_show(struct igel_loop_device *lo,
		int ext_num, char *buf)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	if (ext_num > info->part_exts.n_extents) {
		return sprintf(buf, "\n");
	}

	return sprintf(buf, "%s\n", get_extent_type_name(
				info->part_exts.extent[ext_num - 1].type));
}

static ssize_t loop_attr_extent_name_show(struct igel_loop_device *lo,
		int ext_num, char *buf)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	if (ext_num > info->part_exts.n_extents) {
		return sprintf(buf, "\n");
	}

	return sprintf(buf, "%s\n", info->part_exts.extent[ext_num - 1].name);
}

static ssize_t loop_attr_extent_size_show(struct igel_loop_device *lo,
		int ext_num, char *buf)
{
	struct igel_partition_info *info = &lo->lo_igel_info;
	if (ext_num > info->part_exts.n_extents) {
		return sprintf(buf, "-1\n");
	}

	return sprintf(buf, "%llu\n", info->part_exts.extent[ext_num - 1].length);
}

#define LOOP_EXTENT_ATTR_RO(_name, _num)						\
static ssize_t loop_attr_extent_##_name##_show(struct igel_loop_device *, int, char *);	\
static ssize_t loop_attr_do_show_extent_##_name##_##_num(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return loop_attr_show_extent(d, _num, b, loop_attr_extent_##_name##_show);		\
}									\
static struct device_attribute loop_attr_extent_##_name##_##_num =			\
	__ATTR(extent##_num##_##_name, S_IRUGO, loop_attr_do_show_extent_##_name##_##_num, NULL);

#define LOOP_EXTENT_ATTR_VAR(_name, _num) loop_attr_extent_##_name##_##_num.attr
#define LOOP_EXTENT_ATTR_SET(_num) \
	LOOP_EXTENT_ATTR_RO(type, _num); \
	LOOP_EXTENT_ATTR_RO(name, _num); \
	LOOP_EXTENT_ATTR_RO(size, _num);

#define LOOP_EXTENT_SET_ATTRS(_num, _array, _index)		\
	case (_num - 1):					\
	_array [_index++] = &LOOP_EXTENT_ATTR_VAR(type, _num);	\
	_array [_index++] = &LOOP_EXTENT_ATTR_VAR(name, _num);	\
	_array [_index++] = &LOOP_EXTENT_ATTR_VAR(size, _num);	\
	break


LOOP_ATTR_RO(backing_file);
LOOP_ATTR_RO(offset);
LOOP_ATTR_RO(sizelimit);
LOOP_ATTR_RO(autoclear);
LOOP_ATTR_RO(partscan);
LOOP_ATTR_RO(dio);

LOOP_ATTR_RO(num_extents);
LOOP_ATTR_RO(size);
LOOP_ATTR_RO(hash);
LOOP_ATTR_RO(signature);
LOOP_ATTR_RO(mountorder);
LOOP_ATTR_RO(magic);
LOOP_ATTR_RO(generation);

IGEL_PHDR_ATTR(type, "%d");
IGEL_PHDR_ATTR(name, "%s");
IGEL_PHDR_ATTR(partlen, "%llu");

LOOP_ATTR_RO(flashsize);
LOOP_ATTR_RO(sectionsize);

LOOP_ATTR_RO(data_extent_in_use);
LOOP_ATTR_RO(data_extent_possible);
LOOP_ATTR_RO(locked);
LOOP_ATTR_RO(signed);

LOOP_EXTENT_ATTR_SET(1);
LOOP_EXTENT_ATTR_SET(2);
LOOP_EXTENT_ATTR_SET(3);
LOOP_EXTENT_ATTR_SET(4);
LOOP_EXTENT_ATTR_SET(5);
LOOP_EXTENT_ATTR_SET(6);
LOOP_EXTENT_ATTR_SET(7);
LOOP_EXTENT_ATTR_SET(8);
LOOP_EXTENT_ATTR_SET(9);
LOOP_EXTENT_ATTR_SET(10);

static struct attribute *loop_minor_attrs[] = {
	&loop_attr_num_extents.attr,
	&loop_attr_type.attr,
	&loop_attr_magic.attr,
	&loop_attr_generation.attr,
	&loop_attr_name.attr,
	&loop_attr_partlen.attr,
	&loop_attr_hash.attr,
	&loop_attr_signature.attr,
	&loop_attr_mountorder.attr,

	&loop_attr_locked.attr,
	&loop_attr_signed.attr,
	NULL,
};

static struct attribute *loop_attrs[] = {
	&loop_attr_backing_file.attr,
	&loop_attr_offset.attr,
	&loop_attr_sizelimit.attr,
	&loop_attr_autoclear.attr,
	&loop_attr_partscan.attr,
	&loop_attr_dio.attr,

	&loop_attr_size.attr,
	&loop_attr_sectionsize.attr,
	&loop_attr_flashsize.attr,

	NULL,
};

static struct attribute *loop_extent_attrs[MAX_EXTENT_NUM * 3 + 10] = {0};
struct attribute_group loop_extent_attribute_group = {
	.name = "igel",
	.attrs= loop_extent_attrs,
};

static struct attribute_group loop_attribute_group = {
	.name = "igel",
	.attrs= loop_attrs,
};

static struct attribute_group loop_minor_attribute_group = {
	.name = "igel",
	.attrs= loop_minor_attrs,
};

static uint32_t loop_login_calc_crc(void) {
	uint8_t *crc_tmp;
	uint32_t crc;
	void *info_size = &login_info_cache->size;

	crc_tmp = kmalloc((sizeof(struct igel_login_info) - sizeof(uint32_t)) + (sizeof(struct igel_login_info_element) * MAX_LOGIN_EXTENT_SIZE), GFP_KERNEL);
	memcpy(crc_tmp, info_size, sizeof(struct igel_login_info) - sizeof(uint32_t));
	memcpy(crc_tmp + (sizeof(struct igel_login_info) - sizeof(uint32_t)), login_info_element_cache, sizeof(struct igel_login_info_element) * MAX_LOGIN_EXTENT_SIZE);
	crc = crc32(0xffffffffL,
	            crc_tmp,
	            (sizeof(struct igel_login_info) - sizeof(uint32_t)) +
				(sizeof(struct igel_login_info_element) * MAX_LOGIN_EXTENT_SIZE)) ^ 0xffffffffL;
	kfree(crc_tmp);
	return crc;
}

static int loop_find_login_extent (struct igel_loop_device *lo)
{
	int i;

	for (i = 0; i < lo->lo_igel_info.part_exts.n_extents; ++i) {
			struct igf_partition_extent *extent =
				&lo->lo_igel_info.part_exts.extent[i];
			if (extent->type == EXTENT_TYPE_LOGIN) {
					return i;
			}
	}

	return -1;
}

static loff_t loop_calc_login_extent_offset (struct igel_loop_device *lo) {
	size_t phys_sect;
	loff_t phys_offset;
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1) {
		pr_err("Login extent not present\n");
		return -1;
	}

	phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number,
								lo->lo_igel_info.part_exts.extent[login_extent].offset / IGF_SECT_DATA_LEN);
	phys_offset = START_OF_SECTION(phys_sect);
#ifdef IGF_LOGIN_DEBUG
	pr_info("Partition number %d", lo->lo_number);
	pr_info("Login extent offset: %llu", phys_offset + lo->lo_igel_info.part_exts.extent[login_extent].offset % IGF_SECT_DATA_LEN + IGF_SECT_HDR_LEN);
#endif
	return phys_offset + lo->lo_igel_info.part_exts.extent[login_extent].offset % IGF_SECT_DATA_LEN + IGF_SECT_HDR_LEN;
}

static int loop_read_login_info (struct igel_loop_device *lo,
		const struct igel_login_info *info)
{
	int ret;
	loff_t k_read_position = loop_calc_login_extent_offset(lo);

	if (k_read_position == -1) {
		pr_err("Login extent not present\n");
		return -1;
	}

	ret = kernel_read(lo->igel_private->file, (void __user *)info , sizeof(struct igel_login_info), &k_read_position);
#ifdef IGF_LOGIN_DEBUG
	pr_info ("Read login info: %d\n", ret);
#endif

	if (ret != sizeof(struct igel_login_info)) {
		pr_err ("Read login info failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static int loop_read_login_info_element (struct igel_loop_device *lo,
		const struct igel_login_info_element *element, int position)
{
	int ret;
	loff_t k_read_position = loop_calc_login_extent_offset(lo);

	if (k_read_position == -1) {
		pr_err("Login extent not present\n");
		return -1;
	}

	k_read_position = k_read_position + sizeof(struct igel_login_info) + (position-1) * sizeof(struct igel_login_info_element);

#ifdef IGF_LOGIN_DEBUG
	pr_info ("Read login info element at position %d\n", position);
#endif

	ret = kernel_read(lo->igel_private->file, (void __user *)element, sizeof(struct igel_login_info_element),
				&k_read_position);

#ifdef IGF_LOGIN_DEBUG
	pr_info ("Read login element kernel_read: %d\n", ret);
#endif

	if (ret != sizeof(struct igel_login_info_element)) {
		pr_err ("Read login element failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static size_t loop_login_cache_create(struct igel_loop_device *lo, int size)
{
	login_info_health = kzalloc(sizeof(uint8_t), GFP_KERNEL);
	if (login_info_health == NULL) {
		pr_err("Memory allocation for login ache failed\n");
		return -ENOMEM;
	}
	*login_info_health = 1;
	login_info_cache = kzalloc(sizeof(struct igel_login_info), GFP_KERNEL);
	if (login_info_cache == NULL) {
		pr_err("Memory allocation for login ache failed\n");
		return -ENOMEM;
	}
	login_info_element_cache = kcalloc(MAX_LOGIN_EXTENT_SIZE, sizeof(struct igel_login_info_element), GFP_KERNEL);
	if (login_info_element_cache == NULL) {
		pr_err("Memory allocation for login element cache failed\n");
		return -ENOMEM;
	}
	return 0;
}

static ssize_t loop_login_extent_create(struct igel_loop_device *lo, int size)
{
	size_t ret;
	int i;
	loff_t k_write_position;

	if (login_info_cache != NULL) {
		login_info_cache->size = size;
	login_info_cache->position = 0;
		login_info_cache->initialized = 1;
	login_info_cache->last_login_count = 0;
	login_info_cache->last_login_timestamp = 0;
#ifdef IGF_LOGIN_DEBUG
		pr_info("Login info header size set to %u", login_info_cache->size);
		pr_info("Initialized login info header");
#endif
	} else {
		pr_err("Login info cache not present, exiting\n");
		return -ENOMEM;
	}

	for (i = 0; i < size; i++) {
		if (login_info_element_cache != NULL) {
			login_info_element_cache[i].timestamp = 0;
			login_info_element_cache[i].count = 0;
			login_info_element_cache[i].success = 0;
			login_info_element_cache[i].padding[0] = 0;
			login_info_element_cache[i].padding[1] = 0;
			login_info_element_cache[i].padding[2] = 0;
			k_write_position = loop_calc_login_extent_offset(lo);
			if (k_write_position == -1) {
				pr_err("Write login array element %d failed\n", i);
				return -ENOMEM;
			}
			k_write_position = k_write_position + sizeof(struct igel_login_info);
			k_write_position = k_write_position + (i * sizeof(struct igel_login_info_element));
			ret = kernel_write(lo->igel_private->file, (void __user *)&login_info_element_cache[i],
											sizeof(struct igel_login_info_element),
											&k_write_position);
			if (ret != sizeof(struct igel_login_info_element)) {
				pr_err("Write login array element %d failed\n", i);
				return -ENOMEM;
			}
#ifdef IGF_LOGIN_DEBUG
			pr_info("Initialized login info element %d",i+1);
#endif
		} else {
				pr_err("Login array element cache not presentn");
				return -ENOMEM;
		}
	}

	login_info_cache->crc = loop_login_calc_crc();
	k_write_position = loop_calc_login_extent_offset(lo);

	if (k_write_position == -1) {
			pr_err("Write login array header failed\n");
			return -ENOMEM;
	}

	ret = kernel_write(lo->igel_private->file, (void __user *)login_info_cache,
							   sizeof(struct igel_login_info),
							   &k_write_position);

	if (ret != sizeof(struct igel_login_info)) {
		pr_err("Write login array header %d failed\n",  login_info_cache->size);
		return -ENOMEM;
	}

	return 0;
}

static ssize_t loop_attr_login_extent_initialized_store(struct igel_loop_device *lo, const char *buf, size_t count)
{
	int magic;
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1) {
		pr_err("Login extent not present\n");
		return -1;
	}

	sscanf (buf, "%d", &magic);
	if (magic == 12345) {
		if (loop_login_extent_create(lo, MAX_LOGIN_EXTENT_SIZE) == 0)
			pr_info("Login array reinitialized");
	}
	return count;
}

static ssize_t loop_attr_login_extent_initialized_show(struct igel_loop_device *lo, char *buf)
{
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1) {
		pr_err("Login extent not present\n");
		return -1;
	}

	switch (login_info_cache->initialized) {
		case 1: return sprintf(buf, "%u\n", 1);
		case 2: return sprintf(buf, "%u\n", 2);
	}

	return sprintf(buf, "%u\n", 0);
}

static ssize_t loop_attr_login_extent_array_size_show(struct igel_loop_device *lo, char *buf)
{
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present");
		return -1;
	}

#ifdef IGF_LOGIN_DEBUG
	pr_info ("Returning login array size %u", login_info_cache->size);
#endif

	return sprintf(buf, "%u\n", login_info_cache->size);
}

static ssize_t loop_attr_login_extent_last_login_count_show(struct igel_loop_device *lo, char *buf)
{
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present");
		return -1;
	}

#ifdef IGF_LOGIN_DEBUG
	pr_info("Returning login array last_login_count %u", login_info_cache->last_login_count);
#endif

	return sprintf(buf, "%u\n", login_info_cache->last_login_count);
}

static ssize_t loop_attr_login_extent_last_login_timestamp_show(struct igel_loop_device *lo, char *buf)
{
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present");
		return -1;
	}

#ifdef IGF_LOGIN_DEBUG
	pr_info ("Returning login array last_login_timestamp %llu", login_info_cache->last_login_timestamp);
#endif

	return sprintf(buf, "%llu\n", login_info_cache->last_login_timestamp);
}

static ssize_t loop_attr_login_extent_health_show(struct igel_loop_device *lo, char *buf)
{
	return sprintf(buf, "%hhu\n", *login_info_health);
}

static ssize_t loop_attr_login_extent_success_show(struct igel_loop_device *lo, char *buf)
{
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present");
		return -1;
	}

	if (login_info_cache->position <= 0 || login_info_cache->size < login_info_cache->position) {
		return sprintf(buf, "0\n");
	}

	return sprintf(buf, "%hhu\n", login_info_element_cache[login_info_cache->position-1].success);
}

static ssize_t loop_attr_login_extent_success_store(struct igel_loop_device *lo, const char *buf, size_t count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	struct timespec64 timestamp_time;
#else
	struct timespec timestamp_time;
#endif
	int ret = 0;
	uint32_t write_position = 0;
	loff_t k_write_position = 0;
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present\n");
		return -1;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	ktime_get_real_ts64(&timestamp_time);
#else
	getnstimeofday(&timestamp_time);
#endif

	if (login_info_cache != NULL) {
#ifdef IGF_LOGIN_DEBUG
		pr_info("Success store, login_info_cache->size %u", login_info_cache->size);
		pr_info("Success store, login_info_cache->position %u", login_info_cache->position);
#endif
		if (login_info_cache->size > 0) {
			if (login_info_cache->position == 0) {
#ifdef IGF_LOGIN_DEBUG
				pr_info("Position is zero, initializing\n");
#endif
				login_info_cache->initialized = 2;
				login_info_element_cache[0].count = 1;
				write_position = 0;
			} else if (login_info_cache->position == login_info_cache->size) {
#ifdef IGF_LOGIN_DEBUG
				pr_info("Position %d = size, writing to position 1", login_info_cache->position);
#endif
				login_info_element_cache[0].count  = login_info_element_cache[login_info_cache->size-1].count + 1;
				write_position = 0;
			} else if (login_info_cache->position < login_info_cache->size) {
				login_info_element_cache[login_info_cache->position].count  = login_info_element_cache[login_info_cache->position-1].count + 1;
				write_position = login_info_cache->position;
#ifdef IGF_LOGIN_DEBUG
				pr_info("Position %d, normal operation, writing to %d", login_info_cache->position, write_position);
#endif
			}
			sscanf(buf, "%hhu", &login_info_element_cache[login_info_cache->position].success);
			login_info_element_cache[login_info_cache->position].timestamp = timestamp_time.tv_sec;
			if (login_info_element_cache[login_info_cache->position].success) {
#ifdef IGF_LOGIN_DEBUG
				pr_info("Success = true, resetting last_login_count");
				pr_info("Success = true, last_login_timestamp: %llu", login_info_cache->last_login_timestamp);
#endif
				login_info_cache->last_login_count = 0;
				login_info_cache->last_login_timestamp = timestamp_time.tv_sec;
			} else {
				login_info_cache->last_login_count++;
#ifdef IGF_LOGIN_DEBUG
				pr_info("Success = false, last_login_count = %d", login_info_cache->last_login_count);
				pr_info("Success = false, last_login_timestamp: %llu", login_info_cache->last_login_timestamp);
#endif
			}
			login_info_cache->position++;
			if (write_position == 0)
				login_info_cache->position = 1;

			k_write_position =  loop_calc_login_extent_offset(lo);
			if (k_write_position == -1) {
				pr_err("Write login array element failed\n");
				return -1;
			}
			k_write_position =  k_write_position + sizeof(struct igel_login_info) + (write_position * sizeof(struct igel_login_info_element));
			ret = kernel_write(lo->igel_private->file, (void __user *)&login_info_element_cache[write_position],
								  sizeof(struct igel_login_info_element),
								  &k_write_position);

			if (ret != sizeof(struct igel_login_info_element)) {
				pr_err("Write login array element %d failed",  login_info_cache->position);
				return -1;
			}

			k_write_position = loop_calc_login_extent_offset(lo);
			if (k_write_position == -1) {
				pr_err("Write login array header failed\n");
				return -1;
			}
			login_info_cache->crc = loop_login_calc_crc();
			ret = kernel_write(lo->igel_private->file, (void __user *)login_info_cache,
								  sizeof(struct igel_login_info),
								  &k_write_position);

			if (ret != sizeof(struct igel_login_info )) {
				pr_err("Write login array header failed");
				return -1;
			}
		}
	}
	return count;
}

static ssize_t loop_attr_login_extent_elements_show(struct igel_loop_device *lo, char *buf)
{
	int e = 0;
	struct igel_login_output *output_buf = NULL;
	int login_extent = loop_find_login_extent(lo);

	if (login_extent == -1 || !login_info_cache || !login_info_cache->initialized) {
		pr_err("Login extent not present");
		return -1;
	}

	if ((sizeof(struct igel_login_output) * MAX_LOGIN_EXTENT_SIZE) > PAGE_SIZE) {
		printk("loop_attr_login_extent_elements_show: error output exceeds allowed size.\n");
		return -1;
	}

	memset(buf, 0, PAGE_SIZE);
	output_buf = (struct igel_login_output *)buf;

	for (e = 0; e < MAX_LOGIN_EXTENT_SIZE; e++) {
		output_buf[e].separator1 = '\n';
		sprintf(output_buf[e].time_stamp, "%llu\n", (long long unsigned) login_info_element_cache[e].timestamp);
#ifdef IGF_LOGIN_DEBUG
		pr_info("%s", output_buf[e].time_stamp);
#endif
		output_buf[e].separator2 = '\n';
		sprintf(output_buf[e].count, "%u\n", login_info_element_cache[e].count);
#ifdef IGF_LOGIN_DEBUG
		pr_info("%s",output_buf[e].count);
#endif
		output_buf[e].separator3 = '\n';
		sprintf(&output_buf[e].success, "%hhu\n", login_info_element_cache[e].success);
#ifdef IGF_LOGIN_DEBUG
		pr_info("%s",&output_buf[e].success);
#endif
		output_buf[e].eol = '\n';
	}

	return sizeof(struct igel_login_output) * MAX_LOGIN_EXTENT_SIZE;
}

#define LOOP_LOGIN_EXTENT_ATTR_R(_name)						\
static ssize_t loop_attr_login_extent_##_name##_show(struct igel_loop_device *,	\
		char *);						\
static ssize_t loop_attr_do_show_login_extent_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return loop_attr_show(d, b, loop_attr_login_extent_##_name##_show);		\
}									\
static struct device_attribute loop_attr_login_extent_##_name =			\
	__ATTR(_name, 0444, loop_attr_do_show_login_extent_##_name, NULL);

LOOP_LOGIN_EXTENT_ATTR_R(array_size);
LOOP_LOGIN_EXTENT_ATTR_R(last_login_count);
LOOP_LOGIN_EXTENT_ATTR_R(last_login_timestamp);
LOOP_LOGIN_EXTENT_ATTR_R(health);
LOOP_LOGIN_EXTENT_ATTR_R(elements);

#define LOOP_LOGIN_EXTENT_ATTR_RW(_name)						\
static ssize_t loop_attr_login_extent_##_name##_store(struct igel_loop_device *,	\
		const char *, size_t);						\
static ssize_t loop_attr_do_store_login_extent_##_name(struct device *d,		\
				struct device_attribute *attr, const char *b, size_t c)	\
{									\
	return loop_attr_store(d, b, c, loop_attr_login_extent_##_name##_store);		\
}		\
static ssize_t loop_attr_login_extent_##_name##_show(struct igel_loop_device *,	\
		char *);						\
static ssize_t loop_attr_do_show_login_extent_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return loop_attr_show(d, b, loop_attr_login_extent_##_name##_show);		\
}	\
static struct device_attribute loop_attr_login_extent_##_name =			\
	__ATTR(_name, 0644, loop_attr_do_show_login_extent_##_name, loop_attr_do_store_login_extent_##_name);

LOOP_LOGIN_EXTENT_ATTR_RW(success);
LOOP_LOGIN_EXTENT_ATTR_RW(initialized);

static void loop_sysfs_init(struct igel_loop_device *lo)
{
	lo->sysfs_inited = !sysfs_create_group(&disk_to_dev(lo->lo_disk)->kobj,
						&loop_attribute_group);
	if (lo->lo_number) {
		size_t i, c = 0;
		int data_extent = 0;
		int login_extent_present = 0;
		int start_position = 0;
		int end_position = 0;
		uint32_t crc;

		sysfs_merge_group(&disk_to_dev(lo->lo_disk)->kobj,
						&loop_minor_attribute_group);

		for (i = 0; i < lo->lo_igel_info.part_exts.n_extents; ++i) {
			struct igf_partition_extent *extent =
				&lo->lo_igel_info.part_exts.extent[i];
			if (!extent->type) {
				continue;
			}

			if (extent->type == EXTENT_TYPE_SQUASHFS) {
				data_extent = 1;
			}
			if (extent->type ==  EXTENT_TYPE_LOGIN) {
				login_extent_present = 1;
#ifdef IGF_LOGIN_DEBUG
				pr_info("Login found");
#endif
			} else {
#ifdef IGF_LOGIN_DEBUG
				pr_err("Login extent not found");
#endif
			}

			switch (i) {
			LOOP_EXTENT_SET_ATTRS(1, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(2, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(3, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(4, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(5, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(6, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(7, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(8, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(9, loop_extent_attrs, c);
			LOOP_EXTENT_SET_ATTRS(10, loop_extent_attrs, c);
			}
		}
		if (data_extent) {
			loop_extent_attrs[c++] =
				&loop_attr_data_extent_in_use.attr;
			loop_extent_attrs[c++] =
				&loop_attr_data_extent_possible.attr;
		}
		if (login_extent_present) {
			int e,p,p1;
			loop_login_cache_create(lo, MAX_LOGIN_EXTENT_SIZE);
			loop_read_login_info(lo, login_info_cache);
#ifdef IGF_LOGIN_DEBUG
			if ((login_info_cache->size >= 1) && (login_info_cache->initialized == 1))
				pr_info("Login array reinitialized");
#endif
			if (!login_info_cache->size) {
				*login_info_health = 1;
				pr_err("Login extent health = false, size zero");
			}
#ifdef IGF_LOGIN_DEBUG
			else {
				pr_info("Login extent size is: %u", login_info_cache->size);
			}
#endif
#ifdef IGF_LOGIN_DEBUG
			pr_info("Login extent actual position is %u", login_info_cache->position);
#endif

			if (login_info_cache->size <= MAX_LOGIN_EXTENT_SIZE) {
#ifdef IGF_LOGIN_DEBUG
				pr_info("Login extent size is fine, reading info array now");
#endif
				for (e = 1; e <= login_info_cache->size; e++) {
					loop_read_login_info_element(lo, &login_info_element_cache[e-1], e);
				}
#ifdef IGF_LOGIN_DEBUG
				pr_info("Transfer login info array to cache completed");
#endif
				for (e = 0; e < login_info_cache->size; e++) {
					if (login_info_element_cache[e].count != 0 && login_info_element_cache[e].count < start_position)
						start_position = e;
				}
				for (e = 0; e < login_info_cache->size; e++) {
					if (login_info_element_cache[e].count != 0 && login_info_element_cache[e].count > end_position)
						end_position = e;
				}

				p = start_position;
				for (e = 0; e < login_info_cache->size; e++) {
					p1 = p + 1;
					if (p1 == login_info_cache->size)
						p1 = 0;
#ifdef IGF_LOGIN_DEBUG
					pr_info("P: %u P1: %u", login_info_element_cache[p].count, login_info_element_cache[p1].count); 
#endif
					if (login_info_element_cache[p1].count - login_info_element_cache[p].count == 1 ||
						login_info_element_cache[p].count - login_info_element_cache[p1].count == login_info_element_cache[p].count) {
						*login_info_health = 1;
					} else {
						pr_err("Login extent health = false, count inconsistent");
						*login_info_health = 1;
					}
					if (p == login_info_cache->size-1)
						p = 0;
					else
						p++;
					if (p1 == end_position)
						break;
				}
#ifdef IGF_LOGIN_DEBUG
				pr_info("Reading login info array complete");
#endif
			} else {
				*login_info_health = 0;
				pr_err("Login extent health = false, size inconsistent");
			}

			crc = loop_login_calc_crc();
			if (login_info_cache->crc != crc) {
				*login_info_health = 0;
				pr_err("Login crc mismatch, cache: %u, calc %u", login_info_cache->crc, crc);
			}
#ifdef IGF_LOGIN_DEBUG
			pr_info("Login crc save %u calc %u", login_info_cache->crc, crc);
#endif

			loop_extent_attrs[c++] =
				&loop_attr_login_extent_array_size.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_last_login_count.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_last_login_timestamp.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_success.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_health.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_initialized.attr;
			loop_extent_attrs[c++] =
				&loop_attr_login_extent_elements.attr;
		}
		loop_extent_attrs[c] = NULL;
		if (c > 0)  {
			sysfs_merge_group(&disk_to_dev(lo->lo_disk)->kobj,
						&loop_extent_attribute_group);
		}
	}
}

static void loop_sysfs_exit(struct igel_loop_device *lo)
{
	if (lo->sysfs_inited) {
		sysfs_remove_group(&disk_to_dev(lo->lo_disk)->kobj,
				   &loop_attribute_group);
		/* prevent double frees not perfect but a start */
		if (login_info_health != NULL && login_info_cache != NULL &&
		    login_info_element_cache != NULL && lo->lo_number &&
		    lo->lo_igel_info.part_exts.n_extents > 0) {
			int i = 0;
			for (i = 0; i < lo->lo_igel_info.part_exts.n_extents; ++i) {
				struct igf_partition_extent *extent =
					&lo->lo_igel_info.part_exts.extent[i];
				if (!extent->type || extent->type != EXTENT_TYPE_LOGIN) {
					continue;
				}
				sysfs_remove_group(&disk_to_dev(lo->lo_disk)->kobj,
						   &loop_extent_attribute_group);
				kfree(login_info_health);
				login_info_health = NULL;
				kfree(login_info_cache);
				login_info_cache = NULL;
				kfree(login_info_element_cache);
				login_info_element_cache = NULL;
				break;
			}
		}
	}
}

static void loop_config_discard(struct igel_loop_device *lo)
{
	struct file *file = lo->lo_backing_file;
	struct inode *inode = file->f_mapping->host;
	struct request_queue *q = lo->lo_queue;

	/*
	 * We use punch hole to reclaim the free space used by the
	 * image a.k.a. discard. However we do not support discard if
	 * encryption is enabled, because it may give an attacker
	 * useful information.
	 */
	if (!file->f_op->fallocate) {
		q->limits.discard_granularity = 0;
		q->limits.discard_alignment = 0;
		blk_queue_max_discard_sectors(q, 0);
		blk_queue_max_write_zeroes_sectors(q, 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
		blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
#endif
		return;
	}

	q->limits.discard_granularity = inode->i_sb->s_blocksize;
	q->limits.discard_alignment = 0;

	blk_queue_max_discard_sectors(q, UINT_MAX >> 9);
	blk_queue_max_write_zeroes_sectors(q, UINT_MAX >> 9);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
#endif
}

static void loop_unprepare_queue(struct igel_loop_device *lo)
{
	kthread_flush_worker(&lo->worker);
	kthread_stop(lo->worker_task);
}

static int loop_kthread_worker_fn(void *worker_ptr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
#else
	current->flags |= PF_LESS_THROTTLE;
#endif
	return kthread_worker_fn(worker_ptr);
}

static int loop_prepare_queue(struct igel_loop_device *lo)
{
	kthread_init_worker(&lo->worker);
	lo->worker_task = kthread_run(loop_kthread_worker_fn,
			&lo->worker, "loop%d", lo->lo_number);
	if (IS_ERR(lo->worker_task))
		return -ENOMEM;
	set_user_nice(lo->worker_task, MIN_NICE);
	return 0;
}

static int loop_set_file(struct igel_loop_device *lo, fmode_t mode,
		         struct block_device *bdev, struct file *file)
{
	struct file	*f, *virt_file = NULL;
	struct inode	*inode;
	struct address_space *mapping;
	int		lo_flags = 0;
	int		error;
	loff_t		size;
	bool		partscan;

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);

	f = loop_real_file(file);
	if (f) {
		virt_file = file;
		file = f;
		get_file(file);
	}

//	error = mutex_lock_killable(&igel_loop_ctl_mutex);
//	if (error)
//		goto out_putf;

	error = -EBUSY;
	if (lo->lo_state != Lo_unbound)
		goto out_unlock;

	error = loop_validate_file(file, bdev);
	if (error)
		goto out_unlock;

	mapping = file->f_mapping;
	inode = mapping->host;

	if (!(file->f_mode & FMODE_WRITE) || !(mode & FMODE_WRITE) ||
	    !file->f_op->write_iter)
		lo_flags |= LO_FLAGS_READ_ONLY;

	error = -EFBIG;
	size = get_loop_size(lo, file);
	if ((loff_t)(sector_t)size != size)
		goto out_unlock;
	error = loop_prepare_queue(lo);
	if (error)
		goto out_unlock;

	error = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	set_disk_ro(lo->lo_disk, (lo->lo_flags & LO_FLAGS_READ_ONLY) != 0);
#else
	set_device_ro(bdev, (lo_flags & LO_FLAGS_READ_ONLY) != 0);
#endif

	lo->use_dio = false;
	lo->lo_device = bdev;
	lo->lo_flags = lo_flags;
	lo->lo_backing_file = file;
	lo->lo_backing_virt_file = virt_file;
	lo->transfer = NULL;
	lo->ioctl = NULL;
	lo->lo_sizelimit = 0;
	lo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));

	if (!(lo_flags & LO_FLAGS_READ_ONLY) && file->f_op->fsync)
		blk_queue_write_cache(lo->lo_queue, true, false);

	loop_update_dio(lo);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	if (SECTOR_SHIFT != 9) {
		bd_set_nr_sectors(bdev, (size << 9) >> SECTOR_SHIFT);
	} else {
		bd_set_nr_sectors(bdev, size);
	}
#else
	bd_set_size(bdev, size << 9);
#endif
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) */
	loop_sysfs_init(lo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	if (!set_capacity_and_notify(lo->lo_disk, size))
		kobject_uevent(&disk_to_dev(lo->lo_disk)->kobj, KOBJ_CHANGE);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	/* let user-space know about the new size */
	set_capacity_revalidate_and_notify(lo->lo_disk, size, false);
#else
	set_capacity(lo->lo_disk, size);
	/* let user-space know about the new size */
	kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	set_blocksize(bdev, S_ISBLK(inode->i_mode) ?
		      block_size(inode->i_bdev) : PAGE_SIZE);
#endif

	lo->lo_state = Lo_bound;
	if (part_shift)
		lo->lo_flags |= LO_FLAGS_PARTSCAN;
	partscan = lo->lo_flags & LO_FLAGS_PARTSCAN;

	/* Grab the block_device to prevent its destruction after we
	 * put /dev/loopXX inode. Later in __loop_clr_fd() we bdput(bdev).
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	bdgrab(bdev);
#endif
//	mutex_unlock(&igel_loop_ctl_mutex);
//	if (partscan)
//		loop_reread_partitions(lo, bdev);

	//build_part_info(file, 1, &lo->igel_part_info);

	return 0;

out_unlock:
//	mutex_unlock(&igel_loop_ctl_mutex);
//out_putf:
	fput(file);
	if (virt_file)
		fput(virt_file);
//out:
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	return error;

}


static int loop_set_fd(struct igel_loop_device *lo, fmode_t mode,
		       struct block_device *bdev, unsigned int arg)
{
	struct file *file;
	int error;

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);
	error = -EBADF;
	file = fget(arg);
	if (!file) {
		error = loop_set_file(lo, mode, bdev, file);
	}

	module_put(THIS_MODULE);
	return error;
}

static int __loop_clr_fd(struct igel_loop_device *lo, bool release)
{
	struct file *filp = NULL;
	struct file *virt_filp = lo->lo_backing_virt_file;
	gfp_t gfp = lo->old_gfp_mask;
	struct block_device *bdev = lo->lo_device;
	int err = 0;
	bool partscan = false;
	int lo_number;

	//mutex_lock(&igel_loop_ctl_mutex);
	if (WARN_ON_ONCE(lo->lo_state != Lo_rundown)) {
		err = -ENXIO;
		goto out_unlock;
	}

	filp = lo->lo_backing_file;
	if (filp == NULL) {
		err = -EINVAL;
		goto out_unlock;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	if (test_bit(QUEUE_FLAG_WC, &lo->lo_queue->queue_flags))
		blk_queue_write_cache(lo->lo_queue, false, false);
#endif

	/* freeze request queue during the transition */
	blk_mq_freeze_queue(lo->lo_queue);

	spin_lock_irq(&lo->lo_lock);
	lo->lo_backing_file = NULL;
	lo->lo_backing_virt_file = NULL;
	spin_unlock_irq(&lo->lo_lock);

	lo->transfer = NULL;
	lo->ioctl = NULL;
	lo->lo_device = NULL;
	lo->lo_offset = 0;
	lo->lo_sizelimit = 0;
	memset(lo->lo_file_name, 0, LO_NAME_SIZE);
	blk_queue_logical_block_size(lo->lo_queue, 512);
	blk_queue_physical_block_size(lo->lo_queue, 512);
	blk_queue_io_min(lo->lo_queue, 512);
	if (bdev) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		bdput(bdev);
#endif
		invalidate_bdev(bdev);
		bdev->bd_inode->i_mapping->wb_err = 0;
	}
	set_capacity(lo->lo_disk, 0);
	loop_sysfs_exit(lo);
	if (bdev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	//	bd_set_nr_sectors(bdev, 0);
#else
	//	bd_set_size(bdev, 0);
#endif
		/* let user-space know about this change */
		/* FIXME: figure out why this fails */
		//kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
	}
	mapping_set_gfp_mask(filp->f_mapping, gfp);
	lo->lo_state = Lo_unbound;
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	blk_mq_unfreeze_queue(lo->lo_queue);

	partscan = lo->lo_flags & LO_FLAGS_PARTSCAN && bdev;
	lo_number = lo->lo_number;
	lo->lo_flags = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,132)
	if (!part_shift)
		lo->lo_disk->flags |= GENHD_FL_NO_PART;
#else
	if (!part_shift)
		lo->lo_disk->flags |= GENHD_FL_NO_PART_SCAN;
#endif
	loop_unprepare_queue(lo);
out_unlock:
	//mutex_unlock(&igel_loop_ctl_mutex);
//	if (partscan) {
//		/*
//		 * bd_mutex has been held already in release path, so don't
//		 * acquire it if this function is called in such case.
//		 *
//		 * If the reread partition isn't from release path, lo_refcnt
//		 * must be at least one and it can only become zero when the
//		 * current holder is released.
//		 */
//		if (release)
//			err = __blkdev_reread_part(bdev);
//		else
//			err = blkdev_reread_part(bdev);
//		pr_warn("%s: partition scan of loop%d failed (rc=%d)\n",
//			__func__, lo_number, err);
//		/* Device is gone, no point in returning error */
//		err = 0;
//	}
	/*
	 * Need not hold loop_ctl_mutex to fput backing file.
	 * Calling fput holding loop_ctl_mutex triggers a circular
	 * lock dependency possibility warning as fput can take
	 * bd_mutex which is usually taken before loop_ctl_mutex.
	 */
	if (filp)
		fput(filp);
	if (virt_filp)
		fput(virt_filp);
	return err;
}

static int loop_clr_fd(struct igel_loop_device *lo, bool lock)
{
	int err;

	if (lock) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		err = mutex_lock_killable(&igel_loop_ctl_mutex);
#else
		err = mutex_lock_killable(&lo->lo_mutex);
#endif
		if (err)
			return err;
	}
	if (lo->lo_state != Lo_bound) {
		err = -ENXIO;
		goto out_unlock;
	}
	/*
	 * If we've explicitly asked to tear down the loop device,
	 * and it has an elevated reference count, set it for auto-teardown when
	 * the last reference goes away. This stops $!~#$@ udev from
	 * preventing teardown because it decided that it needs to run blkid on
	 * the loopback device whenever they appear. xfstests is notorious for
	 * failing tests because blkid via udev races with a losetup
	 * <dev>/do something like mkfs/losetup -d <dev> causing the losetup -d
	 * command to fail with EBUSY.
	 */
	if (atomic_read(&lo->lo_refcnt) > 1) {
		lo->lo_flags |= LO_FLAGS_AUTOCLEAR;
		err = -EAGAIN;
		goto out_unlock;
	}
	lo->lo_state = Lo_rundown;

	err = igel_loop_remove(lo, false);
out_unlock:
	if (lock) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		mutex_unlock(&igel_loop_ctl_mutex);
#else
		mutex_unlock(&lo->lo_mutex);
#endif
	}
	return err;
}

static int
loop_set_status(struct igel_loop_device *lo, const struct loop_info64 *info)
{
	int err;
	//struct loop_func_table *xfer;
	//kuid_t uid = current_uid();
	struct block_device *bdev;
	bool partscan = false;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	err = mutex_lock_killable(&igel_loop_ctl_mutex);
#else
	err = mutex_lock_killable(&lo->lo_mutex);
#endif
	if (err)
		return err;
	if (lo->lo_state != Lo_bound) {
		err = -ENXIO;
		goto out_unlock;
	}

	if (lo->lo_offset != info->lo_offset ||
	    lo->lo_sizelimit != info->lo_sizelimit) {
		sync_blockdev(lo->lo_device);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
		invalidate_bdev(lo->lo_device);
#else
		kill_bdev(lo->lo_device);
#endif
	}

	/* I/O need to be drained during transfer transition */
	blk_mq_freeze_queue(lo->lo_queue);


	if (lo->lo_offset != info->lo_offset ||
	    lo->lo_sizelimit != info->lo_sizelimit) {
		/* kill_bdev should have truncated all the pages */
		if (lo->lo_device->bd_inode->i_mapping->nrpages) {
			err = -EAGAIN;
			pr_warn("%s: loop%d (%s) has still dirty pages (nrpages=%lu)\n",
				__func__, lo->lo_number, lo->lo_file_name,
				lo->lo_device->bd_inode->i_mapping->nrpages);
			goto out_unfreeze;
		}
		if (figure_loop_size(lo, info->lo_offset, info->lo_sizelimit)) {
			err = -EFBIG;
			goto out_unfreeze;
		}
	}

	loop_config_discard(lo);

	memcpy(lo->lo_file_name, info->lo_file_name, LO_NAME_SIZE);
	lo->lo_file_name[LO_NAME_SIZE-1] = 0;
	lo->transfer = NULL;
	lo->ioctl = NULL;

	if ((lo->lo_flags & LO_FLAGS_AUTOCLEAR) !=
	     (info->lo_flags & LO_FLAGS_AUTOCLEAR))
		lo->lo_flags ^= LO_FLAGS_AUTOCLEAR;


	/* update dio if lo_offset or transfer is changed */
	__loop_update_dio(lo, lo->use_dio);

out_unfreeze:
	blk_mq_unfreeze_queue(lo->lo_queue);

	if (!err && (info->lo_flags & LO_FLAGS_PARTSCAN) &&
	     !(lo->lo_flags & LO_FLAGS_PARTSCAN)) {
		lo->lo_flags |= LO_FLAGS_PARTSCAN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,132)
		lo->lo_disk->flags &= ~GENHD_FL_NO_PART;
#else
		lo->lo_disk->flags &= ~GENHD_FL_NO_PART_SCAN;
#endif
		bdev = lo->lo_device;
		partscan = true;
	}
out_unlock:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	mutex_unlock(&igel_loop_ctl_mutex);
#else
	mutex_unlock(&lo->lo_mutex);
#endif
	if (partscan)
		loop_reread_partitions(lo, bdev);

	return err;
}

static int
loop_get_status(struct igel_loop_device *lo, struct loop_info64 *info)
{
	struct path path;
	struct kstat stat;
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	ret = mutex_lock_killable(&igel_loop_ctl_mutex);
#else
	ret = mutex_lock_killable(&lo->lo_mutex);
#endif
	if (ret)
		return ret;
	if (lo->lo_state != Lo_bound) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		mutex_unlock(&igel_loop_ctl_mutex);
#else
		mutex_unlock(&lo->lo_mutex);
#endif
		return -ENXIO;
	}

	memset(info, 0, sizeof(*info));
	info->lo_number = lo->lo_number;
	info->lo_offset = lo->lo_offset;
	info->lo_sizelimit = lo->lo_sizelimit;
	info->lo_flags = lo->lo_flags;
	memcpy(info->lo_file_name, lo->lo_file_name, LO_NAME_SIZE);

	/* Drop loop_ctl_mutex while we call into the filesystem. */
	path = lo->lo_backing_file->f_path;
	path_get(&path);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	mutex_unlock(&igel_loop_ctl_mutex);
#else
	mutex_unlock(&lo->lo_mutex);
#endif
	ret = vfs_getattr(&path, &stat, STATX_INO, AT_STATX_SYNC_AS_STAT);
	if (!ret) {
		info->lo_device = huge_encode_dev(stat.dev);
		info->lo_inode = stat.ino;
		info->lo_rdevice = huge_encode_dev(stat.rdev);
	}
	path_put(&path);
	return ret;
}

static int
loop_set_status64(struct igel_loop_device *lo, const struct loop_info64 __user *arg)
{
	struct loop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof (struct loop_info64)))
		return -EFAULT;
	return loop_set_status(lo, &info64);
}

static int
loop_get_status64(struct igel_loop_device *lo, struct loop_info64 __user *arg) {
	struct loop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = loop_get_status(lo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64)))
		err = -EFAULT;

	return err;
}

static int loop_set_capacity(struct igel_loop_device *lo)
{
	if (unlikely(lo->lo_state != Lo_bound))
		return -ENXIO;

	return figure_loop_size(lo, lo->lo_offset, lo->lo_sizelimit);
}

static int loop_set_dio(struct igel_loop_device *lo, unsigned long arg)
{
	int error = -ENXIO;
	if (lo->lo_state != Lo_bound)
		goto out;

	__loop_update_dio(lo, !!arg);
	if (lo->use_dio == !!arg)
		return 0;
	error = -EINVAL;
 out:
	return error;
}

static int loop_set_block_size(struct igel_loop_device *lo, unsigned long arg)
{
	int err = 0;

	if (lo->lo_state != Lo_bound)
		return -ENXIO;

	if (arg < 512 || arg > PAGE_SIZE || !is_power_of_2(arg))
		return -EINVAL;

	if (lo->lo_queue->limits.logical_block_size != arg) {
		sync_blockdev(lo->lo_device);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
		invalidate_bdev(lo->lo_device);
#else
		kill_bdev(lo->lo_device);
#endif
	}

	blk_mq_freeze_queue(lo->lo_queue);

	/* kill_bdev should have truncated all the pages */
	if (lo->lo_queue->limits.logical_block_size != arg &&
			lo->lo_device->bd_inode->i_mapping->nrpages) {
		err = -EAGAIN;
		pr_warn("%s: loop%d (%s) has still dirty pages (nrpages=%lu)\n",
			__func__, lo->lo_number, lo->lo_file_name,
			lo->lo_device->bd_inode->i_mapping->nrpages);
		goto out_unfreeze;
	}

	blk_queue_logical_block_size(lo->lo_queue, arg);
	blk_queue_physical_block_size(lo->lo_queue, arg);
	blk_queue_io_min(lo->lo_queue, arg);
	loop_update_dio(lo);
out_unfreeze:
	blk_mq_unfreeze_queue(lo->lo_queue);

	return err;
}

static int igel_wipe_partition(struct igel_loop_device *lo, uint8_t pattern)
{
	struct igf_part_hdr *phdr = &lo->lo_igel_info.phdr;
	struct igel_section_allocation *allocation;

	loff_t start = phdr->offset_blocks;
	size_t data_len = IGF_SECTION_SIZE - lo->lo_hdrlen;
	size_t section;
	size_t phys_sect;
	loff_t offset;

	section = div64_u64_rem(start, data_len, &offset);

	if (lo->lo_number < 1 || lo->lo_number == sys_minor) {
		return -EINVAL;
	}
	if (lo->lo_igel_info.phdr.type == PTYPE_IGEL_RAW_RO) {
		return -EPERM;
	}

	allocation = make_section_allocation();
	if (!allocation) {
		return -ENOMEM;
	}

	memset(allocation->vmapping, pattern, IGF_SECTION_SIZE);

	file_start_write(lo->igel_private->file);
	for (section = 0; section < lo->lo_igel_info.num_sections; ++section) {
		phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number, section);

		write_section_allocation(allocation, offset,
		                         IGF_SECTION_SIZE - offset,
		                         lo->igel_private->file, phys_sect);
		offset = lo->lo_hdrlen;
	}
	file_end_write(lo->igel_private->file);
	free_section_allocation(allocation);

	return 0;
}

static ssize_t igel_write_extent_slice(struct igel_loop_device *lo,
	struct igf_partition_extent *extent, size_t pos, size_t size,
	uint8_t __user *dest)
{
	ssize_t len;
	size_t ipos = pos + extent->offset;
	size_t data_len = IGF_SECTION_SIZE - lo->lo_hdrlen;
	ssize_t done = 0;
	struct iovec iov = {
		.iov_base = (void *)dest,
		.iov_len = size,
	};

	file_start_write(lo->igel_private->file);
	while (done < size) {
		size_t cpos = ipos + done;
		size_t curr_sect = cpos / data_len;
		size_t phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number, curr_sect);
		size_t offset = (cpos % data_len) + lo->lo_hdrlen;
		size_t max_len = size - done;
		loff_t phys_offset = START_OF_SECTION(phys_sect) + offset;
		struct iov_iter i;

		if (max_len > IGF_SECTION_SIZE - offset) {
			max_len = IGF_SECTION_SIZE - offset;
		}

		iov_iter_init(&i,  WRITE, &iov, 1, max_len);

		/* This has to be done outside the iov_iter_init :/ */
		i.iov_offset = done;

		len = vfs_iter_write(lo->lo_backing_file, &i, &phys_offset, 0);

		if (len < 0) {
			done = -EIO;
			goto out;
		}

		done += len;
	}

out:
	file_end_write(lo->igel_private->file);

	return done;
}

static ssize_t igel_get_extent_slice(struct igel_loop_device *lo,
	struct igf_partition_extent *extent, size_t pos, size_t size,
	uint8_t __user *dest)
{
	ssize_t len;
	size_t ipos = pos + extent->offset;
	size_t data_len = IGF_SECTION_SIZE - lo->lo_hdrlen;
	ssize_t done = 0;
	struct iovec iov = {
		.iov_base = (void *)dest,
		.iov_len = size,
	};

	while (done < size) {
		size_t cpos = ipos + done;
		size_t curr_sect = cpos / data_len;
		size_t phys_sect = get_physical_section(&lo->igel_private->dir, lo->lo_number, curr_sect);
		size_t offset = (cpos % data_len) + lo->lo_hdrlen;
		size_t max_len = size - done;
		loff_t phys_offset = START_OF_SECTION(phys_sect) + offset;
		struct iov_iter i;

		if (max_len > IGF_SECTION_SIZE - offset) {
			max_len = IGF_SECTION_SIZE - offset;
		}

		iov_iter_init(&i,  READ, &iov, 1, max_len);

		/* This has to be done outside the iov_iter_init :/ */
		i.iov_offset = done;

		len = vfs_iter_read(lo->lo_backing_file, &i, &phys_offset, 0);

		if (len < 0)
			return -EIO;

		done += len;
	}

	return done;
}

static int igel_get_extent(struct igel_loop_device *lo, unsigned long arg)
{
	struct partition_extents *extents = &lo->lo_igel_info.part_exts;
	uint16_t extent;

	if (copy_from_user(&extent, (u_int16_t *)arg, sizeof(u_int16_t))) {
		return -EFAULT;
	}

	return igel_get_extent_slice(lo, &extents->extent[extent - 1], 0,
		extents->extent[extent - 1].length, (uint8_t *)arg);
}

static int validate_dir_cb(int id, void *ptr, void *data)
{
	struct directory *dir = data;
	struct igel_loop_device *lo = ptr;

	if (!dir->partition[lo->lo_number].n_fragments) {
		printk("igel-loop: Failed to find %d fragments in directory\n", lo->lo_number);
		return 1;
	}

	return 0;
}

static int load_new_directory(struct igel_loop_private *private)
{
	int err;
	struct directory *dir = vmalloc(sizeof(*dir));
	read_dir(private->file, dir);

	/* Validate that every partition we have loaded atm is available in the
	 * new directory structure. If it's not, we'll keep the old one */
	err = idr_for_each(&private->minors, &validate_dir_cb, dir);

	if (!err) {
		/* Ok. Copy over new directory over the old one.
		 * FIXME: This should probably take a RCU/RW-lock */
		memcpy(&private->dir, dir, sizeof(private->dir));
	}
	vfree(dir);

	return err;
}

static int igel_wipe_part_secure(struct igel_loop_device *lo) {
	int result;
	if ((result = igel_wipe_partition(lo, 0xaa)) != 0)
		return result;

	if ((result = igel_wipe_partition(lo, 0x55)) != 0)
		return result;

	if ((result = igel_wipe_partition(lo, 0xff)) != 0)
		return result;

	return igel_wipe_partition(lo, 0x0);
}

static int igel_erase_section(struct file *file, size_t section)
{
	struct igel_section_allocation *allocation;
	int ret = -1;

	allocation = make_section_allocation();
	if (!allocation) {
		return -ENOMEM;
	}

	memset(allocation->vmapping, 0x00, IGF_SECTION_SIZE);

	file_start_write(file);
	ret = write_section_allocation(allocation, 0, IGF_SECTION_SIZE,
				       file, section);
	file_end_write(file);
	free_section_allocation(allocation);

	return ret;
}

static int get_extent_read_write(struct igel_loop_device *lo,
	struct part_ext_read_write *rw, struct part_ext_read_write __user *src,
	bool write_operation) {
	struct igf_partition_extent *extent = NULL;

	if (copy_from_user(rw, src, sizeof(struct part_ext_read_write))) {
		return -EFAULT;
	}

	/* We are 1 indexed, not 0 indexed for extent numbers */
	if (rw->ext_num < 1 ||
		rw->ext_num > lo->lo_igel_info.part_exts.n_extents) {
		return -ENOENT;
	}

	extent = &lo->lo_igel_info.part_exts.extent[rw->ext_num - 1];
	if (extent->type != EXTENT_TYPE_WRITEABLE &&
		extent->type != EXTENT_TYPE_LOGIN &&
		extent->type != EXTENT_TYPE_APPLICATION &&
		extent->type != EXTENT_TYPE_LICENSE) {
		return -EINVAL;
	}
	/* Application extent data should only be readable */
	if ((extent->type == EXTENT_TYPE_APPLICATION ||
		extent->type == EXTENT_TYPE_LICENSE) &&
		write_operation == true) {
		printk("igel-loop: Write operation not allowed for type application/license\n");
		return -EINVAL;
	}

	/* While we could do short reads, this allows to reuse the same code
	 * for write checking. Also, userspace should know the extent size */
	if (rw->pos + rw->size > extent->length) {
		return -ERANGE;
	}
	if (rw->size > EXTENT_MAX_READ_WRITE_SIZE) {
		return -ERANGE;
	}

	return 0;
}

static int igel_inval_from_private(struct igel_loop_private *private, int part)
{
	struct directory *dir;
	size_t section;
	int ret;
	if (!private->dir.partition[part].n_fragments) {
		printk("igel-loop: Tried to invalidate missing partition: %d\n", part);
		return -ENOENT;
	}

	section = private->dir.fragment[
			private->dir.partition[part].first_fragment]
			.first_section;

	dir = vmalloc(sizeof(*dir));

	if (!dir)
		return -ENOMEM;

	igeldir_delete_partition(&private->dir, dir, part);
	memcpy(&private->dir, dir, sizeof(private->dir));
	vfree(dir);

	ret = igel_erase_section(private->file, section);
	if (ret != 0) {
		printk(KERN_ERR "igel-loop: Could not erase first section of minor %d\n", part);
		load_new_directory(private);
		return ret;
	}
	ret = write_dir(private->file, &private->dir);
	if (ret != 0) {
		printk(KERN_ERR "igel-loop: Could not write updated directory for minor %d (ret: %d)\n", part, ret);
	}

	return 0;
}

static int lo_igel_simple_ioctl(struct igel_loop_device *lo, unsigned int cmd,
			        unsigned long arg)
{
#ifdef LXOS_DEV
	static const int is_dev = 1;
#else
	static const int is_dev = 0;
#endif
	struct igel_loop_device *part_lo;
	if (!lo) {
		return -EINVAL;
	}
	part_lo = idr_find(&lo->igel_private->minors, arg);

	switch (cmd) {
	case IGFLASH_ERASE_SECTION:
	{
		int part = get_partition_from_section(&lo->igel_private->dir, arg);
		WARN_ONCE(is_dev, "IGFLASH_ERASE_SECTION is a deprecated IGF ioctl");
		if (part == sys_minor) {
			return 0;
		}
		if (part > 0) {
			/* Recurse to re-use code that removes it from part table */
			lo_igel_simple_ioctl(lo, IGFLASH_INVAL_PARTITION, part);
		}
		/* Overwrite */
		return igel_erase_section(lo->igel_private->file, arg);
	}
	case IGFLASH_GET_PARTITION_VERSION:
	{
		uint16_t * ret_ptr = (u_int16_t *) arg;
		WARN_ONCE(is_dev, "IGFLASH_GET_LAST_SECTION is a deprecated IGF ioctl");
		put_user(lo->lo_igel_info.generation_number, ret_ptr);
		return 0;
	}
	case IGFLASH_LOCK_PARTITION:
		if (lo->lo_number > 0 && lo->lo_number != sys_minor) {
			if (lo->lo_igel_info.is_valid) {
				lo->lo_igel_info.is_locked = 1;
			}
			return 0;
		}
		return -EFAULT;
	case IGFLASH_WIPE_PARTITION:
		return igel_wipe_partition(lo, 0x00);
	case IGFLASH_WIPE_PARTITION_SECURE:
		return igel_wipe_part_secure(lo);
	case IGFLASH_GET_LAST_SECTION:
	{
		uint32_t * ret_ptr = (u_int32_t *) arg;
		WARN_ONCE(is_dev, "IGFLASH_GET_LAST_SECTION is a deprecated IGF ioctl");
		put_user(lo->lo_igel_info.lastsect, ret_ptr);
		return 0;
	}
	case IGFLASH_GET_EXTENT_SIZE:
	{
		struct partition_extents *extents =
			&lo->lo_igel_info.part_exts;
		WARN_ONCE(is_dev, "IGFLASH_GET_EXTENT_SIZE is a deprecated IGF ioctl");
		if (copy_to_user((struct partition_extents *)arg, extents,
					sizeof(struct partition_extents))) {
			return -EFAULT;
		}
		return 0;
	}
	case IGFLASH_GET_EXTENT:
	{
		WARN_ONCE(is_dev, "IGFLASH_GET_EXTENT is a deprecated IGF ioctl");
		return igel_get_extent(lo, arg);
	}
	case IGFLASH_RECHECK_PARTITIONS:
	{
		int ret;
		int i;
		struct key *keyring = NULL;

		keyring = request_key(&key_type_keyring, "igel_cmty", false);
	        if (IS_ERR(keyring)) {
                	printk(KERN_INFO "igel-loop: unable to get \"igel_cmty\" keyring\n");
        	        return PTR_ERR(keyring);
	        }
		if (!keyring->restrict_link) {
			printk("igel-loop: Recheck not allowed as \"igel_cmty\" keyring is not locked!\n");
			key_put(keyring);
			return 1;
		}
		key_put(keyring);
		if (load_new_directory(lo->igel_private)) {
			return -EBUSY;
		}

		if (lo->igel_private->allow_additional_partitions != 0)
			return 1;

		lo->igel_private->allow_additional_partitions = 1;
		for (i = 1; i < lo->igel_private->dir.max_minors; ++i) {
			if (i == sys_minor)
				continue;
			if (idr_find(&lo->igel_private->minors, i))
				continue;
			if ((ret = igel_loop_add_minor(lo->igel_private, i, 1)) < 0) {
				if (ret == -EKEYREJECTED) {
					printk("igel-loop: Did not add '%d' partition. Signature verification failed!\n", i);
				}
				if (!ret) {
					part_lo = idr_find(&lo->igel_private->minors, i);
					proc_igel_firmware_create_entry(part_lo);
				}
			}
		}

		return 0;
	}
	case IGFLASH_REGISTER_PARTITION:
	{
		int ret;
		if (idr_find(&lo->igel_private->minors, arg)) {
			return -EEXIST;
		}

		if (load_new_directory(lo->igel_private)) {
			return -EBUSY;
		}
		ret = igel_loop_add_minor(lo->igel_private, arg, 0);
		if (!ret) {
			part_lo = idr_find(&lo->igel_private->minors, arg);
			proc_igel_firmware_create_entry(part_lo);
		}

		if (lo->lo_number > 0 && lo->lo_number != sys_minor && (lo->lo_igel_info.phdr.type & 0xFF) == PTYPE_IGEL_RAW_RO) {
			if (lo->lo_igel_info.is_valid) {
				lo->lo_igel_info.is_locked = 1;
			}
		}

		return ret;
	}
	case IGFLASH_INVAL_PARTITION:
		if (!part_lo) {
			return igel_inval_from_private(lo->igel_private, arg);
		}
		printk("igel-loop: Invalidate refcnt: %d\n", atomic_read(&part_lo->lo_refcnt));
		if (atomic_read(&part_lo->lo_refcnt) > 0) {
			return -EBUSY;
		}

		if (part_lo->lo_number < 1 || part_lo->lo_number == sys_minor) {
			return -EFAULT;
		}
		part_lo->lo_igel_info.is_invalidated = 1;

		/* Fall through */
		fallthrough;
	case IGFLASH_DISABLE_PARTITION:
	{
		int ret;
		if (!part_lo) {
			return -ENOENT;
		}
		if (part_lo->lo_number < 1 || part_lo->lo_number == sys_minor) {
			return -EFAULT;
		}
		if (atomic_read(&part_lo->lo_refcnt) > 0) {
			return -EBUSY;
		}
		/* Set invalid */
		part_lo->lo_igel_info.is_valid = 0;
		/* Set it locked here, for immediate effect on any read data */
		part_lo->lo_igel_info.is_locked = 1;

		/* The will remove the block device, once there's no active
		 * fd to it anymore */
		ret = loop_clr_fd(part_lo, false);
		return ret;
	}
	case IGFLASH_READ_EXTENT:
	{
		int ret;
		struct igf_partition_extent *extent = NULL;
		struct part_ext_read_write eread;

		ret = get_extent_read_write(lo, &eread, (struct part_ext_read_write *) arg, false);
		if (ret) {
			return ret;
		}
		extent = &lo->lo_igel_info.part_exts.extent[eread.ext_num - 1];

		return igel_get_extent_slice(lo, extent,
			eread.pos, eread.size, eread.data);
	}
	case IGFLASH_WRITE_EXTENT:
	{
		struct igf_partition_extent *extent = NULL;
		struct part_ext_read_write ewrite;
		int ret;

		ret = get_extent_read_write(lo, &ewrite, (struct part_ext_read_write *) arg, true);
		if (ret) {
			return ret;
		}
		extent = &lo->lo_igel_info.part_exts.extent[ewrite.ext_num - 1];

		return igel_write_extent_slice(lo, extent,
			ewrite.pos, ewrite.size, ewrite.data);
	}
	case IGFLASH_SWITCH_TO_EXTENT:
	{
		struct {
			uint16_t ext_num;
			uint16_t part_num;
		} ext_data;
		if (copy_from_user(&ext_data, (u_int16_t *)arg, sizeof(ext_data))) {
			return -EFAULT;
		}
		part_lo = idr_find(&lo->igel_private->minors, ext_data.part_num);
		if (!part_lo) {
			return -ENOENT;
		}
		if (part_lo->lo_state != Lo_bound) {
			return -EINVAL;
		}
		return set_extent(part_lo, ext_data.ext_num);
	}
	case IGFLASH_GET_DIRECTORY:
		return (copy_to_user((struct directory *)arg, &lo->igel_private->dir,
						sizeof(struct directory)) ? -EFAULT : 0);
	case IGFLASH_GET_MAGIC:
	{
		//return -EFAULT;
		uint32_t magic = lo->lo_igel_info.magic;
		WARN_ONCE(is_dev, "IGFLASH_GET_MAGIC is a deprecated IGF ioctl");
		put_user(magic, (uint32_t *) arg);
		return 0;
	}
	case IGFLASH_GET_SIZE:
	{
		uint64_t size = 0, i;
		WARN_ONCE(is_dev && lo->lo_number, "IGFLASH_GET_SIZE on a parition is a deprecated IGF ioctl");
		if (lo->lo_number) {
			return -EFAULT;
		}
		for (i = 0; i < lo->igel_private->dir.n_fragments; ++i) {
			struct fragment_descriptor *desc = &lo->igel_private->dir.fragment[i];
			if (desc->first_section + desc->length > size) {
				size = (desc->first_section + desc->length);
			}
		}
		put_user(size * IGF_SECTION_SIZE, (u_int64_t *) arg);
		return 0;
	}
	case IGFLASH_RELOAD_PARTITION:
	{
		int f;
		loff_t size;
		
		part_lo = idr_find(&lo->igel_private->minors, arg);
		if (!part_lo) {
			WARN_ONCE(is_dev, "IGFLASH_RELOAD_PARTITION Error partition not found%lu\n", arg);
			return -EEXIST;
		}
		//bdev = lo->lo_device;
		if (load_new_directory(lo->igel_private)) {
			WARN_ONCE(is_dev, "IGFLASH_RELOAD_PARTITION Error load new directory %lu\n", arg);
			return -EFAULT;
		}
		
		part_lo->lo_igel_info.first_section = lo->igel_private->dir.fragment[lo->igel_private->dir.partition[arg].first_fragment].first_section;
		part_lo->lo_igel_info.num_sections = 0;
		part_lo->lo_igel_info.lastsect = part_lo->lo_igel_info.first_section;
		for (f=0;f<lo->igel_private->dir.partition[arg].n_fragments; f++) {
			struct fragment_descriptor *frag= &lo->igel_private->dir.fragment[lo->igel_private->dir.partition[arg].first_fragment + f];
			part_lo->lo_igel_info.num_sections += frag->length;
			part_lo->lo_igel_info.lastsect += frag->length;
		}
		if (read_igf_part_header(&part_lo->lo_igel_info.phdr, part_lo->lo_igel_info.first_section, lo->igel_private->file)) {
			WARN_ONCE(is_dev, "IGFLASH_RELOAD_PARTITION Error reading partition header%lu\n", arg);
			return -EFAULT;
		}
		
		size = get_igel_size(part_lo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		if (!set_capacity_and_notify(part_lo->lo_disk, size))
			kobject_uevent(&disk_to_dev(part_lo->lo_disk)->kobj, KOBJ_CHANGE);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
		/* let user-space know about the new size */
		set_capacity_revalidate_and_notify(part_lo->lo_disk, size, false);
#else
		set_capacity(part_lo->lo_disk, size);
		/* let user-space know about the new size */
		kobject_uevent(&disk_to_dev(part_lo->lo_disk)->kobj, KOBJ_CHANGE);
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) */
		return 0;
	}
	default:
		return lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;
	}
}

static int lo_simple_ioctl(struct igel_loop_device *lo, unsigned int cmd,
			   unsigned long arg)
{
	int err;

	switch (cmd) {
	case LOOP_SET_CAPACITY:
		err = loop_set_capacity(lo);
		break;
	case LOOP_SET_DIRECT_IO:
		err = loop_set_dio(lo, arg);
		break;
	case LOOP_SET_BLOCK_SIZE:
		err = loop_set_block_size(lo, arg);
		break;
	default:
		err = lo_igel_simple_ioctl(lo, cmd, arg);
	}
	return err;
}

//static int create_new_rw_partition(struct igel_loop_private *private,
//                                   const struct igf_create_part_args *args)
//{
//	size_t extent_sizes[MAX_EXTENT_NUM];
//	int extent_types[MAX_EXTENT_NUM];
//	size_t data_size = IGF_SECTION_SIZE - IGF_SECT_HDR_LEN;
//	size_t total_size, i, ext_offset, sections = 0;
//	struct directory *dir = NULL;
//	struct igf_part_hdr *part_hdr = NULL;
//	int err = 0;
//
//	/* Get the lock here, we need to iterate stuff and might have to create
//	 * a new partition! */
//	err = mutex_lock_killable(&igel_loop_ctl_mutex);
//	if (err) {
//		return err;
//	}
//
//	/* First check if the partition already exists */
//	if (idr_find(&igel_loop_index_idr, args->minor)) {
//		err = -EEXIST;
//		goto out_unlock;
//	}
//
//	if (copy_from_user(&extent_sizes, args->extent_sizes, sizeof(size_t) * args->num_extents)) {
//		err = -EINVAL;
//		goto out_unlock;
//	}
//
//	if (copy_from_user(&extent_types, args->extent_types, sizeof(int) * args->num_extents)) {
//		err = -EINVAL;
//		goto out_unlock;
//	}
//
//	total_size = args->size + sizeof(struct igf_part_hdr);
//	for (i = 0; i < args->num_extents; ++i) {
//		total_size += extent_sizes[i];
//		total_size += sizeof(struct igf_partition_extent);
//	}
//
//	sections = (total_size + data_size - 1) / data_size;
//
//	/* Ok, we need to allocate the partition */
//	dir = kmalloc(sizeof(*dir), GFP_KERNEL);
//	if (!dir) {
//		err = -ENOMEM;
//		goto out_unlock;
//	}
//
//	/* Scope the stack for this nonesense */
//	{
//		struct fragment_descriptor frags[16];
//		if (allocate_fragments(&private->dir, frags,
//		                       sizeof(frags) / sizeof(frags[0]),
//				       sections)) {
//			err = -ENOSPC;
//			goto out_directory;
//		}
//		igeldir_add_partition(&private->dir, dir, args->minor,
//		                      frags, sizeof(frags) / sizeof(frags[0]));
//	}
//
//	/* After we set up the basic stuff in directory, we need to write
//	 * headers to disk, so we can find it again after shutdown */
//	part_hdr = kmalloc(sizeof(struct igf_part_hdr) + sizeof(struct igf_partition_extent) * args->num_extents, GFP_KERNEL);
//	if (!part_hdr) {
//		goto out_directory;
//	}
//
//	part_hdr->type = PTYPE_IGEL_RAW;
//	part_hdr->hdrlen = sizeof(struct igf_part_hdr) + sizeof(struct igf_partition_extent) * args->num_extents;
//	part_hdr->partlen = total_size;
//	part_hdr->n_blocks = 0;
//	part_hdr->offset_blocktable = part_hdr->hdrlen;
//	part_hdr->offset_blocks = part_hdr->hdrlen;
//	part_hdr->n_clusters = 0;
//	part_hdr->cluster_shift = 0;
//	part_hdr->n_extents = args->num_extents;;
//
//	ext_offset = part_hdr->hdrlen;
//	for (i = 0; i < args->num_extents; ++i) {
//		/* Yay! Maths */
//		struct igf_partition_extent *extent =
//			((struct igf_partition_extent *)(part_hdr + 1)) + i;
//
//		extent->type = extent_types[i];
//		extent->length = extent_sizes[i];
//		extent->offset = ext_offset;
//		memset(extent->name, 0, sizeof(extent->name));
//		ext_offset += extent_sizes[i];
//	}
//
//	file_start_write(private->file);
//	{
//		struct kvec iov = {
//			.iov_base = part_hdr,
//			.iov_len = part_hdr->hdrlen,
//		};
//		struct iov_iter i;
//		size_t phys_sect = get_physical_section(dir, args->minor, 0);
//		loff_t phys_pos = START_OF_SECTION(phys_sect) + 32;
//		iov_iter_kvec(&i, /*ITER_KVEC |*/ WRITE, &iov, 1, part_hdr->hdrlen);
//
//		vfs_iter_write(private->file, &i, &phys_pos, 0);
//	}
//
//	for (i = 0; i < sections; ++i) {
//		struct igf_sect_hdr *hdr = (struct igf_sect_hdr *)part_hdr;
//		struct kvec iov = {
//			.iov_base = hdr,
//			.iov_len = 32,
//		};
//		size_t phys_sect = get_physical_section(dir, args->minor, i);
//		loff_t phys_pos = START_OF_SECTION(phys_sect);
//		struct iov_iter iter;
//
//		hdr->magic = 0; /* FIXME: */
//		hdr->section_type = SECT_TYPE_IGEL_V6;
//		hdr->section_size = 0x2;
//		hdr->partition_minor = args->minor;
//		hdr->generation = 1;
//		hdr->section_in_minor = i;
//		hdr->next_section = get_physical_section(dir, args->minor, i + 1);
//
//		iov_iter_kvec(&iter, /*ITER_KVEC |*/ WRITE, &iov, 1, sizeof(struct igf_sect_hdr));
//
//		vfs_iter_write(private->file, &iter, &phys_pos, 0);
//	}
//
//	{
//		struct kvec iov = {
//			.iov_base = dir,
//			.iov_len = DIR_SIZE,
//		};
//		struct iov_iter i;
//		loff_t phys_pos = DIR_OFFSET;
//
//		iov_iter_kvec(&i, /*ITER_KVEC |*/ WRITE, &iov, 1, DIR_SIZE);
//		vfs_iter_write(private->file, &i, &phys_pos, 0);
//	}
//
//	file_end_write(private->file);
//
//	memcpy(&private->dir, dir, sizeof(*dir));
//
//	err = igel_loop_add_minor(private, args->minor, 0);
////out_part:
//	kfree(part_hdr);
//out_directory:
//	kfree(dir);
//out_unlock:
//	mutex_unlock(&igel_loop_ctl_mutex);
//	return err;
//}

static int lo_ioctl(struct block_device *bdev, fmode_t mode,
	unsigned int cmd, unsigned long arg)
{
	struct igel_loop_device *lo = bdev->bd_disk->private_data;
	int err;

	switch (cmd) {
//	case IGFLASH_CREATE_PARTITON:
//	{
//		struct igf_create_part_args args;
//		if (copy_from_user(&args, (struct igf_create_part_args *)arg, sizeof(args))) {
//			return -EINVAL;
//		}
//
//		return create_new_rw_partition(lo->igel_private, &args);
//	}
	case LOOP_SET_FD:
		return loop_set_fd(lo, mode, bdev, arg);
	case LOOP_CHANGE_FD:
		return loop_change_fd(lo, bdev, arg);
	case LOOP_CLR_FD:
		return loop_clr_fd(lo, true);
	case LOOP_SET_STATUS64:
		err = -EPERM;
		if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN)) {
			err = loop_set_status64(lo,
					(struct loop_info64 __user *) arg);
		}
		break;
	case LOOP_GET_STATUS64:
		return loop_get_status64(lo, (struct loop_info64 __user *) arg);
	case LOOP_SET_CAPACITY:
	case LOOP_SET_DIRECT_IO:
	case LOOP_SET_BLOCK_SIZE:
		if (!(mode & FMODE_WRITE) && !capable(CAP_SYS_ADMIN))
			return -EPERM;
		/* Fall through */
		fallthrough;
	default:
		err = lo_simple_ioctl(lo, cmd, arg);
		break;
	}

	return err;
}

#if 0
//#ifdef LXOS_DEV
static void print_current_tree(int num)
{
	struct task_struct *it = current;

	while (it) {
		char *cmdline = kstrdup_quotable_cmdline(it, GFP_KERNEL);
		printk("igel-loop open(%d): %d -> %s\n", num, it->pid, cmdline);
		kfree(cmdline);

		if (it->pid == 0) {
			break;
		}
		it = it->real_parent;
		
	}
}
//#else
//static void print_current_tree(int num) {}
//#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
static int lo_open(struct block_device *bdev, fmode_t mode)
{
	struct igel_loop_device *lo = bdev->bd_disk->private_data;
	int err;

	if (!lo)
		return -ENXIO;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;

	if (lo->lo_state == Lo_deleting)
		err = -ENXIO;
	else
		atomic_inc(&lo->lo_refcnt);

	mutex_unlock(&lo->lo_mutex);

	return err;
}
#else
static int lo_open(struct gendisk *disk, blk_mode_t mode)
{
	struct igel_loop_device *lo = disk->private_data;
	int err;

	if (!lo)
		return -ENXIO;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;

	if (lo->lo_state == Lo_deleting || lo->lo_state == Lo_rundown)
		err = -ENXIO;
	else
		atomic_inc(&lo->lo_refcnt);

	mutex_unlock(&lo->lo_mutex);

	return err;
}
#endif

static int igel_loop_remove(struct igel_loop_device *lo, bool release)
{
	struct igel_loop_private *private = lo->igel_private;

	__loop_clr_fd(lo, release);

	if (lo->lo_igel_info.is_invalidated && lo->lo_number > 0 && lo->lo_number != sys_minor) {
		igel_inval_from_private(lo->igel_private, lo->lo_number);

		proc_igel_remove_part(lo);
	}

	/**
	 * The issue here: We can't loop_remove in the release context :/
	 * We will keep this device around, but it should be free soon-ish.
	 * When it's free, it's save to remove the driver / delete the device
	 */
	if (!release) {
		if (!lo->lo_number) {
			private->part_zero = NULL;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
		lo->lo_state = Lo_deleting;
		mutex_unlock(&lo->lo_mutex);
#endif
		idr_remove(&private->minors, lo->lo_number);
		loop_remove(lo);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	}
#else
	} else {
		mutex_unlock(&lo->lo_mutex);
	}
#endif

	if (!private->part_zero && idr_is_empty(&private->minors)) {
		destroy_igel_loop_device(private);
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
/* If the section was invalidated, we erase the first section of the partition.
 * This contains the partition header and prevents the partition from being
 * found again, if we boot into CRC-check mode.
 * FIXME: discard the entire storage taken up by partition (aka TRIM) */
static void lo_release(struct gendisk *disk, fmode_t mode)
{
	struct igel_loop_device *lo = disk->private_data;

	mutex_lock(&lo->lo_mutex);

	if (atomic_dec_return(&lo->lo_refcnt))
		goto out_unlock;

	if (lo->lo_flags & LO_FLAGS_AUTOCLEAR) {
		if (lo->lo_state != Lo_bound)
			goto out_unlock;
		lo->lo_state = Lo_rundown;
		/*
		 * In autoclear mode, stop the loop thread
		 * and remove configuration after last close.
		 * mutex_unlock happening inside igel_loop_remove
		 */
		igel_loop_remove(lo, true);
		return;
	} else if (lo->lo_state == Lo_bound) {
		/*
		 * Otherwise keep thread (if running) and config,
		 * but flush possible ongoing bios in thread.
		 */
		blk_mq_freeze_queue(lo->lo_queue);
		blk_mq_unfreeze_queue(lo->lo_queue);
	}

out_unlock:
	mutex_unlock(&lo->lo_mutex);
}
#else
static void lo_release(struct gendisk *disk)
{
	struct igel_loop_device *lo = disk->private_data;

	mutex_lock(&lo->lo_mutex);

	if (atomic_dec_return(&lo->lo_refcnt))
		goto out_unlock;

	if (lo->lo_state == Lo_bound && (lo->lo_flags & LO_FLAGS_AUTOCLEAR)) {
		if (lo->lo_state != Lo_bound)
			goto out_unlock;
		lo->lo_state = Lo_rundown;
		/*
		 * In autoclear mode, stop the loop thread
		 * and remove configuration after last close.
		 * mutex_unlock happening inside igel_loop_remove
		 */
		igel_loop_remove(lo, true);
		return;
	}

out_unlock:
	mutex_unlock(&lo->lo_mutex);
}
#endif

static const struct block_device_operations lo_fops = {
	.owner =	THIS_MODULE,
	.open =		lo_open,
	.release =	lo_release,
	.ioctl =	lo_ioctl,
};

/*
 * And now the modules code and kernel interface.
 */
module_param(max_part, int, 0);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per loop device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(LOOP_MAJOR);

static blk_status_t loop_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct igel_loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct igel_loop_device *lo = rq->q->queuedata;

	blk_mq_start_request(rq);

	if (lo->lo_state != Lo_bound)
		return BLK_STS_IOERR;

	switch (req_op(rq)) {
	case REQ_OP_FLUSH:
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		cmd->use_aio = false;
		break;
	default:
		cmd->use_aio = lo->use_dio;
		break;
	}

	/* always use the first bio's css */
	/*
#ifdef CONFIG_BLK_CGROUP
	if (cmd->use_aio && rq->bio && rq->bio->bi_css) {
		cmd->css = rq->bio->bi_css;
		css_get(cmd->css);
	} else
#endif
*/ // FIXME: This is changes for 5.0 Revisit!
		cmd->css = NULL;
	kthread_queue_work(&lo->worker, &cmd->work);

#if 0
	loff_t pos = ((loff_t) blk_rq_pos(rq) << 9);
	if (op_is_write(req_op(rq)) && lo->lo_number != 254 && pos < 4096 * 1024) {
		printk("igel-loop(%d): Writing to luks header! %s(%d)\n", lo->lo_number, current->comm, current->pid);
	}
#endif

	return BLK_STS_OK;
}

static void loop_handle_cmd(struct igel_loop_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	const bool write = op_is_write(req_op(rq));
	struct igel_loop_device *lo = rq->q->queuedata;
	int ret = 0;

	if (write && (lo->lo_flags & LO_FLAGS_READ_ONLY)) {
		ret = -EIO;
		goto failed;
	}

	ret = do_req_filebacked(lo, rq);
 failed:
	/* complete non-aio request */
	if (!cmd->use_aio || ret) {
		cmd->ret = ret ? -EIO : 0;
		blk_mq_complete_request(rq);
	}
}

static void loop_queue_work(struct kthread_work *work)
{
	struct igel_loop_cmd *cmd =
		container_of(work, struct igel_loop_cmd, work);

	loop_handle_cmd(cmd);
}

static int loop_init_request(struct blk_mq_tag_set *set, struct request *rq,
		unsigned int hctx_idx, unsigned int numa_node)
{
	struct igel_loop_cmd *cmd = blk_mq_rq_to_pdu(rq);

	kthread_init_work(&cmd->work, loop_queue_work);
	return 0;
}

static const struct blk_mq_ops loop_mq_ops = {
	.queue_rq       = loop_queue_rq,
	.init_request	= loop_init_request,
	.complete	= lo_complete_rq,
};

static int loop_add(struct igel_loop_device **l,
                    struct igel_loop_private *private,
                    const char *basename, int i,
		    int mount_order, uint32_t cmty_pkid)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	struct queue_limits lim = {
		/*
		 * Random number picked from the historic block max_sectors cap.
		 */
		.max_hw_sectors		= 2560u,
	};
#endif
	struct igel_loop_device *lo;
	struct gendisk *disk;
	int err;

	err = -ENOMEM;
	lo = kzalloc(sizeof(*lo), GFP_KERNEL);
	if (!lo)
		goto out;

	lo->lo_state = Lo_unbound;
	lo->mount_order = mount_order;
	lo->cmty_pkid = cmty_pkid;

	err = mutex_lock_killable(&igel_loop_ctl_mutex);
	if (err) {
		goto out_free_dev;
	}
	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i > 0) {
		err = idr_alloc(&private->minors, lo, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = 0;
		//err = idr_alloc(&private->minors, lo, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_unlock;
	i = err;

	err = -ENOMEM;
	lo->tag_set.ops = &loop_mq_ops;
	lo->tag_set.nr_hw_queues = 1;
	lo->tag_set.queue_depth = 128;
	lo->tag_set.numa_node = NUMA_NO_NODE;
	lo->tag_set.cmd_size = sizeof(struct igel_loop_cmd);
	lo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	lo->tag_set.driver_data = lo;

	err = blk_mq_alloc_tag_set(&lo->tag_set);
	if (err)
		goto out_free_idr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
	lo->lo_queue = blk_mq_init_queue(&lo->tag_set);
	if (IS_ERR_OR_NULL(lo->lo_queue)) {
		err = PTR_ERR(lo->lo_queue);
		goto out_cleanup_tags;
	}
	lo->lo_queue->queuedata = lo;

	blk_queue_max_hw_sectors(lo->lo_queue, BLK_DEF_MAX_SECTORS);

	/*
	 * By default, we do buffer IO, so it doesn't make sense to enable
	 * merge because the I/O submitted to backing file is handled page by
	 * page. For directio mode, merge does help to dispatch bigger request
	 * to underlayer disk. We will enable merge once directio is enabled.
	 */
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->lo_queue);

	err = -ENOMEM;
	disk = lo->lo_disk = alloc_disk(1 << part_shift);
	if (!disk)
		goto out_free_queue;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
	disk = lo->lo_disk = blk_mq_alloc_disk(&lo->tag_set, lo);
#else
	disk = lo->lo_disk = blk_mq_alloc_disk(&lo->tag_set, &lim, lo);
#endif
        if (IS_ERR(disk)) {
                err = PTR_ERR(disk);
                goto out_cleanup_tags;
        }
        lo->lo_queue = lo->lo_disk->queue;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,8,0)
        blk_queue_max_hw_sectors(lo->lo_queue, BLK_DEF_MAX_SECTORS);
#else
        blk_queue_max_hw_sectors(lo->lo_queue, BLK_DEF_MAX_SECTORS_CAP);
#endif

        /*
         * By default, we do buffer IO, so it doesn't make sense to enable
         * merge because the I/O submitted to backing file is handled page by
         * page. For directio mode, merge does help to dispatch bigger request
         * to underlayer disk. We will enable merge once directio is enabled.
         */
        blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->lo_queue);

#endif

	/*
	 * Disable partition scanning by default. The in-kernel partition
	 * scanning can be requested individually per-device during its
	 * setup. Userspace can always add and remove partitions from all
	 * devices. The needed partition minors are allocated from the
	 * extended minor space, the main loop device numbers will continue
	 * to match the loop minors, regardless of the number of partitions
	 * used.
	 *
	 * If max_part is given, partition scanning is globally enabled for
	 * all loop devices. The minors for the main loop devices will be
	 * multiples of max_part.
	 *
	 * Note: Global-for-all-devices, set-only-at-init, read-only module
	 * parameteters like 'max_loop' and 'max_part' make things needlessly
	 * complicated, are too static, inflexible and may surprise
	 * userspace tools. Parameters like this in general should be avoided.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,132)
	if (!part_shift)
		disk->flags |= GENHD_FL_NO_PART;
#else
	if (!part_shift)
		disk->flags |= GENHD_FL_NO_PART_SCAN;
	disk->flags |= GENHD_FL_EXT_DEVT;
#endif
	atomic_set(&lo->lo_refcnt, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	mutex_init(&lo->lo_mutex);
#endif
	lo->lo_number		= i;
	spin_lock_init(&lo->lo_lock);
	disk->major		= private->major;
	disk->first_minor	= i << part_shift;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	disk->minors		= 1 << part_shift;
#endif
	disk->fops		= &lo_fops;
	disk->private_data	= lo;
	disk->queue		= lo->lo_queue;
	sprintf(disk->disk_name, "%s%d", basename, i);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)
	add_disk(disk);
#else
	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;
#endif
	*l = lo;
	mutex_unlock(&igel_loop_ctl_mutex);
	return lo->lo_number;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
out_free_queue:
	blk_cleanup_queue(lo->lo_queue);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
out_cleanup_disk:
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
        blk_cleanup_disk(disk);
#else
	put_disk(disk);
#endif
#endif
out_cleanup_tags:
	blk_mq_free_tag_set(&lo->tag_set);
out_free_idr:
	idr_remove(&private->minors, i);
out_unlock:
	mutex_unlock(&igel_loop_ctl_mutex);
out_free_dev:
	kfree(lo);
out:
	return err;
}

static void loop_remove(struct igel_loop_device *lo)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
	del_gendisk(lo->lo_disk);
	blk_cleanup_queue(lo->lo_queue);
	blk_mq_free_tag_set(&lo->tag_set);
	put_disk(lo->lo_disk);
#else
	del_gendisk(lo->lo_disk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
	blk_cleanup_disk(lo->lo_disk);
#else
	put_disk(lo->lo_disk);
#endif
	blk_mq_free_tag_set(&lo->tag_set);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	mutex_destroy(&lo->lo_mutex);
#endif
	kfree(lo);
}

//static int find_free_cb(int id, void *ptr, void *data)
//{
//	struct igel_loop_device *lo = ptr;
//	struct igel_loop_device **l = data;
//
//	if (lo->lo_state == Lo_unbound) {
//		*l = lo;
//		return 1;
//	}
//	return 0;
//}

//static int loop_lookup(struct igel_loop_device **l, int i)
//{
//	struct igel_loop_device *lo;
//	int ret = -ENODEV;
//
//	if (i < 0) {
//		int err;
//
//		err = idr_for_each(&igel_loop_index_idr, &find_free_cb, &lo);
//		if (err == 1) {
//			*l = lo;
//			ret = lo->lo_number;
//		}
//		goto out;
//	}
//
//	/* lookup and return a specific i */
//	lo = idr_find(&igel_loop_index_idr, i);
//	if (lo) {
//		*l = lo;
//		ret = lo->lo_number;
//	}
//out:
//	return ret;
//}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
static struct kobject *loop_probe(dev_t dev, int *part, void *data)
{
	//struct igel_loop_device *lo;
	struct kobject *kobj = NULL;
	//int err;

	mutex_lock(&igel_loop_ctl_mutex);
//	err = loop_lookup(&lo, MINOR(dev) >> part_shift);
//	if (err < 0)
//		err = loop_add(&lo, data, MINOR(dev) >> part_shift);
//	if (err < 0)
//		kobj = NULL;
//	else
//		kobj = get_disk_and_module(lo->lo_disk);
	mutex_unlock(&igel_loop_ctl_mutex);

	*part = 0;
	return kobj;
}
#endif

static int remove_igel_loop_device(struct igel_loop_private *private)
{
	int ret = 0;
	unsigned long id;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
	unsigned long tmp;
#endif
	struct igel_loop_device *lo;

	mutex_lock(&igel_loop_ctl_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
	idr_for_each_entry_ul(&private->minors, lo, tmp, id) {
#else
	idr_for_each_entry_ul(&private->minors, lo, id) {
#endif
		int tmp;
		if ((tmp = loop_clr_fd(lo, false))) {
			if (tmp == -EAGAIN) {
				ret = -EAGAIN;
			} else {
				printk("igel-loop: Failed to clear fd: %d\n", tmp);
			}
		}
	}
	proc_igel_remove(private);
	ret = loop_clr_fd(private->part_zero, false);
	mutex_unlock(&igel_loop_ctl_mutex);

	return ret;
}

static int create_igel_loop_file(struct file *file, int major, const char *name);

static int add_new_device(struct igel_flash_dev_desc *desc)
{
	int ret = 0;
	struct igel_loop_private *priv;
	struct file *file;

	if (strnlen(desc->name, sizeof(desc->name)) >= sizeof(desc->name)) {
		return -EINVAL;
	}

	if (!(file = fget(desc->fd))) {
		return -EBADF;
	}

	list_for_each_entry(priv, &loop_private, link) {
		if (priv->file->f_inode == file->f_inode) {
			printk("igel-loop: Tried to allocate a new igflach device for file already used!\n");
			ret = -EEXIST;
			goto out_file;
		}
	}

	if (register_blkdev(desc->major, desc->name)) {
		ret = -EIO;
		goto out_file;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	blk_register_region(MKDEV(desc->major, 0), DIR_MAX_MINORS,
				  THIS_MODULE, loop_probe, NULL, "igel-loop");
#endif


	if ((ret = create_igel_loop_file(file, desc->major, desc->name))) {
		printk("igel-loop: Failed to create loop file\n");
		goto out_dev;
	}

	return 0;

out_dev:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	blk_unregister_region(MKDEV(desc->major, 0), DIR_MAX_MINORS);
#endif
	unregister_blkdev(desc->major, desc->name);
out_file:
	fput(file);
	return ret;
}

static long loop_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	int ret;

//	ret = mutex_lock_killable(&igel_loop_ctl_mutex);
//	if (ret)
//		return ret;

	ret = -ENOSYS;
	switch (cmd) {
	case IGFLASH_REMOVE_DEVICE:
	{
		struct igel_loop_private *priv, *tmp;
		char name[25];
		long retval = 0;

		name[sizeof(name) - 1] = '\0';
		retval = strncpy_from_user(name,
			                  (const char __user *)parm,
			                  sizeof(name) - 1);

		if (retval < 0)
			return -ENOENT;

		list_for_each_entry_safe(priv, tmp, &loop_private, link) {
			if (!strcmp(priv->basename, name)) {
				int ret;
				ret = remove_igel_loop_device(priv);

				return ret;
			}
		}

		return -ENOENT;
		break;
	}
	case IGFLASH_ADD_DEVICE:
	{
		struct igel_flash_dev_desc desc;
		if (max_devices) {
			int count = 0;
			struct list_head *it;
			list_for_each(it, &loop_private) {
				++count;
			}
			if (count >= max_devices) {
				ret = -ENOSPC;
				break;
			}
		}
		if (!parm) {
			ret = -EIO;
			break;
		}
		if (copy_from_user(&desc, (void *)parm, sizeof (desc))) {
			ret = -EIO;
			break;
		}

		ret = add_new_device(&desc);
		break;
	}
	case LOOP_CTL_ADD:
	case LOOP_CTL_REMOVE:
	case LOOP_CTL_GET_FREE:
		break;
	}
//	mutex_unlock(&igel_loop_ctl_mutex);

	return ret;
}

static ssize_t loop_control_write(struct file *file, const char __user *data, size_t len, loff_t *offset)
{
	struct igel_loop_private *priv, *tmp;
	list_for_each_entry_safe(priv, tmp, &loop_private, link) {
		remove_igel_loop_device(priv);
	}
	return len;
}

static const struct file_operations loop_ctl_fops = {
	.open		= nonseekable_open,
	.write          = loop_control_write,
	.unlocked_ioctl	= loop_control_ioctl,
	.compat_ioctl	= loop_control_ioctl,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

static struct miscdevice loop_misc = {
	.minor		= LOOP_CTRL_MINOR + 10,
	.name		= "igel-control",
	.fops		= &loop_ctl_fops,
};

static int write_dir(struct file *file, struct directory *dir)
{
	uint8_t *buffer;
	int ret;
	struct igel_section_allocation *allocation = make_section_allocation();
	if (!allocation) {
		return -ENOMEM;
	}
	buffer = allocation->vmapping;
	memcpy(buffer + DIR_OFFSET, dir, sizeof(*dir));


	file_start_write(file);
	ret = write_section_allocation(allocation, DIR_OFFSET, sizeof(*dir),
		file, 0);
	file_end_write(file);
	free_section_allocation(allocation);
	return ret;
}

static int read_dir(struct file *file, struct directory *dir)
{
	uint8_t *buffer;
	struct igel_section_allocation *allocation = make_section_allocation();
	if (!allocation) {
		return -ENOMEM;
	}
	if (read_section_allocation(allocation, file, 0)) {
		free_section_allocation(allocation);
		return -EIO;
	}

	buffer = allocation->vmapping;
	memcpy(dir, buffer + DIR_OFFSET, sizeof(*dir));

	free_section_allocation(allocation);
	return 0;
}

//int build_hash_info(struct igel_loop_device *lo);
int build_hash_info(struct igel_loop_private *private, int part, uint8_t **blk_ptr,
		    int *mount_order, uint32_t *cmty_pkid);

static int setup_igel_information(struct igel_loop_device *lo,
		struct igel_loop_private *private)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	struct block_device *bdev = NULL, *bdev_ref = NULL;
#else
	struct block_device *bdev = NULL;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	struct file *bdev_file;
# else
	struct bdev_handle *bdev_handle;
# endif /* 6.9.0 */
#endif

	struct igf_sect_hdr shdr;
	struct partition_descriptor *pdesc = &private->dir.partition[lo->lo_number];
	size_t i = 0;
	int ret = 0;


	lo->lo_igel_info.first_section = private->dir.fragment[pdesc->first_fragment].first_section;
	if (read_igf_sect_header(&shdr, lo->lo_igel_info.first_section, private->file)) {
		return -1;
	}
	if (read_igf_part_header(&lo->lo_igel_info.phdr, lo->lo_igel_info.first_section, private->file)) {
		return -1;
	}


	/* special case for minor 1 since there are bootloaders out there not working with
	 * set PFLAG_HAS_IGEL_HASH we must use the ident block of the hash header to detect
	 * its presence */

	if (! lo->lo_igel_info.has_hash_info) {
		struct igel_hash_header hash_hdr;
		int ret;
		loff_t off = START_OF_SECTION(lo->lo_igel_info.first_section)
			     + IGF_SECT_HDR_LEN + sizeof(struct igf_part_hdr)
			     + sizeof(struct igf_partition_extent) * lo->lo_igel_info.phdr.n_extents;
                ret = kernel_read(private->file, (void __user *)&hash_hdr,
                         sizeof(struct igel_hash_header),
                         &off);
                if (ret == sizeof(struct igel_hash_header)) {
                        if (hash_hdr.ident[0] == 'c' &&
			    hash_hdr.ident[1] == 'h' &&
			    hash_hdr.ident[2] == 'k' &&
			    hash_hdr.ident[3] == 's' &&
			    hash_hdr.ident[4] == 'u' &&
			    hash_hdr.ident[5] == 'm') {
				lo->lo_igel_info.has_hash_info = 1;
			}
                }
	}

	lo->lo_igel_info.part_exts.n_extents = lo->lo_igel_info.phdr.n_extents;

	{
		loff_t off = START_OF_SECTION(lo->lo_igel_info.first_section) + IGF_SECT_HDR_LEN + sizeof(struct igf_part_hdr);
		int ret;

		ret = kernel_read(private->file, (void __user *)lo->lo_igel_info.part_exts.extent,
			 sizeof(struct igf_partition_extent) * lo->lo_igel_info.phdr.n_extents,
			 &off);
		if (ret != sizeof(struct igf_partition_extent) * lo->lo_igel_info.phdr.n_extents) {
			return -1;
		}
	}


	for (i = 0; i < pdesc->n_fragments; ++i) {
		struct fragment_descriptor *desc = &private->dir.fragment[pdesc->first_fragment + i];
		lo->lo_igel_info.num_sections += desc->length;
		lo->lo_igel_info.lastsect = desc->first_section + desc->length;
	}

	lo->lo_igel_info.magic = shdr.magic;
	lo->lo_igel_info.generation_number = shdr.generation;
	lo->lo_hdrlen = IGF_SECT_HDR_LEN;
	if ((lo->lo_igel_info.phdr.type & 0xFF) == PTYPE_IGEL_RAW_4K_ALIGNED) {
		lo->lo_hdrlen = 4096;
	}
	lo->igel_private = private;
	lo->lo_igel_info.is_valid = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
	bdev = xa_load(&lo->lo_disk->part_tbl, 0);
#else
	bdev = bdget_disk(lo->lo_disk, 0);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
# if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	bdev_ref = bdgrab(bdev);
# else
	bdev_ref = bdev;
# endif /* 5.13.0 */
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
#  if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
	blkdev_get_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
#  else
#   if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
	bdev_handle =    bdev_open_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
#   else
	bdev_file = bdev_file_open_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
#   endif /* 6.9.0 */
#  endif /* 6.8.0 */
# else
	blkdev_get_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL);
# endif /* 6.5.0 */
#else
	blkdev_get(bdgrab(bdev), FMODE_READ | FMODE_WRITE, NULL);
#endif /* 5.10.0 */
	set_igel_offset(lo);
	loop_set_file(lo, lo->lo_igel_info.phdr.type == PTYPE_IGEL_RAW_RO ? FMODE_READ : FMODE_READ | FMODE_WRITE, bdev, get_file(private->file));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
# if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
	blkdev_put(bdev, NULL);
# else
#  if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
	bdev_release(bdev_handle);
	bdev_handle = NULL;
#  else
	bdev_fput(bdev_file);
#  endif /* 6.9.0 */
# endif /* 6.8.0 */
#else
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
#endif /* 6.5.0 */

	return ret;
}


static int igel_loop_add_minor(struct igel_loop_private *private, size_t minor, int only_raw_ro)
{
	int ret = 0;
	struct igel_loop_device *lo = NULL;
	size_t section;
	struct igf_part_hdr hdr;
	uint8_t type;
	uint8_t *hash_block = NULL;
	int mount_order = 0;
	uint32_t cmty_pkid = 0;

	if (!private->dir.partition[minor].n_fragments) {
		return 1;
	}
	section = private->dir.fragment[private->dir.partition[minor].first_fragment].first_section;
	if (read_igf_part_header(&hdr, section, private->file)) {
		return -1;
	}

	type = hdr.type & 0xFF;
	if (only_raw_ro && type != PTYPE_IGEL_RAW_RO)
		return -1;
	if (type != PTYPE_IGEL_RAW_RO && type != PTYPE_IGEL_RAW && type != PTYPE_IGEL_RAW_4K_ALIGNED) {
		printk("Skipping part %zu, because it's type: %s\n",
		       minor, get_part_type_name(hdr.type));
		printk("Hdrlen: %u, offset_blocks: %llu\n", hdr.hdrlen, hdr.offset_blocks);
		return -1;
	}

	if (type == PTYPE_IGEL_RAW_RO) {
		if ((ret = build_hash_info(private, minor, &hash_block, &mount_order, &cmty_pkid))) {
			printk("igel-loop: Not adding %zu because hash info couldn't be built: %d\n",
			       minor, ret);
			return ret;
		}
	}

	ret = loop_add(&lo, private, private->basename, minor, mount_order, cmty_pkid);
	if (ret < 0) {
		return ret;
	}
	ret = setup_igel_information(lo, private);
	if (ret) {
		loop_remove(lo);
		return ret;
	}
	if (hash_block) {
		lo->lo_igel_info.has_hash_info = 1;
		lo->lo_igel_info.hash_block = hash_block;
	}

	//idr_alloc(&private->minors, lo, minor, minor + 1, GFP_KERNEL);
	return 0;
}

static int loop_summary_cb(int id, void *ptr, void *data)
{
	struct igel_loop_device *lo = ptr;

	printk("igel-loop: /dev/%s%d: capacity: %llu, sections (256K): %u, %s, gen: %u\n",
	       lo->igel_private->basename,
	       lo->lo_number, get_igel_size(lo), lo->lo_igel_info.num_sections,
	       "uncompressed (raw)",
	       lo->lo_igel_info.generation_number);

	return 0;
}

static int create_igel_loop_file(struct file *file, int major, const char *name)
{
	int ret;
	size_t i;
	struct igel_loop_private *private;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	struct block_device *bdev = NULL, *bdev_ref = NULL;
#else
	struct block_device *bdev = NULL;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	struct file *bdev_file;
# else
	struct bdev_handle *bdev_handle;
# endif
#endif

	printk("Going to add device for '%s'\n", name);
	private = vzalloc(sizeof(*private));
	if (!private) {
		return -ENOMEM;
	}

	if (failsafe || read_dir(file, &private->dir)) {
		printk("igel-loop: Going to build directory\n");
		if (build_directory(file, &private->dir, crc_check, sys_minor)) {
			printk("igel-loop: Failed to build a directory :/\n");
			vfree(private);
			return -1;
		}
	}

	private->major = major;
	snprintf(private->basename, sizeof(private->basename), "%s", name);
	private->file = get_file(file);
	idr_init(&private->minors);
	idr_init(&private->crc_cache);

	ret = loop_add(&private->part_zero, private, name, 0, 0, 0);
	if (ret < 0) {
		printk("igel-loop: Failed to add part_zero\n");
		return ret;
	}
	private->part_zero->igel_private = private;

	/* This is a bit through the back into the front, but we have to do
	 * go this weirdo way because we aren't supposed to open the file
	 * from kernel code */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
	bdev = xa_load(&private->part_zero->lo_disk->part_tbl, 0);
#else
	bdev = bdget_disk(private->part_zero->lo_disk, 0);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	bdev_ref = bdgrab(bdev);
#else
	bdev_ref = bdev;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
# if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
	blkdev_get_by_dev(bdev->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
# else
#  if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
	bdev_handle =    bdev_open_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
#  else
	bdev_file = bdev_file_open_by_dev(bdev_ref->bd_dev, FMODE_READ | FMODE_WRITE, NULL, NULL);
#  endif /* 6.9.0 */
# endif
#else
	blkdev_get_by_dev(bdev->bd_dev, FMODE_READ | FMODE_WRITE, NULL);
#endif
#else
	blkdev_get(bdgrab(bdev), FMODE_READ | FMODE_WRITE, NULL);
#endif
	loop_set_file(private->part_zero, FMODE_READ | FMODE_WRITE, bdev, get_file(file));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
# if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
	blkdev_put(bdev, NULL);
# else
#  if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
	bdev_release(bdev_handle);
	bdev_handle = NULL;
#  else
	bdev_fput(bdev_file);
#  endif /* 6.9.0 */
# endif /* 6.8.0 */
#else
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
#endif /* 6.5.0 */



	/* Skip 0. It's not useful here */
	/* The sys partition (sys_minor) has some special handling,
	 * because it contains the update utility and everything we need to
	 * actually display anything! */
	if ((ret = igel_loop_add_minor(private, sys_minor, 0)) < 0) {
		if (ret == -EKEYREJECTED) {
			loop_remove(private->part_zero);
			idr_destroy(&private->minors);
			idr_destroy(&private->crc_cache);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
			mutex_unlock(&igel_loop_ctl_mutex);
#endif
			vfree(private);
			printk("igel-loop: system partition rejected for non-verifiable partition signature!\n");
			return ret;
		}
	}

	/* Skip sys_minor. It has some special handling.*/
	for (i = 1; i < private->dir.max_minors; ++i) {
		if (i == sys_minor)
			continue;
		if ((ret = igel_loop_add_minor(private, i, 0)) < 0) {
			if (ret == -EKEYREJECTED) {
				printk("igel-loop: Did not add '%zu' partition. Signature verification failed!\n", i);
			} else {
				printk("igel-loop: Error during setup of partition '%zu': %d\n",
				       i, ret);
			}
		}
	}

	mutex_lock(&igel_loop_ctl_mutex);
	list_add(&private->link, &loop_private);
	mutex_unlock(&igel_loop_ctl_mutex);

	init_waitqueue_head(&private->validate_wait);
	proc_igel_create(private);

	printk("igel-loop: Registered %s:%d (%llu)\n", private->basename, private->major,
	       get_loop_size(private->part_zero, private->file));

	idr_for_each(&private->minors, &loop_summary_cb, NULL);

	return 0;
}

static int kfree_cb(int id, void *ptr, void *data)
{
	kfree(ptr);
	return 0;
}

static void destroy_igel_loop_device(struct igel_loop_private *private)
{
	idr_for_each(&private->crc_cache, &kfree_cb, NULL);
	idr_destroy(&private->crc_cache);
	idr_destroy(&private->minors);
	fput(private->file);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	blk_unregister_region(MKDEV(private->major, 0), DIR_MAX_MINORS);
#endif
	unregister_blkdev(private->major, private->basename);
	printk("igel-loop: Unregistered %s:%d\n", private->basename, private->major);
	list_del(&private->link);
	vfree(private);
}

/* Taking a filename is a temporary evil */
static int create_igel_loop_name(const char *filename)
{
	struct  file *file = filp_open(filename,O_RDWR|O_LARGEFILE,0x00);
	int ret;

	if (!file) {
		return -ENOENT;
	}

	if (register_blkdev(LOOP_MAJOR, IGF_DEV_NAME)) {
		return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	blk_register_region(MKDEV(LOOP_MAJOR, 0), DIR_MAX_MINORS,
				  THIS_MODULE, loop_probe, NULL, IGF_DEV_NAME);
#endif

	ret = create_igel_loop_file(file, LOOP_MAJOR, IGF_DEV_NAME);
	fput(file);

	if (ret) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
		blk_unregister_region(MKDEV(LOOP_MAJOR, 0), DIR_MAX_MINORS);
#endif
		unregister_blkdev(LOOP_MAJOR, IGF_DEV_NAME);
	}

	return ret;
}

static void register_key(key_ref_t keyring, const char *name,
                         const uint8_t *data, size_t keylen)
{
	key_ref_t keyref;
	keyref = key_create_or_update(make_key_ref(igf_keyring, 1),
	                     "user", name, data, keylen,
			     KEY_OTH_VIEW | KEY_OTH_READ | KEY_OTH_WRITE | KEY_OTH_SEARCH|
			     KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE | KEY_USR_SEARCH,
			     KEY_ALLOC_NOT_IN_QUOTA | KEY_ALLOC_BUILT_IN | KEY_ALLOC_BYPASS_RESTRICTION);

	key_ref_put(keyref);
}

static int keystuff_init(void)
{
	key_ref_t test_ref;
	size_t i;
	igf_keyring = keyring_alloc("IGF_PARTITION_KEYS",
		              KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
		              ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			        KEY_OTH_VIEW | KEY_OTH_READ | KEY_OTH_WRITE | KEY_OTH_SEARCH|
			        KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);


	for (i = 0; i < igel_key_count; ++i) {
		register_key(test_ref,
		             igel_keystore[i].name,
		             igel_keystore[i].data,
		             igel_keystore[i].len);
	}

	return 0;
}

MODULE_ALIAS_MISCDEV(LOOP_CTRL_MINOR);
MODULE_ALIAS("devname:igel-control");

static int __init loop_init(void)
{
	int err;

	if ((err = keystuff_init())) {
		goto err_out;
	}

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can decide correct minor number
		 * if [s]he want to create more devices.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}

	if ((1UL << part_shift) > DISK_MAX_PARTS) {
		err = -EINVAL;
		goto err_out;
	}

	err = misc_register(&loop_misc);
	if (err < 0)
		goto err_out;

	proc_igel_startup();
	if (file) {
		if (create_igel_loop_name(file)) {
			err = -EIO;
			goto misc_out;
		}
	}

	printk(KERN_INFO "igel-loop: module loaded\n");
	return 0;


misc_out:
	misc_deregister(&loop_misc);
	proc_igel_cleanup();
err_out:
	return err;
}

static int loop_exit_cb(int id, void *ptr, void *data)
{
	struct igel_loop_device *lo = ptr;

	printk("Removing: %d\n", lo->lo_number);
	loop_remove(lo);
	return 0;
}

static void __exit loop_exit(void)
{
	idr_for_each(&igel_loop_index_idr, &loop_exit_cb, NULL);
	idr_destroy(&igel_loop_index_idr);

	misc_deregister(&loop_misc);
	if (igf_keyring) {
		keyring_clear(igf_keyring);
		key_put(igf_keyring);
		igf_keyring = NULL;
	}
	proc_igel_cleanup();
	printk(KERN_INFO "igel-loop: module unloaded\n");
}

module_init(loop_init);
module_exit(loop_exit);

#ifndef MODULE
static int __init max_loop_setup(char *str)
{
	max_loop = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_loop=", max_loop_setup);
#endif

