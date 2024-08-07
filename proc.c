#include <linux/bvec.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "section_allocation.h"
#include "loop.h"
#include "igel.h"

/* END of section */

static const u_int64_t END_SECTION = 0xffffffffffffffff >> ((8 - sizeof(((struct igf_sect_hdr *)0)->next_section)) * 8);

/* Modulo for section in minor */

static const u_int64_t MOD_SECT_IN_MINOR = (u_int64_t) 1UL << (sizeof(((struct igf_sect_hdr *)0)->section_in_minor) * 8);

uint32_t calculate_section_hash(uint8_t *section);
void proc_igel_firmware_create_entry(struct igel_loop_device *lo);
void proc_igel_create(struct igel_loop_private *private);
void proc_igel_remove_part(struct igel_loop_device *lo);
void proc_igel_remove(struct igel_loop_private *private);
void proc_igel_cleanup(void);
int proc_igel_startup(void);

static uint32_t
get_section_hash(uint8_t *section, struct igel_loop_private *private,
                 size_t part, size_t max_section, size_t index)
{
	uint32_t *crc_cache = idr_find(&private->crc_cache, part);
	if (!crc_cache) {
		crc_cache = kzalloc(sizeof(uint32_t) * max_section, GFP_KERNEL);

		idr_alloc(&private->crc_cache, crc_cache, part, part + 1, GFP_KERNEL);
	}

	if (!crc_cache[index]) {
		crc_cache[index] = calculate_section_hash(section);
	}

	return crc_cache[index];
}

static int proc_read_sect (struct igel_section_allocation *allocation,
                           struct igel_loop_private *private,
                           int part, int snum)
{
	uint8_t *section = allocation->vmapping;
	uint32_t num_sections = 0;
	uint32_t physical_section;
	size_t read = 0, i;
	struct partition_descriptor *pdesc = &private->dir.partition[part];

	for (i = 0; i < pdesc->n_fragments; ++i) {
		struct fragment_descriptor *desc =
			&private->dir.fragment[pdesc->first_fragment + i];
		num_sections += desc->length;
	}

	physical_section = get_physical_section(&private->dir, part, snum);

	if (physical_section == END_SECTION)
		return -1;

	read = read_section_allocation(allocation, private->file, physical_section);
	if (read)
		return -1;

//	if (lo->lo_igel_info.is_locked == 1)
//		return 0;

	((struct igf_sect_hdr *)section)->section_in_minor = snum % MOD_SECT_IN_MINOR;
	((struct igf_sect_hdr *)section)->generation = 4096;
	((struct igf_sect_hdr *)section)->next_section = num_sections;
	((struct igf_sect_hdr *)section)->crc =
		get_section_hash(section, private, part, num_sections, snum);

	return 0;
}

static ssize_t
proc_read_part(struct file *file, char __user *buf,
	       size_t size, loff_t *ppos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	struct igel_loop_private *private = (struct igel_loop_private *)pde_data(file->f_inode);
#else
	struct igel_loop_private *private = (struct igel_loop_private *)PDE_DATA(file->f_inode);
#endif
	size_t done = 0;
	uint8_t *section = NULL;
	int last_sect = -1;
	int err = 0;
	long part;
	struct igel_section_allocation *allocation = NULL;

	if (kstrtol(file->f_path.dentry->d_iname, 10, &part) || !part) {
		return -EINVAL;
	}

	allocation = make_section_allocation();
	if (allocation == NULL) {
		printk(KERN_ERR "%s: unable to allocate %llu bytes for section\n",
				"igel-loop", (unsigned long long) IGF_SECTION_SIZE);
		return 0;
	}
	section = allocation->vmapping;

	/* read requested size, section by section */
	while (done < size) {
		size_t toread = size - done;
		int curr_sect = ((int)(*ppos+done)) / IGF_SECTION_SIZE;
		loff_t offset = ((int)(*ppos+done)) % IGF_SECTION_SIZE;
		size_t len = IGF_SECTION_SIZE - offset;

		if (toread < len) {
			len = toread;
		}

		/* read section only if it is not the previous one */
		if ((last_sect != curr_sect)) {
			if (proc_read_sect(allocation, private, part, curr_sect)) {
				last_sect = -1;
				break;
			}

			last_sect = curr_sect;
		}

		err = copy_to_user(buf + done, section + offset, len);
		if (err) {
			err = -EFAULT;
			break;
		}
		done += len;
	}

	free_section_allocation(allocation);

	if (done < size) {
		if (done <= 0)
			return err;
	} else
		done = size;

	*ppos += done;
	return done;
}

static int proc_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	struct igel_loop_private *private = (struct igel_loop_private *)pde_data(inode);
#else
	struct igel_loop_private *private = (struct igel_loop_private *)PDE_DATA(inode);
#endif

	atomic_inc(&private->part_zero->lo_refcnt);
	return 0;
}

static int proc_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	struct igel_loop_private *private = (struct igel_loop_private *)pde_data(inode);
#else
	struct igel_loop_private *private = (struct igel_loop_private *)PDE_DATA(inode);
#endif

	atomic_dec(&private->part_zero->lo_refcnt);
	return 0;
}

static ssize_t
proc_verify_read(struct file *file, char __user *buf,
	         size_t size, loff_t *ppos) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	struct igel_loop_private *private = (struct igel_loop_private *)pde_data(file_inode(file));
#else
	struct igel_loop_private *private = (struct igel_loop_private *)PDE_DATA(file_inode(file));
#endif
	int id;
	struct igel_loop_device *entry;
	size_t written = 0;
	char buffer [512];
	int err;

	idr_for_each_entry(&private->minors, entry, id) {
		if (entry->lo_igel_info.has_hash_info && entry->lo_igel_info.has_wrong_hash) {
			written += snprintf(buffer + written, size - written, "%d ", entry->lo_number);
		}
		if (written >= sizeof(buffer)) {
			break;
		}
	}

	if (*ppos < written) {
		err = copy_to_user(buf, buffer + *ppos, written - *ppos);
		if (err) {
			return -EFAULT;
		}
		written = written - *ppos;

		*ppos += written;
	} else {
		written = 0;
	}

	return written;
}

static __poll_t proc_verify_poll(struct file *file, poll_table *wait)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	struct igel_loop_private *private = (struct igel_loop_private *)pde_data(file_inode(file));
#else
	struct igel_loop_private *private = (struct igel_loop_private *)PDE_DATA(file_inode(file));
#endif
	struct igel_loop_device *entry;
	int id;

	poll_wait(file, &private->validate_wait, wait);

	idr_for_each_entry(&private->minors, entry, id) {
		if (entry->lo_igel_info.has_hash_info && entry->lo_igel_info.has_wrong_hash) {
			return EPOLLIN | POLLRDNORM;
		}
	}

	return 0;
}

static int proc_verify_open(struct inode *inode, struct file *file)
{
	return 0;
}


static int proc_verify_release(struct inode *inode, struct file *file)
{
	return 0;
}

static struct proc_dir_entry *proc_igel_root = NULL;
static struct proc_dir_entry *proc_igel_verify = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
static const struct proc_ops proc_verify_fops = {
	.proc_read = proc_verify_read,
	.proc_open = proc_verify_open,
	.proc_poll = proc_verify_poll,
	.proc_release = proc_verify_release,
	.proc_lseek = default_llseek,
};

static const struct proc_ops proc_igel_fops = {
	.proc_read = proc_read_part,
	.proc_open = proc_open,
	.proc_release = proc_release,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations proc_verify_fops = {
	.read = proc_verify_read,
	.open = proc_verify_open,
	.poll = proc_verify_poll,
	.release = proc_verify_release,
	.llseek = default_llseek,
};

static const struct file_operations proc_igel_fops = {
	.read = proc_read_part,
	.open = proc_open,
	.release = proc_release,
	.llseek = default_llseek,
};
#endif

static void proc_igel_verify_create(struct igel_loop_private *private)
{
	if (!strcmp(private->basename, "igf")) {
		proc_igel_verify = proc_create_data("verification", S_IFREG|S_IRUSR|S_IRGRP|S_IROTH, proc_igel_root,
			&proc_verify_fops, (void *)private);
	}
}

void proc_igel_firmware_create_entry(struct igel_loop_device *lo)
{
	struct proc_dir_entry *ent;
	char name[4];

	if (!lo)
		return;
//	if ((lo->lo_igel_info.phdr.type & 0xFF) != PTYPE_IGEL_RAW_RO) {
//		return;
//	}
	if (lo->lo_igel_info.is_locked == 1)
		return;
	sprintf(name, "%d", lo->lo_number);
	ent = proc_create_data(name, S_IFREG|S_IRUSR,
			lo->igel_private->proc_entry,
			&proc_igel_fops, (void *)lo->igel_private);
	if (!ent)
		return;
	proc_set_size(ent, lo->lo_igel_info.num_sections * IGF_SECTION_SIZE);
}

static void proc_igel_firmware_create(struct igel_loop_private *private)
{
	unsigned long id;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
	unsigned long tmp;
#endif
	struct igel_loop_device *lo;

	if (!strcmp(private->basename, "igf")) {
		private->proc_entry = proc_mkdir("firmware", proc_igel_root);
	} else {
		private->proc_entry = proc_mkdir(private->basename,
		                                proc_igel_root);
	}
	if (!private->proc_entry) return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
	idr_for_each_entry_ul(&private->minors, lo, tmp, id) {
#else
	idr_for_each_entry_ul(&private->minors, lo, id) {
#endif
		proc_igel_firmware_create_entry(lo);
	}

	proc_igel_verify_create(private);

	return;
}

void proc_igel_create(struct igel_loop_private *private)
{
//	if (strcmp(cloop_name, "igf") == 0) {
//		proc_igel_root = proc_mkdir("igel", 0);
//	} else {
//		proc_igel_root = proc_mkdir(cloop_name, 0);
//	}

	proc_igel_firmware_create(private);

	return;
}

void proc_igel_remove_part(struct igel_loop_device *lo)
{
	char name[4];

	if (!lo /*|| (lo->lo_igel_info.phdr.type & 0xFF) != PTYPE_IGEL_RAW_RO*/) {
		return;
	}

	if (lo->lo_number && lo->igel_private->proc_entry) {
		sprintf(name, "%d", lo->lo_number);
		remove_proc_entry(name, lo->igel_private->proc_entry);
	}
}

void proc_igel_remove(struct igel_loop_private *private)
{
	if (!proc_igel_root) return;

	if (private->proc_entry) {
		if (!strcmp(private->basename, "igf")) {
			printk("Going to remove firmware directory\n");
			remove_proc_subtree("firmware", proc_igel_root);
		} else {
			remove_proc_subtree(private->basename, proc_igel_root);
		}
	}


	if (proc_igel_verify && strcmp(private->basename, "igf") == 0) {
		proc_remove(proc_igel_verify);
		proc_igel_verify = NULL;
	}

	return;
}

void proc_igel_cleanup(void)
{
	proc_remove(proc_igel_root);
	proc_igel_root = NULL;
}

int proc_igel_startup(void)
{
	if (!(proc_igel_root = proc_mkdir("igel", 0))) {
		return -1;
	}

	return 0;
}
