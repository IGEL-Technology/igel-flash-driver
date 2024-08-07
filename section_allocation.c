#include <linux/bvec.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

#include "section_allocation.h"
#include "igelsdk.h"

void
free_section_allocation(struct igel_section_allocation *allocation)
{
	size_t i;
	for (i = 0;
	     i < sizeof(allocation->pages) / sizeof(allocation->pages[0]);
	     ++i) {
		if (!allocation->pages[i]) {
			break;
		}

		put_page(allocation->pages[i]);
	}
	if (allocation->vmapping) {
		vunmap(allocation->vmapping);
	}
	vfree(allocation);
}

struct igel_section_allocation * 
make_section_allocation(void)
{
	size_t i;
	struct igel_section_allocation *allocation = vzalloc(sizeof(*allocation));
	if (!allocation) {
		return NULL;
	}

	for (i = 0;
	     i < sizeof(allocation->pages) / sizeof(allocation->pages[0]);
	     ++i) {
		allocation->pages[i] = alloc_page(GFP_KERNEL);
		if (!allocation->pages[i]) {
			printk("igel-loop: Failed to allocate page %zu for section allocation\n",
			       i);
			goto fail;
		}

		allocation->bios[i].bv_page = allocation->pages[i];
		allocation->bios[i].bv_len = 4096;
		allocation->bios[i].bv_offset = 0;
	}

	allocation->vmapping = vmap(allocation->pages,
		sizeof(allocation->pages) / sizeof(allocation->pages[0]),
		0, PAGE_KERNEL);

	if (!allocation->vmapping) {
		printk("igel-loop: Failed to create vmapping for section allocation!\n");
		goto fail;
	}

	return allocation;

fail:
	free_section_allocation(allocation);
	return NULL;
}


int
read_section_allocation(struct igel_section_allocation *allocation,
                        struct file *file, size_t section)
{
	struct iov_iter i;
	ssize_t len;
	loff_t phys_offset = START_OF_SECTION(section);

	iov_iter_bvec(&i, READ, allocation->bios, 64, IGF_SECTION_SIZE);

	len = vfs_iter_read(file, &i, &phys_offset, 0);
	return len < 0 ? -EIO : 0;
}

int
write_section_allocation(struct igel_section_allocation *allocation,
                         size_t offset, size_t len,
                         struct file *file, size_t section)
{
	struct iov_iter i;
	ssize_t ret;
	loff_t phys_offset = START_OF_SECTION(section) + offset;

	BUG_ON (len + offset > IGF_SECTION_SIZE);

	iov_iter_bvec(&i, WRITE, allocation->bios, 64, len + offset);

	iov_iter_advance(&i, offset);

	ret = vfs_iter_write(file, &i, &phys_offset, 0);
	return ret < 0 ? -EIO : 0;
}
