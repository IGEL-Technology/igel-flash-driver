#include <linux/bvec.h>

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

#include "section_allocation.h"
#include "igelsdk.h"

/* END of section */

static const u_int64_t END_SECTION = 0xffffffffffffffff >> ((8 - sizeof(((struct igf_sect_hdr *)0)->next_section)) * 8);

/* crc offsets for section and directory header */
static const u_int32_t crc_sh_offset = offsetof(struct igf_sect_hdr, crc) + sizeof(((struct igf_sect_hdr *)0) ->crc);
static const u_int32_t crc_dir_offset = offsetof(struct directory, crc) + sizeof(((struct directory *)0) ->crc);

struct dir_build_tmp {
	struct list_head frags;
	struct list_head free_frags;
	struct list_head parts;
};

struct dir_build_frag {
	struct list_head link;
	uint32_t minor;
	uint16_t generation;
	uint32_t magic;

	/* This is an optimization for building up
	 * the actual partition tables */
	uint32_t start_in_minor;
	uint32_t next_section;

	struct fragment_descriptor desc;
};

struct dir_build_partition {
	struct list_head link;

	uint16_t generation;
	uint32_t magic;
	uint32_t minor;

	/* Used to check if we really found the entire partition */
	uint64_t partlen;
	uint64_t offset_blocks;

	/* Used to decide what to do with it later on */
	int validated;
	int completed;
	int broken;

	struct list_head frags;
};

uint32_t calculate_section_hash(uint8_t *section);
int build_directory(struct file *file, struct directory *dir, int do_crc, int sys_minor);

uint32_t calculate_section_hash(uint8_t *section) {
	/* Pre-seed with ~0 and XOR with ~0 at the end to get the correct crc function */
	return crc32(0xffffffffL,
	             section + crc_sh_offset,
	             IGF_SECTION_SIZE - crc_sh_offset) ^ 0xffffffffL;
}

static int init_build_tmp(struct dir_build_tmp *build_tmp, size_t sections)
{
	struct dir_build_frag *current_frag = NULL;
	INIT_LIST_HEAD(&build_tmp->frags);
	INIT_LIST_HEAD(&build_tmp->free_frags);
	INIT_LIST_HEAD(&build_tmp->parts);

	current_frag = vmalloc(sizeof(*current_frag));
	if (!current_frag) {
		return -ENOMEM;
	}
	/* Sections contains the 0 section, which we need to avoid */
	current_frag->desc.first_section = 1;
	current_frag->desc.length = sections - 1;
	list_add(&current_frag->link, &build_tmp->free_frags);

	return 0;
}

/* Scan over the entire file (section by section) and find fragments of igel
 * sections belonging together.
 * This is mostly IO and state keeping. The fragment lists can then be used
 * to build up partitions. */
static int dir_scan_file(struct file *file, struct dir_build_tmp *build_tmp,
                         size_t sections, struct kvec *iov)
{
	int ret;
	size_t i;
	struct igf_sect_hdr *shdr = iov->iov_base;
	struct dir_build_frag *current_frag = NULL;

	if ((ret = init_build_tmp(build_tmp, sections))) {
		return ret;
	}

	/* Skip the 0th section, it contains bootreg + directory */
	for (i = 1; i < sections; ++i) {
		loff_t phys_pos = START_OF_SECTION(i);
		struct iov_iter iter;

		iov_iter_kvec(&iter, READ, iov,
		              1, sizeof(struct igf_sect_hdr));
		if ((ret = vfs_iter_read(file, &iter, &phys_pos, 0)) !=
		    sizeof(struct igf_sect_hdr)) {
			printk("igel-loop: Failed to read phys-section: %zu while building directory: %d\n",
			       i, ret);
			continue;
		}

		/* The next section belongs to the previous one.
		 * Just go on as usual */
		if (current_frag
			&& current_frag->minor == shdr->partition_minor
			&& current_frag->generation == shdr->generation
			&& current_frag->magic == shdr->magic
			&& i == current_frag->next_section) {
			++current_frag->desc.length;
			current_frag->next_section = shdr->next_section;
			continue;
		}

		if (current_frag) {
			/* We need to "fix" the free fragments list. */
			/* We are always in the last free fragment.
			 * We essentially just keep it around for accounting */
			struct dir_build_frag *new_frag = NULL;
			struct dir_build_frag *free_frag =
				list_last_entry(&build_tmp->free_frags,
			                        struct dir_build_frag, link);

			/* Either we can just advance the current fragment
			 * for keeping track of free sections, or we have
			 * to allocate a new one in the else branch */
			if (free_frag->desc.first_section ==
					current_frag->desc.first_section) {
				free_frag->desc.first_section +=
					current_frag->desc.length;
				free_frag->desc.length -=
					current_frag->desc.length;
			} else {
				new_frag = vmalloc(sizeof(*new_frag));
				if (!new_frag) {
					return -ENOMEM;
				}
				list_add_tail(&new_frag->link,
				              &build_tmp->free_frags);
				new_frag->desc.first_section =
					current_frag->desc.first_section +
					current_frag->desc.length;
				new_frag->desc.length =
					free_frag->desc.first_section
					+ free_frag->desc.length
					- new_frag->desc.first_section;

				free_frag->desc.length =
					current_frag->desc.first_section -
					free_frag->desc.first_section;
			}
			
			current_frag = NULL;
		}

		/* Ok, we consider this one a free section */
		if (shdr->section_type != SECT_TYPE_IGEL_V6
			|| shdr->section_size != LOG2_SECT_SIZE
			|| shdr->partition_minor > DIR_MAX_MINORS) {
			continue;
		}

		/* We need to start a new fragment,
		 * possibly start iterating a partition */
		current_frag = vmalloc(sizeof(*current_frag));
		current_frag->generation = shdr->generation;
		current_frag->magic = shdr->magic;
		current_frag->minor = shdr->partition_minor;
		current_frag->start_in_minor = shdr->section_in_minor;
		current_frag->next_section = shdr->next_section;
		current_frag->desc.first_section = i;
		current_frag->desc.length = 1;
		list_add_tail(&current_frag->link, &build_tmp->frags);
	}

	return 0;
}

/* Take the fragments read from file before and use the information provided
 * to build up partition info.
 * This will remove most entries from the build_tmp->frags list and move them
 * into fragment lists inside partitions placed into build_tmp->parts */
static int build_partitions(struct dir_build_tmp *build_tmp)
{
	int done;
	/* We can't just use the normal _safe variants,
	 * because we remove more than/ * different elements than just the one
	 * we currently look at */
	done = 0;
	while (!done) {
		struct dir_build_frag *current_frag = NULL;
		done = 1;
		list_for_each_entry(current_frag, &build_tmp->frags, link) {
			struct dir_build_partition *part;
			struct dir_build_frag *tmp, *last_frag;
			if (current_frag->start_in_minor) {
				continue;
			}

			if (!(part = vmalloc(sizeof(*part)))) {
				return -ENOMEM;
			}

			done = 0;

			INIT_LIST_HEAD(&part->frags);
			part->generation = current_frag->generation;
			part->magic = current_frag->magic;
			part->minor = current_frag->minor;
			list_add_tail(&part->link, &build_tmp->parts);

			list_del(&current_frag->link);
			list_add(&current_frag->link, &part->frags);

			list_for_each_entry_safe(current_frag, tmp, &build_tmp->frags, link) {
				if (current_frag->minor == part->minor
					&& current_frag->generation == part->generation
					&& current_frag->magic == part->magic) {
					struct dir_build_frag *last_frag =
						container_of(part->frags.prev,
							     struct dir_build_frag, link);
					if (current_frag->desc.first_section != last_frag->next_section) {
						continue;
					}
					if (current_frag->start_in_minor != last_frag->start_in_minor + last_frag->desc.length) {
						continue;
					}
					/* This is sorted for now. Should we ever allow for
					 * chains to go back in phys section number, we have
					 * to do this a bit more complicated */
					list_del(&current_frag->link);
					list_add_tail(&current_frag->link, &part->frags);
				}
			}

			last_frag = container_of(part->frags.prev,
				                 struct dir_build_frag, link);
			if (last_frag->next_section != END_SECTION) {
				printk("igel-loop: Found a partition with the last fragment missing\n");
			}

			break;
		}
	}

	return 0;
}

static int crc_check_build_tmp(struct file *file,
                               struct dir_build_tmp *build_tmp)
{
	size_t i;
	struct dir_build_partition *cur_part, *tmp_part = NULL;
	struct igel_section_allocation *allocation = make_section_allocation();

	list_for_each_entry_safe(cur_part, tmp_part, &build_tmp->parts, link) {
		struct dir_build_frag *current_frag = NULL;
		int ret = 0;

		list_for_each_entry(current_frag, &cur_part->frags, link) {
			size_t limit = current_frag->desc.length + current_frag->desc.first_section;
			for (i = current_frag->desc.first_section; i < limit; ++i) {
				uint8_t *section = allocation->vmapping;
				struct igf_part_hdr *phdr = (struct igf_part_hdr *)(section + 32);
				struct igf_sect_hdr *shdr = allocation->vmapping;
				uint32_t crc;

				read_section_allocation(allocation, file, i);
				if (ret) {
					printk("igel-loop: Failed to read phys-section: %zu while checking partition: %d\n",
					       i, ret);
					ret = -EIO;
					goto crc_done;
				}

				if (i == current_frag->desc.first_section && current_frag->start_in_minor == 0) {
					if ((phdr->type & 0xFF) != PTYPE_IGEL_RAW_RO) {
						ret = 1;
						goto crc_done;
					}
				}

				crc = calculate_section_hash(section);
				if (crc != shdr->crc) {
					printk("igel-loop: Found section with wrong crc: %zu, in %u [%08x]",
					       i, cur_part->minor, cur_part->magic);
					ret = -1;
					goto crc_done;
				}
			} /* Sections */
		} /* Fragments */
crc_done:
		if (ret < 0) {
			struct dir_build_frag *tmp_frag = NULL;
			list_del(&cur_part->link);
			list_for_each_entry_safe(current_frag, tmp_frag, &cur_part->frags, link) {
				list_move_tail(&current_frag->link, build_tmp->free_frags.prev);
			}
			vfree(cur_part);
		} else {
			if (ret) {
				printk("igel-loop: Skipped partition: %d [%08x]", cur_part->minor, cur_part->magic);
			} else {
				printk("igel-loop: Validated partition: %d [%08x]", cur_part->minor, cur_part->magic);
			}
		}
	} /* Partitions */
	free_section_allocation(allocation);

	return 0;
}

/* Find and return the system partition we want to use.
 * Right now this only checks for highest generation.
 *
 * TODO: This should try to find the correct kernel in the partition extent,
 * to make sure, we will be able to load kernel modules from our system
 * partition once we switched to it */
static struct dir_build_partition *
find_system_part(const struct dir_build_tmp *build_tmp, int sys_minor)
{
	struct dir_build_partition *found = NULL;
	struct dir_build_partition *cur_part;
	/* First, find the system partition. We get the valid major from that one */
	list_for_each_entry(cur_part, &build_tmp->parts, link) {
		if (cur_part->minor != sys_minor) {
			continue;
		}

		if (!found) {
			found = cur_part;
			continue;
		}

		if (found->generation < cur_part->generation) {
			found = cur_part;
		}
	}

	return found;
}

/* Remove partitions from the build_tmp that don't have a the magic provided
 * here.
 * This should be called, after the system parittion is known, to filter out
 * partitions from the wrong version. Unlikely to happen, but better be safe.
 *
 * The fragments from those partitions will be moved into the free_frags list,
 * while it's not used at the moment, it's intended for keeping tabs on
 * the entire state */
static void remove_wrong_magic(struct dir_build_tmp *build_tmp, uint32_t magic)
{
	struct dir_build_partition *cur_part, *tmp_part;
	list_for_each_entry_safe(cur_part, tmp_part, &build_tmp->parts, link) {
		/* Do never remove WFS (255) or LIC (254) partitions even if
		 * magic differs. This can happen due to migration or perserve
		 * settings in OSC */
		if (cur_part->minor == 255 || cur_part->minor == 254) {
			continue;
		}
		if (cur_part->magic != magic) {
			struct dir_build_frag *current_frag, *tmp_frag;
			list_del(&cur_part->link);
			list_for_each_entry_safe(current_frag, tmp_frag,
			                         &cur_part->frags, link) {
				list_move_tail(&current_frag->link,
				               build_tmp->free_frags.prev);
			}
			vfree(cur_part);
		}
	}
}

/* Fill the used_parts array with the corresponding best-fitting partition
 * descriptor from build_tmp.
 * The only check performed here, is for highest generation.
 * The build_tmp should only contain valid (magic/crc) partitions */
static void find_best_partitions(const struct dir_build_tmp *build_tmp,
                                 struct dir_build_partition **used_parts)
{
	struct dir_build_partition *cur_part;
	list_for_each_entry(cur_part, &build_tmp->parts, link) {
		size_t index= cur_part->minor -1;
		if (cur_part->minor < 1) {
			continue;
		}

		if (!used_parts[index]) {
			used_parts[index] = cur_part;
		}

		if (used_parts[index]->generation < cur_part->generation) {
			used_parts[index] = cur_part;
		}
	}
}

/* Use the data from provided via used_parts partitions to build up a new
 * directory in dir.
 * Sections is required for correctly sizing the free fragment list in the
 * new directory; */
static int fill_directory(struct directory *dir, size_t sections,
                          struct dir_build_partition *const *used_parts)
{
	int ret = 0;
	size_t i;
	struct directory *tmp_dir, *cur_dir = dir, *other_dir;
	if (!(tmp_dir = vmalloc(sizeof(*tmp_dir)))) {
		return -ENOMEM;
	}
	other_dir = tmp_dir;

	create_empty_directory(cur_dir, sections);
	for (i = 0; i < DIR_MAX_MINORS; ++i) {
		struct dir_build_frag *current_frag;
		struct dir_build_partition *cur_part = used_parts[i];
		struct directory *swp_dir;

		if (!cur_part) {
			continue;
		}

		/* If we only have a singular fragment in the partition
		 * fragment list, we can use this as optimization
		 * and avoid an allocation and some copies */
		if (list_is_singular(&cur_part->frags)) {
			current_frag = list_first_entry(&cur_part->frags,
			                                struct dir_build_frag,
			                                link);
			igeldir_add_partition(cur_dir, other_dir,
			                      cur_part->minor,
			                      &current_frag->desc, 1);
		} else {
			struct fragment_descriptor *descs;
			size_t count = 0;
			list_for_each_entry(current_frag, &cur_part->frags, link) {
				++count;
			}
			descs = kmalloc(sizeof(struct fragment_descriptor) * count, GFP_KERNEL);
			if (!descs) {
				ret = -ENOMEM;
				goto out;
			}
			count = 0;
			list_for_each_entry(current_frag, &cur_part->frags, link) {
				descs[count].first_section = current_frag->desc.first_section;
				descs[count].length = current_frag->desc.length;
				++count;
			}

			igeldir_add_partition(cur_dir, other_dir,
			                      cur_part->minor, descs, count);
			kfree(descs);
		}
		swp_dir = cur_dir;
		cur_dir = other_dir;
		other_dir = swp_dir;
	}

	if (cur_dir != dir) {
		memcpy(dir, cur_dir, sizeof(struct directory));
	}

out:
	vfree(tmp_dir);
	return ret;
}

/* Take a pre-check (but unsorted) dir_build_tmp and build a buffer of used
 * (aka highest generation, and magic equal the chosen system partition)
 * partitions.
 * The returned buffer should be vfree()'d. Partitions pointed to by the buffer
 * are removed from the build_tmp. They have to be free()'d manually as well.
 * The return buffer size will always be DIR_MAX_MINORS
 * If an error occurs, used_parts will not be touched*/
static int fill_best_partitions(struct dir_build_tmp *build_tmp,
                                struct dir_build_partition ***used_parts_p, int sys_minor)
{
	size_t i;
	struct dir_build_partition **used_parts;

	used_parts = vmalloc(sizeof(*used_parts) * DIR_MAX_MINORS);
	if (!used_parts) {
		return -ENOMEM;
	}
	memset(used_parts, 0, sizeof(*used_parts) * DIR_MAX_MINORS);

	used_parts[0] = find_system_part(build_tmp, sys_minor);
	if (!used_parts[0]) {
		vfree(used_parts);
		return -ENOENT;
	}
	list_del_init(&used_parts[0]->link);

	remove_wrong_magic(build_tmp, used_parts[0]->magic);

	find_best_partitions(build_tmp, used_parts);
	for (i = 1; i < DIR_MAX_MINORS; ++i) {
		if (used_parts[i]) {
			list_del_init(&used_parts[i]->link);
		}
	}

	*used_parts_p = used_parts;
	return 0;
}

/* Calls vfree on the fragment */
static void free_build_frag(struct dir_build_frag *frag)
{
	if (!frag) {
		return;
	}
	list_del(&frag->link);
	vfree(frag);
}

/* Calls vfree on the partition */
static void free_build_partition(struct dir_build_partition *part)
{
	struct dir_build_frag *frag, *tmp;
	if (!part) {
		return;
	}
	list_for_each_entry_safe(frag, tmp, &part->frags, link) {
		free_build_frag(frag);
	}
	list_del(&part->link);
	vfree(part);
}

/* vFrees all members, but doesn't free() the build_tmp itself */
static void destroy_build_tmp(struct dir_build_tmp *build_tmp)
{
	struct dir_build_frag *frag, *ftmp;
	struct dir_build_partition *part, *ptmp;

	list_for_each_entry_safe(frag, ftmp, &build_tmp->free_frags, link) {
		free_build_frag(frag);
	}

	list_for_each_entry_safe(frag, ftmp, &build_tmp->frags, link) {
		free_build_frag(frag);
	}

	list_for_each_entry_safe(part, ptmp, &build_tmp->parts, link) {
		free_build_partition(part);
	}
}

static int dir_check_file(struct file *file, struct kvec *iov)
{
	loff_t phys_pos = 0;
	struct iov_iter iter;
	struct igel_bootreg_header *hdr = iov->iov_base;

	iov_iter_kvec(&iter, READ, iov, 1, 512);

	if (vfs_iter_read(file, &iter, &phys_pos, 0) != 512) {
		printk("igel-loop: Failed to read bootreg header while checking file\n");
		return -EIO;
	}

	if (strncmp(hdr->ident_legacy, BOOTREG_IDENT, sizeof(hdr->ident_legacy))) {
		printk("id: %s\n", hdr->ident_legacy);
		return -EINVAL;
	}

	return 0;
}

int build_directory(struct file *file, struct directory *dir, int do_crc, int sys_minor)
{
	int ret = 0;
	struct dir_build_partition **used_parts;
	size_t size = i_size_read(file->f_mapping->host);
	const size_t sections = size / IGF_SECTION_SIZE;
	struct kvec iov = {
		.iov_base = NULL,
		.iov_len = 512,
	};
	struct dir_build_tmp build_tmp;


	if (!dir) {
		return -EFAULT;
	}

	iov.iov_base = kmalloc(512, GFP_KERNEL);

	if ((ret = dir_check_file(file, &iov))) {
		goto out_io;
	}

	if ((ret = dir_scan_file(file, &build_tmp, sections, &iov))) {
		goto out_buffer;
	}

	if (list_empty(&build_tmp.frags)) {
		ret = -ENOENT;
		goto out_buffer;
	}

	/* At this point, we built up all fragments!
	 * Now to find the partitions */
	if ((ret = build_partitions(&build_tmp))) {
		goto out_buffer;
	}

	if (list_empty(&build_tmp.parts)) {
		ret = -ENOENT;
		goto out_buffer;
	}

	if (do_crc) {
		if ((ret = crc_check_build_tmp(file, &build_tmp))) {
			goto out_buffer;
		}
	}

	if ((ret = fill_best_partitions(&build_tmp, &used_parts, sys_minor))) {
		goto out_buffer;
	}

	ret = fill_directory(dir, sections, used_parts);

	{
		size_t i;
		for (i = 0; i < DIR_MAX_MINORS; ++i) {
			free_build_partition(used_parts[i]);
		}
		vfree(used_parts);
	}

out_buffer:
	destroy_build_tmp(&build_tmp);
out_io:
	kfree(iov.iov_base);

	return ret;
}
