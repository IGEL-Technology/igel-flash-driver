/*
 *  IGELFS Partition Directory V6
 *
 *  Basically the headers of IGEL partitions and IGEL sections contain
 *  all the information necessary for accessing their payload data.
 *  Before accessing this data, it is necessary to read in all section
 *  headers in order to determine the sequences of sections the partitions
 *  are made of.
 *  However, the old design was made with moderate storage media sizes
 *  in mind. (4 MB to 16 MB) Today's storage media sizes (as of 2016)
 *  are in the range 2GB and above. Since the initialization effort
 *  grows linearly with flash size, it is unacceptable to scan all
 *  section headers.
 *
 *  The "partition directory" is a supplemental data set which makes the
 *  access of IGEL partition data faster, just like directories/FATs work
 *  in filesystems. For each partition it maintains a section list
 *  in compact representation. It draws benefits from the fact, that
 *  the sequences of sections are almost contiguous. In other words,
 *  there usually is very little fragmentation.
 *
 *  This code is both used for igelfs_tools, for the kernel driver module
 *  and for the bootcode. The only functions needed for the bootcode are
 *  get_physical_section() and read_directory().
 *
 *  Copyright (C) 2007-2016, IGEL Technology GmbH, Thomas Kraetzig
 */

#ifdef GRUB_FILE
#include <grub/igel_partition.h>

/* define offsetof explicit */
#ifndef offsetof
#define offsetof(st, m) __builtin_offsetof(st, m)
#endif /*offsetof*/
#endif

#ifndef __KERNEL__
#ifndef GRUB2_BOOTCODE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <igel.h>
#endif /* GRUB2_BOOTCODE */
#else /* __KERNEL__ */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "igel.h"
#endif /* __KERNEL__ */

#ifndef __KERNEL__
#ifndef GRUB2_BOOTCODE
/* functions from igel_crc.c */
extern uint32_t updcrc(unsigned char * s, unsigned n);
extern void makecrc(void);
#endif /* GRUB2_BOOTCODE */
#else /* __KERNEL__ */
#undef TEST
#endif /* __KERNEL__ */

/*----------------------------------------------------------------------
 *  Local data
 */

#ifdef TEST
/*
 * We use two memory buffers for directories.
 * This makes modifications easy: While the original version of a directory
 * is beeing kept unchanged, the modified version can be created "from scratch"
 * by copying elements from the original version and by doing the required
 * modifications on the fly.
 */
static struct directory dir1, dir2;

/*
 * An intermediate fragment list
 */
static struct fragment_descriptor new_fragments[16];
#endif


#ifndef GRUB2_BOOTCODE
/*----------------------------------------------------------------------
 *  Functions operating on fragment lists
 *  require, that all fragment lists are in ascending order, i.e
 *
 *  for all i,j:
 *  i < j  implies  fragment[i].first_section < fragment[j].first_section
 *
 *  and fragments must not overlap.
 */

/*
 *  Create a fragment list from a section list.
 *  Return value is the number of fragments.
 */
int sections_to_fragments(uint32_t *sections, int n_sections,
                          struct fragment_descriptor *fragments,
                          int max_fragments)
{
    int i, j, current_section;

    if (n_sections <= 0)
        return 0;
    if (max_fragments <= 0)
    {
#ifndef __KERNEL__
	fprintf(stderr, "sections_to_fragments: too many fragments\n");
#else
	printk(KERN_ERR "sections_to_fragments: too many fragments\n");
#endif
	return 0;
    }

    fragments[0].first_section = current_section = sections[0];
    fragments[0].length = 1;

    for (i = 1, j = 0; i<n_sections; i++)
    {
        if (sections[i] == current_section + 1)
        {
            /* section belongs to the current fragment */
            current_section++;
            fragments[j].length++;
        }
        else
        {
            /* new fragment */
            j++;
            if (j >= max_fragments)
            {
#ifndef __KERNEL__
                fprintf(stderr, "sections_to_fragments: too many fragments\n");
#else
                printk(KERN_ERR "sections_to_fragments: too many fragments\n");
#endif
                return 0;
            }
            fragments[j].first_section = current_section = sections[i];
            fragments[j].length = 1;
        }
    }
    return j + 1;
}


/*
 *  Merge two sequences of fragments.
 *  Overlapping fragments are handled correctly, although this
 *  will never happen in reasonable fragment sets.
 *
 *  This function is needed for adding sections to the freelist.
 *
 *  Return value is the number of fragments in the merged sequence.
 */
int merge_fragments(struct fragment_descriptor *fragments1, int n1,
                    struct fragment_descriptor *fragments2, int n2,
                    struct fragment_descriptor *merged_fragments)
{
    int i, j, k, l1, l2, r1, r2;
    int merged_l, merged_r;

    if ((n1 == 0) && (n2 == 0))
        return 0;

    l1 = l2 = r1 = r2 = 0;   /* stop compiler warnings */
    i = j = k = 0;
    merged_l = merged_r = -1; /* we start with an invalid fragment */
    if (n1 > 0)
    {
        l1 = fragments1[0].first_section;
        r1 = l1 + fragments1[0].length;
    }
    if (n2 > 0)
    {
        l2 = fragments2[0].first_section;
        r2 = l2 + fragments2[0].length;
    }

    while ((i < n1) || (j < n2))
    {
        if (((l1 <= l2) && (i < n1)) || (j >= n2))
        {
            /*
             * l1 is the next number in the merged ordered list because
             * l1 is smaller than l2 or because the second list is exhausted.
             */
            if (l1 > merged_r)
            {
                /* the new fragment is not coherent with the stored fragment:
                   write out the stored fragment */
                if (merged_l >= 0)
                {
                    merged_fragments[k].first_section = merged_l;
                    merged_fragments[k].length = merged_r - merged_l;
                    k++;
                }
                /* set up a new stored fragment */
                merged_l = l1;
                merged_r = r1;
            }
            else
            {
                /* the new fragment is coherent/overlaps/is part of the
                   stored fragment: merge with the stored fragment */
                if (r1 > merged_r)
                    merged_r = r1;
            }
            /* advance one step in the first fragment list */
            i++;
            if (i < n1)
            {
                l1 = fragments1[i].first_section;
                r1 = l1 + fragments1[i].length;
            }
        }
        else if (((l2 < l1) && (j < n2)) || (i >= n1))
        {
            /*
             * l2 is the next number in the merged ordered list because
             * l2 is smaller than l1 or because the first list is exhausted.
             */
            /* l2 is the next number in the merged ordered list */
            if (l2 > merged_r)
            {
                /* the new fragment is not coherent with the stored fragment:
                   write out the stored fragment */
                if (merged_l >= 0)
                {
                    merged_fragments[k].first_section = merged_l;
                    merged_fragments[k].length = merged_r - merged_l;
                    k++;
                }
                /* set up a new stored fragment */
                merged_l = l2;
                merged_r = r2;
            }
            else
            {
                /* the new fragment is coherent/overlaps/is part of the
                   stored fragment: merge with the stored fragment */
                if (r2 > merged_r)
                    merged_r = r2;
            }
            /* advance one step in the second fragment list */
            j++;
            if (j < n2)
            {
                l2 = fragments2[j].first_section;
                r2 = l2 + fragments2[j].length;
            }
        }
    }
    /* write out the last stored segment */
    merged_fragments[k].first_section = merged_l;
    merged_fragments[k].length = merged_r - merged_l;
    k++;

    return k;
}


/*
 *  Take away fragments2 from fragments1.
 *  This function is needed for removing sections from the freelist.
 *
 *  Return value is the number of fragments in the reduced sequence.
 */
int take_away_fragments(struct fragment_descriptor *fragments1, int n1,
                    struct fragment_descriptor *fragments2, int n2,
                    struct fragment_descriptor *result_fragments)
{
    int i, j, k, l2, r2;
    int reduced_l, reduced_r;

    if (n1 == 0)
        return 0;
    if (n2 == 0)
    {
        /* nothing to reduce, copy the original fragment list */
        for (i=0; i<n1; i++)
            result_fragments[i] = fragments1[i];
        return n1;
    }

    i = j = k = 0;

    reduced_l = fragments1[0].first_section;
    reduced_r = reduced_l + fragments1[0].length;

    while ((i < n1) && (j < n2))
    {
        l2 = fragments2[j].first_section;
        r2 = l2 + fragments2[j].length;
        
        if (r2 <= reduced_l)
        {
            /* [l2;r2) is too far left: no intersection */
            j++;
            continue;
        }
        else if ((l2 <= reduced_l) && (r2 >= reduced_r))
        {
            /* [reduced_l;reduced_r) is deleted completely */
            i++;
            if (i < n1)
            {
                reduced_l = fragments1[i].first_section;
                reduced_r = reduced_l + fragments1[i].length;
            }
            else
                reduced_l = reduced_r = -1; /* nothing left */
            continue;
        }
        else if ((l2 <= reduced_l) && (r2 < reduced_r))
        {
            /* cut left */
            reduced_l = r2;
            j++;
            continue;
        }
        else if ((l2 > reduced_l) && (r2 < reduced_r))
        {
            /* cut out a piece in the middle, output lefthand piece */
            result_fragments[k].first_section = reduced_l;
            result_fragments[k].length = l2 - reduced_l;
            k++;
            reduced_l = r2;
            j++;
            continue;           
        }
        else if ((l2 < reduced_r) && (r2 >= reduced_r))
        {
            /* cut right, output lefthand piece */
            result_fragments[k].first_section = reduced_l;
            result_fragments[k].length = l2 - reduced_l;
            k++;
            i++;
            if (i < n1)
            {
                reduced_l = fragments1[i].first_section;
                reduced_r = reduced_l + fragments1[i].length;
            }
            else
                reduced_l = reduced_r = -1; /* nothing left */
            continue;
        }
        else if (l2 >= reduced_r)
        {
            /* [l2;r2) is too far right: no intersection, output */
            result_fragments[k].first_section = reduced_l;
            result_fragments[k].length = reduced_r - reduced_l;
            k++;
            i++;
            if (i < n1)
            {
                reduced_l = fragments1[i].first_section;
                reduced_r = reduced_l + fragments1[i].length;
            }
            else
                reduced_l = reduced_r = -1; /* nothing left */
            continue;
        }
    }
    /*
     * At this point, there is either nothing left to reduce
     * i.e list1 is exhausted (i == n1, reduced_l = -1),
     * or there is nothing left to take away, i.e list2 is exhausted,
     * or both.
     */
    if (reduced_l >= 0)
    {
        /* output the remaining fragments from list1 */
        result_fragments[k].first_section = reduced_l;
        result_fragments[k].length = reduced_r - reduced_l;
        k++;
        i++;
        while (i < n1)
        {
            result_fragments[k].first_section = fragments1[i].first_section;
            result_fragments[k].length = fragments1[i].length;
            i++;
            k++;
        }
    }
    return k;
}


/*----------------------------------------------------------------------
 *  Functions operating on directories
 */

/*
 *  Initialize a directory to an empty state. Partition 0, the freelist,
 *  is initialized as one contiguous fragment with n_sections sections.
 */
void *create_empty_directory(struct directory *dir, int n_sections)
{
    int i;

#ifdef __KERNEL__
    memset(dir, 0, sizeof(struct directory));
#else
    bzero(dir, sizeof(struct directory));
#endif
    dir->magic = DIRECTORY_MAGIC;
    dir->crc = CRC_DUMMY;
    dir->dir_type = 0;		/* for future extensions */
    dir->max_minors = DIR_MAX_MINORS;
    dir->version = 1;		/* update count, never used so far */
    dir->dummy = 0;
    dir->n_fragments = 1;	/* the freelist has exactly one fragment */
    dir->max_fragments = MAX_FRAGMENTS;
    for (i = 0; i < 8; i++)
	dir->extension[i] = 0;

    /* Initialize the freelist */
    dir->partition[0].minor = 0;
    dir->partition[0].type = PTYPE_IGEL_FREELIST;
    dir->partition[0].first_fragment = 0;
    dir->partition[0].n_fragments = 1;
    dir->fragment[0].first_section = 1; /* section 0 is reserved for boot */
    dir->fragment[0].length = n_sections - 1;

    /*
     * Note: There is no need to initialize an empty partition table
     * since the whole directory structure is zeroed. This implies
     * dir->partition_descriptor[i].type = PTYPE_EMPTY
     * for all i > 0
     */

    /* TODO: dir->crc = ... (can be postponed to writing) */

    return dir;
}


/*
 *  Delete partition number "minor" from directory "src_dir" to "dst_dir"
 */
void igeldir_delete_partition(struct directory *src_dir, struct directory *dst_dir,
                      int minor)
{
    int n_frag_this;
    int n_frag_free_old, n_frag_free_new, src_frag, dst_frag;
    int i, j, n;

    if ((minor < 1) || (minor >= IGF_MAX_MINORS))
    {
        /* invalid minor */
        memcpy(dst_dir, src_dir, sizeof(struct directory));
        return;
    }

    if ((n_frag_this = src_dir->partition[minor].n_fragments) == 0)
    {
        /* partition does not exist */
        memcpy(dst_dir, src_dir, sizeof(struct directory));
        return;
    }

    /* initialize the new directory */
#ifdef __KERNEL__
    memset(dst_dir, 0, sizeof(struct directory));
#else
    bzero(dst_dir, sizeof(struct directory));
#endif
    dst_dir->magic = DIRECTORY_MAGIC;
    dst_dir->crc = CRC_DUMMY;
    dst_dir->dir_type = 0;		/* for future extensions */
    dst_dir->max_minors = DIR_MAX_MINORS;
    dst_dir->version = src_dir->version;
    dst_dir->dummy = 0;
    dst_dir->max_fragments = MAX_FRAGMENTS;
    for (i = 0; i < 8; i++)
	dst_dir->extension[i] = 0;

    /* copy the partition table */
    memcpy(dst_dir->partition, src_dir->partition,
           DIR_MAX_MINORS * sizeof(struct partition_descriptor));

    /* create a new freelist by merging the old freelist
       with the partition to delete */
    n_frag_free_old = src_dir->partition[0].n_fragments;
    n_frag_free_new = merge_fragments(
        &(src_dir->fragment[src_dir->partition[0].first_fragment]),
        n_frag_free_old,
        &(src_dir->fragment[src_dir->partition[minor].first_fragment]),
        n_frag_this,
        &(dst_dir->fragment[0]));

    /* update the freelist in the new partition table */
    /* (the freelist always starts at fragment 0)     */
    dst_dir->partition[0].first_fragment = 0;
    dst_dir->partition[0].n_fragments = n_frag_free_new;

    /* update all other partitions and fragments */
    dst_frag = n_frag_free_new; /* index into new fragment list */
    for (i = 1; i < DIR_MAX_MINORS; i++)
    {
        if (i == minor)
        {
            /* delete this partition  TODO: handle hash conflicts */
            dst_dir->partition[i].minor = 0;
            dst_dir->partition[i].type = PTYPE_EMPTY;
            dst_dir->partition[i].first_fragment = 0;
            dst_dir->partition[i].n_fragments = 0;
        }
        else
        {
            /* keep this partition */
            src_frag = src_dir->partition[i].first_fragment;
            n = src_dir->partition[i].n_fragments;
            dst_dir->partition[i].first_fragment = dst_frag;
            dst_dir->partition[i].n_fragments = n;
            for (j = 0; j < n; j++)
                dst_dir->fragment[dst_frag++] = src_dir->fragment[src_frag++];
        }
    }
    dst_dir->n_fragments = dst_frag; /* total number of fragments */
}


/*
 *  Add a partition number "minor", consisting of fragments given in a
 *  list fragments[n], to the directory "src_dir".
 */
void igeldir_add_partition(struct directory *src_dir,
                   struct directory *dst_dir, int minor,
                   struct fragment_descriptor *new_fragments, int n_frag_new)
{
    int i, j, n;
    int n_frag_free_old, n_frag_free_new, src_frag, dst_frag;

    if ((minor < 1) || (minor >= IGF_MAX_MINORS))
        return; /* invalid minor */

    /*  if a partition with this minor number already exists, delete it */
    /*  CAUTION: src_dir will be modified in this case !                */
    if ((n = src_dir->partition[minor].n_fragments) > 0)
    {
        igeldir_delete_partition(src_dir, dst_dir, minor);
        memcpy(src_dir, dst_dir, sizeof(struct directory));
    }

    /* initialize the new directory */
#ifdef __KERNEL__
    memset(dst_dir, 0, sizeof(struct directory));
#else
    bzero(dst_dir, sizeof(struct directory));
#endif
    dst_dir->magic = DIRECTORY_MAGIC;
    dst_dir->crc = CRC_DUMMY;
    dst_dir->dir_type = 0;		/* for future extensions */
    dst_dir->max_minors = DIR_MAX_MINORS;
    dst_dir->version = src_dir->version;
    dst_dir->dummy = 0;
    dst_dir->max_fragments = MAX_FRAGMENTS;
    for (i = 0; i < 8; i++)
	dst_dir->extension[i] = 0;

    /* copy the partition table */
    memcpy(dst_dir->partition, src_dir->partition,
           DIR_MAX_MINORS * sizeof(struct partition_descriptor));

    /* create a new freelist by taking away the fragments
       of the new partition from the old freelist */
    n_frag_free_old = src_dir->partition[0].n_fragments;
    n_frag_free_new = take_away_fragments(
        &(src_dir->fragment[src_dir->partition[0].first_fragment]),
        n_frag_free_old,
        new_fragments, n_frag_new,
        &(dst_dir->fragment[0]));

    /* update the freelist in the new partition table */
    /* (the freelist always starts at fragment 0)     */
    dst_dir->partition[0].first_fragment = 0;
    dst_dir->partition[0].n_fragments = n_frag_free_new;

    /* update all other partitions and fragments */
    dst_frag = n_frag_free_new; /* index into new fragment list */
    for (i = 1; i < DIR_MAX_MINORS; i++)
    {
        if (i == minor)
        {
            /* add the new partition  TODO: handle hash conflicts */
            dst_dir->partition[i].minor = minor;
            dst_dir->partition[i].type = PTYPE_IGEL_COMPRESSED;	/* TODO: function argument ? */
            dst_dir->partition[i].first_fragment = dst_frag;
            dst_dir->partition[i].n_fragments = n_frag_new;
            for (j=0; j<n_frag_new; j++)
                dst_dir->fragment[dst_frag++] = new_fragments[j];
        }
        else
        {
            /* keep the other partitions */
            src_frag = src_dir->partition[i].first_fragment;
            n = src_dir->partition[i].n_fragments;
            dst_dir->partition[i].first_fragment = dst_frag;
            dst_dir->partition[i].n_fragments = n;
            for (j = 0; j < n; j++)
                dst_dir->fragment[dst_frag++] = src_dir->fragment[src_frag++];
        }
    }
    dst_dir->n_fragments = dst_frag; /* total number of fragments */
}


/*
 *  Get free sections from the free list
 *  without actually changing the directory's content.
 *
 *  The caller must provide storage for the returned fragment list.
 *  Return value is the number of fragments in the returned fragment list.
 */
int allocate_fragments(struct directory *dir,
                        struct fragment_descriptor *fragments,
                        int max_fragments, int n_sections)
{
    int i, j, len, n;

    /*
     * Walk through the free list and use the first fragment big
     * enough to make the allocation in one piece.
     */
    i = dir->partition[0].first_fragment; /* usually 0, but not necessaryly */
    for (j = 0; (j < dir->partition[0].n_fragments) && (j < max_fragments);
         j++, i++)
    {
        len = dir->fragment[i].length;
        if (len >= n_sections)
        {
            fragments[0].first_section = dir->fragment[i].first_section;
            fragments[0].length = n_sections;
            return 1; /* we are done */
        }
    }
    /*
     * We didn't find a single fragment big enough:
     * Walk through the free list again,
     * and collect as many fragments as needed from left to right.
     */
    n = n_sections; /* sections still to allocate */
    i = dir->partition[0].first_fragment; /* usually 0, but not necessarily */
    for (j = 0; (j < dir->partition[0].n_fragments) && (j < max_fragments);
         j++, i++)
    {
        len =  dir->fragment[i].length;
        fragments[j].first_section = dir->fragment[i].first_section;
        if (len < n)
        {
            fragments[j].length = len;
            n -= len;
        }
        else
        {
            fragments[j].length = n;
            n = 0;
            j++;
            break; /* we are done */
        }
    }
    if (n == 0)
        return j;
    else
    {
#ifndef __KERNEL__
#ifdef TEST
        printf("Not enough space in free list to allocate %d sections\n",
               n_sections);
#endif
#endif
        return 0;
    }
}

/*
 *  Merge all fragments of all partitions into one fragment list.
 *  In an ordinary directory, this list will be complementary to the free list.
 *  The directory's itself is not changed.
 *
 *  This special function is needed by the update tool, which may want
 *  to exclude the running system's storage space from beeing used by
 *  allocate_fragments().
 *
 *  The caller must provide storage for the returned fragment list.
 *  Return value is the number of fragments in the merged list.
 */
int merge_partitions(struct directory *dir,
                     struct fragment_descriptor *merged_fragments)
{
    int i, n;
    int n_tmp_fragments = 0;
    int n_merged_fragments = 0;
    struct fragment_descriptor *tmp_fragments;
    struct partition_descriptor *part;

#ifdef __KERNEL__
    if ((tmp_fragments = vmalloc(MAX_FRAGMENTS * sizeof(struct fragment_descriptor))) == NULL) {
        printk(KERN_ERR "%s: Could not allocate %llu bytes for temp fragments list\n",
               /*CLOOP_NAME*/"igel-loop", (unsigned long long) MAX_FRAGMENTS * sizeof(struct fragment_descriptor));
        return 0;
    }
#else
    if ((tmp_fragments = malloc(MAX_FRAGMENTS * sizeof(struct fragment_descriptor))) == NULL) {
        printf("Could not allocate %llu bytes for temp fragments list\n",
               (unsigned long long) MAX_FRAGMENTS * sizeof(struct fragment_descriptor));
        return 0;
    }
#endif

    for (i = 1; i < DIR_MAX_MINORS; i++)
    {
        part = &(dir->partition[i]);
        if ((n = part->n_fragments) > 0)
	{
	    n_merged_fragments =
            merge_fragments(&(dir->fragment[part->first_fragment]), n,
                            tmp_fragments, n_tmp_fragments,
                            merged_fragments);
            memcpy(tmp_fragments, merged_fragments,
                   n_merged_fragments * sizeof(struct fragment_descriptor));
            n_tmp_fragments = n_merged_fragments;
	}
    }
#ifdef __KERNEL__
    vfree(tmp_fragments);
#else
    free(tmp_fragments);
#endif
    return n_merged_fragments;
}
#endif /* ifndef GRUB2_BOOTCODE */


/*
 *  Given a partition number minor and a logical section number i,
 *  determine the corresponding pysical section number
 *  by walking through the partition's fragment list.
 *
 *  Negative return values indicate error conditions.
 */
uint32_t get_physical_section(struct directory *dir, uint32_t minor, uint32_t i)
{
    struct partition_descriptor *part;
    struct fragment_descriptor *frag;
    size_t j;
	uint16_t n_frag;
	int n;

    if (minor >= IGF_MAX_MINORS)
        return 0xffffffff; /* invalid minor */
    if (minor >= DIR_MAX_MINORS)
	return 0xffffffff; /* hashing not yet implemented. TODO: implement! */
    part = &(dir->partition[minor]);
    if (part->minor != minor)
	return 0xffffffff; /* minors don't match -> hash conflict */
	/* TODO: Implement hash conflicts */
    if ((n_frag = part->n_fragments) == 0)
        return 0xffffffff; /* partition does not exist or is empty */
    frag = &(dir->fragment[part->first_fragment]);

    /* find the fragment to which section i belongs */
    n = 1;                 /* # of fragments examined */
    j = 0;                 /* # of sections contained in previous fragments */
    while (i > j + frag->length - 1)
    {
        n++;
        if (n > n_frag)
            return 0xffffffff;    /* section number i exceeds partition length */
        j += frag->length;
        frag++;            /* next fragment */
    }
    return frag->first_section + i - j;
}

/*
 *  Given a physical section number, determine the partition number
 *  to which this section belongs (freelist = 0). If the section
 *  doesn't belong to any partition, even not to the freelist,
 *  the directory is in an inconsistent state. Return -1 in that case.
 *
 *  This function is only needed for the kernel driver
 *  ioctl IGFLASH_ERASE_SECTION.
 */
int get_partition_from_section(struct directory *dir, uint32_t sect)
{
	struct partition_descriptor *part;
	struct fragment_descriptor *frag;
	int minor;
	uint16_t n_frag;
	int i;
	uint32_t first_sect;

	/* hashing not yet implemented. TODO: implement! */
	for (minor = 0; minor < DIR_MAX_MINORS; minor++)
	{
		part = &(dir->partition[minor]);
		if ((n_frag = part->n_fragments) == 0)
			continue; /* partition does not exist */
		for (i=0; i<n_frag; i++)
		{
			frag = &(dir->fragment[part->first_fragment+i]);
			first_sect = frag->first_section;
			if (sect < first_sect)
				break;
			else if (sect < first_sect + frag->length)
				return minor;
		}
	}
	return -1; /* section doesn't belong to any partition */
}


/*----------------------------------------------------------------------
 *  Input / Output
 */

///*
// *  Given a filedescriptor "rawfd" referring to the raw storage media,
// *  this functions locates and reads a valid directory block from
// *  section #0 into a caller provided buffer.
// *  A directory is valid, if it contains a proper magic value and
// *  if it passes the crc check. There are no consistency checks !
// *
// *  Return value is the offset at which a valid directory was found,
// *  0, if none could be found.
// *
// *  TODO: if there are multiple valid directories, find the one
// *        with the most recent "version" entry.
// */
//#ifdef GRUB2_BOOTCODE
//int read_directory(struct directory *dir, grub_disk_t disk, grub_uint64_t part_offset)
//#elif defined __KERNEL__
//int read_directory(struct file *file, struct directory *dir)
//#else
//int read_directory(int rawfd, struct directory *dir)
//#endif
//{
//    loff_t offset;
//    uint32_t crc;
//    //int found = 0;
//
//    /* crc offsets for directory header */
//#ifdef GRUB2_BOOTCODE
//    static const grub_uint32_t crc_dir_offset = (offsetof(struct directory, crc) + sizeof (((struct directory*)0)->crc));
//#else
//    static const uint32_t crc_dir_offset = (offsetof(struct directory, crc) + sizeof (((struct directory*)0)->crc));
//#endif
//
//    makecrc(); /* crc initial table setup */
//
//    offset = DIR_OFFSET;
//
//#ifdef GRUB2_BOOTCODE
//    offset += part_offset;
//    igelpart_disk_read (disk, offset, sizeof (struct directory), dir);
//#elif defined __KERNEL__
////    cloop0_nocache_read_from_file(clo_get(0), file, (unsigned char *)dir,
////            offset, sizeof(struct directory));
//#else
//    if (lseek(rawfd, offset, SEEK_SET) == -1)
//    {
//        fprintf(stderr, "Error seeking flash position\n");
//        return 0;
//    }
//    if (read(rawfd, dir, sizeof(struct directory)) < 0)
//    {
//        fprintf(stderr, "Error reading directory\n");
//        return 0;
//    }
//#endif
//    if (dir->magic != DIRECTORY_MAGIC)
//        return 0;
//    /*
//     * calculate the checksum of the whole directory structure
//     * except the first 8 bytes (magic and crc)
//     */
//    (void) updcrc(NULL, 0); /* reset crc calculation state */
//    crc = updcrc((uint8_t *)dir + crc_dir_offset, sizeof(struct directory) - crc_dir_offset);
//
//    if (crc == dir->crc)
//    {
//#ifdef TEST
//        printf("Found valid directory at offset 0x%x\n", offset);
//#endif       
//        //found = 1;
//        return (int)offset;
//    }
//#ifdef __KERNEL__
//    printk(KERN_INFO "%s: no directory found\n", "igel-loop"/*CLOOP_NAME*/);
//#endif
//    return 0;
//}
//
//
#ifndef GRUB2_BOOTCODE
///*
// *  Given a filedescriptor "rawfd" referring to the raw storage media,
// *  and a pointer to a directory structure, this function calculates
// *  the directory's crc cecksum and writes the whole block to position
// *  "offset" within section #0.
// *
// *  TODO: dir->version !
// */
//#ifdef __KERNEL__
//void write_directory(struct file *file, struct directory *dir, int offset)
//#else /* __KERNEL__ */
//void write_directory(int rawfd, struct directory *dir, int offset)
//#endif /* __KERNEL__ */
//{
//    makecrc(); /* crc initial table setup */
//    /*
//     * calculate the checksum of the whole directory structure
//     * except the first 8 bytes (magic and crc)
//     */
//    (void) updcrc(NULL, 0); /* reset crc calculation state */
//    dir->crc = updcrc((unsigned char *)dir + 8, sizeof(struct directory) - 8);
//#ifdef __KERNEL__
//    //igel_write_to_file(file, (char *)dir, sizeof(struct directory), offset);
//#else /* __KERNEL__ */
//    if (lseek(rawfd, offset, SEEK_SET) == -1)
//    {
//        printf("Error seeking flash position\n");
//        return;
//    }
//    if (write(rawfd, dir, sizeof(struct directory)) < 0)
//    {
//        printf("Error writing directory\n");
//        return;
//    }
//#endif /* __KERNEL__ */
//}

static void print_fragment_list(struct fragment_descriptor *fragments, int n)
{
    int i, first, length, length_total;

    if (n == 0)
    {
#ifdef __KERNEL__
        printk(KERN_INFO "%s: fragment_list:  (empty)\n", /*CLOOP_NAME*/"igel-loop");
#else
        printf("  (empty)\n");
#endif
        return;
    }
    for (i=0, length_total=0; i<n; i++)
    {
        first  = fragments[i].first_section;
        length = fragments[i].length;
        length_total += length;
#ifdef __KERNEL__
	printk(KERN_INFO "  %3d-%3d", first, first + length - 1);
#else
        printf("  %3d-%3d", first, first + length - 1);
#endif
    }
#ifdef __KERNEL__
    printk(KERN_INFO "  total: %d\n", length_total);
#else
    printf("  total: %d\n", length_total);
#endif
}


void print_directory(char *title, struct directory *dir)
{
    int i;
    int n_fragments;
#ifdef TEST
    int n_merged;
    struct fragment_descriptor merged_fragments[MAX_FRAGMENTS];
#endif

#ifdef __KERNEL__
    printk(KERN_INFO "\n%s\n", title);
    printk(KERN_INFO "magic: %0lx  crc: %0lx  version: %lu  n_fragments: %lu\n",
            (long unsigned int)dir->magic, (long unsigned int)dir->crc, (long unsigned int)dir->version, (long unsigned int)dir->n_fragments);
#else /* __KERNEL__ */
    printf("\n%s\n", title);
    printf("magic: %0lx  crc: %0lx  version: %lu  n_fragments: %lu\n",
            (long unsigned int)dir->magic, (long unsigned int)dir->crc, (long unsigned int)dir->version, (long unsigned int)dir->n_fragments);
#endif /* __KERNEL__ */

    for (i = 0; i < DIR_MAX_MINORS; i++)
        if ((n_fragments = dir->partition[i].n_fragments) > 0 || (i == 0))
            {
                if (i == 0)
#ifdef __KERNEL__
                    printk(KERN_INFO "free list:  ");
#else
                    printf("free list:  ");
#endif
                else
#ifdef __KERNEL__
                    printk(KERN_INFO "partition %d:", i);
#else
                    printf("partition %d:", i);
#endif
                print_fragment_list(
                    &(dir->fragment[dir->partition[i].first_fragment]),
                    n_fragments);
            }
#ifdef TEST
    n_merged = merge_partitions(dir, merged_fragments);
    printf("merged list:");
    print_fragment_list(merged_fragments, n_merged);
#endif
}


#ifdef TEST
/*----------------------------------------------------------------------
 *  Testing
 */
int main(int argc, char *argv[])
{
    int i, n;
    int sys_size, usr_size;

    printf("\n\n");
    create_empty_directory(&dir1, 100);
    print_directory("initial empty state", &dir1);
    
    /*
     * Test 1
     * Simulation of a typical update scenario (multiple times).
     *
     * At each update, both the sys partition (partition 1)
     * and the usr partition (partition 2) grow a bit.
     */
    for (i=0; i<11; i++)
    {
        if (i == 0)
            printf("\nInitial installation\n");
        else
            printf("\n%d. Update\n", i);
        /*
         * The usr partition (and eventually other partitions) is deleted
         * in the sense, that the occupied fragments go back to the free
         * list. They can be claimed again by allocate_fragments().
         */
        igeldir_delete_partition(&dir1, &dir2, 2);
        print_directory("usr deleted", &dir2);

        /* 
         * The old sys partition is not deleted yet.
         * We allocate additional sections/fragments for the new version
         * of the sys partition without deleting the old one.
         */
        n = allocate_fragments(&dir2, new_fragments, 16, 20+i);

        /*
         * By updating the directory, the old sys partition entry is replaced
         * by the the new one and the fragments occupied by the old sys
         * partition go back to the free list. But the data sections of the
         * old sys partition are still there.
         */
        igeldir_add_partition(&dir2, &dir1, 1, new_fragments, n);
        print_directory("sys updated", &dir1);

        /*
         * Finally, (after a reboot) a new usr partition
         * (and eventually others) is getting installed.
         * Only here, the fragments of the old sys partition are reused.
         */
        n = allocate_fragments(&dir1, new_fragments, 16, 50+2*i);
        igeldir_add_partition(&dir1, &dir2, 2, new_fragments, n);
        print_directory("usr updated", &dir2);
    }

    /*
     * Test 2
     * Mapping of logical section numbers to physical sections
     */
    printf("\nSection table of partition 2:\n");
    usr_size = 50+2*(i-1);
    for (i=0; i<usr_size; i++)
    {
        printf("%3d  %3d\n", i, get_physical_section(&dir2, 2, i));
    }
    
    return 0;
}
#endif /* ifdef TEST */
#endif /* ifndef GRUB2_BOOTCODE */

