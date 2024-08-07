#ifndef _IGEL_KERNEL_H
#define _IGEL_KERNEL_H

/* Use zlib_inflate from lib/zlib_inflate */
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/version.h>

//#include "igel_table.h"

/*
 * IGEL flash structure 
 */
#define IGEL_DEVICE_NAME                "IGEL Flash Disk"
#define IGF_DEV_NAME                    "igf"

//struct cloop_device
//{
//	/* Copied straight from the file */
//	struct cloop_head head;
//
//	/* An array of offsets of compressed blocks within the file */
//	loff_t *offsets;
//
//	/* Type of partition */
//	uint16_t part_type;
//	/* start of the compressed block clusters   */
//	uint64_t offset_blocks;
//	/* len of data in section should be in most cases IGF_SECT_DATA_LEN */
//	uint64_t section_data_len;
//	/* len of hdr in section should be in most cases IGF_SECT_HDR_LEN */
//	uint64_t section_hdr_len;
//
//	/* We buffer some uncompressed blocks for performance */
//	loff_t buffered_blocknum[BUFFERED_BLOCKS];
//	int current_bufnum;
//	void *buffer[BUFFERED_BLOCKS];
//	void *compressed_buffer;
//
//	z_stream zstream;
//
//	struct file   *backing_file;  /* associated file */
//	struct inode  *backing_inode; /* for bmap */
//
//	size_t largest_block;
//	unsigned int underlying_blksize;
//	uintptr_t minor;  /* in original cloop code: int clo_number */
//	int refcnt;
//	struct block_device *bdev;
//	int isblkdev;
//	/* Lock for kernel block device queue */
//	spinlock_t queue_lock;
//	/* lang@igel.de: we use a global mutex for ioctl() */
//	/* mutex for ioctl() */
//	/* struct mutex clo_ctl_mutex; */
//	struct list_head clo_list;
//	struct task_struct *clo_thread;
//	wait_queue_head_t clo_event;
//	struct request_queue *clo_queue;
//	struct gendisk *clo_disk;
//	char clo_file_name[LO_NAME_SIZE];
//	u_int16_t is_locked;
//};
//
///* function prototypes */
//
u_int32_t updcrc(unsigned char *s, unsigned int n);
void makecrc(void);
//int igel_write_to_file(struct file *f, const char *buf, const int len, loff_t pos);
//ssize_t cloop0_nocache_read_from_file(struct cloop_device *clo, struct file *f, char *buf,
//                                             loff_t pos, size_t buf_len);

#include "igelsdk.h"
//#include "loop.h"
struct igel_loop_device;

/* This is a basic private data struct of the driver.
 * It will be used by every block device based on the same file.
 * It contains the directory, the file reference and some management data.
 *
 * It should be created when a file is attached and is "owned" by partition 0
 */
struct igel_loop_private {
	struct list_head link; 	/* The list node to keep this around */
	struct file *file;	/* The file backing our structure */
	struct igel_loop_device *part_zero;	/* The partition 0 aka normal
						 * loop dev on entire file */
	struct idr minors;
	struct idr crc_cache;
	wait_queue_head_t validate_wait;

	struct directory dir;	/* The directory of the backing file */
	char basename[25];	/* The base name of devices created with this instance (igf) */
	int major;		/* The major to use for devices from this instance (61) */
	struct proc_dir_entry *proc_entry;
	int allow_additional_partitions;
};


/* defines for status in section info */
#define SECT_OK 1	/* regular section, CRC check (if any) passed  */
#define SECT_BOOT 2	/* reserved for boot code */
#define SECT_FF 3	/* erased section */
#define SECT_COMMIT 4	/* after a succesfully commited update */
#define SECT_BAD 5	/* section failed CRC check without being empty */

/* entry in kernel section array */
struct igel_section_info
{
	struct igf_sect_hdr shdr;
	u_int8_t status;
} __packed;

/* entries to save fragments a linked list, needed only for failsafe case */
struct igel_partition_frags
{
	u_int32_t section;
	u_int32_t length;
	struct igel_partition_frags *next;
} __packed;

/* entry in kernel partition array */
struct igel_partition_info
{
	struct {
		u_int16_t is_valid:		1;
		u_int16_t is_locked:		1;
		u_int16_t is_invalidated:	1;
		u_int16_t has_hash_info:	1;
		u_int16_t has_wrong_hash:	1;
	};
	u_int16_t generation_number;
	u_int32_t first_section;
	u_int32_t lastsect;
	u_int32_t num_sections;
	u_int32_t magic;
	uint8_t *hash_block; 
	struct igf_part_hdr phdr;
	struct partition_extents part_exts;
	u_int16_t use_ext_instead;
} __packed;

/* this struct is also needed mainly for failsafe case and contain more detailed
 * info to the partition, also it is used for a linked list if more then one
 * partition is present, the linked list is deleted after the partition with
 * the highest generation is determined. But later this will probably also be
 * useful for the partial update feature */

struct igel_failsafe_info
{
	u_int32_t next_section;
	u_int32_t section_in_minor;
	u_int8_t invalid;
	struct igel_partition_frags *frags;
	struct igel_partition_info *alternative;
} __packed;

struct igel_login_info_element
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    time64_t timestamp;
#else
    time_t timestamp;
#endif
    uint32_t count;
    uint8_t success;
    uint8_t padding[3];
};

struct igel_login_info
{
    uint32_t crc;
    uint32_t size;
    uint32_t position;
    uint8_t  initialized;
    uint32_t last_login_count;
    uint64_t last_login_timestamp;
};

struct igel_login_output
{
	char separator1;
	char time_stamp[12];
	char separator2;
	char count[10];
	char separator3;
	char success;
	char eol;
};

#endif /*_IGEL_KERNEL_H*/

