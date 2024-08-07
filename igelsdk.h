/*
 * IGEL defines and data structures commonly used
 * in three different environments:
 *
 * kernel space: flash kernel driver module
 * grub:	 boot code extensions
 * user space:   tools for creating and analyzing partition images
 * 		 tools for the in system update
 *
 *
 * The IGEL firmware is hosted by an fdisk partition of the storage
 * medium, usually /dev/sda1. This partition doesn't contain a
 * filesystem in the usual sense, but instead contains subpartitions
 * structured in a special IGEL way.
 *
 * One can nevertheless regard this structure as a simple kind of
 * a filesystem with the subpartitions playing the role of simple
 * files: Subpartitions can be dynamically created or deleted or
 * changed in size.
 *
 * In the system's view, a subpartition (= "IGEL partition" or short
 * just "partition") is a block device usually containing a filesystem
 * very similar to a loop-mounted file.
 * 
 * A partition is a linked list of sections defining a subdevice
 * The partition number is the minor of the kernel block device.
 * Such a partition is comparable to a file in a filesystem.
 *
 * Sections are storage blocks of fixed size (typically 256K or 1M)
 * comparable to filesystem blocks. Historically they have been
 * units for flash memory erasure, given by hardware constraints.
 * Section #0 plays a special role as it contains the directory
 * (ref. further down) and the "boot registry".
 *
 * IGEL partitions are referred to by block devices /dev/igf0,
 * /dev/igf1, /dev/igf2, ... with the major number 62 (ref.
 * linux/major.h). The minor number refers to the particular
 * IGEL partition:
 *     0	/dev/igf0, equivalent to /dev/sda1
 *		allows for read/write/erase to the whole flash.
 *		It is used for firmware updates.
 *     >= 1	partitions consisting of a sequence of sections
 *
 * September 2016, IGEL Technology GmbH, Thomas Kraetzig
 */


#ifndef IGEL_H_INCLUDED
#define IGEL_H_INCLUDED

#ifndef GRUB2_BOOTCODE
#ifndef __KERNEL__
/*
 * The following include defines data types like uint32_t
 *
 * In other contexts, like bootcode, it should probably
 * be replaced by something similiar.
 */
#include <stdint.h>
#include <stddef.h>
#endif
#endif

struct directory;
struct partition_extents;

/*
 * There are various functions of the IGEL kernel module
 * available in userspace by ioctls
 * which are mainly used by the update procedure.
 */
#define IGEL_LETTER                     'i'
#define IGFLASH_ERASE_SECTION           _IO  (IGEL_LETTER, 1)
#define IGFLASH_INVAL_BUFFERS           _IO  (IGEL_LETTER, 2)
/* Removes the partition from the system. This removes the block device,
 * the firmware export in /proc/ and overwrites entries on disk.
 * Aka, removes the directory entry and writes over the part header to prevent
 * re-adding on crc-check. But does not wipe contents */
#define IGFLASH_INVAL_PARTITION         _IO  (IGEL_LETTER, 3)
#define IGFLASH_GET_FREE_SECTION        _IOWR(IGEL_LETTER, 4,  uint32_t *)
#define IGFLASH_GET_PARTITION_VERSION   _IOWR(IGEL_LETTER, 5,  uint16_t *)
#define IGFLASH_COMMIT_SECTION          _IO  (IGEL_LETTER, 6)
#define IGFLASH_GET_SIZE                _IOWR(IGEL_LETTER, 7,  uint64_t *)
#define IGFLASH_GET_HWCONFIG            _IOWR(IGEL_LETTER, 8,  uint32_t *)
#define IGFLASH_GET_RAWDEVICE           _IOWR(IGEL_LETTER, 9,  dev_t *)
#define IGFLASH_INIT                    _IO  (IGEL_LETTER, 10)
#define IGFLASH_GET_LAST_SECTION        _IOWR(IGEL_LETTER, 11, uint32_t *)
#define IGFLASH_GET_MAGIC               _IOWR(IGEL_LETTER, 12, uint32_t *)
#define IGFLASH_UPDATE_GENERATION       _IO  (IGEL_LETTER, 13)
#define IGFLASH_GET_FREE_SECTIONS       _IOWR(IGEL_LETTER, 14, uint32_t *)
#define IGFLASH_GET_DIRECTORY           _IOWR(IGEL_LETTER, 15, struct directory *)
#define IGFLASH_GET_RAWIGFDISK          _IOWR(IGEL_LETTER, 16, uint32_t *)
#define IGFLASH_REGISTER_PARTITION      _IO  (IGEL_LETTER, 17)
/* This disables a partition. The partition's block device will be removed,
 * but it stays around. The proc interface will be available (for buddy server)
 * and the entry in directory persists (so it won't be overwritten with new
 * partitions). */
#define IGFLASH_DISABLE_PARTITION       _IO  (IGEL_LETTER, 18)
#define IGFLASH_GET_EXTENT_SIZE         _IOWR(IGEL_LETTER, 19, struct partition_extents *)
#define IGFLASH_GET_EXTENT              _IOWR(IGEL_LETTER, 20, uint32_t *)
#define IGFLASH_WIPE_PARTITION          _IO  (IGEL_LETTER, 21)
#define IGFLASH_WIPE_PARTITION_SECURE   _IO  (IGEL_LETTER, 22)
#define IGFLASH_LOCK_PARTITION          _IO  (IGEL_LETTER, 23)
#define IGFLASH_SWITCH_TO_EXTENT	_IOWR(IGEL_LETTER, 24, uint32_t *)
#define IGFLASH_READ_EXTENT             _IOWR(IGEL_LETTER, 25, struct part_ext_read_write *)
#define IGFLASH_WRITE_EXTENT            _IOWR(IGEL_LETTER, 26, struct part_ext_read_write *)

/*
 * Other features provided by the IGEL kernel module
 * available in userspace by ioctls.
 * BUT called on the igel-control device,
 * not the block devices
 */

#define IGFLASH_REMOVE_DEVICE        _IOW(IGEL_LETTER, 27,  int)
#define IGFLASH_ADD_DEVICE           _IOWR(IGEL_LETTER, 28, struct igel_flash_dev_desc *)
#define IGFLASH_RELOAD_PARTITION	 _IO  (IGEL_LETTER, 29)

/* Used for IGFLASH_GET_RAWIGFDISK ioctl */
struct rawblkdev
{
  uint32_t major;
  uint32_t minor;
} __attribute__((packed));

struct igel_flash_dev_desc {
	int major;	/* The major device number, the device should use */
	int fd;		/* An RW-fd to the backing file of the new device */
	char name[8];	/* The basename the device nodes should use" */
} __attribute__((packed));


/**
 **  Section Header:
 ** 
 **  Each section (except section #0 and uninitialized sections)
 **  starts with a section header:
 **
 **  We maintain a section_type, allowing for future extensions/modifications
 **  of the section header format.
 **  The section_size is somewhat redundant, but it allows for detecting
 **  incompatible sections easier during the evaluation phase.
 **/
#define SECT_TYPE_INVALID	0
#define SECT_TYPE_IGEL_V6	1

/*
 * The equation: section_size = log2((section size in bytes)/65536),
 * leads to the following defines:
 */
#define SECT_SIZE_64K   0U
#define SECT_SIZE_128K  1U
#define SECT_SIZE_256K  2U
#define SECT_SIZE_512K  3U
#define SECT_SIZE_1M    4U
#define SECT_SIZE_2M    5U
#define SECT_SIZE_4M    6U
#define SECT_SIZE_8M    7U
#define SECT_SIZE_16M   8U

/*
 * The section size is set at compile time and can't be changed dynamically.
 * It is not intended even to change it during a firmware update.
 * Changing the section size requires recompilation
 * of all involved software components.
 */
#define LOG2_SECT_SIZE	SECT_SIZE_256K
#define IGF_SECTION_SIZE  (uint64_t)(0x10000UL << (LOG2_SECT_SIZE & 0xf))

/*
 * helper macros START_OF_SECTION(n), SECTION_OF(x) and OFFSET_OF(x) is needed 
 * in kernel and bootcode, also IGF_SECTION_SHIFT is used there.
 */

#define IGF_SECTION_SHIFT       (16 + (LOG2_SECT_SIZE & 0xf))
#define START_OF_SECTION(n)     (uint64_t)(((uint64_t)n) << (IGF_SECTION_SHIFT))
#define SECTION_OF(x)		((x) >> (IGF_SECTION_SHIFT))
#define OFFSET_OF(x)		((x) & (IGF_SECTION_SIZE - 1))

/*
 * We reserve 32 bytes for the section header, although the real
 * section header data is a bit shorter. This gives us some
 * headroom for later extensions without changing the payload size.
 */
#define IGF_SECT_HDR_LEN  32	/* we assume section hdrs to be that long! */
#define IGF_SECT_DATA_LEN (IGF_SECTION_SIZE - IGF_SECT_HDR_LEN) /* payload size */
#define SECTION_IMAGE_CRC_START	sizeof(uint32_t) /* bytes to skip when calculating the crc */

/*
 * For historical reasons, we support 256 minors. This is mainly
 * for static tables in the kernel driver. In future, all code should
 * be prepared to handle 20 bit minors efficiently.
 * We can then change this constant to 1048576 smoothly, or omit
 * this constant entirely.
 */
#define IGF_MAX_MINORS	  256

struct igf_sect_hdr
{
	uint32_t crc;			/* crc of the rest of the section         */
	uint32_t magic;			/* magic number (erase count long ago)    */
	uint16_t section_type;
	uint16_t section_size;		/* log2((section size in bytes)/65536)    */
	uint32_t partition_minor;	/* partition number (driver minor number) */
	uint16_t generation;		/* update generation count                */
	uint32_t section_in_minor;	/* n = 0,...,(number of sect.-1)          */
	uint32_t next_section;		/* index of the next section or           */
					/* 0xffffffff = end of chain              */
} __attribute__((packed));

/*
 * These devices names are used for writing or reading from the
 * underlying low level device. This is the block device partition
 * containing IGEL sections (usually /dev/sda1).
 *
 * TODO: Do we really need all 3 of them ?
 */
#define IGF_DEV_0_NAME	  "/dev/flashdisk"
#define IGF_DISK_NAME     "/dev/igfdisk"
#define IGF_BOOT_NAME     "/dev/igfboot" /* low level device with IGEL MBR */


/**
 **  Partition Header:
 **
 **  The first section of a partition contains the partition header right after
 **  its section header. It already belongs to the section chain's payload.
 **
 **  A raw partition contains a number of uncompressed 1K blocks
 **  A compressed partition contains a sequence of compressed clusters
 **  A compressed cluster is a contiguous sequence of (usually 32) filesystem
 **  1K blocks
 **
 **  A partition may have so called "extents", containing optional data
 **  which we don't want to access via a filesystem. The SYS (root) partition
 **  contains an extent with a bootable kernel and another one with an initial
 **  ramdisk image.
 **
 **  A partition may contain a signature extent which consists (as of 2016)
 **  of a 64 byte sha512 signature. This signature is a fingerprint of most of
 **  the files in the partition's filesystem. By means of the signature, the
 **  update procedure can determine whether a partition needs to be updated
 **  at all. Furthermore the update procedure can determine if a server provided
 **  update image has changed during an update. This can happen when a long
 **  lasting background update is interrupted and later on resumend.
 **/

/* Partition types */
#define PTYPE_EMPTY			0	/* partition descriptor is free */
#define PTYPE_IGEL_RAW			1	/* an uncompressed an writable partition */
#define PTYPE_IGEL_COMPRESSED		2	/* a compressed read-only partition */
#define PTYPE_IGEL_FREELIST		3	/* only used by the partition directory */
#define PTYPE_IGEL_RAW_RO		4	/* an uncompressed read-only partition (so CRC is valid and should be checked) */
#define PTYPE_IGEL_RAW_4K_ALIGNED	5	/* an uncompressed an writable partition which is aligned to 4k sectors */
#define PFLAG_UPDATE_IN_PROGRESS	0x100	/* flag indicating a not yet to use partition */
#define PFLAG_HAS_IGEL_HASH		0x200	/* flag indicating the presence of a igel hash block after the header */
#define PFLAG_HAS_CRYPT			0x400   /* flag indicating the presence of a encryption */

struct igf_part_hdr
{
	uint16_t type;		    /* partition type                           */
	uint16_t hdrlen;	    /* length of the complete partition header  */
	uint64_t partlen;	    /* length of this partition (incl. header)  */
	uint64_t n_blocks;	    /* number of uncompressed 1k blocks         */
	uint64_t offset_blocktable; /* needed for compressed partitions         */
	uint64_t offset_blocks;	    /* start of the compressed block clusters   */
	uint32_t n_clusters;	    /* number of clusters                       */
	uint16_t cluster_shift;	    /* 2^x blocks make up a cluster             */
	uint16_t n_extents;	    /* number of extents, if any                */
	uint8_t  name[16];	    /* optional character code (for pdir)       */
	uint8_t  update_hash[64];   /* a high level hash over allmost all files */
				    /* used to determine if an update is needed */
} __attribute__((packed));

/*
 * Note:  A variable array of n_extents instances of struct igf_partition_extent 
 *        immediately follows this header.
 */
#define EXTENT_TYPE_KERNEL	1
#define EXTENT_TYPE_RAMDISK	2
#define EXTENT_TYPE_SPLASH	3
#define EXTENT_TYPE_CHECKSUMS	4
#define EXTENT_TYPE_SQUASHFS	5
#define EXTENT_TYPE_WRITEABLE	6
#define EXTENT_TYPE_LOGIN	7
#define EXTENT_TYPE_SEC_KERNEL	8
#define EXTENT_TYPE_DEVICE_TREE	9
#define EXTENT_TYPE_APPLICATION	10
#define EXTENT_TYPE_LICENSE	11

/* Set max read/write size to 5MiB for IGFLASH_READ_EXTENT and IGFLASH_WRITE_EXTENT IOCTLs */

#define EXTENT_MAX_READ_WRITE_SIZE 0x500000

/*
 * Make live easier especially for IOCTL define a MAX_EXTENT_NUM
 */

#define MAX_EXTENT_NUM		10

struct igf_partition_extent
{
	uint16_t type;
	uint64_t offset;
	uint64_t length;
	uint8_t name[8];	/* optional character code */
}  __attribute__((packed));

struct partition_extents
{
	uint16_t n_extents;
	struct igf_partition_extent extent[MAX_EXTENT_NUM];
} __attribute__((packed));

struct part_ext_read_write
{
	uint8_t  ext_num;	/* extent number where to read from */
	uint64_t pos;		/* position inside extent to start reading from */
	uint64_t size;		/* size of data (WARNING limited to EXTENT_MAX_READ_WRITE_SIZE) */
	uint8_t *data;		/* destination/src pointer for the data to */
}  __attribute__((packed));


/*
 * Note: igf_part_cromdisk is a historical name.
 * The suffix "cromdisk" means "compressed romdisk" and refers to an
 * early block device compression scheme introduced by IGEL GmbH in 1995.
 * At that time flash memory was not yet widely available.
 * The system was stored in a set of 4 EPROMS.
 */
#define igf_part_cromdisk igf_part_hdr


/**
 **  Partition directory
 **
 **  The directory is a redundant supplemental data set which makes the
 **  access of IGEL partition data faster, just like a directories/FATs
 **  in filesystems. For each partition it maintains a section
 **  list in compact representation. It draws benefits from the fact, that
 **  the sequences of sections are almost contiguous. In other words, there
 **  usually is very little fragmentation.
 **/

#define DIRECTORY_MAGIC 0x52494450UL	/* "PDIR" */
#define CRC_DUMMY 0x55555555UL

/*
 * fixed position of BOOTREG BLOCK which begins with BOOTREG MAGIC
 * Since the stage2 boot loader is no longer in section #0,
 * we can use the full first 32K for the boot registry
 */
#define IGEL_BOOTREG_OFFSET	0x00000000UL
#define IGEL_BOOTREG_SIZE	0x00008000UL		/* 32 K size */
#define IGEL_BOOTREG_MAGIC	0x4F4F42204C454749ULL	/* "IGEL BOO" */

/*
 * Two alternative fixed positions within section #0
 * ... and leave enough space for the boot registry that starts at offset 0
 */
#define DIR_OFFSET		(IGEL_BOOTREG_OFFSET+IGEL_BOOTREG_SIZE)	/* Starts after the boot registry */
#define DIR_SIZE		(IGF_SECTION_SIZE-DIR_OFFSET) /* Reserve the rest of section #0 for the directory */

/*
 * Note: DIR_MAX_MINORS is not the amount of minor numbers
 *       we actually support (2**32, kernel 2**20), but the
 *       number of partition descriptors we can store in
 *       a static table in the directory.
 *
 * If it ever happens that we need more than 512 partitions
 * at the same time, we can upgrade the directory version and
 * proceed to a partiton descriptor table with dynamic length.
 */
#define DIR_MAX_MINORS 512

/*
 * Experience shows that partition fragmentation occurs very rarely.
 * This means that most partitions consist of exactly one fragment.
 * The free list is an exeption. It can get somewhat fragmented after
 * some updates.
 *
 * Providing a static fragment table of nearly three times as many
 * fragments as partitions seams more than a reasonable choice.
 * If we ever need more fragments, we could upgrade the directory
 * version (see above).
 *
 * We choose the size of the fragment table such that the
 * size of a directory is exactly 16K bytes:
 * 32 + 512 * sizeof(partition_desc) + 1404 * sizeof(fragment_desc) =
 * 32 + 512 * 10 + 1404 * 8 = 32 + 5120 + 11232 = 16384    
 */
#define MAX_FRAGMENTS 1404

/*
 * Fragment descriptor
 *
 * A fragment is a consecutive sequence of sections.
 * Usually, the most partitions consist of only one fragment.
 * (i.e. they are "not fragmented" at all)
 */  
struct fragment_descriptor
{    
	uint32_t first_section;
	uint32_t length;           /* number of sections */
}  __attribute__((packed));
    
/*
 * Partition descriptor
 *
 * The partition descriptor replicates some attributes
 * contained in the partition header.
 *
 * Most partitions are not fragmented: n_fragments = 1.
 *
 * We maintain a separate table of fragments. We specify
 * the index of the descriptor of the first fragment and
 * the number of fragments. The other fragment descriptors
 * (if any) immediately follow the first one.
 */
struct partition_descriptor
{
	uint32_t minor;		   /* a replication of igf_sect_hdr.partition */
	uint16_t type;             /* partition type (UPDATE_IN_PROGRESS)     */
				   /* a replication of igf_part_hdr.type      */
	uint16_t first_fragment;   /* index of the first fragment             */
	uint16_t n_fragments;      /* number of additional fragments          */
} __attribute__((packed));

/*
 * Directory
 *
 * The directory consists of:
 * - header (32 bytes),
 * - array of partition descriptors,
 *   (partition number 0 is the free list)
 * - array of fragment descriptors
 * 
 * Note: The header contains some yet unused dummy bytes
 * to fill up the header length to 32 bytes. If little more
 * header data is required in future, it can be added without
 * changing the offsets of the partition and the fragment tables.
 */
struct directory
{
	uint32_t magic;
	uint32_t crc;
	uint16_t dir_type;	/* allows for future extensions             */
	uint16_t max_minors;	/* redundant, allows for dynamic part table */
	uint16_t version;	/* update count, never used so far          */
	uint16_t dummy;		/* for future extensions                    */
	uint32_t n_fragments;	/* total number of fragments                */
	uint32_t max_fragments;	/* redundant, allows for dynamic frag table */
	uint8_t  extension[8]; 	/* unspecified, for future extensions       */

	struct partition_descriptor partition[DIR_MAX_MINORS];
	struct fragment_descriptor fragment[MAX_FRAGMENTS];
} __attribute__((packed));

/*
 * Bootsplash Header definitions to be able to store more then one Bootsplash
 * in the extent and grub switches then according to bootreg setting to the
 * correct bootsplash.
 */

#define BOOTSPLASH_MAGIC "IGELBootSplash"

struct igel_bootsplash_hdr
{
	uint8_t magic[14];
	uint8_t num_splashs;
} __attribute__((packed));

/* splash header aka splash extents */

struct igel_splash
{
	uint64_t offset;
	uint64_t length;
	uint8_t ident[8];
} __attribute__((packed));


/*
 * Bootreg structures for IGEL OS 11
 */

#define _HAS_IGEL_BOOTREG_STRUCTURES	1

/* encryption algo as num will be the first 4 bit of a uint8_t so up to 15 values possible */

#define BOOTREG_ENC_PLAINTEXT   	0

/* magic for identifying new bootreg header */

#define BOOTREG_MAGIC			"163L"

/* bootreg legacy ident */

#define BOOTREG_IDENT	                "IGEL BOOTREGISTRY"

/* flag register  */

#define BOOTREG_FLAG_LOCK               0x0001

/*
 * Bootreg entries
 *_________________________________________________________
 * | flag |       key       |            value             |
 * | 2Byte| < ----------- block size 62 Byte   ---------  >|
 *
 *
 * key length is defined in flags (0x3F)
 * value is null terminated
 *
 *
 * Multi Block sample
 * index = 1:   | flag = b000001000 1 xxxxxx |   key       |  value     |
 * index = 8:   | flag = b000000000 0 000000 |          value           |
 *
 *
 ******************************************************************************
 * Flag
 *
 * Bits:  |     9     | 1 |    6   |
 *        | xxxxxxxxx | x | xxxxxx |
 *
 * 9 Bits: Next Block Index
 * 1 Bit : Next Block Present
 * 6 Bits: Key Length
 *
 */

struct igel_bootreg_entry {
	uint16_t flag;		/* first 9 bits next, 1 bit next present, 6 bit len key */
	uint8_t data[62];
} __attribute__((packed));


struct igel_bootreg_header {
	char                       ident_legacy[17];    /* "IGEL BOOTREGISTRY" */
	char                       magic[4];            /* BOOTREG_MAGIC */
	uint8_t                    hdr_version;         /* 0x01 for the first */
	char		           boot_id[21];         /* boot_id */
	uint8_t                    enc_alg;             /* encryption algorithm */
        uint16_t                   flags;               /* flags */
	uint8_t		           empty[82];           /* placeholder */
	uint8_t                    free[64];		/* bitmap with free 64 byte blocks */
	uint8_t                    used[64];		/* bitmap with used 64 byte blocks */
	uint8_t                    dir[252];		/* directory bitmap (4 bits for each block -> key len) */
	uint8_t                    reserve[4];		/* placeholder */
	struct igel_bootreg_entry  entry[504];		/* real data */
} __attribute__((packed));

/*
 * IGEL Hash Header block
 */

/* define to check if igel hash header is available */

#define _HAS_IGEL_HASH_HEADER		1

/* defines for signature algos 0-255 */

#define HASH_SIGNATURE_TYPE_NONE	0

/* defines for hash algos 0-255 */

#define HASH_ALGO_TYPE_NONE		0

/* Number of bytes in a single section hash */

#define HASH_BYTE_LEN 64

/* Number of bytes used for the section signature */

#define SIGNATURE_BYTE_SIZE 512

/*
 * the igel_hash_exclude struct is used to mark areas which should be excluded from hashing 
 *
 * the start, end and size are based on absolute addresses not relative to section or partition headers
 */

struct igel_hash_exclude {
	uint64_t	start;			/* start of area to exclude */
	uint32_t	size;			/* size of area to exclude */
	uint32_t	repeat;			/* repeat after ... bytes if 0 -> no repeat */
	uint64_t	end;			/* end address where the exclude area end (only used if repeat is defined */
} __attribute__((packed));

struct igel_hash_header {
	uint8_t		ident[6];		/* Ident string "chksum" */
	uint16_t	version;		/* version number of header probably use with flags 
						 * something like version = version & 0xff; if (version |= FLAG ... */
	uint8_t		signature[512];		/* 512 Bytes -> 4096bit signature length */
	uint64_t	count_hash;		/* count of hash values */
	uint8_t		signature_algo;		/* Used signature algo (which is a define like HASH_SIGNATURE_TYPE_NONE */
	uint8_t		hash_algo;		/* Used hash algo (which is a define like HASH_ALGO_TYPE_NONE */
	uint16_t	hash_bytes;		/* bytes used for hash sha256 -> 32bytes, sha512 -> 64bytes */
	uint32_t	blocksize;		/* size of data used for hashing */
	uint32_t	hash_header_size;	/* size of the hash_header (with hash excludes) */
	uint32_t	hash_block_size;	/* size of the hash values block */
	uint16_t	count_excludes;		/* count of struct igel_hash_exclude variables */
	uint16_t	excludes_size;		/* size of struct igel_hash_exclude variables in Bytes */
	uint32_t	offset_hash;		/* offset of hash block from section header in bytes */
	uint32_t	offset_hash_excludes;	/* offset of hash_excludes block from start of igel_hash_header in bytes */
	uint8_t		reserved[4];		/* reserverd for further use/padding for excludes alignment*/
} __attribute__((packed));
	
/*
 * Function prototypes for directories
 */
#ifndef GRUB2_BOOTCODE
int sections_to_fragments(uint32_t *sections, int n_sections,
                          struct fragment_descriptor *fragments,
                          int max_fragments);
void *create_empty_directory(struct directory *dir, int n_sections);

/* using igeldir_ prefix fo delete_partition and add_partition because of 
 * collision with functions already present in kernelcode */

void igeldir_delete_partition(struct directory *src_dir, struct directory *dst_dir,
                      int minor);

void igeldir_add_partition(struct directory *src_dir,
                   struct directory *dst_dir, int minor,
                   struct fragment_descriptor *new_fragments, int n_frag_new);

int allocate_fragments(struct directory *dir,
                       struct fragment_descriptor *fragments1,
                       int max_fragments, int n_sections);
int allocate_fragments_with_offset(struct directory *dir,
                                   struct fragment_descriptor *fragments1,
                                   int max_fragments, int n_sections, 
                                   int off_section);
int merge_partitions(struct directory *dir,
                     struct fragment_descriptor *merged_fragments);
void print_directory(char *title, struct directory *dir);
int merge_fragments(struct fragment_descriptor *fragments1, int n1,
                    struct fragment_descriptor *fragments2, int n2,
                    struct fragment_descriptor *merged_fragments);
int take_away_fragments(struct fragment_descriptor *fragments1, int n1,
                    struct fragment_descriptor *fragments2, int n2,
                    struct fragment_descriptor *result_fragments);
#ifdef __KERNEL__
void write_directory(struct file *file, struct directory *dir, int offset);
int read_directory(struct file *file, struct directory *dir);
#else /* __KERNEL__ */
void write_directory(int rawfd, struct directory *dir, int offset);
int read_directory(int rawfd, struct directory *dir);
#endif /* __KERNEL__ */
#else /* GRUB2_BOOTCODE */
int read_directory(struct directory *dir, grub_disk_t disk, grub_uint64_t part_offset);
#endif /* GRUB2_BOOTCODE */
uint32_t get_physical_section(struct directory *dir, uint32_t minor, uint32_t i);
int get_partition_from_section(struct directory *dir, uint32_t sect);

#endif /* #ifndef IGEL_H_INCLUDED */

