#include <linux/bvec.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/akcipher.h>

#include </usr/include/igel64/igel.h>

#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <linux/key.h>
#include <crypto/public_key.h>

#include "section_allocation.h"
#include "igel.h"
#include "loop.h"
#include "blake2.h"
#include "igel_keys.h"

uint32_t calculate_section_hash(uint8_t *section);
struct igel_hash_info {
	uint32_t offset_cache;
	uint32_t offset_hashes;
	uint32_t count_blocks;
	uint32_t block_size;
	uint16_t count_excludes;
	uint16_t hash_size;
};

int do_validate_block(struct igel_loop_device *lo, size_t block);
int validate_block(struct igel_loop_device *lo, size_t block);
int validate_slice(struct igel_loop_device *lo, size_t begin, size_t len);
int verify_hash_info(struct igel_hash_header *hhdr, struct igel_hash_info *hihdr,
		     int *mount_order, uint32_t *cmty_pkid, int allow_additional_partitions);
int build_hash_info(struct igel_loop_private *private, int part, uint8_t **blk_ptr,
		    int *mount_order, uint32_t *cmty_pkid);

//static int read_slice(uint8_t *buffer, struct file *file, loff_t offset, size_t len)
//{
//	mm_segment_t old_fs = get_fs();
//	int ret;
//
//	set_fs(get_ds());
//	ret = vfs_read(file, buffer, len, &offset);
//	set_fs(old_fs);
//
//	return ret != len ? -EIO : 0;
//}


//static int read_section(uint8_t *buffer, struct file *file, size_t section)
//{
//	return read_slice(buffer, file, START_OF_SECTION(section), IGF_SECTION_SIZE);
//}

static void generate_hash(uint8_t *block_data,
                          uint8_t *hash_buffer,
                          struct igel_hash_info *hinfo,
			  size_t block_index)
{
	struct igel_hash_exclude *excludes =
		(struct igel_hash_exclude *)(hinfo + 1);
	size_t pos = block_index * hinfo->block_size;
	size_t i;

	/* This is a stupid hack around an issue with the igelupdate utility
	 * up to (but not including) 11.02.100.
	 * It writes the current partition minor into the section_in_minor field,
	 * instead of keeping the strictly increasing counter (which is in there during signage).
	 * So we have to fix it here =.= */
	{
		struct igf_sect_hdr *hdr = (struct igf_sect_hdr *)block_data;
		if (hdr->section_in_minor == hdr->partition_minor) {
			hdr->section_in_minor = block_index;
		}
	}

	for (i = 0; i < hinfo->count_excludes; ++i) {
		size_t repeat;
		/* Simple case, we have the exclude in our block */
		if (excludes[i].start >= pos &&
				excludes[i].start < pos + hinfo->block_size) {

			memset(block_data + excludes[i].start, 0, excludes[i].size);
			continue;
		}

		if (!excludes[i].repeat || excludes[i].end < pos) {
			continue;
		}

		repeat =
			(pos / excludes[i].repeat) * excludes[i].repeat + excludes[i].start;
		/* repeat <= pos from the previous calculation */
		if (repeat <= pos && repeat + excludes[i].size > pos) {
			/* parens here to force correct unsigned math */
			size_t size = (repeat + excludes[i].size) - pos;
			memset(block_data, 0, size);
			continue;
		}

		if (repeat >= pos && repeat < pos + hinfo->block_size) {
			memset(block_data + repeat - pos, 0, excludes[i].size);
			continue;
		}
	}


	blake2b(hash_buffer, hinfo->hash_size, block_data, hinfo->block_size, NULL, 0);
}

static int validate_block_data(uint8_t *block_data,
                               struct igel_hash_info *hinfo,
			       size_t block_index)
{
	uint8_t *hash;
	uint8_t *cache;
	uint8_t hash_buffer[64];

	hash = ((uint8_t *)hinfo) +
		hinfo->offset_hashes +
		block_index * hinfo->hash_size;
	cache = ((uint8_t *)hinfo) +
		hinfo->offset_cache;

	generate_hash(block_data, hash_buffer, hinfo, block_index);
	if (crypto_memneq(hash_buffer, hash, hinfo->hash_size)) {
		return false;
	}

	cache[block_index] = true;
	return true;
}

int do_validate_block(struct igel_loop_device *lo, size_t block)
{
	int ret = 0;
	uint8_t *block_buffer = NULL;
	struct igel_section_allocation *allocation = NULL;
	struct igel_hash_info *hihdr =
		(struct igel_hash_info *) lo->lo_igel_info.hash_block;

	allocation = make_section_allocation();

	if (!allocation) {
		return -ENOMEM;
	}
	block_buffer = allocation->vmapping;

//	ret = read_slice(block_buffer, lo->igel_private->file,
//	                 block * hihdr->block_size, hihdr->block_size);
	ret = read_section_allocation(allocation, lo->igel_private->file, get_physical_section(&lo->igel_private->dir, lo->lo_number, block));
	if (ret) {
		goto out;
	}

	if (validate_block_data(block_buffer, hihdr, block)) {
		ret = 0;
	} else {
		ret = -EINVAL;
	}
out:
	free_section_allocation(allocation);
	return ret;
}

int validate_block(struct igel_loop_device *lo, size_t block)
{
	uint8_t *cache = NULL;
	struct igel_hash_info *hinfo =
		(struct igel_hash_info *) lo->lo_igel_info.hash_block;
	if (!lo->lo_igel_info.has_hash_info) {
		return 0;
	}

	if (!hinfo) {
		return -ENOENT;
	}

	cache = lo->lo_igel_info.hash_block + hinfo->offset_cache;
	if (cache[block]) {
		return 0;
	}

	return do_validate_block(lo, block);
}

int validate_slice(struct igel_loop_device *lo, size_t begin, size_t len)
{
	size_t end = begin + len;
	size_t first_block, last_block, cur_block;
	struct igel_hash_info *hinfo =
		(struct igel_hash_info *) lo->lo_igel_info.hash_block;

	if (!lo || !lo->lo_igel_info.has_hash_info) {
		return 0;
	}

	if (!hinfo) {
		return -ENOENT;
	}

	first_block = (begin / hinfo->block_size);
	last_block = (end / hinfo->block_size);


	for (cur_block = first_block; cur_block <= last_block; ++cur_block) {
		int ret;
		if ((ret = validate_block(lo, cur_block))) {
			return ret;
		}
	}

	return 0;
}

static int check_with_key(const unsigned char *key_data, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          const uint8_t *signature, size_t siglen)
{
	int ret = 0;
	struct akcipher_request *req = NULL;
	struct crypto_wait cwait;
	struct crypto_akcipher *tfm = NULL;
	struct scatterlist src_sg[2];

	tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		printk("igel-loop: Failed to alloc akcipher\n");
		return PTR_ERR(tfm);
	}

	ret = crypto_akcipher_set_pub_key(tfm, key_data, key_len);
	if (ret < 0) {
		printk("igel-loop: Failed to set pubkey\n");
		goto out_free_tfm;
	}

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk("igel-loop: Failed to alloc request\n");
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	/* This code and comment works only for kernel 5.2 onwards! */
	/* The api for akcipher_verify is a bit weird.
	 * We set both the signature and the digest (aka signed value) as input
	 * data for our operation, set output to NULL, but use the individual
	 * sizes of those two in the request for input/output size.
	 * Return value will be 0 on success, and error code otherwise.
	 * Probably -EKEYREJECTED, which we want to return either way */
	sg_init_table(src_sg, 2);
	sg_set_buf(&src_sg[0], signature, siglen);
	sg_set_buf(&src_sg[1], data, data_len);

	akcipher_request_set_crypt(req, src_sg, NULL, siglen, data_len);

	crypto_init_wait(&cwait);

	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG| CRYPTO_TFM_REQ_MAY_SLEEP,
	                              crypto_req_done, &cwait);

	ret = crypto_akcipher_verify(req);
	ret = crypto_wait_req(ret, &cwait);

	if (ret == -EINVAL) {
		ret = -EKEYREJECTED;
	}
	akcipher_request_free(req);

out_free_tfm:
	crypto_free_akcipher(tfm);

	return ret;
}

static int verify_cmty_part(uint8_t *digest, size_t dgstlen,
                            uint8_t *signature, size_t siglen,
			    uint32_t *cmty_pkid)
{
	struct public_key_signature pks;
	struct key *keyring = NULL;
	int ret = 0;

	*cmty_pkid = 0;

	/* find our keyring */
	keyring = request_key(&key_type_keyring, "igel_cmty", false);
	if (IS_ERR(keyring)) {
		printk(KERN_INFO "igel-loop: unable to get \"igel_cmty\" keyring\n");
		return PTR_ERR(keyring);
	}
	printk(KERN_DEBUG "igel-loop: keyring = %p\n", keyring);

	/* prepare signature verification struct */
	memset(&pks, 0x00, sizeof(pks));
	pks.s = signature;
	pks.s_size = siglen;
	pks.digest = digest;
	pks.digest_size = dgstlen;
	pks.pkey_algo = "rsa";
	pks.hash_algo = "sha256";
	pks.encoding = "pkcs1";

	ret = verify_signature_igel(keyring, &pks, cmty_pkid);
	printk(KERN_DEBUG "igel-loop: verify_signature() = %d\n", ret);

	/* release keyring */
	key_put(keyring);

	return ret;
}

int verify_hash_info(struct igel_hash_header *hhdr, struct igel_hash_info *hihdr, int *mount_order, uint32_t *cmty_pkid, int allow_additional_partitions)
{
	struct crypto_shash *alg = NULL;
	uint8_t digest[32];
	size_t i = 0;
	int ret = 1;

	alg = crypto_alloc_shash("sha256", CRYPTO_ALG_TYPE_SHASH, 0);
	{
		SHASH_DESC_ON_STACK(desc, alg);
		desc->tfm = alg;

		crypto_shash_init(desc);
		crypto_shash_update(desc, (uint8_t *)(hihdr + 1), hihdr->count_excludes * sizeof(struct igel_hash_exclude));
		crypto_shash_update(desc, ((uint8_t *)hihdr) + hihdr->offset_hashes, hihdr->count_blocks * hihdr->hash_size);

		crypto_shash_final(desc, digest);
	}
	crypto_free_shash(alg);

	*cmty_pkid = 0;

	/* Most of the time, this should be a single one.
	 * * Iterating multiple is only for internal (or maybe migration?) */
	for (i = 0; i < igel_key_count; ++i) {
		ret = check_with_key(igel_keystore[i].data,
				     igel_keystore[i].len,
				     digest, sizeof(digest),
				     hhdr->signature,
				     igel_keystore[i].len == 270 ? 256 : 512);
		if (!ret) {
			printk("Validated with key: %s\n", igel_keystore[i].name);
			/* Here we grab the position of the signature in the igel_keys array,
			 * which is the mount order. If we insert or add new signatures
			 * Dev signature is ordered to mount_order 1 */
			*mount_order = (int)i + 1;
			if (strcmp(igel_keystore[i].name, "11.03 - INTERNAL") == 0) 
				*mount_order = 1;
			return 0;
		}
	}

	if (allow_additional_partitions != 0)  /* detect community partition  */ {
		ret = verify_cmty_part(digest, sizeof(digest),
		                       hhdr->signature, sizeof(hhdr->signature),
				       cmty_pkid);
		/* Use mount_order with highest number for community apps */
		if (!ret)
			*mount_order =  igel_key_count;
	}

	return ret;
}

static int is_hash_header(const struct igel_hash_header *hash_hdr)
{
	return hash_hdr->ident[0] == 'c' &&
	       hash_hdr->ident[1] == 'h' &&
	       hash_hdr->ident[2] == 'k' &&
	       hash_hdr->ident[3] == 's' &&
	       hash_hdr->ident[4] == 'u' &&
	       hash_hdr->ident[5] == 'm';
}

int build_hash_info(struct igel_loop_private *private, int part, uint8_t **blk_ptr,
		    int *mount_order, uint32_t *cmty_pkid)
{
	int ret = 0, logical_section = 0;
	size_t section_to_read = 0, first_section = 0, alloc_size = 0, to_copy = 0, read_now = 0;
	off_t off_src = 0, off_dst = 0;
	struct igf_part_hdr *phdr;
	struct igel_hash_header hhdr, *phhdr;
	struct igel_hash_info *hihdr;
	struct igel_section_allocation *allocation;
	uint8_t *section = NULL, *helper = NULL, *ptr = NULL;

	*blk_ptr = NULL;
	allocation = make_section_allocation();
	if (!allocation) {
		return -ENOMEM;
	}
	section = allocation->vmapping;
	if (!section) {
		return -ENOMEM;
	}

	phdr = (struct igf_part_hdr *)(section + IGF_SECT_HDR_LEN);
	helper = (uint8_t *)(phdr + 1);
	section_to_read =
		get_physical_section(&private->dir, part, logical_section++);
	if (section_to_read == 0xffffffff) {
		ret = -ENOENT;
		goto out;
	}

	first_section = section_to_read;
	ret = read_section_allocation(allocation, private->file, section_to_read);
	if (ret) {
		goto out;
	}

	phhdr = (struct igel_hash_header *)(helper + phdr->n_extents * sizeof(struct igf_partition_extent));

	if (!is_hash_header(phhdr)) {
		ret = -ENOENT;
		goto out;
	}

	memcpy((uint8_t *)&hhdr, (uint8_t *)phhdr, sizeof(struct igel_hash_header));

	alloc_size =
		/* Our hash info header */
		sizeof(struct igel_hash_info) +
		/* Enough storage to fit the excludes we need later on */
		hhdr.count_excludes * hhdr.excludes_size +
		/* The hashes themselves are stored in here */
		hhdr.count_hash * hhdr.hash_bytes +
		/* Storage used to cache the validated state */
		hhdr.count_hash;

	*blk_ptr = vzalloc(alloc_size);

	if (!*blk_ptr) {
		ret = -ENOMEM;
		goto out;
	}

	hihdr = (struct igel_hash_info *)*blk_ptr;
	hihdr->count_excludes = hhdr.count_excludes;
	hihdr->block_size = hhdr.blocksize;
	hihdr->count_blocks = hhdr.count_hash;
	hihdr->hash_size = hhdr.hash_bytes;

	hihdr->offset_cache =
		sizeof(struct igel_hash_info) +
		hhdr.count_excludes * hhdr.excludes_size;
	hihdr->offset_hashes = hihdr->offset_cache + hhdr.count_hash;

	memcpy(*blk_ptr + sizeof(struct igel_hash_info),
	       ((uint8_t *)phhdr) + hhdr.offset_hash_excludes,
	       hhdr.count_excludes * hhdr.excludes_size);

	to_copy = hhdr.count_hash * hhdr.hash_bytes;
	off_dst = hihdr->offset_hashes;
	off_src = IGF_SECT_HDR_LEN + hhdr.offset_hash;
	if (off_src + to_copy > IGF_SECTION_SIZE) {
		read_now = IGF_SECTION_SIZE - off_src;
		ptr = *blk_ptr + off_dst;
		while (to_copy > 0) {
			memcpy(ptr, section + off_src, read_now);
			to_copy -= read_now;
			ptr += (uintptr_t) read_now;
			if (to_copy > 0) {
				section_to_read =
					get_physical_section(&private->dir, part, logical_section++);
				if (section_to_read == 0xffffffff) {
					ret = -ENOENT;
					goto out;
				}
				ret = read_section_allocation(allocation, private->file, section_to_read);
				if (ret) {
					goto out;
				}
			}
			if (to_copy > IGF_SECT_DATA_LEN) {
				read_now = IGF_SECT_DATA_LEN;
			} else {
				read_now = to_copy;
			}
			off_src = IGF_SECT_HDR_LEN;
		}
	} else {
		memcpy(*blk_ptr + off_dst,
		       section + off_src,
		       to_copy);
	}

	ret = verify_hash_info(&hhdr, hihdr, mount_order, cmty_pkid, private->allow_additional_partitions);
	if (ret) {
		printk("igel-loop: %d -> verify_hash_info: %d\n", part, ret);
	} else {
		if (first_section != section_to_read) {
			ret = read_section_allocation(allocation, private->file, first_section);
			if (ret) {
				goto out;
			}
		}

		/* Negate here to from bool to our usual command style thingy */
		if (!validate_block_data(section, hihdr, 0)) {
			ret = -EINVAL;
		}
	}
out:
	free_section_allocation(allocation);
	if (ret) {
		if (*blk_ptr) {
			vfree(*blk_ptr);
			*blk_ptr = NULL;
		}
		printk("igel-loop: Signature verification failed: %d\n", part);
	}
	return ret;
}
