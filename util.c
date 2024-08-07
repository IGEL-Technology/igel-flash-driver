#include <linux/fs.h>
#include </usr/include/igel64/igel.h>
#include "util.h"

const char *
get_part_type_name(uint16_t type) {
	switch (type & 0xff) {
		case PTYPE_EMPTY:
			return "empty";
		case PTYPE_IGEL_RAW:
			return "raw";
		case PTYPE_IGEL_RAW_4K_ALIGNED:
			return "raw (4k aligned)";
		case PTYPE_IGEL_COMPRESSED:
			return "compressed";
		case PTYPE_IGEL_RAW_RO:
			return "raw (ro)";
	}
	return "unknown";
}

const char *
get_extent_type_name(uint16_t type) {
	switch (type) {
	case EXTENT_TYPE_KERNEL:
		return "kernel";
	case EXTENT_TYPE_RAMDISK:
		return "ramdisk";
	case EXTENT_TYPE_SPLASH:
		return "splash";
	case EXTENT_TYPE_CHECKSUMS:
		return "checksums";
	case EXTENT_TYPE_WRITEABLE:
		return "read-write";
	case EXTENT_TYPE_SQUASHFS:
		return "squashfs";
	case EXTENT_TYPE_LOGIN:
		return "login";
	case EXTENT_TYPE_APPLICATION:
		return "application";
	case EXTENT_TYPE_LICENSE:
		return "license";
	}

	return "unknown";
}
