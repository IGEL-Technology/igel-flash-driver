#include <linux/types.h>

#include "igel_keys.h"

#include "hsm_key.c"
#include "os12_base_key.c"
#include "os12_app_key.c"
#include "os12_sdk_key.c"
#include "os12_3rdparty_key.c"

/* The position of the key in the igel_keysore is used to order patition mounting.
If keys are added or removed check verify_hash_info function in validate.c!
igfmount needs changes too. mount_optional_partitions calls need to be added and
a new key type needs to be added to the enum in igelpart.h. */
struct igel_key igel_keystore[] = {
#ifdef IGELOS12
	{ .data = base_system_os12_key,
	  .len = sizeof(base_system_os12_key) / sizeof(base_system_os12_key[0]),
	  .name = "OS 12 Base System" },
	{ .data = app_os12_key,
	  .len = sizeof(app_os12_key) / sizeof(app_os12_key[0]),
	  .name = "OS 12 First Party Apps" },
	{ .data = app_3rdparty_key,
	  .len = sizeof(app_3rdparty_key) / sizeof(app_3rdparty_key[0]),
	  .name = "OS 12 Third Party Apps" },
#else /* IGELOS12 */
#ifdef IGELOS1x
	{ .data = base_system_os12_key,
	  .len = sizeof(base_system_os12_key) / sizeof(base_system_os12_key[0]),
	  .name = "OS 12 Base System" },
#endif
	{ .data = hsm_key_data,
	  .len = sizeof(hsm_key_data) / sizeof(hsm_key_data[0]),
	  .name = "OS 11" },
#endif /* IGELOS12 */
#ifdef LXOS_SDK /* For the SDK build, we want to have a key we can hand partners */
	{ .data = sdk_os12_key,
	  .len = sizeof(sdk_os12_key) / sizeof(sdk_os12_key[0]),
	  .name = "OS 12 SDK Partner Apps" },
#endif
};

const size_t igel_key_count = sizeof(igel_keystore) / sizeof(igel_keystore[0]);
