#ifndef __IGEL_KEYS__
#define __IGEL_KEYS__

struct igel_key {
	const unsigned char *data;
	const unsigned int len;
	const char *name;
};

extern struct igel_key igel_keystore[];
extern const size_t igel_key_count;

#endif /* __IGEL_KEYS__ */
