#ifndef __SECTION_ALLOCATION_H__
#define __SECTION_ALLOCATION_H__

struct igel_section_allocation {
	struct page *pages[64];
	struct bio_vec bios[64];
	void *vmapping;
};

struct igel_section_allocation * 
make_section_allocation(void);

void
free_section_allocation(struct igel_section_allocation *allocation);

int
read_section_allocation(struct igel_section_allocation *allocation,
                        struct file *file, size_t section);
int
write_section_allocation(struct igel_section_allocation *allocation,
                         size_t offset, size_t len,
                         struct file *file, size_t section);

#endif /* __SECTION_ALLOCATION_H__ */
