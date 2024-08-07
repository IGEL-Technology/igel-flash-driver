#
# Makefile for IGEL Flashdisk device driver.
#

ccflags-y := -Wall

# in case of in-tree build
#obj-$(CONFIG_BLK_DEV_IGEL) += igel-flash.o
#igel-flash-objs	:= compressed_loop.o directory.o

# in case of out-of-tree build
#obj-m += igel-flash.o
#igel-flash-objs	:= compressed_loop.o directory.o
obj-m += igel-flash.o
#igel-flash-objs	:= loop.o directory.o
igel-flash-objs	:= loop.o crc_check.o util.o directory.o proc.o blake2b-ref.o validate.o igel_keys.o section_allocation.o

# in case of out-of-tree build
#obj-m += igel-migrate-flash.o
#igel-migrate-flash-objs	:= compressed_loop-migrate.o directory.o

SRC=$(shell pwd)
all:
	make -C $(KERNEL_SRC) M=$(SRC)

install_modules:
	make -C $(KERNEL_SRC) M=$(SRC) install_modules

clean:
	 rm -rf *.o Module.symvers modules.order igel-flash.* igel-migrate-flash.* .compressed_loop-migrate.o.cmd .built-in.o.cmd .compressed_loop.o.cmd .directory.o.cmd .igel-migrate-flash.* .igel-flash.ko.cmd .igel-flash.mod.o.cmd .igel-flash.o.cmd .tmp_versions .compressed_loop.o.d
