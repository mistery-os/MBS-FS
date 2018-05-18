#
# Makefile for the linux NV2NVMM filesystem routines.
#

obj-m += mbs.o

#PS_brd-y := balloc.o bbuild.o dax.o dir.o file.o inode.o ioctl.o namei.o stats.o super.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
