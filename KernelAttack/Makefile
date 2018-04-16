obj-m += armCache.o
armCache-objs := ./src/armCache.o
KBUILD_CFLAGS += -g -w
EXTRA_CFLAGS  += -save-temps
CROSS_COMPILE =~/CodeSourcery/Sourcery_G++_Lite/bin/arm-none-linux-gnueabi-
TARG_KDIR ?=~/extDisk/imx/i.MX53-QSB-Android-Gingerbread-Release4.2/src/kernel_imx
ARCH=arm

all:
	make -C $(TARG_KDIR) M=$(PWD) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	rm *.ko src/*.o
	
remak:
	rm *.ko *.o
	make -C $(TARG_KDIR) M=$(PWD) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) modules

