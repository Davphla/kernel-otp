KVERSION = $(shell uname -r)

EXTRA_CFLAGS += -DCRYPTO

obj-m += otp.o
otp-objs += ./src/otp_module.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
