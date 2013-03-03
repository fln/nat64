obj-m += nat64.o
nat64-objs := nat64_core.o nat64_netdev.o nat64_session.o
CFLAGS_nat64.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
