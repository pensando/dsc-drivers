#
# usage: make KDIR=/path/to/kernel/build/area
#
MODNAME = pciesvc

obj-m := $(MODNAME).o

$(shell echo '#define PCIESVC_VERSION "'`date`'"' >version.h)

kpci :=

pciesvc-src := $(shell cd $(PWD) && ls pciesvc/src/*.c)
pciesvc-obj := $(patsubst %.c,%.o,$(pciesvc-src))
kpci += $(pciesvc-obj)

INCLUDES = -I$(PWD) \
	   -I$(PWD)/pciesvc/include \
	   -I$(PWD)/pciesvc/src

$(MODNAME)-y := $(kpci) kpci_get_entry.o kpcimgr_module.o kpcinterface.o \
	     kpci_entry.o kpci_kexec.o kpci_test.o pciesvc_end.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
UTS := X$(shell grep UTS_RELEASE $(KDIR)/include/generated/utsrelease.h)
REL := $(shell echo $(UTS) | awk '{ print $$3 }' | sed -e 's/"//g')

# find CC like the kernel build does
ifneq ($(LLVM),)
CC = clang
else
CC = $(CROSS_COMPILE)gcc
endif

# Check for cc flag support, if yes emit the flag else alternate (or null)
# Usage: CFLAGS += $(call cc-option,-fno-store-merging,)
cc-option = $(shell set -e;		\
	TMPO=/tmp/cc-option-$$$$-tmp.o;	\
	trap "rm -rf $$TMPO" EXIT;	\
	if ($(CC) -Werror $(1) -c -x c /dev/null -o $$TMPO) >/dev/null 2>&1; \
	then echo "$(1)";		\
	else echo "$(2)";		\
	fi)

KCFLAGS = -fno-jump-tables -fno-stack-protector -fno-function-sections
KCFLAGS += -fno-data-sections -mstrict-align
KCFLAGS += $(call cc-option,-fno-store-merging,)
KCFLAGS += $(INCLUDES) -DASIC_ELBA -DPCIESVC_SYSTEM_EXTERN
KOPT = KCFLAGS="$(KCFLAGS)"

all:
	make pciesvc.ko
	make pciesvc_upg.ko

buildmod:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KOPT) modules
	@mkdir -p $(REL)
	@mv $(patsubst %.o,%.ko,$(obj-m)) $(REL)
	@echo Checking for illegal relocations...
	tools/reloc_check $(REL)/$(MODNAME).ko

pciesvc.ko:
	$(MAKE) buildmod MODNAME=pciesvc

pciesvc_upg.ko:
	$(MAKE) buildmod MODNAME=pciesvc_upg

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) -r $(REL)
