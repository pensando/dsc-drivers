# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc.

# filechk
FILECHK_TIMESTAMP := $(shell date +"%N")
TMP_FILE := tmp.$(FILECHK_TIMESTAMP)

define filecheck
	$(Q)set -e;
	$(if Q,echo '  CHK     $@';)        \
	mkdir -p $(dir $@); \
	$(call filechk_$(1)) < $< > $@.$(TMP_FILE);    \
	if [ -r $@ ] && cmp -s $@ $@.$(TMP_FILE); then  \
		rm -f $@.$(TMP_FILE);   \
	else    \
		$(if Q,echo '  UPD     $@';)    \
		mv -f $@.$(TMP_FILE) $@;    \
	fi
endef

# autocompat.h depends on the kernel compiled against.
# However, there is nothing stopping the user compiling on multiple
# machines in the same directory. The .kpath target provides a simple
# dependency check for this.
$(obj)/.kpath: FORCE
	@if ! [ -f $@ ] || [ $$(cat $@) != $(objtree) ]; then		\
		echo $(objtree) >$@;					\
		$(if $(MMAKE_IN_KBUILD),,rm -f $(obj)/*.symvers;)	\
	fi

_KSRC := $(or $(KBUILD_SRC),$(KSRC),$(CURDIR))
ODIR := $(CURDIR)
ifeq ($(_KSRC), $(KBUILD_EXTMOD))
	_KSRC := $(srctree)
endif
ifeq ($(ODIR), $(KBUILD_EXTMOD))
	ODIR := $(srctree)
endif

ifeq ($(wildcard $(OFA_KSRC)),)
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k $(_KSRC) -o "$(ODIR)" -a $(ARCH) $(if $(filter 1,$(V)),-v,-q)
endef
else
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k $(_KSRC) -o "$(ODIR)" -a $(ARCH) -i '$(LINUXINCLUDE)' -f $(OFA_KSRC) $(if $(filter 1,$(V)),-v,-q)
endef
endif

$(src)/autocompat.h: $(obj)/.kpath $(src)/kernel_compat.sh $(srcroot)/etc/kernel_compat_funcs.sh
	+$(call filecheck,autocompat.h)
	@touch $@
