# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2019 Intel Corporation.

# (thanks Intel!)
#
#####################
# Helpful functions #
#####################

readlink = $(shell readlink -f ${1})

# helper functions for converting kernel version to version codes
get_kver = $(or $(word ${2},$(subst ., ,${1})),0)
get_kvercode = $(shell [ "${1}" -ge 0 -a "${1}" -le 255 2>/dev/null ] && \
                       [ "${2}" -ge 0 -a "${2}" -le 255 2>/dev/null ] && \
                       [ "${3}" -ge 0 -a "${3}" -le 255 2>/dev/null ] && \
                       printf %d $$(( ( ${1} << 16 ) + ( ${2} << 8 ) + ( ${3} ) )) )

################
# depmod Macro #
################

cmd_depmod = /sbin/depmod $(if ${SYSTEM_MAP_FILE},-e -F ${SYSTEM_MAP_FILE}) \
                          $(if $(strip ${INSTALL_MOD_PATH}),-b ${INSTALL_MOD_PATH}) \
                          -a ${KVER}

################
# dracut Macro #
################

cmd_initrd := $(shell \
                if which dracut > /dev/null 2>&1 ; then \
                    echo "dracut --force"; \
                elif which update-initramfs > /dev/null 2>&1 ; then \
                    echo "update-initramfs -u"; \
                fi )

#####################
# Environment tests #
#####################

DRIVER_UPPERCASE := $(shell echo ${DRIVER} | tr "[:lower:]" "[:upper:]")

ifeq (,${BUILD_KERNEL})
BUILD_KERNEL=$(shell uname -r)
endif

# Kernel Search Path
# All the places we look for kernel source
KSP :=  /lib/modules/${BUILD_KERNEL}/build \
	/lib/modules/${BUILD_KERNEL}/source \
        /usr/src/linux-${BUILD_KERNEL} \
        /usr/src/linux-$(shell echo ${BUILD_KERNEL} | sed 's/-.*//') \
        /usr/src/kernel-headers-${BUILD_KERNEL} \
        /usr/src/kernel-source-${BUILD_KERNEL} \
        /usr/src/linux-$(shell echo ${BUILD_KERNEL} | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/') \
        /usr/src/linux \
        /usr/src/kernels/${BUILD_KERNEL} \
        /usr/src/kernels

# prune the list down to only values that exist and have an include/linux
# sub-directory. We can't use include/config because some older kernels don't
# have this.
test_dir = $(shell [ -e ${dir}/include/linux -o -e ${dir}/include/generated ] && echo ${dir})
KSP := $(foreach dir, ${KSP}, ${test_dir})

# we will use this first valid entry in the search path
ifeq (,${KSRC})
  KSRC := $(firstword ${KSP})
endif

ifeq (,${KSRC})
  $(warning *** Kernel header files not in any of the expected locations.)
  $(warning *** Install the appropriate kernel development package, e.g.)
  $(error kernel-devel, for building kernel modules and try again)
else
ifeq (/lib/modules/${BUILD_KERNEL}/source, ${KSRC})
  KOBJ :=  /lib/modules/${BUILD_KERNEL}/build
else
  KOBJ :=  ${KSRC}
endif
endif

# Version file Search Path
VSP :=  ${KOBJ}/include/generated/utsrelease.h \
        ${KOBJ}/include/linux/utsrelease.h \
        ${KOBJ}/include/linux/version.h \
        ${KOBJ}/include/generated/uapi/linux/version.h \
        /boot/vmlinuz.version.h

# Config file Search Path
CSP :=  ${KOBJ}/include/generated/autoconf.h \
        ${KOBJ}/include/linux/autoconf.h \
        /boot/vmlinuz.autoconf.h

# System.map Search Path (for depmod)
MSP := ${KSRC}/System.map \
       /boot/System.map-${BUILD_KERNEL}

# prune the lists down to only files that exist
test_file = $(shell [ -f ${file} ] && echo ${file})
VSP := $(foreach file, ${VSP}, ${test_file})
CSP := $(foreach file, ${CSP}, ${test_file})
MSP := $(foreach file, ${MSP}, ${test_file})


# and use the first valid entry in the Search Paths
ifeq (,${VERSION_FILE})
  VERSION_FILE := $(firstword ${VSP})
endif

ifeq (,${CONFIG_FILE})
  CONFIG_FILE := $(firstword ${CSP})
endif

ifeq (,${SYSTEM_MAP_FILE})
  SYSTEM_MAP_FILE := $(firstword ${MSP})
endif

ifeq (,$(wildcard ${VERSION_FILE}))
  $(error Linux kernel source not configured - missing version header file)
endif

ifeq (,$(wildcard ${CONFIG_FILE}))
  $(error Linux kernel source not configured - missing autoconf.h)
endif

ifeq (,$(wildcard ${SYSTEM_MAP_FILE}))
  $(warning Missing System.map file - depmod will not check for missing symbols)
endif

ifneq ($(words $(subst :, ,$(CURDIR))), 1)
  $(error Sources directory '$(CURDIR)' cannot contain spaces nor colons. Rename directory or move sources to another path)
endif

########################
# Extract config value #
########################

get_config_value = $(shell ${CC} -E -dM ${CONFIG_FILE} 2> /dev/null |\
                           grep -m 1 ${1} | awk '{ print $$3 }')

########################
# Check module signing #
########################

CONFIG_MODULE_SIG_ALL := $(call get_config_value,CONFIG_MODULE_SIG_ALL)
CONFIG_MODULE_SIG_FORCE := $(call get_config_value,CONFIG_MODULE_SIG_FORCE)
CONFIG_MODULE_SIG_KEY := $(call get_config_value,CONFIG_MODULE_SIG_KEY)

SIG_KEY_SP := ${KOBJ}/${CONFIG_MODULE_SIG_KEY} \
              ${KOBJ}/certs/signing_key.pem

SIG_KEY_FILE := $(firstword $(foreach file, ${SIG_KEY_SP}, $(call test_file,${file})))

# print a warning if the kernel configuration attempts to sign modules but
# the signing key can't be found.
ifneq (${SIG_KEY_FILE},)
warn_signed_modules := : ;
else
warn_signed_modules :=
ifeq (${CONFIG_MODULE_SIG_ALL},1)
warn_signed_modules += \
    echo "****************************************************************" ; \
    echo "*** The target kernel has CONFIG_MODULE_SIG_ALL enabled, but ***" ; \
    echo "*** the signing key cannot be found. Module signing has been ***" ; \
    echo "*** disabled for this build.                                 ***" ; \
    echo "****************************************************************" ;
endif # CONFIG_MODULE_SIG_ALL=y
ifeq (${CONFIG_MODULE_SIG_FORCE},1)
  warn_signed_modules += \
    echo "**************************************************************" ; \
    echo "*** warning: The target kernel has CONFIG_MODULE_SIG_FORCE ***" ; \
    echo "*** warning: enabled, but the signing key cannot be found. ***" ; \
    echo "*** warning: The module must be signed manually using      ***" ; \
    echo "*** warning: 'scripts/sign-file'.                          ***" ; \
    echo "**************************************************************" ;
endif # CONFIG_MODULE_SIG_FORCE
DISABLE_MODULE_SIGNING := Yes
endif

#######################
# Linux Version Setup #
#######################

# The following command line parameter is intended for development of KCOMPAT
# against upstream kernels such as net-next which have broken or non-updated
# version codes in their Makefile. They are intended for debugging and
# development purpose only so that we can easily test new KCOMPAT early. If you
# don't know what this means, you do not need to set this flag. There is no
# arcane magic here.

# Convert LINUX_VERSION into LINUX_VERSION_CODE
ifneq (${LINUX_VERSION},)
  LINUX_VERSION_CODE=$(call get_kvercode,$(call get_kver,${LINUX_VERSION},1),$(call get_kver,${LINUX_VERSION},2),$(call get_kver,${LINUX_VERSION},3))
endif

# Honor LINUX_VERSION_CODE
ifneq (${LINUX_VERSION_CODE},)
  $(warning Forcing target kernel to build with LINUX_VERSION_CODE of ${LINUX_VERSION_CODE}$(if ${LINUX_VERSION}, from LINUX_VERSION=${LINUX_VERSION}). Do this at your own risk.)
  KVER_CODE := ${LINUX_VERSION_CODE}
  EXTRA_CFLAGS += -DLINUX_VERSION_CODE=${LINUX_VERSION_CODE}
endif

# Determine SLE_LOCALVERSION_CODE for SuSE SLE >= 11 (needed by kcompat)
# This assumes SuSE will continue setting CONFIG_LOCALVERSION to the string
# appended to the stable kernel version on which their kernel is based with
# additional versioning information (up to 3 numbers), a possible abbreviated
# git SHA1 commit id and a kernel type, e.g. CONFIG_LOCALVERSION=-1.2.3-default
# or CONFIG_LOCALVERSION=-999.gdeadbee-default
ifeq (1,$(shell ${CC} -E -dM ${CONFIG_FILE} 2> /dev/null |\
          grep -m 1 CONFIG_SUSE_KERNEL | awk '{ print $$3 }'))

ifneq (10,$(shell ${CC} -E -dM ${CONFIG_FILE} 2> /dev/null |\
	  grep -m 1 CONFIG_SLE_VERSION | awk '{ print $$3 }'))

  LOCALVERSION := $(shell ${CC} -E -dM ${CONFIG_FILE} 2> /dev/null |\
                    grep -m 1 CONFIG_LOCALVERSION | awk '{ print $$3 }' |\
                    cut -d'-' -f2 | sed 's/\.g[[:xdigit:]]\{7\}//')
  LOCALVER_A := $(shell echo ${LOCALVERSION} | cut -d'.' -f1)
  LOCALVER_B := $(shell echo ${LOCALVERSION} | cut -s -d'.' -f2)
  LOCALVER_C := $(shell echo ${LOCALVERSION} | cut -s -d'.' -f3)
  SLE_LOCALVERSION_CODE := $(shell expr ${LOCALVER_A} \* 65536 + \
                                        0${LOCALVER_B} \* 256 + 0${LOCALVER_C})
  EXTRA_CFLAGS += -DSLE_LOCALVERSION_CODE=${SLE_LOCALVERSION_CODE}
endif
endif


# get the kernel version - we use this to find the correct install path
KVER := $(shell ${CC} ${EXTRA_CFLAGS} -E -dM ${VERSION_FILE} | grep UTS_RELEASE | \
        awk '{ print $$3 }' | sed 's/\"//g')

# assume source symlink is the same as build, otherwise adjust KOBJ
ifneq (,$(wildcard /lib/modules/${KVER}/build))
  ifneq (${KSRC},$(call readlink,/lib/modules/${KVER}/build))
    KOBJ=/lib/modules/${KVER}/build
  endif
endif

ifeq (${KVER_CODE},)
  KVER_CODE := $(shell ${CC} ${EXTRA_CFLAGS} -E -dM ${VSP} 2> /dev/null |\
                 grep -m 1 LINUX_VERSION_CODE | awk '{ print $$3 }' | sed 's/\"//g')
endif

# minimum_kver_check
#
# helper function to provide uniform output for different drivers to abort the
# build based on kernel version check. Usage: "$(call minimum_kver_check,2,6,XX)".
define _minimum_kver_check
ifeq (0,$(shell [ ${KVER_CODE} -lt $(call get_kvercode,${1},${2},${3}) ]; echo "$$?"))
  $$(warning *** Aborting the build.)
  $$(error This driver is not supported on kernel versions older than ${1}.${2}.${3})
endif
endef
minimum_kver_check = $(eval $(call _minimum_kver_check,${1},${2},${3}))

####################
#  check for clang #
####################
CONFIG_CC_VERSION_TEXT:=$(call get_config_value,CONFIG_CC_VERSION_TEXT)
ifeq ($(findstring clang, ${CONFIG_CC_VERSION_TEXT}),clang)
  LLVM=1
endif
