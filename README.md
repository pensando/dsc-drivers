# dsc-drivers

## Overview

This directory holds the three drivers that are used for device support
inside the Pensando DSC: ionic/ionic_mnic, mnet, and mnet_uio_pdrv_genirq.
These are all out-of-tree drivers, not used in the standard kernel tree.
However, a variant of the ionic driver is in the upstream kernel, but does
not support the internal DSC platform.

When building for the host, only the "ionic" driver is built,
and uses ionic_bus_pci.c.  In tandem with the kconfig files, this
driver can be built on a number of different Linux distributions and
kernel versions.  When building for the DSC, "ionic_mnic" is built, with
ionic_bus_platform.c, along with mnet and mnet_uio_pdrv_genirq drivers.
The mnet and mnet_uio_pdrv_genirq drivers are only built on the DSC
Linux kernel, so don't make use of the kcompat facilities.

In the DSC build the driver .ko files are found in /platform/drivers,
and are loaded by /nic/tools/sysinit.sh.  Later, the nicmgr process reads
its device description file, e.g. /platform/etc/nicmgrd/device.json,
to determine what network interface ports are to be created.  It then uses
ioctl() calls into the mnet driver to instantiate those network interfaces.

## Drivers

drivers/common:
	API description files for communication between drivers
	and the DSC.

drivers/linux/eth/ionic:
	Driver that supports standard network interface ports.

drivers/linux/mnet:
	Driver that listens for ioctl() commands from userland to start
	and stop the network interface ports.

drivers/linux/mnet_uio_pdrv_genirq:
	UIO interface driver for supporting userspace I/O platform drivers.

## Building

The Makefile in drivers/linux will build all three drivers when
ARCH=aarch64, else will build the host version of ionic.  Simply cd to
the drivers/linux directory and type 'make'.

Well, okay maybe not that simple any more - it should be, but some things
changed in the makefiles internally, and it's a little more complex.  Also,
we wanted to keep this archive closer to what is used internally.

If the headers for your current Linux kernel are findable under
/lib/modules with kernel config values defined, this should work:
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.4.8\\\"" modules

If the kernel config file doesn't have the Pensando configuration strings
set in it, you can add them in the make line.

For Naples drivers:
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.4.8\\\"" CONFIG_IONIC_MNIC=m CONFIG_MNET=m CONFIG_MNET_UIO_PDRV_GENIRQ=m modules

For the host driver:
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.4.8\\\"" CONFIG_IONIC=m modules

As usual, if the Linux headers are elsewhere, add the appropriate -C magic:
    make -C <kernel-header-path> M=`pwd` ...

## History

2020-07-07 - initial drivers using 1.8.0-E-48

2021-01-08 - driver updates to 1.15.3-C-14
 - FW update fixes
 - Makefile cleanups
 - Add support for choosing individual Tx and Rx interrupts rather than paired
 - Fix memory leaks and timing issues
 - Kcompat fixes for newer upstream and Red Hat kernels
 - Add interrupt affinity option for mnic_ionic use
 - Other optimizations and stability fixes

2021-02-02 - driver updates to 1.15.4-C-8
 - Added support for PTP
 - Dropped support for macvlan offload
 - Cleaned some 'sparse' complaints
 - Add support for devlink firmware update
 - Dynamic interrupt coalescing
 - Add support for separate Tx interrupts
 - Rework queue reconfiguration for better memory handling
 - Reorder some configuration steps to remove race conditions
 - Changes to napi handling for better performance

