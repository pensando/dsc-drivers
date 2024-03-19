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
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.9.7\\\"" modules

If the kernel config file doesn't have the Pensando configuration strings
set in it, you can add them in the make line.

For Naples drivers:
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.9.7\\\"" CONFIG_IONIC_MNIC=m CONFIG_MDEV=m CONFIG_MNET_UIO_PDRV_GENIRQ=m modules

For the host driver:
    make M=`pwd` KCFLAGS="-Werror -Ddrv_ver=\\\"1.15.9.7\\\"" CONFIG_IONIC=m modules

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

2021-02-24 - driver updates to 1.15.5-C-4
 - Add weak links for PTP api for compile and load on DSC kernel without PTP support
 - Don't set up PTP in ionic_mnic if PTP bar is not available
 - Closed a small window to prevent starting queues when in FW reset
 - Other small bug fixes to PTP support
 - Compat fixes for compiling on Linux v5.11
 - Guard against adminq use after free

2021-03-29 - driver updates to 1.15.6-C-8
 - better error case handling
 - bug fixes for PTP support and error handling
 - clean up mnet code to upstream code format standards
 - updates for compiling under v5.10

2021-04-30 - driver updates to 1.15.7-C-3
 - Copyright updates
 - Minor code cleanups to better match upstream drivers
 - Renamed mnet to mdev to be more generic
 - Added support in mdev for future mcrypt devices

2021-05-19 - driver updates to 1.15.8-C-12
 - added support for cmb-rings - Tx/Rx descriptor rings allocated in
   DSC Controller Memory Buffers rather than on host
 - rx_mode locking to block thread race
 - struct ionic_lif rework for better cache line layout

2021-06-30 - driver updates for 1.15.9-C-7
 - monitoring fw status generation for fw restart hints
 - catch lack of PTP support earlier in service routine
 - makefile fixes for sles 15 sp3
 - lower page splitting limit to better account for headers
 - VF stats area fix for PF
 - better thread-safe rx_mode work

    drivers: updates for 1.15.9.21
    
2021-08-04 - driver updates for 1.15.9-C-21
 - Added watchdog to platform for closer tracking of FW updates
   and crash recycle
 - Fixed dynamic interrupt management accounting
 - Fixes for mac filter management

2021-08-16 - driver updates for 1.15.9-C-26
 - Add work-around for Elba doorbell issue

2021-08-19 - driver updates for 1.15.9-C-28
 - Additional queue config locking for stress timing issue
 - Suppressed unnecessary log message

2021-08-25 - driver update for 1.15.9-C-32
 - added use of reserved memory region for dma

2022-02-02 - driver update for 1.15.9-C-64
 - Remove an unnecessary kcompat macro

2022-02-03 - driver update for 1.15.9-C-65
 - add vlan filter management to mac filter management
 - update filter management for handling overflow
 - updates for recent upstream kernels and distros
 - better handling of various FW recovery scenarios

2022-06-20 - driver update for 1.15.9-C-100
 - various code cleanups
 - add debugfs support to count number of Tx/Rx allocations
 - better memory handling
 - minor bug fixes

2022-12-05 - driver update for 22.11.1-001
 - update ionic drivers to 22.11.1-001; version numbers now follow
   the driver release numbers rather than the DSC firmware release version
 - enable tunnel offloads
 - support for changes in MTU, queue count, and ring length while CMB is active
 - set random VF mac addresses by default
 - better oprom debugging support
 - Rx/Tx performance tuning
 - fixes imported from upstream driver
 - bug fixes

2023-04-10 - driver update for 23.04.1-001
 - kcompat updates for RHEL 8.7, Linux v6.2, RHEL 9.x
 - remove support for event queues
 - split cmb-rings control to conform to tx-push and rx-push ringparams
 - code cleaning to better match upstream code
 - module parameter to set DMA mask at load time
 - bug fixes

2023-07-25 - driver update for 23.07.1-001
 - kcompat update for RHEL 8.8
 - add FLR handling
 - add new ethtool extended stat link_down_count
 - add custom Dynamic IRQ Moderation profile
 - fix a use-after-free issue seen on ARM
 - replace WARN_ON with dev_warn()

2023-08-29 - driver update for 23.08.1-001
 - updates to FLR handling
 - improved handling of scatter-gather with TSO
 - better error handling for ionic_start_queues_reconfig
 - fix up initial coalesce_usec values
 - various other small updates from upstream

2023-11-10 - driver update for 23.09.1-001
 - bug fix for copying the page_cache pointer in queue reconfig
 - some general code and Makefile cleaning
 - fix 16bit math issue when PAGE_SIZE >= 64KB
 - restrict page-cache allocation to Rx queues

23-12-14 - driver update for 23.12.2-001
 - updates from upstream kernel fixes
 - updates to FLR handling
 - added AER error handling

24-03-19 - driver update for 24.03.1-002
 - Add XDP support
 - Refactor Tx and Rx fast paths for performance
 - Refactor struct sizes, layout, and usage for memory savings and performance
