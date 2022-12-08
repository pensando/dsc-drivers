.. SPDX-License-Identifier: GPL-2.0+
.. note: can be edited and viewed with /usr/bin/formiko-vim

========================================================
Linux Driver for the Pensando(R) DSC adapter family
========================================================

Pensando Linux Core driver.
Copyright(c) 2022 Pensando Systems, Inc

Identifying the Adapter
=======================

To find if one or more Pensando PCI Core devices are installed on the
host, check for the PCI devices::

  # lspci -d 1dd8:100c
  39:00.0 Processing accelerators: Pensando Systems Device 100c
  3a:00.0 Processing accelerators: Pensando Systems Device 100c

If such devices are listed as above, then the pds_core.ko driver should find
and configure them for use.  There should be log entries in the kernel
messages such as these::

  $ dmesg | grep pds_core
  pds_core 0000:b5:00.0: 126.016 Gb/s available PCIe bandwidth (8.0 GT/s PCIe x16 link)
  pds_core 0000:b5:00.0: FW: 1.51.0-73
  pds_core 0000:b6:00.0: 126.016 Gb/s available PCIe bandwidth (8.0 GT/s PCIe x16 link)
  pds_core 0000:b5:00.0: FW: 1.51.0-73

Driver and firmware version information can be gathered with devlink::

  $ devlink dev info pci/0000:b5:00.0
  pci/0000:b5:00.0:
    driver pds_core
    serial_number FLM18420073
    versions:
        fixed:
          asic.id 0x0
          asic.rev 0x0
        running:
          fw 1.51.0-73
        stored:
          fw.goldfw 1.15.9-C-22
          fw.mainfwa 1.51.0-73
          fw.mainfwb 1.51.0-57


Info versions
=============

The ``pds_core`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``fw``
     - running
     - Version of firmware running on the device
   * - ``fw.goldfw``
     - stored
     - Version of firmware stored in the goldfw slot
   * - ``fw.mainfwa``
     - stored
     - Version of firmware stored in the mainfwa slot
   * - ``fw.mainfwb``
     - stored
     - Version of firmware stored in the mainfwb slot
   * - ``asic.id``
     - fixed
     - The ASIC type for this device
   * - ``asic.rev``
     - fixed
     - The revision of the ASIC for this device


Parameters
==========

The ``pds_core`` driver implements the following generic
parameters for controlling the functionality to be made available
as auxiliary_bus devices.

.. list-table:: Generic parameters implemented
   :widths: 5 5 8 82

   * - Name
     - Mode
     - Type
     - Description
   * - ``enable_eth``
     - runtime
     - Boolean
     - Enables ethernet functionality through an auxiliary_bus device
   * - ``enable_vnet``
     - runtime
     - Boolean
     - Enables vDPA functionality through an auxiliary_bus device


The ``pds_core`` driver also implements the following driver-specific
parameters for similar uses, as well as for selecting the next boot firmware:

.. list-table:: Driver-specific parameters implemented
   :widths: 5 5 8 82

   * - Name
     - Mode
     - Type
     - Description
   * - ``enable_lm``
     - runtime
     - Boolean
     - Enables Live Migration functionality through an auxiliary_bus device
   * - ``enable_core``
     - runtime
     - Boolean
     - Enables a test interface through an auxiliary_bus device
   * - ``boot_fw``
     - runtime
     - String
     - Selects the Firmware slot to use for the next DSC boot


Firmware Management
===================

Using the ``devlink`` utility's ``flash`` command the DSC firmware can be
updated.  The downloaded firmware will be loaded into either of mainfwa or
mainfwb firmware slots, whichever is not currrently in use, and that slot
will be then selected for the next boot.  The firmware currently in use can
be found by inspecting the ``running`` firmware from the devlink dev info.

The ``boot_fw`` parameter can inspect and select the firmware slot to be
used in the next DSC boot up.  The mainfwa and mainfwb slots are used for
for normal operations, and the goldfw slot should only be selected for
recovery purposes if both the other slots have bad or corrupted firmware.


Enabling the driver
===================

The driver is enabled via the standard kernel configuration system,
using the make command::

  make oldconfig/menuconfig/etc.

The driver is located in the menu structure at:

  -> Device Drivers
    -> Network device support (NETDEVICES [=y])
      -> Ethernet driver support
        -> Pensando devices
          -> Pensando Ethernet PDS_CORE Support

Support
=======

For general Linux networking support, please use the netdev mailing
list, which is monitored by Pensando personnel::

  netdev@vger.kernel.org

For more specific support needs, please use the Pensando driver support
email::

  drivers@pensando.io
