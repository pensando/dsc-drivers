.. SPDX-License-Identifier: GPL-2.0+
.. note: can be edited and viewed with /usr/bin/formiko-vim

==========================================================
PCI VFIO driver for the Pensando(R) DSC adapter family
==========================================================

Pensando Linux VFIO PCI Device Driver
Copyright(c) 2022 Pensando Systems, Inc

Overview
========

The ``pds_vfio`` driver is both a PCI and auxiliary bus driver. The
PCI driver supports Live Migration capable NVMe Virtual Function (VF)
devices and the auxiliary driver is used to communicate with the
``pds_core`` driver and hardware.

Using the device
================

The pds_vfio device is enabled via multiple configuration steps and
depends on the ``pds_core`` driver to create and enable SR-IOV Virtual
Function devices.

Shown below are the steps to bind the driver to a VF and also to the
associated auxiliary device created by the ``pds_core`` driver. This
example assumes the pds_core and pds_vfio modules are already
loaded.

.. code-block:: bash
  :name: example-setup-script

  #!/bin/bash

  PF_BUS="0000:60"
  PF_BDF="0000:60:00.0"
  VF_BDF="0000:60:00.1"

  # Enable live migration VF auxiliary device(s)
  devlink dev param set pci/$PF_BDF name enable_lm value true cmode runtime

  # Prevent nvme driver from probing the NVMe VF device
  echo 0 > /sys/class/pci_bus/$PF_BUS/device/$PF_BDF/sriov_drivers_autoprobe

  # Create single VF for NVMe Live Migration via VFIO
  echo 1 > /sys/bus/pci/drivers/pds_core/$PF_BDF/sriov_numvfs

  # Allow the VF to be bound to the pds_vfio driver
  echo "pds_vfio" > /sys/class/pci_bus/$PF_BUS/device/$VF_BDF/driver_override

  # Bind the VF to the pds_vfio driver
  echo "$VF_BDF" > /sys/bus/pci/drivers/pds_vfio/bind

After performing the steps above the pds_vfio driver's PCI probe should
have been called, the pds_vfio driver's auxiliary probe should have
been called, and a file in /dev/vfio/<iommu_group> should have been created.
There will also be an entry in /sys/bus/auxiliary/device/pds_core.LM.<nn>
for the VF's auxiliary device and the associated driver registered by the
pds_vfio module will be at /sys/bus/auxiliary/drivers/pds_vfio.lm.


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
          -> Pensando Ethernet PDS_VFIO_PCI Support

Support
=======

For general Linux networking support, please use the netdev mailing
list, which is monitored by Pensando personnel::

  netdev@vger.kernel.org

For more specific support needs, please use the Pensando driver support
email::

  drivers@pensando.io
