.. SPDX-License-Identifier: GPL-2.0+
.. note: can be edited and viewed with /usr/bin/formiko-vim

==========================================================
PCI vDPA driver for the Pensando(R) DSC adapter family
==========================================================

Pensando vDPA VF Device Driver
Copyright(c) 2022 Pensando Systems, Inc

Overview
========

The ``pds_vdpa`` driver is a PCI and auxiliary bus driver and supplies
a vDPA device for use by the virtio network stack.  It is used with
the Pensando Virtual Function devices that offer vDPA and virtio queue
services.  It depends on the ``pds_core`` driver and hardware for the PF
and for device configuration services.

Using the device
================

The ``pds_vdpa`` device is enabled via multiple configuration steps and
depends on the ``pds_core`` driver to create and enable SR-IOV Virtual
Function devices.

Shown below are the steps to bind the driver to a VF and also to the
associated auxiliary device created by the ``pds_core`` driver. This
example assumes the pds_core and pds_vdpa modules are already
loaded.

.. code-block:: bash

  #!/bin/bash

  modprobe pds_core
  modprobe pds_vdpa

  PF_BDF=`grep "vDPA.*1" /sys/kernel/debug/pds_core/*/viftypes | head -1 | awk -F / '{print $6}'`

  # Enable vDPA VF auxiliary device(s) in the PF
  devlink dev param set pci/$PF_BDF name enable_vnet value true cmode runtime

  # Create a VF for vDPA use
  echo 1 > /sys/bus/pci/drivers/pds_core/$PF_BDF/sriov_numvfs

  # Find the vDPA services/devices available
  PDS_VDPA_MGMT=`vdpa mgmtdev show | grep vDPA | head -1 | cut -d: -f1`

  # Create a vDPA device for use in virtio network configurations
  vdpa dev add name vdpa1 mgmtdev $PDS_VDPA_MGMT mac 00:11:22:33:44:55

  # Set up an ethernet interface on the vdpa device
  modprobe virtio_vdpa



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
          -> Pensando Ethernet PDS_VDPA Support

Support
=======

For general Linux networking support, please use the netdev mailing
list, which is monitored by Pensando personnel::

  netdev@vger.kernel.org

For more specific support needs, please use the Pensando driver support
email::

  drivers@pensando.io
