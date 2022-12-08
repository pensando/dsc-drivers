#ifndef _PCI_DRV_H
#define _PCI_DRV_H

#include <linux/pci.h>

bool
pds_vfio_is_vfio_pci_driver(struct pci_dev *pdev);

#endif /* _PCI_DRV_H */
