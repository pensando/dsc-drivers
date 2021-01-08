#ifndef _MNET_DRV_H
#define _MNET_DRV_H

#include <linux/ioctl.h>

#define DRV_VERSION         "0.1"
#define DRV_DESCRIPTION     "Pensando mnet Driver"
#define DRV_NAME            "mnet"
#define MNET_CHAR_DEV_NAME  "pen-mnet"

#define NUM_MNET_DEVICES    1
#define MAX_MNET_DEVICES    32

#define MNIC_NAME_LEN       32

struct mnet_dev_create_req_t {
	uint64_t regs_pa;
	uint64_t drvcfg_pa;
	uint64_t msixcfg_pa;
	uint64_t doorbell_pa;
	int is_uio_dev;
	char iface_name[MNIC_NAME_LEN];
};

#define MNET_CREATE_DEV 		_IOWR('Q', 11, struct mnet_dev_create_req_t)
#define MNET_DESTROY_DEV 		_IOW('Q', 12, const char*)

#endif

