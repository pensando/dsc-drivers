/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2022 Pensando Systems, Inc */

#ifndef _PDS_VDPA_IF_H_
#define _PDS_VDPA_IF_H_

#include "pds_common.h"

#define PDS_DEV_TYPE_VDPA_STR	"vDPA"
#define PDS_VDPA_DEV_NAME	PDS_CORE_DRV_NAME "." PDS_DEV_TYPE_VDPA_STR

/**
 * enum pds_vdpa_cmd_opcode - vDPA Device commands
 */
enum pds_vdpa_cmd_opcode {
	PDS_VDPA_CMD_INIT		= 48,
	PDS_VDPA_CMD_IDENT		= 49,
	PDS_VDPA_CMD_RESET		= 51,
	PDS_VDPA_CMD_VQ_RESET		= 52,
	PDS_VDPA_CMD_VQ_INIT		= 53,
	PDS_VDPA_CMD_STATUS_UPDATE	= 54,
	PDS_VDPA_CMD_SET_FEATURES	= 55,
	PDS_VDPA_CMD_SET_ATTR		= 56,
};

/**
 * struct pds_vdpa_cmd - generic command
 * @opcode: Opcode
 * @vdpa_index: Index for vdpa subdevice
 * @vf_id:  VF id
 */
struct pds_vdpa_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
};

/**
 * struct pds_vdpa_comp - generic command completion
 * @status: Status of the command (enum pds_core_status_code)
 */
struct pds_vdpa_comp {
	u8 status;
	u8 rsvd[14];
	u8 color;
};

/**
 * struct pds_vdpa_init_cmd - INIT command
 * @opcode:	Opcode PDS_VDPA_CMD_INIT
 * @vdpa_index: Index for vdpa subdevice
 * @vf_id:	VF id
 * @len:	length of config info DMA space
 * @config_pa:	address for DMA of virtio_net_config struct
 */
struct pds_vdpa_init_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	__le32 len;
	__le64 config_pa;
};

/**
 * struct pds_vdpa_ident - vDPA identification data
 * @hw_features:	vDPA features supported by device
 * @max_vqs:		max queues available (2 queues for a single queuepair)
 * @max_qlen:		log(2) of maximum number of descriptors
 * @min_qlen:		log(2) of minimum number of descriptors
 *
 * This struct is used in a DMA block that is set up for the PDS_VDPA_CMD_IDENT
 * transaction.  Set up the DMA block and send the address in the IDENT cmd
 * data, the DSC will write the ident information, then we can remove the DMA
 * block after reading the answer.  If the completion status is 0, then there
 * is valid information, else there was an error and the data should be invalid.
 */
struct pds_vdpa_ident {
	__le64 hw_features;
	__le16 max_vqs;
	__le16 max_qlen;
	__le16 min_qlen;
};

/**
 * struct pds_vdpa_ident_cmd - IDENT command
 * @opcode:	Opcode PDS_VDPA_CMD_IDENT
 * @vf_id:	VF id
 * @len:	length of ident info DMA space
 * @ident_pa:	address for DMA of ident info (struct pds_vdpa_ident)
 *			only used for this transaction, then forgotten by DSC
 */
struct pds_vdpa_ident_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 vf_id;
	__le32 len;
	__le64 ident_pa;
};

/**
 * struct pds_vdpa_status_cmd - STATUS_UPDATE command
 * @opcode:	Opcode PDS_VDPA_CMD_STATUS_UPDATE
 * @vdpa_index: Index for vdpa subdevice
 * @vf_id:	VF id
 * @status:	new status bits
 */
struct pds_vdpa_status_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	u8     status;
};

/**
 * enum pds_vdpa_attr - List of VDPA device attributes
 * @PDS_VDPA_ATTR_MAC:         MAC address
 * @PDS_VDPA_ATTR_MAX_VQ_PAIRS Max virtqueue pairs
 */
enum pds_vdpa_attr {
	PDS_VDPA_ATTR_MAC          = 1,
	PDS_VDPA_ATTR_MAX_VQ_PAIRS = 2,
};

/**
 * struct pds_vdpa_setattr_cmd - SET_ATTR command
 * @opcode:		Opcode PDS_VDPA_CMD_SET_ATTR
 * @vdpa_index: 	Index for vdpa subdevice
 * @vf_id:		VF id
 * @attr:		attribute to be changed (enum pds_vdpa_attr)
 * @mac:		new mac address to be assigned as vdpa device address
 * @max_vq_pairs:	new limit of virtqueue pairs
 */
struct pds_vdpa_setattr_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	u8     attr;
	u8     pad[3];
	union {
		u8 mac[6];
		__le16 max_vq_pairs;
	} __packed;
};

/**
 * struct pds_vdpa_vq_init_cmd - queue init command
 * @opcode: Opcode PDS_VDPA_CMD_VQ_INIT
 * @vdpa_index:	Index for vdpa subdevice
 * @vf_id:	VF id
 * @qid:	Queue id (bit0 clear = rx, bit0 set = tx, qid=N is ctrlq)
 * @len:	log(2) of max descriptor count
 * @desc_addr:	DMA address of descriptor area
 * @avail_addr:	DMA address of available descriptors (aka driver area)
 * @used_addr:	DMA address of used descriptors (aka device area)
 * @intr_index:	interrupt index
 */
struct pds_vdpa_vq_init_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	__le16 qid;
	__le16 len;
	__le64 desc_addr;
	__le64 avail_addr;
	__le64 used_addr;
	__le16 intr_index;
};

/**
 * struct pds_vdpa_vq_init_comp - queue init completion
 * @status:	Status of the command (enum pds_core_status_code)
 * @hw_qtype:	HW queue type, used in doorbell selection
 * @hw_qindex:	HW queue index, used in doorbell selection
 */
struct pds_vdpa_vq_init_comp {
	u8     status;
	u8     hw_qtype;
	__le16 hw_qindex;
	u8     rsvd[11];
	u8     color;
};

/**
 * struct pds_vdpa_vq_reset_cmd - queue reset command
 * @opcode:	Opcode PDS_VDPA_CMD_VQ_RESET
 * @vdpa_index:	Index for vdpa subdevice
 * @vf_id:	VF id
 * @qid:	Queue id
 */
struct pds_vdpa_vq_reset_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	__le16 qid;
};

/**
 * struct pds_vdpa_set_features_cmd - set hw features
 * @opcode: Opcode PDS_VDPA_CMD_SET_FEATURES
 * @vdpa_index:	Index for vdpa subdevice
 * @vf_id:	VF id
 * @features:	Feature bit mask
 */
struct pds_vdpa_set_features_cmd {
	u8     opcode;
	u8     vdpa_index;
	__le16 vf_id;
	__le32 rsvd;
	__le64 features;
};

#endif /* _PDS_VDPA_IF_H_ */
