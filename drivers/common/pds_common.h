/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) OR BSD-2-Clause */
/* Copyright (c) 2022 Pensando Systems, Inc.  All rights reserved. */

#ifndef _PDS_COMMON_H_
#define _PDS_COMMON_H_

#define PDS_CORE_DRV_NAME			"pds_core"

/* the device's internal addressing uses up to 52 bits */
#define PDS_CORE_ADDR_LEN	52
#define PDS_CORE_ADDR_MASK	(BIT_ULL(PDS_ADDR_LEN) - 1)

/* Static size checks */
#define PDS_CORE_SIZE_CHECK(type, N, X)                                        \
    enum pds_core_static_assert_enum_##X                                       \
    {                                                                          \
        pds_core_static_assert_##X = (N) / (sizeof(type X) <= (N))             \
    }
#define PDS_CORE_CHECK_CMD_LENGTH(X)      PDS_CORE_SIZE_CHECK(struct, 60, X)
#define PDS_CORE_CHECK_CMD_LENGTH_UN(X)   PDS_CORE_SIZE_CHECK(union, 60, X)
#define PDS_CORE_CHECK_COMP_LENGTH(X)     PDS_CORE_SIZE_CHECK(struct, 16, X)
#define PDS_CORE_CHECK_COMP_LENGTH_UN(X)  PDS_CORE_SIZE_CHECK(union, 16, X)

/**
 * enum pds_core_status_code - Device command return codes
 */
enum pds_core_status_code {
	PDS_RC_SUCCESS	= 0,	/* Success */
	PDS_RC_EVERSION	= 1,	/* Incorrect version for request */
	PDS_RC_EOPCODE	= 2,	/* Invalid cmd opcode */
	PDS_RC_EIO	= 3,	/* I/O error */
	PDS_RC_EPERM	= 4,	/* Permission denied */
	PDS_RC_EQID	= 5,	/* Bad qid */
	PDS_RC_EQTYPE	= 6,	/* Bad qtype */
	PDS_RC_ENOENT	= 7,	/* No such element */
	PDS_RC_EINTR	= 8,	/* operation interrupted */
	PDS_RC_EAGAIN	= 9,	/* Try again */
	PDS_RC_ENOMEM	= 10,	/* Out of memory */
	PDS_RC_EFAULT	= 11,	/* Bad address */
	PDS_RC_EBUSY	= 12,	/* Device or resource busy */
	PDS_RC_EEXIST	= 13,	/* object already exists */
	PDS_RC_EINVAL	= 14,	/* Invalid argument */
	PDS_RC_ENOSPC	= 15,	/* No space left or alloc failure */
	PDS_RC_ERANGE	= 16,	/* Parameter out of range */
	PDS_RC_BAD_ADDR	= 17,	/* Descriptor contains a bad ptr */
	PDS_RC_DEV_CMD	= 18,	/* Device cmd attempted on AdminQ */
	PDS_RC_ENOSUPP	= 19,	/* Operation not supported */
	PDS_RC_ERROR	= 29,	/* Generic error */
	PDS_RC_ERDMA	= 30,	/* Generic RDMA error */
	PDS_RC_EVFID	= 31,	/* VF ID does not exist */
	PDS_RC_BAD_FW	= 32,	/* FW file is invalid or corrupted */
	PDS_RC_ECLIENT	= 33,   /* No such client id */
};

enum pds_core_driver_type {
	PDS_DRIVER_LINUX   = 1,
	PDS_DRIVER_WIN     = 2,
	PDS_DRIVER_DPDK    = 3,
	PDS_DRIVER_FREEBSD = 4,
	PDS_DRIVER_IPXE    = 5,
	PDS_DRIVER_ESXI    = 6,
};

enum pds_core_vif_types {
	PDS_DEV_TYPE_CORE	= 0,
	PDS_DEV_TYPE_VDPA	= 1,
	PDS_DEV_TYPE_VFIO	= 2,
	PDS_DEV_TYPE_ETH	= 3,
	PDS_DEV_TYPE_RDMA	= 4,
	PDS_DEV_TYPE_LM		= 5,

	/* new ones added before this line */
	PDS_DEV_TYPE_MAX	= 16   /* don't change - used in struct size */
};

/* PDSC interface uses identity version 1 and PDSC uses 2 */
#define PDSC_IDENTITY_VERSION_1		1
#define PDSC_IDENTITY_VERSION_2		2

#define PDS_CORE_IFNAMSIZ		16

/**
 * enum pds_core_logical_qtype - Logical Queue Types
 * @PDSC_QTYPE_ADMINQ:    Administrative Queue
 * @PDSC_QTYPE_NOTIFYQ:   Notify Queue
 * @PDSC_QTYPE_RXQ:       Receive Queue
 * @PDSC_QTYPE_TXQ:       Transmit Queue
 * @PDSC_QTYPE_EQ:        Event Queue
 * @PDSC_QTYPE_MAX:       Max queue type supported
 */
enum pds_core_logical_qtype {
	PDS_CORE_QTYPE_ADMINQ  = 0,
	PDS_CORE_QTYPE_NOTIFYQ = 1,
	PDS_CORE_QTYPE_RXQ     = 2,
	PDS_CORE_QTYPE_TXQ     = 3,
	PDS_CORE_QTYPE_EQ      = 4,

	PDS_CORE_QTYPE_MAX     = 16   /* don't change - used in struct size */
};


typedef void (*pds_core_cb)(void *cb_arg);

#endif /* _PDS_COMMON_H_ */
