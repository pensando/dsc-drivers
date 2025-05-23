/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) OR BSD-2-Clause */
/* Copyright (c) 2017 - 2021 Pensando Systems, Inc.  All rights reserved. */

#ifndef _IONIC_IF_H_
#define _IONIC_IF_H_

#define IONIC_DEV_INFO_SIGNATURE		0x44455649      /* 'DEVI' */
#define IONIC_DEV_INFO_VERSION			1
#define IONIC_IFNAMSIZ				16

#ifdef __CHECKER__
#define IONIC_SIZE_CHECK(type, N, X)
#define IONIC_CHECK_CMD_LENGTH(X)
#define IONIC_CHECK_COMP_LENGTH(X)
#define IONIC_CHECK_CMD_DATA_LENGTH(X)
#define IONIC_CHECK_OPROM_LENGTH(X)
#define IONIC_CHECK_DEV_INFO_REGS_LENGTH(X)
#else
#define IONIC_SIZE_CHECK(type, N, X)		enum ionic_static_assert_enum_##X \
		{ ionic_static_assert_##X = (N) / (sizeof(type X) == (N)) }
#define IONIC_CHECK_CMD_LENGTH(X)		IONIC_SIZE_CHECK(struct, 64, X)
#define IONIC_CHECK_COMP_LENGTH(X)		IONIC_SIZE_CHECK(struct, 16, X)
#define IONIC_CHECK_CMD_DATA_LENGTH(X)		IONIC_SIZE_CHECK(union, 1912, X)
#define IONIC_CHECK_OPROM_LENGTH(X)		IONIC_SIZE_CHECK(struct, 32, X)
#define IONIC_CHECK_DEV_INFO_REGS_LENGTH(X)	IONIC_SIZE_CHECK(union, 2048, X)
#endif

/**
 * enum ionic_cmd_opcode - Device commands
 */
enum ionic_cmd_opcode {
	IONIC_CMD_NOP				= 0,

	/* Device commands */
	IONIC_CMD_IDENTIFY			= 1,
	IONIC_CMD_INIT				= 2,
	IONIC_CMD_RESET				= 3,
	IONIC_CMD_GETATTR			= 4,
	IONIC_CMD_SETATTR			= 5,
	IONIC_CMD_DEBUG				= 6,

	/* Port commands */
	IONIC_CMD_PORT_IDENTIFY			= 10,
	IONIC_CMD_PORT_INIT			= 11,
	IONIC_CMD_PORT_RESET			= 12,
	IONIC_CMD_PORT_GETATTR			= 13,
	IONIC_CMD_PORT_SETATTR			= 14,

	/* LIF commands */
	IONIC_CMD_LIF_IDENTIFY			= 20,
	IONIC_CMD_LIF_INIT			= 21,
	IONIC_CMD_LIF_RESET			= 22,
	IONIC_CMD_LIF_GETATTR			= 23,
	IONIC_CMD_LIF_SETATTR			= 24,
	IONIC_CMD_LIF_SETPHC			= 25,

	IONIC_CMD_RX_MODE_SET			= 30,
	IONIC_CMD_RX_FILTER_ADD			= 31,
	IONIC_CMD_RX_FILTER_DEL			= 32,

	/* Queue commands */
	IONIC_CMD_Q_IDENTIFY			= 39,
	IONIC_CMD_Q_INIT			= 40,
	IONIC_CMD_Q_CONTROL			= 41,

	/* RDMA commands */
	IONIC_CMD_RDMA_RESET_LIF		= 50,
	IONIC_CMD_RDMA_CREATE_EQ		= 51,
	IONIC_CMD_RDMA_CREATE_CQ		= 52,
	IONIC_CMD_RDMA_CREATE_ADMINQ		= 53,

	/* SR/IOV commands */
	IONIC_CMD_VF_GETATTR			= 60,
	IONIC_CMD_VF_SETATTR			= 61,
	IONIC_CMD_VF_CTRL			= 62,

	/* CMB command */
	IONIC_CMD_DISCOVER_CMB			= 80,

	IONIC_CMD_RESERVED_98			= 98,
	IONIC_CMD_RESERVED_99			= 99,

	/* UPT command */
	IONIC_CMD_UPT_MESSAGE			= 100,

	/* UEFI HII commands */
	IONIC_CMD_HII_IDENTIFY			= 235,
	IONIC_CMD_HII_GETATTR			= 236,
	IONIC_CMD_HII_SETATTR			= 237,
	IONIC_CMD_HII_INIT			= 238,
	IONIC_CMD_HII_RESET			= 239,

	/* QoS commands */
	IONIC_CMD_QOS_CLASS_IDENTIFY		= 240,
	IONIC_CMD_QOS_CLASS_INIT		= 241,
	IONIC_CMD_QOS_CLASS_RESET		= 242,
	IONIC_CMD_QOS_CLASS_UPDATE		= 243,
	IONIC_CMD_QOS_CLEAR_STATS		= 244,
	IONIC_CMD_QOS_RESET			= 245,

	/* Firmware commands */
	IONIC_CMD_FW_DOWNLOAD                   = 252,
	IONIC_CMD_FW_CONTROL                    = 253,
	IONIC_CMD_FW_DOWNLOAD_V1		= 254,
	IONIC_CMD_FW_CONTROL_V1		        = 255,
};

/**
 * enum ionic_status_code - Device command return codes
 */
enum ionic_status_code {
	IONIC_RC_SUCCESS	= 0,	/* Success */
	IONIC_RC_EVERSION	= 1,	/* Incorrect version for request */
	IONIC_RC_EOPCODE	= 2,	/* Invalid cmd opcode */
	IONIC_RC_EIO		= 3,	/* I/O error */
	IONIC_RC_EPERM		= 4,	/* Permission denied */
	IONIC_RC_EQID		= 5,	/* Bad qid */
	IONIC_RC_EQTYPE		= 6,	/* Bad qtype */
	IONIC_RC_ENOENT		= 7,	/* No such element */
	IONIC_RC_EINTR		= 8,	/* operation interrupted */
	IONIC_RC_EAGAIN		= 9,	/* Try again */
	IONIC_RC_ENOMEM		= 10,	/* Out of memory */
	IONIC_RC_EFAULT		= 11,	/* Bad address */
	IONIC_RC_EBUSY		= 12,	/* Device or resource busy */
	IONIC_RC_EEXIST		= 13,	/* object already exists */
	IONIC_RC_EINVAL		= 14,	/* Invalid argument */
	IONIC_RC_ENOSPC		= 15,	/* No space left or alloc failure */
	IONIC_RC_ERANGE		= 16,	/* Parameter out of range */
	IONIC_RC_BAD_ADDR	= 17,	/* Descriptor contains a bad ptr */
	IONIC_RC_DEV_CMD	= 18,	/* Device cmd attempted on AdminQ */
	IONIC_RC_ENOSUPP	= 19,	/* Operation not supported */
	IONIC_RC_ERROR		= 29,	/* Generic error */
	IONIC_RC_ERDMA		= 30,	/* Generic RDMA error */
	IONIC_RC_EVFID		= 31,	/* VF ID does not exist */
	IONIC_RC_BAD_FW		= 32,	/* FW file is invalid or corrupted */
};

enum ionic_notifyq_opcode {
	IONIC_EVENT_LINK_CHANGE		= 1,
	IONIC_EVENT_RESET		= 2,
	IONIC_EVENT_HEARTBEAT		= 3,
	IONIC_EVENT_LOG			= 4,
	IONIC_EVENT_XCVR		= 5,
};

/**
 * struct ionic_upt_cmd - command format for all UPT commands
 * @opcode:         Opcode for the command
 * @vf_index:       VF Index.
 * @upt_cmd_data:   UPT specific command bytes
 */
struct ionic_upt_cmd {
	u8         opcode;
	u8         rsvd;
	__le16	   vf_index;
	u8	   rsvd1[4];
	u8         upt_cmd_data[56];
};
IONIC_CHECK_CMD_LENGTH(ionic_upt_cmd);

/**
 * struct ionic_upt_comp - UPT command completion.
 * @status:     Status of the command (enum ionic_status_code)
 */
struct ionic_upt_comp {
	u8         status;
	u8         rsvd[15];
};
IONIC_CHECK_COMP_LENGTH(ionic_upt_comp);

/**
 * struct ionic_admin_cmd - General admin command format
 * @opcode:     Opcode for the command
 * @lif_index:  LIF index
 * @cmd_data:   Opcode-specific command bytes
 */
struct ionic_admin_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	u8     cmd_data[60];
};

/**
 * struct ionic_admin_comp - General admin command completion format
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @cmd_data:   Command-specific bytes
 * @color:      Color bit (Always 0 for commands issued to the
 *              Device Cmd Registers)
 */
struct ionic_admin_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	u8     cmd_data[11];
	u8     color;
#define IONIC_COMP_COLOR_MASK  0x80
};

static inline u8 color_match(u8 color, u8 done_color)
{
	return (!!(color & IONIC_COMP_COLOR_MASK)) == done_color;
}

/**
 * struct ionic_nop_cmd - NOP command
 * @opcode: opcode
 */
struct ionic_nop_cmd {
	u8 opcode;
	u8 rsvd[63];
};

/**
 * struct ionic_nop_comp - NOP command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_nop_comp {
	u8 status;
	u8 rsvd[15];
};

/**
 * struct ionic_dev_init_cmd - Device init command
 * @opcode:    opcode
 * @type:      Device type
 */
struct ionic_dev_init_cmd {
	u8     opcode;
	u8     type;
	u8     rsvd[62];
};

/**
 * struct ionic_dev_init_comp - Device init command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_dev_init_comp {
	u8 status;
	u8 rsvd[15];
};

/**
 * struct ionic_dev_reset_cmd - Device reset command
 * @opcode: opcode
 */
struct ionic_dev_reset_cmd {
	u8 opcode;
	u8 rsvd[63];
};

/**
 * struct ionic_dev_reset_comp - Reset command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_dev_reset_comp {
	u8 status;
	u8 rsvd[15];
};

#define IONIC_IDENTITY_VERSION_1	1
#define IONIC_DEV_IDENTITY_VERSION_1	IONIC_IDENTITY_VERSION_1
#define IONIC_DEV_IDENTITY_VERSION_2	(IONIC_DEV_IDENTITY_VERSION_1 + 1)

/**
 * struct ionic_dev_identify_cmd - Driver/device identify command
 * @opcode:  opcode
 * @ver:     Highest version of identify supported by driver
 */
struct ionic_dev_identify_cmd {
	u8 opcode;
	u8 ver;
	u8 rsvd[62];
};

/**
 * struct ionic_dev_identify_comp - Driver/device identify command completion
 * @status: Status of the command (enum ionic_status_code)
 * @ver:    Version of identify returned by device
 */
struct ionic_dev_identify_comp {
	u8 status;
	u8 ver;
	u8 rsvd[14];
};

enum ionic_debug_type {
	IONIC_DEBUG_TYPE_MSG     = 1,
	IONIC_DEBUG_TYPE_STATS   = 2,
};

/**
 * struct ionic_dev_debug_stats - Driver/device debug stats struct
 * @fld:	A string specifying the field name
 * @cnt:	Counter value for the field
 */
struct ionic_dev_debug_stats {
	char     fld[56];
	uint64_t cnt;
} __attribute__((packed));
IONIC_SIZE_CHECK(struct, 64, ionic_dev_debug_stats);

/**
 * struct ionic_dev_debug_cmd - Driver/device debug command
 * @opcode:	opcode
 * @debug_type:	debug_type (enum ionic_debug_type)
 * @stats:	Debug stats region properties
 *	@stats.count:		Number of (field, cnt) pairs
 *	@stats.stats_pa:	Physical address of the debug stats region
 */
struct ionic_dev_debug_cmd {
	u8 opcode;
	u8 debug_type;
	u8 rsvd[6];
	union {
		struct {
			__le16 count;
			u8 rsvd2[6];
			__le64 stats_pa;
		} stats;
	};
	u8 rsvd3[40];
};
IONIC_CHECK_CMD_LENGTH(ionic_dev_debug_cmd);

/**
 * struct ionic_dev_debug_comp - Driver/device debug command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_dev_debug_comp {
	u8 status;
	u8 rsvd[15];
};
IONIC_CHECK_COMP_LENGTH(ionic_dev_debug_comp);

enum ionic_os_type {
	IONIC_OS_TYPE_LINUX   = 1,
	IONIC_OS_TYPE_WIN     = 2,
	IONIC_OS_TYPE_DPDK    = 3,
	IONIC_OS_TYPE_FREEBSD = 4,
	IONIC_OS_TYPE_IPXE    = 5,
	IONIC_OS_TYPE_ESXI    = 6,
};

/**
 * union ionic_drv_identity - driver identity information
 * @os_type:          OS type (see enum ionic_os_type)
 * @os_dist:          OS distribution, numeric format
 * @os_dist_str:      OS distribution, string format
 * @kernel_ver:       Kernel version, numeric format
 * @kernel_ver_str:   Kernel version, string format
 * @driver_ver_str:   Driver version, string format
 */
union ionic_drv_identity {
	struct {
		__le32 os_type;
		__le32 os_dist;
		char   os_dist_str[128];
		__le32 kernel_ver;
		char   kernel_ver_str[32];
		char   driver_ver_str[32];
	};
	__le32 words[478];
};

/**
 * enum ionic_dev_capability - Device capabilities
 * @IONIC_DEV_CAP_VF_CTRL:     Device supports VF ctrl operations
 * @IONIC_DEV_CAP_DISC_CMB:    Device supports CMB discovery operations
 */
enum ionic_dev_capability {
	IONIC_DEV_CAP_VF_CTRL        = BIT(0),
	IONIC_DEV_CAP_DISC_CMB       = BIT(1),
};

/**
 * union ionic_dev_identity - device identity information
 * @version:          Version of device identify
 * @type:             Identify type (0 for now)
 * @nports:           Number of ports provisioned
 * @nlifs:            Number of LIFs provisioned
 * @nintrs:           Number of interrupts provisioned
 * @ndbpgs_per_lif:   Number of doorbell pages per LIF
 * @intr_coal_mult:   Interrupt coalescing multiplication factor
 *                    Scale user-supplied interrupt coalescing
 *                    value in usecs to device units using:
 *                    device units = usecs * mult / div
 * @intr_coal_div:    Interrupt coalescing division factor
 *                    Scale user-supplied interrupt coalescing
 *                    value in usecs to device units using:
 *                    device units = usecs * mult / div
 * @eq_count:         Number of shared event queues
 * @hwstamp_mask:     Bitmask for subtraction of hardware tick values.
 * @hwstamp_mult:     Hardware tick to nanosecond multiplier.
 * @hwstamp_shift:    Hardware tick to nanosecond divisor (power of two).
 * @capabilities:     Device capabilities
 */
union ionic_dev_identity {
	struct {
		u8     version;
		u8     type;
		u8     rsvd[2];
		u8     nports;
		u8     rsvd2[3];
		__le32 nlifs;
		__le32 nintrs;
		__le32 ndbpgs_per_lif;
		__le32 intr_coal_mult;
		__le32 intr_coal_div;
		__le32 eq_count;
		__le64 hwstamp_mask;
		__le32 hwstamp_mult;
		__le32 hwstamp_shift;
		__le64 capabilities;
	};
	__le32 words[478];
};

enum ionic_lif_type {
	IONIC_LIF_TYPE_CLASSIC = 0,
	IONIC_LIF_TYPE_MACVLAN = 1,
	IONIC_LIF_TYPE_NETQUEUE = 2,
};

#define IONIC_LIF_IDENTITY_VERSION_1	IONIC_DEV_IDENTITY_VERSION_1

/**
 * struct ionic_lif_identify_cmd - LIF identify command
 * @opcode:  opcode
 * @type:    LIF type (enum ionic_lif_type)
 * @ver:     Version of identify returned by device
 */
struct ionic_lif_identify_cmd {
	u8 opcode;
	u8 type;
	u8 ver;
	u8 rsvd[61];
};

/**
 * struct ionic_lif_identify_comp - LIF identify command completion
 * @status:  Status of the command (enum ionic_status_code)
 * @ver:     Version of identify returned by device
 */
struct ionic_lif_identify_comp {
	u8 status;
	u8 ver;
	u8 rsvd2[14];
};

/**
 * enum ionic_lif_capability - LIF capabilities
 * @IONIC_LIF_CAP_ETH:     LIF supports Ethernet
 * @IONIC_LIF_CAP_RDMA:    LIF supports RDMA
 */
enum ionic_lif_capability {
	IONIC_LIF_CAP_ETH        = BIT(0),
	IONIC_LIF_CAP_RDMA       = BIT(1),
};

/**
 * enum ionic_logical_qtype - Logical Queue Types
 * @IONIC_QTYPE_ADMINQ:    Administrative Queue
 * @IONIC_QTYPE_NOTIFYQ:   Notify Queue
 * @IONIC_QTYPE_RXQ:       Receive Queue
 * @IONIC_QTYPE_TXQ:       Transmit Queue
 * @IONIC_QTYPE_EQ:        Event Queue
 * @IONIC_QTYPE_MAX:       Max queue type supported
 */
enum ionic_logical_qtype {
	IONIC_QTYPE_ADMINQ  = 0,
	IONIC_QTYPE_NOTIFYQ = 1,
	IONIC_QTYPE_RXQ     = 2,
	IONIC_QTYPE_TXQ     = 3,
	IONIC_QTYPE_EQ      = 4,
	IONIC_QTYPE_MAX     = 16,
};

/**
 * enum ionic_q_feature - Common Features for most queue types
 *
 * Common features use bits 0-15. Per-queue-type features use higher bits.
 *
 * @IONIC_QIDENT_F_CQ:      Queue has completion ring
 * @IONIC_QIDENT_F_SG:      Queue has scatter/gather ring
 * @IONIC_QIDENT_F_EQ:      Queue can use event queue
 * @IONIC_QIDENT_F_CMB:     Queue is in cmb bar
 * @IONIC_Q_F_2X_DESC:      Double main descriptor size
 * @IONIC_Q_F_2X_CQ_DESC:   Double cq descriptor size
 * @IONIC_Q_F_2X_SG_DESC:   Double sg descriptor size
 * @IONIC_Q_F_4X_DESC:      Quadruple main descriptor size
 * @IONIC_Q_F_4X_CQ_DESC:   Quadruple cq descriptor size
 * @IONIC_Q_F_4X_SG_DESC:   Quadruple sg descriptor size
 * @IONIC_QIDENT_F_EXPDB:   Queue supports express doorbell
 */
enum ionic_q_feature {
	IONIC_QIDENT_F_CQ		= BIT_ULL(0),
	IONIC_QIDENT_F_SG		= BIT_ULL(1),
	IONIC_QIDENT_F_EQ		= BIT_ULL(2),
	IONIC_QIDENT_F_CMB		= BIT_ULL(3),
	IONIC_Q_F_2X_DESC		= BIT_ULL(4),
	IONIC_Q_F_2X_CQ_DESC		= BIT_ULL(5),
	IONIC_Q_F_2X_SG_DESC		= BIT_ULL(6),
	IONIC_Q_F_4X_DESC		= BIT_ULL(7),
	IONIC_Q_F_4X_CQ_DESC		= BIT_ULL(8),
	IONIC_Q_F_4X_SG_DESC		= BIT_ULL(9),
	IONIC_QIDENT_F_EXPDB		= BIT_ULL(10),
};

/**
 * enum ionic_rxq_feature - RXQ-specific Features
 *
 * Per-queue-type features use bits 16 and higher.
 *
 * @IONIC_RXQ_F_HWSTAMP:   Queue supports Hardware Timestamping
 */
enum ionic_rxq_feature {
	IONIC_RXQ_F_HWSTAMP		= BIT_ULL(16),
};

/**
 * enum ionic_txq_feature - TXQ-specific Features
 *
 * Per-queue-type features use bits 16 and higher.
 *
 * @IONIC_TXQ_F_HWSTAMP:   Queue supports Hardware Timestamping
 */
enum ionic_txq_feature {
	IONIC_TXQ_F_HWSTAMP		= BIT_ULL(16),
};

/**
 * enum ionic_hwstamp_bits - Hardware timestamp decoding bits
 * @IONIC_HWSTAMP_INVALID:          Invalid hardware timestamp value
 * @IONIC_HWSTAMP_CQ_NEGOFFSET:     Timestamp field negative offset
 *                                  from the base cq descriptor.
 */
enum ionic_hwstamp_bits {
	IONIC_HWSTAMP_INVALID	    = ~0ull,
	IONIC_HWSTAMP_CQ_NEGOFFSET  = 8,
};

/**
 * struct ionic_lif_logical_qtype - Descriptor of logical to HW queue type
 * @qtype:          Hardware Queue Type
 * @qid_count:      Number of Queue IDs of the logical type
 * @qid_base:       Minimum Queue ID of the logical type
 */
struct ionic_lif_logical_qtype {
	u8     qtype;
	u8     rsvd[3];
	__le32 qid_count;
	__le32 qid_base;
};

/**
 * enum ionic_lif_state - LIF state
 * @IONIC_LIF_DISABLE:     LIF disabled
 * @IONIC_LIF_ENABLE:      LIF enabled
 * @IONIC_LIF_QUIESCE:     LIF Quiesced
 */
enum ionic_lif_state {
	IONIC_LIF_QUIESCE	= 0,
	IONIC_LIF_ENABLE	= 1,
	IONIC_LIF_DISABLE	= 2,
};

/**
 * union ionic_lif_config - LIF configuration
 * @state:          LIF state (enum ionic_lif_state)
 * @name:           LIF name
 * @mtu:            MTU
 * @mac:            Station MAC address
 * @vlan:           Default Vlan ID
 * @features:       Features (enum ionic_eth_hw_features)
 * @queue_count:    Queue counts per queue-type
 */
union ionic_lif_config {
	struct {
		u8     state;
		u8     rsvd[3];
		char   name[IONIC_IFNAMSIZ];
		__le32 mtu;
		u8     mac[6];
		__le16 vlan;
		__le64 features;
		__le32 queue_count[IONIC_QTYPE_MAX];
	} __attribute__((packed));
	__le32 words[64];
};

/**
 * enum ionic_lif_rdma_stats_type - LIF stat type
 * @IONIC_LIF_RDMA_STAT_GLOBAL:     Global stats
 * @IONIC_LIF_RDMA_STAT_QP:         Queue pair stats
 */
enum ionic_lif_rdma_cap_stats {
	IONIC_LIF_RDMA_STAT_GLOBAL = BIT(0),
	IONIC_LIF_RDMA_STAT_QP = BIT(1),
};

/**
 * struct ionic_lif_identity - LIF identity information (type-specific)
 *
 * @capabilities:        LIF capabilities
 *
 * @eth:                    Ethernet identify structure
 *	@eth.version:            Ethernet identify structure version
 *	@eth.max_ucast_filters:  Number of perfect unicast addresses supported
 *	@eth.max_mcast_filters:  Number of perfect multicast addresses supported
 *	@eth.min_frame_size:     Minimum size of frames to be sent
 *	@eth.max_frame_size:     Maximum size of frames to be sent
 *	@eth.hwstamp_tx_modes:   Bitmask of BIT_ULL(enum ionic_txstamp_mode)
 *	@eth.hwstamp_rx_filters: Bitmask of enum ionic_pkt_class
 *	@eth.config:             LIF config struct with features, mtu, mac, q counts
 *
 * @rdma:                RDMA identify structure
 *	@rdma.version:         RDMA capability version
 *	@rdma.qp_opcodes:      Number of RDMA queue pair opcodes supported
 *	@rdma.admin_opcodes:   Number of RDMA admin opcodes supported
 *	@rdma.minor_version:   RDMA capability minor version
 *	@rdma.npts_per_lif:    Page table size per LIF
 *	@rdma.nmrs_per_lif:    Number of memory regions per LIF
 *	@rdma.nahs_per_lif:    Number of address handles per LIF
 *	@rdma.max_stride:      Max work request stride
 *	@rdma.cl_stride:       Cache line stride
 *	@rdma.pte_stride:      Page table entry stride
 *	@rdma.rrq_stride:      Remote RQ work request stride
 *	@rdma.rsq_stride:      Remote SQ work request stride
 *	@rdma.dcqcn_profiles:  Number of DCQCN profiles
 *	@rdma.page_size_cap:   Supported page sizes
 *	@rdma.aq_qtype:        RDMA Admin Qtype
 *	@rdma.sq_qtype:        RDMA Send Qtype
 *	@rdma.rq_qtype:        RDMA Receive Qtype
 *	@rdma.cq_qtype:        RDMA Completion Qtype
 *	@rdma.eq_qtype:        RDMA Event Qtype
 *	@rdma.stats_type:      Supported statistics type (enum ionic_lif_rdma_cap_stats)
 */
union ionic_lif_identity {
	struct {
		__le64 capabilities;

		struct {
			u8 version;
			u8 rsvd[3];
			__le32 max_ucast_filters;
			__le32 max_mcast_filters;
			__le16 rss_ind_tbl_sz;
			__le32 min_frame_size;
			__le32 max_frame_size;
			u8 rsvd2[2];
			__le64 hwstamp_tx_modes;
			__le64 hwstamp_rx_filters;
			u8 rsvd3[88];
			union ionic_lif_config config;
		} __attribute__((packed)) eth;

		struct {
			u8 version;
			u8 qp_opcodes;
			u8 admin_opcodes;
			u8 minor_version;
			__le32 npts_per_lif;
			__le32 nmrs_per_lif;
			__le32 nahs_per_lif;
			u8 max_stride;
			u8 cl_stride;
			u8 pte_stride;
			u8 rrq_stride;
			u8 rsq_stride;
			u8 dcqcn_profiles;
			u8 udma_shift;
			u8 rsvd_dimensions;
			__le64 page_size_cap;
			struct ionic_lif_logical_qtype aq_qtype;
			struct ionic_lif_logical_qtype sq_qtype;
			struct ionic_lif_logical_qtype rq_qtype;
			struct ionic_lif_logical_qtype cq_qtype;
			struct ionic_lif_logical_qtype eq_qtype;
			__le16 stats_type;
			u8 rsvd1[162];
		} __attribute__((packed)) rdma;
	} __attribute__((packed));
	__le32 words[478];
};

/**
 * struct ionic_lif_init_cmd - LIF init command
 * @opcode:       Opcode
 * @type:         LIF type (enum ionic_lif_type)
 * @index:        LIF index
 * @info_pa:      Destination address for LIF info (struct ionic_lif_info)
 */
struct ionic_lif_init_cmd {
	u8     opcode;
	u8     type;
	__le16 index;
	__le32 rsvd;
	__le64 info_pa;
	u8     rsvd2[48];
};

/**
 * struct ionic_lif_init_comp - LIF init command completion
 * @status:	Status of the command (enum ionic_status_code)
 * @hw_index:	Hardware index of the initialized LIF
 */
struct ionic_lif_init_comp {
	u8 status;
	u8 rsvd;
	__le16 hw_index;
	u8 rsvd2[12];
};

/**
 * struct ionic_q_identify_cmd - queue identify command
 * @opcode:     opcode
 * @lif_type:   LIF type (enum ionic_lif_type)
 * @type:       Logical queue type (enum ionic_logical_qtype)
 * @ver:        Highest queue type version that the driver supports
 */
struct ionic_q_identify_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_type;
	u8     type;
	u8     ver;
	u8     rsvd2[58];
};

/**
 * struct ionic_q_identify_comp - queue identify command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @ver:        Queue type version that can be used with FW
 */
struct ionic_q_identify_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	u8     ver;
	u8     rsvd2[11];
};

/**
 * union ionic_q_identity - queue identity information
 *     @version:        Queue type version that can be used with FW
 *     @supported:      Bitfield of queue versions, first bit = ver 0
 *     @features:       Queue features (enum ionic_q_feature, etc)
 *     @desc_sz:        Descriptor size
 *     @comp_sz:        Completion descriptor size
 *     @sg_desc_sz:     Scatter/Gather descriptor size
 *     @max_sg_elems:   Maximum number of Scatter/Gather elements
 *     @sg_desc_stride: Number of Scatter/Gather elements per descriptor
 */
union ionic_q_identity {
	struct {
		u8      version;
		u8      supported;
		u8      rsvd[6];
		__le64  features;
		__le16  desc_sz;
		__le16  comp_sz;
		__le16  sg_desc_sz;
		__le16  max_sg_elems;
		__le16  sg_desc_stride;
	};
	__le32 words[478];
};

/**
 * struct ionic_q_init_cmd - Queue init command
 * @opcode:       opcode
 * @type:         Logical queue type
 * @ver:          Queue type version
 * @lif_index:    LIF index
 * @index:        (LIF, qtype) relative admin queue index
 * @intr_index:   Interrupt control register index, or Event queue index
 * @pid:          Process ID
 * @flags:
 *    IRQ:        Interrupt requested on completion
 *    ENA:        Enable the queue.  If ENA=0 the queue is initialized
 *                but remains disabled, to be later enabled with the
 *                Queue Enable command.  If ENA=1, then queue is
 *                initialized and then enabled.
 *    SG:         Enable Scatter-Gather on the queue.
 *                in number of descs.  The actual ring size is
 *                (1 << ring_size).  For example, to
 *                select a ring size of 64 descriptors write
 *                ring_size = 6.  The minimum ring_size value is 2
 *                for a ring size of 4 descriptors.  The maximum
 *                ring_size value is 16 for a ring size of 64k
 *                descriptors.  Values of ring_size <2 and >16 are
 *                reserved.
 *    EQ:         Enable the Event Queue
 * @cos:          Class of service for this queue
 * @ring_size:    Queue ring size, encoded as a log2(size)
 * @ring_base:    Queue ring base address
 * @cq_ring_base: Completion queue ring base address
 * @sg_ring_base: Scatter/Gather ring base address
 * @features:     Mask of queue features to enable, if not in the flags above.
 */
struct ionic_q_init_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	u8     type;
	u8     ver;
	u8     rsvd1[2];
	__le32 index;
	__le16 pid;
	__le16 intr_index;
	__le16 flags;
#define IONIC_QINIT_F_IRQ	0x01	/* Request interrupt on completion */
#define IONIC_QINIT_F_ENA	0x02	/* Enable the queue */
#define IONIC_QINIT_F_SG	0x04	/* Enable scatter/gather on the queue */
#define IONIC_QINIT_F_EQ	0x08	/* Enable event queue */
#define IONIC_QINIT_F_CMB	0x10	/* Enable cmb-based queue */
#define IONIC_QINIT_F_DEBUG	0x80	/* Enable queue debugging */
	u8     cos;
	u8     ring_size;
	__le64 ring_base;
	__le64 cq_ring_base;
	__le64 sg_ring_base;
	u8     rsvd2[12];
	__le64 features;
} __attribute__((packed));

IONIC_CHECK_CMD_LENGTH(ionic_q_init_cmd);

/**
 * struct ionic_q_init_comp - Queue init command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @hw_index:   Hardware Queue ID
 * @hw_type:    Hardware Queue type
 * @color:      Color
 */
struct ionic_q_init_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	__le32 hw_index;
	u8     hw_type;
	u8     rsvd2[6];
	u8     color;
};

/* the device's internal addressing uses up to 52 bits */
#define IONIC_ADDR_LEN		52
#define IONIC_ADDR_MASK		(BIT_ULL(IONIC_ADDR_LEN) - 1)

enum ionic_txq_desc_opcode {
	IONIC_TXQ_DESC_OPCODE_CSUM_NONE = 0,
	IONIC_TXQ_DESC_OPCODE_CSUM_PARTIAL = 1,
	IONIC_TXQ_DESC_OPCODE_CSUM_HW = 2,
	IONIC_TXQ_DESC_OPCODE_TSO = 3,
};

/**
 * struct ionic_txq_desc - Ethernet Tx queue descriptor format
 * @cmd:          Tx operation, see IONIC_TXQ_DESC_OPCODE_*:
 *
 *                   IONIC_TXQ_DESC_OPCODE_CSUM_NONE:
 *                      Non-offload send.  No segmentation,
 *                      fragmentation or checksum calc/insertion is
 *                      performed by device; packet is prepared
 *                      to send by software stack and requires
 *                      no further manipulation from device.
 *
 *                   IONIC_TXQ_DESC_OPCODE_CSUM_PARTIAL:
 *                      Offload 16-bit L4 checksum
 *                      calculation/insertion.  The device will
 *                      calculate the L4 checksum value and
 *                      insert the result in the packet's L4
 *                      header checksum field.  The L4 checksum
 *                      is calculated starting at @csum_start bytes
 *                      into the packet to the end of the packet.
 *                      The checksum insertion position is given
 *                      in @csum_offset, which is the offset from
 *                      @csum_start to the checksum field in the L4
 *                      header.  This feature is only applicable to
 *                      protocols such as TCP, UDP and ICMP where a
 *                      standard (i.e. the 'IP-style' checksum)
 *                      one's complement 16-bit checksum is used,
 *                      using an IP pseudo-header to seed the
 *                      calculation.  Software will preload the L4
 *                      checksum field with the IP pseudo-header
 *                      checksum.
 *
 *                      For tunnel encapsulation, @csum_start and
 *                      @csum_offset refer to the inner L4
 *                      header.  Supported tunnels encapsulations
 *                      are: IPIP, GRE, and UDP.  If the @encap
 *                      is clear, no further processing by the
 *                      device is required; software will
 *                      calculate the outer header checksums.  If
 *                      the @encap is set, the device will
 *                      offload the outer header checksums using
 *                      LCO (local checksum offload) (see
 *                      Documentation/networking/checksum-offloads.rst
 *                      for more info).
 *
 *                   IONIC_TXQ_DESC_OPCODE_CSUM_HW:
 *                      Offload 16-bit checksum computation to hardware.
 *                      If @csum_l3 is set then the packet's L3 checksum is
 *                      updated. Similarly, if @csum_l4 is set the L4
 *                      checksum is updated. If @encap is set then encap header
 *                      checksums are also updated.
 *
 *                   IONIC_TXQ_DESC_OPCODE_TSO:
 *                      Device performs TCP segmentation offload
 *                      (TSO).  @hdr_len is the number of bytes
 *                      to the end of TCP header (the offset to
 *                      the TCP payload).  @mss is the desired
 *                      MSS, the TCP payload length for each
 *                      segment.  The device will calculate/
 *                      insert IP (IPv4 only) and TCP checksums
 *                      for each segment.  In the first data
 *                      buffer containing the header template,
 *                      the driver will set IPv4 checksum to 0
 *                      and preload TCP checksum with the IP
 *                      pseudo header calculated with IP length = 0.
 *
 *                      Supported tunnel encapsulations are IPIP,
 *                      layer-3 GRE, and UDP. @hdr_len includes
 *                      both outer and inner headers.  The driver
 *                      will set IPv4 checksum to zero and
 *                      preload TCP checksum with IP pseudo
 *                      header on the inner header.
 *
 *                      TCP ECN offload is supported.  The device
 *                      will set CWR flag in the first segment if
 *                      CWR is set in the template header, and
 *                      clear CWR in remaining segments.
 *    flags:
 *                vlan:
 *                    Insert an L2 VLAN header using @vlan_tci
 *                encap:
 *                    Calculate encap header checksum
 *                csum_l3:
 *                    Compute L3 header checksum
 *                csum_l4:
 *                    Compute L4 header checksum
 *                tso_sot:
 *                    TSO start
 *                tso_eot:
 *                    TSO end
 *    num_sg_elems: Number of scatter-gather elements in SG
 *                descriptor
 *    addr:         First data buffer's DMA address
 *                (Subsequent data buffers are on txq_sg_desc)
 * @len:          First data buffer's length, in bytes
 * @vlan_tci:     VLAN tag to insert in the packet (if requested
 *                by @V-bit).  Includes .1p and .1q tags
 * @hdr_len:      Length of packet headers, including
 *                encapsulating outer header, if applicable
 *                Valid for opcodes IONIC_TXQ_DESC_OPCODE_CALC_CSUM and
 *                IONIC_TXQ_DESC_OPCODE_TSO.  Should be set to zero for
 *                all other modes.  For
 *                IONIC_TXQ_DESC_OPCODE_CALC_CSUM, @hdr_len is length
 *                of headers up to inner-most L4 header.  For
 *                IONIC_TXQ_DESC_OPCODE_TSO, @hdr_len is up to
 *                inner-most L4 payload, so inclusive of
 *                inner-most L4 header.
 * @mss:          Desired MSS value for TSO; only applicable for
 *                IONIC_TXQ_DESC_OPCODE_TSO
 * @csum_start:   Offset from packet to first byte checked in L4 checksum
 * @csum_offset:  Offset from csum_start to L4 checksum field
 */
struct ionic_txq_desc {
	__le64  cmd;
#define IONIC_TXQ_DESC_OPCODE_MASK		0xf
#define IONIC_TXQ_DESC_OPCODE_SHIFT		4
#define IONIC_TXQ_DESC_FLAGS_MASK		0xf
#define IONIC_TXQ_DESC_FLAGS_SHIFT		0
#define IONIC_TXQ_DESC_NSGE_MASK		0xf
#define IONIC_TXQ_DESC_NSGE_SHIFT		8
#define IONIC_TXQ_DESC_ADDR_MASK		(BIT_ULL(IONIC_ADDR_LEN) - 1)
#define IONIC_TXQ_DESC_ADDR_SHIFT		12

/* common flags */
#define IONIC_TXQ_DESC_FLAG_VLAN		0x1
#define IONIC_TXQ_DESC_FLAG_ENCAP		0x2

/* flags for csum_hw opcode */
#define IONIC_TXQ_DESC_FLAG_CSUM_L3		0x4
#define IONIC_TXQ_DESC_FLAG_CSUM_L4		0x8

/* flags for tso opcode */
#define IONIC_TXQ_DESC_FLAG_TSO_SOT		0x4
#define IONIC_TXQ_DESC_FLAG_TSO_EOT		0x8

	__le16  len;
	union {
		__le16  vlan_tci;
		__le16  hword0;
	};
	union {
		__le16  csum_start;
		__le16  hdr_len;
		__le16  hword1;
	};
	union {
		__le16  csum_offset;
		__le16  mss;
		__le16  hword2;
	};
};

static inline u64 encode_txq_desc_cmd(u8 opcode, u8 flags,
				      u8 nsge, u64 addr)
{
	u64 cmd;

	cmd = (opcode & IONIC_TXQ_DESC_OPCODE_MASK) << IONIC_TXQ_DESC_OPCODE_SHIFT;
	cmd |= (flags & IONIC_TXQ_DESC_FLAGS_MASK) << IONIC_TXQ_DESC_FLAGS_SHIFT;
	cmd |= (nsge & IONIC_TXQ_DESC_NSGE_MASK) << IONIC_TXQ_DESC_NSGE_SHIFT;
	cmd |= (addr & IONIC_TXQ_DESC_ADDR_MASK) << IONIC_TXQ_DESC_ADDR_SHIFT;

	return cmd;
};

static inline void decode_txq_desc_cmd(u64 cmd, u8 *opcode, u8 *flags,
				       u8 *nsge, u64 *addr)
{
	*opcode = (cmd >> IONIC_TXQ_DESC_OPCODE_SHIFT) & IONIC_TXQ_DESC_OPCODE_MASK;
	*flags = (cmd >> IONIC_TXQ_DESC_FLAGS_SHIFT) & IONIC_TXQ_DESC_FLAGS_MASK;
	*nsge = (cmd >> IONIC_TXQ_DESC_NSGE_SHIFT) & IONIC_TXQ_DESC_NSGE_MASK;
	*addr = (cmd >> IONIC_TXQ_DESC_ADDR_SHIFT) & IONIC_TXQ_DESC_ADDR_MASK;
};

/**
 * struct ionic_txq_sg_elem - Transmit scatter-gather (SG) descriptor element
 * @addr:      DMA address of SG element data buffer
 * @len:       Length of SG element data buffer, in bytes
 */
struct ionic_txq_sg_elem {
	__le64 addr;
	__le16 len;
	__le16 rsvd[3];
};

/**
 * struct ionic_txq_sg_desc - Transmit scatter-gather (SG) list
 * @elems:     Scatter-gather elements
 */
struct ionic_txq_sg_desc {
#define IONIC_TX_MAX_SG_ELEMS		8
#define IONIC_TX_SG_DESC_STRIDE		8
	struct ionic_txq_sg_elem elems[IONIC_TX_MAX_SG_ELEMS];
};

struct ionic_txq_sg_desc_v1 {
#define IONIC_TX_MAX_SG_ELEMS_V1		15
#define IONIC_TX_SG_DESC_STRIDE_V1		16
	struct ionic_txq_sg_elem elems[IONIC_TX_SG_DESC_STRIDE_V1];
};

/**
 * struct ionic_txq_comp - Ethernet transmit queue completion descriptor
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @color:      Color bit
 */
struct ionic_txq_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	u8     rsvd2[11];
	u8     color;
};

enum ionic_rxq_desc_opcode {
	IONIC_RXQ_DESC_OPCODE_SIMPLE = 0,
	IONIC_RXQ_DESC_OPCODE_SG = 1,
};

/**
 * struct ionic_rxq_desc - Ethernet Rx queue descriptor format
 * @opcode:       Rx operation, see IONIC_RXQ_DESC_OPCODE_*:
 *
 *                   IONIC_RXQ_DESC_OPCODE_SIMPLE:
 *                      Receive full packet into data buffer
 *                      starting at @addr.  Results of
 *                      receive, including actual bytes received,
 *                      are recorded in Rx completion descriptor.
 *
 * @len:          Data buffer's length, in bytes
 * @addr:         Data buffer's DMA address
 */
struct ionic_rxq_desc {
	u8     opcode;
	u8     rsvd[5];
	__le16 len;
	__le64 addr;
};

/**
 * struct ionic_rxq_sg_elem - Receive scatter-gather (SG) descriptor element
 * @addr:      DMA address of SG element data buffer
 * @len:       Length of SG element data buffer, in bytes
 */
struct ionic_rxq_sg_elem {
	__le64 addr;
	__le16 len;
	__le16 rsvd[3];
};

/**
 * struct ionic_rxq_sg_desc - Receive scatter-gather (SG) list
 * @elems:     Scatter-gather elements
 */
struct ionic_rxq_sg_desc {
#define IONIC_RX_MAX_SG_ELEMS		8
#define IONIC_RX_SG_DESC_STRIDE		8
	struct ionic_rxq_sg_elem elems[IONIC_RX_SG_DESC_STRIDE];
};

/**
 * struct ionic_rxq_comp - Ethernet receive queue completion descriptor
 * @status:       Status of the command (enum ionic_status_code)
 * @num_sg_elems: Number of SG elements used by this descriptor
 * @comp_index:   Index in the descriptor ring for which this is the completion
 * @rss_hash:     32-bit RSS hash
 * @csum:         16-bit sum of the packet's L2 payload
 *                If the packet's L2 payload is odd length, an extra
 *                zero-value byte is included in the @csum calculation but
 *                not included in @len.
 * @vlan_tci:     VLAN tag stripped from the packet.  Valid if @VLAN is
 *                set.  Includes .1p and .1q tags.
 * @len:          Received packet length, in bytes.  Excludes FCS.
 * @csum_calc     L2 payload checksum is computed or not
 * @csum_flags:   See IONIC_RXQ_COMP_CSUM_F_*:
 *
 *                  IONIC_RXQ_COMP_CSUM_F_TCP_OK:
 *                    The TCP checksum calculated by the device
 *                    matched the checksum in the receive packet's
 *                    TCP header.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_TCP_BAD:
 *                    The TCP checksum calculated by the device did
 *                    not match the checksum in the receive packet's
 *                    TCP header.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_UDP_OK:
 *                    The UDP checksum calculated by the device
 *                    matched the checksum in the receive packet's
 *                    UDP header
 *
 *                  IONIC_RXQ_COMP_CSUM_F_UDP_BAD:
 *                    The UDP checksum calculated by the device did
 *                    not match the checksum in the receive packet's
 *                    UDP header.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_IP_OK:
 *                    The IPv4 checksum calculated by the device
 *                    matched the checksum in the receive packet's
 *                    first IPv4 header.  If the receive packet
 *                    contains both a tunnel IPv4 header and a
 *                    transport IPv4 header, the device validates the
 *                    checksum for the both IPv4 headers.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_IP_BAD:
 *                    The IPv4 checksum calculated by the device did
 *                    not match the checksum in the receive packet's
 *                    first IPv4 header. If the receive packet
 *                    contains both a tunnel IPv4 header and a
 *                    transport IPv4 header, the device validates the
 *                    checksum for both IP headers.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_VLAN:
 *                    The VLAN header was stripped and placed in @vlan_tci.
 *
 *                  IONIC_RXQ_COMP_CSUM_F_CALC:
 *                    The checksum was calculated by the device.
 *
 * @pkt_type_color: Packet type and color bit; see IONIC_RXQ_COMP_PKT_TYPE_MASK
 */
struct ionic_rxq_comp {
	u8     status;
	u8     num_sg_elems;
	__le16 comp_index;
	__le32 rss_hash;
	__le16 csum;
	__le16 vlan_tci;
	__le16 len;
	u8     csum_flags;
#define IONIC_RXQ_COMP_CSUM_F_TCP_OK	0x01
#define IONIC_RXQ_COMP_CSUM_F_TCP_BAD	0x02
#define IONIC_RXQ_COMP_CSUM_F_UDP_OK	0x04
#define IONIC_RXQ_COMP_CSUM_F_UDP_BAD	0x08
#define IONIC_RXQ_COMP_CSUM_F_IP_OK	0x10
#define IONIC_RXQ_COMP_CSUM_F_IP_BAD	0x20
#define IONIC_RXQ_COMP_CSUM_F_VLAN	0x40
#define IONIC_RXQ_COMP_CSUM_F_CALC	0x80
	u8     pkt_type_color;
#define IONIC_RXQ_COMP_PKT_TYPE_MASK	0x7f
};

enum ionic_pkt_type {
	IONIC_PKT_TYPE_NON_IP		= 0x00,
	IONIC_PKT_TYPE_IPV4		= 0x01,
	IONIC_PKT_TYPE_IPV4_TCP		= 0x03,
	IONIC_PKT_TYPE_IPV4_UDP		= 0x05,
	IONIC_PKT_TYPE_IPV6		= 0x08,
	IONIC_PKT_TYPE_IPV6_TCP		= 0x18,
	IONIC_PKT_TYPE_IPV6_UDP		= 0x28,
	/* below types are only used if encap offloads are enabled on lif */
	IONIC_PKT_TYPE_ENCAP_NON_IP	= 0x40,
	IONIC_PKT_TYPE_ENCAP_IPV4	= 0x41,
	IONIC_PKT_TYPE_ENCAP_IPV4_TCP	= 0x43,
	IONIC_PKT_TYPE_ENCAP_IPV4_UDP	= 0x45,
	IONIC_PKT_TYPE_ENCAP_IPV6	= 0x48,
	IONIC_PKT_TYPE_ENCAP_IPV6_TCP	= 0x58,
	IONIC_PKT_TYPE_ENCAP_IPV6_UDP	= 0x68,
};

enum ionic_eth_hw_features {
	IONIC_ETH_HW_VLAN_TX_TAG	= BIT(0),
	IONIC_ETH_HW_VLAN_RX_STRIP	= BIT(1),
	IONIC_ETH_HW_VLAN_RX_FILTER	= BIT(2),
	IONIC_ETH_HW_RX_HASH		= BIT(3),
	IONIC_ETH_HW_RX_CSUM		= BIT(4),
	IONIC_ETH_HW_TX_SG		= BIT(5),
	IONIC_ETH_HW_RX_SG		= BIT(6),
	IONIC_ETH_HW_TX_CSUM		= BIT(7),
	IONIC_ETH_HW_TSO		= BIT(8),
	IONIC_ETH_HW_TSO_IPV6		= BIT(9),
	IONIC_ETH_HW_TSO_ECN		= BIT(10),
	IONIC_ETH_HW_TSO_GRE		= BIT(11),
	IONIC_ETH_HW_TSO_GRE_CSUM	= BIT(12),
	IONIC_ETH_HW_TSO_IPXIP4		= BIT(13),
	IONIC_ETH_HW_TSO_IPXIP6		= BIT(14),
	IONIC_ETH_HW_TSO_UDP		= BIT(15),
	IONIC_ETH_HW_TSO_UDP_CSUM	= BIT(16),
	IONIC_ETH_HW_RX_CSUM_GENEVE	= BIT(17),
	IONIC_ETH_HW_TX_CSUM_GENEVE	= BIT(18),
	IONIC_ETH_HW_TSO_GENEVE		= BIT(19),
	IONIC_ETH_HW_TIMESTAMP		= BIT(20),
};

/**
 * enum ionic_pkt_class - Packet classification mask.
 *
 * Used with rx steering filter, packets indicated by the mask can be steered
 * toward a specific receive queue.
 *
 * @IONIC_PKT_CLS_NTP_ALL:          All NTP packets.
 * @IONIC_PKT_CLS_PTP1_SYNC:        PTPv1 sync
 * @IONIC_PKT_CLS_PTP1_DREQ:        PTPv1 delay-request
 * @IONIC_PKT_CLS_PTP1_ALL:         PTPv1 all packets
 * @IONIC_PKT_CLS_PTP2_L4_SYNC:     PTPv2-UDP sync
 * @IONIC_PKT_CLS_PTP2_L4_DREQ:     PTPv2-UDP delay-request
 * @IONIC_PKT_CLS_PTP2_L4_ALL:      PTPv2-UDP all packets
 * @IONIC_PKT_CLS_PTP2_L2_SYNC:     PTPv2-ETH sync
 * @IONIC_PKT_CLS_PTP2_L2_DREQ:     PTPv2-ETH delay-request
 * @IONIC_PKT_CLS_PTP2_L2_ALL:      PTPv2-ETH all packets
 * @IONIC_PKT_CLS_PTP2_SYNC:        PTPv2 sync
 * @IONIC_PKT_CLS_PTP2_DREQ:        PTPv2 delay-request
 * @IONIC_PKT_CLS_PTP2_ALL:         PTPv2 all packets
 * @IONIC_PKT_CLS_PTP_SYNC:         PTP sync
 * @IONIC_PKT_CLS_PTP_DREQ:         PTP delay-request
 * @IONIC_PKT_CLS_PTP_ALL:          PTP all packets
 */
enum ionic_pkt_class {
	IONIC_PKT_CLS_NTP_ALL		= BIT(0),

	IONIC_PKT_CLS_PTP1_SYNC		= BIT(1),
	IONIC_PKT_CLS_PTP1_DREQ		= BIT(2),
	IONIC_PKT_CLS_PTP1_ALL		= BIT(3) |
		IONIC_PKT_CLS_PTP1_SYNC | IONIC_PKT_CLS_PTP1_DREQ,

	IONIC_PKT_CLS_PTP2_L4_SYNC	= BIT(4),
	IONIC_PKT_CLS_PTP2_L4_DREQ	= BIT(5),
	IONIC_PKT_CLS_PTP2_L4_ALL	= BIT(6) |
		IONIC_PKT_CLS_PTP2_L4_SYNC | IONIC_PKT_CLS_PTP2_L4_DREQ,

	IONIC_PKT_CLS_PTP2_L2_SYNC	= BIT(7),
	IONIC_PKT_CLS_PTP2_L2_DREQ	= BIT(8),
	IONIC_PKT_CLS_PTP2_L2_ALL	= BIT(9) |
		IONIC_PKT_CLS_PTP2_L2_SYNC | IONIC_PKT_CLS_PTP2_L2_DREQ,

	IONIC_PKT_CLS_PTP2_SYNC		=
		IONIC_PKT_CLS_PTP2_L4_SYNC | IONIC_PKT_CLS_PTP2_L2_SYNC,
	IONIC_PKT_CLS_PTP2_DREQ		=
		IONIC_PKT_CLS_PTP2_L4_DREQ | IONIC_PKT_CLS_PTP2_L2_DREQ,
	IONIC_PKT_CLS_PTP2_ALL		=
		IONIC_PKT_CLS_PTP2_L4_ALL | IONIC_PKT_CLS_PTP2_L2_ALL,

	IONIC_PKT_CLS_PTP_SYNC		=
		IONIC_PKT_CLS_PTP1_SYNC | IONIC_PKT_CLS_PTP2_SYNC,
	IONIC_PKT_CLS_PTP_DREQ		=
		IONIC_PKT_CLS_PTP1_DREQ | IONIC_PKT_CLS_PTP2_DREQ,
	IONIC_PKT_CLS_PTP_ALL		=
		IONIC_PKT_CLS_PTP1_ALL | IONIC_PKT_CLS_PTP2_ALL,
};

/**
 * struct ionic_q_control_cmd - Queue control command
 * @opcode:     opcode
 * @type:       Queue type
 * @lif_index:  LIF index
 * @index:      Queue index
 * @oper:       Operation (enum ionic_q_control_oper)
 */
struct ionic_q_control_cmd {
	u8     opcode;
	u8     type;
	__le16 lif_index;
	__le32 index;
	u8     oper;
	u8     rsvd[55];
};

typedef struct ionic_admin_comp ionic_q_control_comp;

enum ionic_q_control_oper {
	IONIC_Q_DISABLE		= 0,
	IONIC_Q_ENABLE		= 1,
	IONIC_Q_HANG_RESET	= 2,
};

/**
 * enum ionic_phy_type - Physical connection type
 * @IONIC_PHY_TYPE_NONE:    No PHY installed
 * @IONIC_PHY_TYPE_COPPER:  Copper PHY
 * @IONIC_PHY_TYPE_FIBER:   Fiber PHY
 */
enum ionic_phy_type {
	IONIC_PHY_TYPE_NONE	= 0,
	IONIC_PHY_TYPE_COPPER	= 1,
	IONIC_PHY_TYPE_FIBER	= 2,
};

/**
 * enum ionic_xcvr_state - Transceiver status
 * @IONIC_XCVR_STATE_REMOVED:        Transceiver removed
 * @IONIC_XCVR_STATE_INSERTED:       Transceiver inserted
 * @IONIC_XCVR_STATE_PENDING:        Transceiver pending
 * @IONIC_XCVR_STATE_SPROM_READ:     Transceiver data read
 * @IONIC_XCVR_STATE_SPROM_READ_ERR: Transceiver data read error
 */
enum ionic_xcvr_state {
	IONIC_XCVR_STATE_REMOVED	 = 0,
	IONIC_XCVR_STATE_INSERTED	 = 1,
	IONIC_XCVR_STATE_PENDING	 = 2,
	IONIC_XCVR_STATE_SPROM_READ	 = 3,
	IONIC_XCVR_STATE_SPROM_READ_ERR	 = 4,
};

/**
 * enum ionic_xcvr_pid - Supported link modes
 */
enum ionic_xcvr_pid {
	IONIC_XCVR_PID_UNKNOWN           = 0,

	/* CU */
	IONIC_XCVR_PID_QSFP_100G_CR4     = 1,
	IONIC_XCVR_PID_QSFP_40GBASE_CR4  = 2,
	IONIC_XCVR_PID_SFP_25GBASE_CR_S  = 3,
	IONIC_XCVR_PID_SFP_25GBASE_CR_L  = 4,
	IONIC_XCVR_PID_SFP_25GBASE_CR_N  = 5,
	IONIC_XCVR_PID_QSFP_50G_CR2_FC   = 6,
	IONIC_XCVR_PID_QSFP_50G_CR2      = 7,
	IONIC_XCVR_PID_QSFP_200G_CR4     = 8,
	IONIC_XCVR_PID_QSFP_400G_CR4     = 9,
	/* Fiber */
	IONIC_XCVR_PID_QSFP_100G_AOC    = 50,
	IONIC_XCVR_PID_QSFP_100G_ACC    = 51,
	IONIC_XCVR_PID_QSFP_100G_SR4    = 52,
	IONIC_XCVR_PID_QSFP_100G_LR4    = 53,
	IONIC_XCVR_PID_QSFP_100G_ER4    = 54,
	IONIC_XCVR_PID_QSFP_40GBASE_ER4 = 55,
	IONIC_XCVR_PID_QSFP_40GBASE_SR4 = 56,
	IONIC_XCVR_PID_QSFP_40GBASE_LR4 = 57,
	IONIC_XCVR_PID_QSFP_40GBASE_AOC = 58,
	IONIC_XCVR_PID_SFP_25GBASE_SR   = 59,
	IONIC_XCVR_PID_SFP_25GBASE_LR   = 60,
	IONIC_XCVR_PID_SFP_25GBASE_ER   = 61,
	IONIC_XCVR_PID_SFP_25GBASE_AOC  = 62,
	IONIC_XCVR_PID_SFP_10GBASE_SR   = 63,
	IONIC_XCVR_PID_SFP_10GBASE_LR   = 64,
	IONIC_XCVR_PID_SFP_10GBASE_LRM  = 65,
	IONIC_XCVR_PID_SFP_10GBASE_ER   = 66,
	IONIC_XCVR_PID_SFP_10GBASE_AOC  = 67,
	IONIC_XCVR_PID_SFP_10GBASE_CU   = 68,
	IONIC_XCVR_PID_QSFP_100G_CWDM4  = 69,
	IONIC_XCVR_PID_QSFP_100G_PSM4   = 70,
	IONIC_XCVR_PID_SFP_25GBASE_ACC  = 71,
	IONIC_XCVR_PID_SFP_10GBASE_T    = 72,
	IONIC_XCVR_PID_SFP_1000BASE_T   = 73,
	IONIC_XCVR__PID_QSFP_200G_AOC   = 74,
	IONIC_XCVR__PID_QSFP_200G_FR4   = 75,
	IONIC_XCVR__PID_QSFP_200G_DR4   = 76,
	IONIC_XCVR__PID_QSFP_200G_SR4   = 77,
	IONIC_XCVR__PID_QSFP_200G_ACC   = 78,
	IONIC_XCVR__PID_QSFP_400G_FR4   = 79,
	IONIC_XCVR__PID_QSFP_400G_DR4   = 80,
	IONIC_XCVR__PID_QSFP_400G_SR4   = 81,
	IONIC_XCVR__PID_QSFP_400G_VR4   = 82,
};

/**
 * enum ionic_port_admin_state - Port config state
 * @IONIC_PORT_ADMIN_STATE_NONE:    Port admin state not configured
 * @IONIC_PORT_ADMIN_STATE_DOWN:    Port admin disabled
 * @IONIC_PORT_ADMIN_STATE_UP:      Port admin enabled
 */
enum ionic_port_admin_state {
	IONIC_PORT_ADMIN_STATE_NONE = 0,
	IONIC_PORT_ADMIN_STATE_DOWN = 1,
	IONIC_PORT_ADMIN_STATE_UP   = 2,
};

/**
 * enum ionic_port_oper_status - Port operational status
 * @IONIC_PORT_OPER_STATUS_NONE:    Port disabled
 * @IONIC_PORT_OPER_STATUS_UP:      Port link status up
 * @IONIC_PORT_OPER_STATUS_DOWN:    Port link status down
 */
enum ionic_port_oper_status {
	IONIC_PORT_OPER_STATUS_NONE  = 0,
	IONIC_PORT_OPER_STATUS_UP    = 1,
	IONIC_PORT_OPER_STATUS_DOWN  = 2,
};

/**
 * enum ionic_port_fec_type - Ethernet Forward error correction (FEC) modes
 * @IONIC_PORT_FEC_TYPE_NONE:       FEC Disabled
 * @IONIC_PORT_FEC_TYPE_FC:         FireCode FEC
 * @IONIC_PORT_FEC_TYPE_RS:         ReedSolomon FEC
 */
enum ionic_port_fec_type {
	IONIC_PORT_FEC_TYPE_NONE = 0,
	IONIC_PORT_FEC_TYPE_FC   = 1,
	IONIC_PORT_FEC_TYPE_RS   = 2,
};

/**
 * enum ionic_port_pause_type - Ethernet pause (flow control) modes
 * @IONIC_PORT_PAUSE_TYPE_NONE:     Disable Pause
 * @IONIC_PORT_PAUSE_TYPE_LINK:     Link level pause
 * @IONIC_PORT_PAUSE_TYPE_PFC:      Priority-Flow Control
 */
enum ionic_port_pause_type {
	IONIC_PORT_PAUSE_TYPE_NONE = 0,
	IONIC_PORT_PAUSE_TYPE_LINK = 1,
	IONIC_PORT_PAUSE_TYPE_PFC  = 2,
};

/**
 * enum ionic_port_loopback_mode - Loopback modes
 * @IONIC_PORT_LOOPBACK_MODE_NONE:  Disable loopback
 * @IONIC_PORT_LOOPBACK_MODE_MAC:   MAC loopback
 * @IONIC_PORT_LOOPBACK_MODE_PHY:   PHY/SerDes loopback
 */
enum ionic_port_loopback_mode {
	IONIC_PORT_LOOPBACK_MODE_NONE = 0,
	IONIC_PORT_LOOPBACK_MODE_MAC  = 1,
	IONIC_PORT_LOOPBACK_MODE_PHY  = 2,
};

/**
 * struct ionic_xcvr_status - Transceiver Status information
 * @state:    Transceiver status (enum ionic_xcvr_state)
 * @phy:      Physical connection type (enum ionic_phy_type)
 * @pid:      Transceiver link mode (enum ionic_xcvr_pid)
 * @sprom:    Transceiver sprom contents
 */
struct ionic_xcvr_status {
	u8     state;
	u8     phy;
	__le16 pid;
	u8     sprom[256];
};

/**
 * union ionic_port_config - Port configuration
 * @speed:              port speed (in Mbps)
 * @mtu:                mtu
 * @state:              port admin state (enum ionic_port_admin_state)
 * @an_enable:          autoneg enable
 * @fec_type:           fec type (enum ionic_port_fec_type)
 * @pause_type:         pause type (enum ionic_port_pause_type)
 * @loopback_mode:      loopback mode (enum ionic_port_loopback_mode)
 */
union ionic_port_config {
	struct {
#define IONIC_SPEED_400G	400000	/* 400G in Mbps */
#define IONIC_SPEED_200G	200000	/* 200G in Mbps */
#define IONIC_SPEED_100G	100000	/* 100G in Mbps */
#define IONIC_SPEED_50G		50000	/* 50G in Mbps */
#define IONIC_SPEED_40G		40000	/* 40G in Mbps */
#define IONIC_SPEED_25G		25000	/* 25G in Mbps */
#define IONIC_SPEED_10G		10000	/* 10G in Mbps */
#define IONIC_SPEED_1G		1000	/* 1G in Mbps */
		__le32 speed;
		__le32 mtu;
		u8     state;
		u8     an_enable;
		u8     fec_type;
#define IONIC_PAUSE_TYPE_MASK		0x0f
#define IONIC_PAUSE_FLAGS_MASK		0xf0
#define IONIC_PAUSE_F_TX		0x10
#define IONIC_PAUSE_F_RX		0x20
		u8     pause_type;
		u8     loopback_mode;
	};
	__le32 words[64];
};

/**
 * struct ionic_port_status - Port Status information
 * @status:             link status (enum ionic_port_oper_status)
 * @id:                 port id
 * @speed:              link speed (in Mbps)
 * @link_down_count:    number of times link went from up to down
 * @fec_type:           fec type (enum ionic_port_fec_type)
 * @xcvr:               transceiver status
 */
struct ionic_port_status {
	__le32 id;
	__le32 speed;
	u8     status;
	__le16 link_down_count;
	u8     fec_type;
	u8     rsvd[48];
	struct ionic_xcvr_status  xcvr;
} __attribute__((packed));

/**
 * struct ionic_port_identify_cmd - Port identify command
 * @opcode:     opcode
 * @index:      port index
 * @ver:        Highest version of identify supported by driver
 */
struct ionic_port_identify_cmd {
	u8 opcode;
	u8 index;
	u8 ver;
	u8 rsvd[61];
};

/**
 * struct ionic_port_identify_comp - Port identify command completion
 * @status: Status of the command (enum ionic_status_code)
 * @ver:    Version of identify returned by device
 */
struct ionic_port_identify_comp {
	u8 status;
	u8 ver;
	u8 rsvd[14];
};

/**
 * struct ionic_port_init_cmd - Port initialization command
 * @opcode:     opcode
 * @index:      port index
 * @info_pa:    destination address for port info (struct ionic_port_info)
 */
struct ionic_port_init_cmd {
	u8     opcode;
	u8     index;
	u8     rsvd[6];
	__le64 info_pa;
	u8     rsvd2[48];
};

/**
 * struct ionic_port_init_comp - Port initialization command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_port_init_comp {
	u8 status;
	u8 rsvd[15];
};

/**
 * struct ionic_port_reset_cmd - Port reset command
 * @opcode:     opcode
 * @index:      port index
 */
struct ionic_port_reset_cmd {
	u8 opcode;
	u8 index;
	u8 rsvd[62];
};

/**
 * struct ionic_port_reset_comp - Port reset command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_port_reset_comp {
	u8 status;
	u8 rsvd[15];
};

/**
 * enum ionic_stats_ctl_cmd - List of commands for stats control
 * @IONIC_STATS_CTL_RESET:      Reset statistics
 */
enum ionic_stats_ctl_cmd {
	IONIC_STATS_CTL_RESET		= 0,
};

/**
 * enum ionic_txstamp_mode - List of TX Timestamping Modes
 * @IONIC_TXSTAMP_OFF:           Disable TX hardware timetamping.
 * @IONIC_TXSTAMP_ON:            Enable local TX hardware timetamping.
 * @IONIC_TXSTAMP_ONESTEP_SYNC:  Modify TX PTP Sync packets.
 * @IONIC_TXSTAMP_ONESTEP_P2P:   Modify TX PTP Sync and PDelayResp.
 */
enum ionic_txstamp_mode {
	IONIC_TXSTAMP_OFF		= 0,
	IONIC_TXSTAMP_ON		= 1,
	IONIC_TXSTAMP_ONESTEP_SYNC	= 2,
	IONIC_TXSTAMP_ONESTEP_P2P	= 3,
};

/**
 * enum ionic_port_attr - List of device attributes
 * @IONIC_PORT_ATTR_STATE:      Port state attribute
 * @IONIC_PORT_ATTR_SPEED:      Port speed attribute
 * @IONIC_PORT_ATTR_MTU:        Port MTU attribute
 * @IONIC_PORT_ATTR_AUTONEG:    Port autonegotiation attribute
 * @IONIC_PORT_ATTR_FEC:        Port FEC attribute
 * @IONIC_PORT_ATTR_PAUSE:      Port pause attribute
 * @IONIC_PORT_ATTR_LOOPBACK:   Port loopback attribute
 * @IONIC_PORT_ATTR_STATS_CTRL: Port statistics control attribute
 */
enum ionic_port_attr {
	IONIC_PORT_ATTR_STATE		= 0,
	IONIC_PORT_ATTR_SPEED		= 1,
	IONIC_PORT_ATTR_MTU		= 2,
	IONIC_PORT_ATTR_AUTONEG		= 3,
	IONIC_PORT_ATTR_FEC		= 4,
	IONIC_PORT_ATTR_PAUSE		= 5,
	IONIC_PORT_ATTR_LOOPBACK	= 6,
	IONIC_PORT_ATTR_STATS_CTRL	= 7,
};

/**
 * struct ionic_port_setattr_cmd - Set port attributes on the NIC
 * @opcode:         Opcode
 * @index:          Port index
 * @attr:           Attribute type (enum ionic_port_attr)
 * @state:          Port state
 * @speed:          Port speed
 * @mtu:            Port MTU
 * @an_enable:      Port autonegotiation setting
 * @fec_type:       Port FEC type setting
 * @pause_type:     Port pause type setting
 * @loopback_mode:  Port loopback mode
 * @stats_ctl:      Port stats setting
 */
struct ionic_port_setattr_cmd {
	u8     opcode;
	u8     index;
	u8     attr;
	u8     rsvd;
	union {
		u8      state;
		__le32  speed;
		__le32  mtu;
		u8      an_enable;
		u8      fec_type;
		u8      pause_type;
		u8      loopback_mode;
		u8      stats_ctl;
		u8      rsvd2[60];
	};
};

/**
 * struct ionic_port_setattr_comp - Port set attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @color:      Color bit
 */
struct ionic_port_setattr_comp {
	u8     status;
	u8     rsvd[14];
	u8     color;
};

/**
 * struct ionic_port_getattr_cmd - Get port attributes from the NIC
 * @opcode:     Opcode
 * @index:      port index
 * @attr:       Attribute type (enum ionic_port_attr)
 */
struct ionic_port_getattr_cmd {
	u8     opcode;
	u8     index;
	u8     attr;
	u8     rsvd[61];
};

/**
 * struct ionic_port_getattr_comp - Port get attr command completion
 * @status:         Status of the command (enum ionic_status_code)
 * @state:          Port state
 * @speed:          Port speed
 * @mtu:            Port MTU
 * @an_enable:      Port autonegotiation setting
 * @fec_type:       Port FEC type setting
 * @pause_type:     Port pause type setting
 * @loopback_mode:  Port loopback mode
 * @color:          Color bit
 */
struct ionic_port_getattr_comp {
	u8     status;
	u8     rsvd[3];
	union {
		u8      state;
		__le32  speed;
		__le32  mtu;
		u8      an_enable;
		u8      fec_type;
		u8      pause_type;
		u8      loopback_mode;
		u8      rsvd2[11];
	} __attribute__((packed));
	u8     color;
};

/**
 * struct ionic_lif_status - LIF status register
 * @eid:             most recent NotifyQ event id
 * @port_num:        port the LIF is connected to
 * @link_status:     port status (enum ionic_port_oper_status)
 * @link_speed:      speed of link in Mbps
 * @link_down_count: number of times link went from up to down
 */
struct ionic_lif_status {
	__le64 eid;
	u8     port_num;
	u8     rsvd;
	__le16 link_status;
	__le32 link_speed;		/* units of 1Mbps: eg 10000 = 10Gbps */
	__le16 link_down_count;
	u8      rsvd2[46];
};

/**
 * struct ionic_lif_reset_cmd - LIF reset command
 * @opcode:    opcode
 * @index:     LIF index
 */
struct ionic_lif_reset_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 index;
	__le32 rsvd2[15];
};

typedef struct ionic_admin_comp ionic_lif_reset_comp;

enum ionic_dev_state {
	IONIC_DEV_DISABLE	= 0,
	IONIC_DEV_ENABLE	= 1,
	IONIC_DEV_HANG_RESET	= 2,
};

/**
 * enum ionic_dev_attr - List of device attributes
 * @IONIC_DEV_ATTR_STATE:     Device state attribute
 * @IONIC_DEV_ATTR_NAME:      Device name attribute
 * @IONIC_DEV_ATTR_FEATURES:  Device feature attributes
 */
enum ionic_dev_attr {
	IONIC_DEV_ATTR_STATE    = 0,
	IONIC_DEV_ATTR_NAME     = 1,
	IONIC_DEV_ATTR_FEATURES = 2,
};

/**
 * struct ionic_dev_setattr_cmd - Set Device attributes on the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_dev_attr)
 * @state:      Device state (enum ionic_dev_state)
 * @name:       The bus info, e.g. PCI slot-device-function, 0 terminated
 * @features:   Device features
 */
struct ionic_dev_setattr_cmd {
	u8     opcode;
	u8     attr;
	__le16 rsvd;
	union {
		u8      state;
		char    name[IONIC_IFNAMSIZ];
		__le64  features;
		u8      rsvd2[60];
	} __attribute__((packed));
};

/**
 * struct ionic_dev_setattr_comp - Device set attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @features:   Device features
 * @color:      Color bit
 */
struct ionic_dev_setattr_comp {
	u8     status;
	u8     rsvd[3];
	union {
		__le64  features;
		u8      rsvd2[11];
	} __attribute__((packed));
	u8     color;
};

/**
 * struct ionic_dev_getattr_cmd - Get Device attributes from the NIC
 * @opcode:     opcode
 * @attr:       Attribute type (enum ionic_dev_attr)
 */
struct ionic_dev_getattr_cmd {
	u8     opcode;
	u8     attr;
	u8     rsvd[62];
};

/**
 * struct ionic_dev_getattr_comp - Device set attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @features:   Device features
 * @color:      Color bit
 */
struct ionic_dev_getattr_comp {
	u8     status;
	u8     rsvd[3];
	union {
		__le64  features;
		u8      rsvd2[11];
	} __attribute__((packed));
	u8     color;
};

/*
 * RSS parameters
 */
#define IONIC_RSS_HASH_KEY_SIZE		40

enum ionic_rss_hash_types {
	IONIC_RSS_TYPE_IPV4	= BIT(0),
	IONIC_RSS_TYPE_IPV4_TCP	= BIT(1),
	IONIC_RSS_TYPE_IPV4_UDP	= BIT(2),
	IONIC_RSS_TYPE_IPV6	= BIT(3),
	IONIC_RSS_TYPE_IPV6_TCP	= BIT(4),
	IONIC_RSS_TYPE_IPV6_UDP	= BIT(5),
};

/**
 * enum ionic_lif_attr - List of LIF attributes
 * @IONIC_LIF_ATTR_STATE:       LIF state attribute
 * @IONIC_LIF_ATTR_NAME:        LIF name attribute
 * @IONIC_LIF_ATTR_MTU:         LIF MTU attribute
 * @IONIC_LIF_ATTR_MAC:         LIF MAC attribute
 * @IONIC_LIF_ATTR_FEATURES:    LIF features attribute
 * @IONIC_LIF_ATTR_RSS:         LIF RSS attribute
 * @IONIC_LIF_ATTR_STATS_CTRL:  LIF statistics control attribute
 * @IONIC_LIF_ATTR_TXSTAMP:     LIF TX timestamping mode
 * @IONIC_LIF_ATTR_MGMT_IPV4:   LIF internal mgmt ipv4 address
 */
enum ionic_lif_attr {
	IONIC_LIF_ATTR_STATE        = 0,
	IONIC_LIF_ATTR_NAME         = 1,
	IONIC_LIF_ATTR_MTU          = 2,
	IONIC_LIF_ATTR_MAC          = 3,
	IONIC_LIF_ATTR_FEATURES     = 4,
	IONIC_LIF_ATTR_RSS          = 5,
	IONIC_LIF_ATTR_STATS_CTRL   = 6,
	IONIC_LIF_ATTR_TXSTAMP      = 7,
	IONIC_LIF_ATTR_MGMT_IPV4    = 254,
	IONIC_LIF_ATTR_MAX          = 255,
};

/**
 * struct ionic_lif_setattr_cmd - Set LIF attributes on the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_lif_attr)
 * @index:      LIF index
 * @state:      LIF state (enum ionic_lif_state)
 * @name:       The netdev name string, 0 terminated
 * @mtu:        Mtu
 * @mac:        Station mac
 * @features:   Features (enum ionic_eth_hw_features)
 * @rss:        RSS properties
 *	@rss.types:     The hash types to enable (see rss_hash_types)
 *	@rss.key:       The hash secret key
 *	@rss.addr:      Address for the indirection table shared memory
 * @stats_ctl:  stats control commands (enum ionic_stats_ctl_cmd)
 * @txstamp_mode:    TX Timestamping Mode (enum ionic_txstamp_mode)
 * @mgmt_ipv4:  ip address to set on internal mgmt interface
 */
struct ionic_lif_setattr_cmd {
	u8     opcode;
	u8     attr;
	__le16 index;
	union {
		u8      state;
		char    name[IONIC_IFNAMSIZ];
		__le32  mtu;
		u8      mac[6];
		__le64  features;
		struct {
			__le16 types;
			u8     key[IONIC_RSS_HASH_KEY_SIZE];
			u8     rsvd[6];
			__le64 addr;
		} rss;
		u8      stats_ctl;
		__le16  txstamp_mode;
		struct {
			__be32 addr;
			u8     subnet;
		} mgmt_ipv4;
		u8      rsvd[60];
	} __attribute__((packed));
};

/**
 * struct ionic_lif_setattr_comp - LIF set attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @features:   features (enum ionic_eth_hw_features)
 * @color:      Color bit
 */
struct ionic_lif_setattr_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	union {
		__le64  features;
		u8      rsvd2[11];
	} __attribute__((packed));
	u8     color;
};

/**
 * struct ionic_lif_getattr_cmd - Get LIF attributes from the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_lif_attr)
 * @index:      LIF index
 */
struct ionic_lif_getattr_cmd {
	u8     opcode;
	u8     attr;
	__le16 index;
	u8     rsvd[60];
};

/**
 * struct ionic_lif_getattr_comp - LIF get attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @state:      LIF state (enum ionic_lif_state)
 * @mtu:        Mtu
 * @mac:        Station mac
 * @features:   Features (enum ionic_eth_hw_features)
 * @txstamp_mode:    TX Timestamping Mode (enum ionic_txstamp_mode)
 * @color:      Color bit
 */
struct ionic_lif_getattr_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	union {
		u8      state;
		__le32  mtu;
		u8      mac[6];
		__le64  features;
		__le16 txstamp_mode;
		u8      rsvd2[11];
	} __attribute__((packed));
	u8     color;
};

/**
 * struct ionic_lif_setphc_cmd - Set LIF PTP Hardware Clock
 * @opcode:     Opcode
 * @lif_index:  LIF index
 * @tick:       Hardware stamp tick of an instant in time.
 * @nsec:       Nanosecond stamp of the same instant.
 * @frac:       Fractional nanoseconds at the same instant.
 * @mult:       Cycle to nanosecond multiplier.
 * @shift:      Cycle to nanosecond divisor (power of two).
 */
struct ionic_lif_setphc_cmd {
	u8	opcode;
	u8	rsvd1;
	__le16  lif_index;
	u8      rsvd2[4];
	__le64	tick;
	__le64	nsec;
	__le64	frac;
	__le32	mult;
	__le32	shift;
	u8     rsvd3[24];
};

IONIC_CHECK_CMD_LENGTH(ionic_lif_setphc_cmd);

enum ionic_rx_mode {
	IONIC_RX_MODE_F_UNICAST		= BIT(0),
	IONIC_RX_MODE_F_MULTICAST	= BIT(1),
	IONIC_RX_MODE_F_BROADCAST	= BIT(2),
	IONIC_RX_MODE_F_PROMISC		= BIT(3),
	IONIC_RX_MODE_F_ALLMULTI	= BIT(4),
	IONIC_RX_MODE_F_RDMA_SNIFFER	= BIT(5),
};

/**
 * struct ionic_rx_mode_set_cmd - Set LIF's Rx mode command
 * @opcode:     opcode
 * @lif_index:  LIF index
 * @rx_mode:    Rx mode flags:
 *                  IONIC_RX_MODE_F_UNICAST: Accept known unicast packets
 *                  IONIC_RX_MODE_F_MULTICAST: Accept known multicast packets
 *                  IONIC_RX_MODE_F_BROADCAST: Accept broadcast packets
 *                  IONIC_RX_MODE_F_PROMISC: Accept any packets
 *                  IONIC_RX_MODE_F_ALLMULTI: Accept any multicast packets
 *                  IONIC_RX_MODE_F_RDMA_SNIFFER: Sniff RDMA packets
 */
struct ionic_rx_mode_set_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	__le16 rx_mode;
	__le16 rsvd2[29];
};

typedef struct ionic_admin_comp ionic_rx_mode_set_comp;

enum ionic_rx_filter_match_type {
	IONIC_RX_FILTER_MATCH_VLAN	= 0x0,
	IONIC_RX_FILTER_MATCH_MAC	= 0x1,
	IONIC_RX_FILTER_MATCH_MAC_VLAN	= 0x2,
	IONIC_RX_FILTER_STEER_PKTCLASS	= 0x10,
};

/**
 * struct ionic_rx_filter_add_cmd - Add LIF Rx filter command
 * @opcode:     opcode
 * @qtype:      Queue type
 * @lif_index:  LIF index
 * @qid:        Queue ID
 * @match:      Rx filter match type (see IONIC_RX_FILTER_MATCH_xxx)
 * @vlan:       VLAN filter
 *	@vlan.vlan:  VLAN ID
 * @mac:        MAC filter
 *	@mac.addr:  MAC address (network-byte order)
 * @mac_vlan:   MACVLAN filter
 *	@mac_vlan.vlan:  VLAN ID
 *	@mac_vlan.addr:  MAC address (network-byte order)
 * @pkt_class:  Packet classification filter
 */
struct ionic_rx_filter_add_cmd {
	u8     opcode;
	u8     qtype;
	__le16 lif_index;
	__le32 qid;
	__le16 match;
	union {
		struct {
			__le16 vlan;
		} vlan;
		struct {
			u8     addr[6];
		} mac;
		struct {
			__le16 vlan;
			u8     addr[6];
		} mac_vlan;
		__le64 pkt_class;
		u8 rsvd[54];
	} __attribute__((packed));
};

/**
 * struct ionic_rx_filter_add_comp - Add LIF Rx filter command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @filter_id:  Filter ID
 * @color:      Color bit
 */
struct ionic_rx_filter_add_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	__le32 filter_id;
	u8     rsvd2[7];
	u8     color;
};

/**
 * struct ionic_rx_filter_del_cmd - Delete LIF Rx filter command
 * @opcode:     opcode
 * @lif_index:  LIF index
 * @filter_id:  Filter ID
 */
struct ionic_rx_filter_del_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	__le32 filter_id;
	u8     rsvd2[56];
};

typedef struct ionic_admin_comp ionic_rx_filter_del_comp;

enum ionic_vf_attr {
	IONIC_VF_ATTR_SPOOFCHK	= 1,
	IONIC_VF_ATTR_TRUST	= 2,
	IONIC_VF_ATTR_MAC	= 3,
	IONIC_VF_ATTR_LINKSTATE	= 4,
	IONIC_VF_ATTR_VLAN	= 5,
	IONIC_VF_ATTR_RATE	= 6,
	IONIC_VF_ATTR_STATSADDR	= 7,
};

/**
 * enum ionic_vf_link_status - Virtual Function link status
 * @IONIC_VF_LINK_STATUS_AUTO:   Use link state of the uplink
 * @IONIC_VF_LINK_STATUS_UP:     Link always up
 * @IONIC_VF_LINK_STATUS_DOWN:   Link always down
 */
enum ionic_vf_link_status {
	IONIC_VF_LINK_STATUS_AUTO = 0,
	IONIC_VF_LINK_STATUS_UP   = 1,
	IONIC_VF_LINK_STATUS_DOWN = 2,
};

/**
 * struct ionic_vf_setattr_cmd - Set VF attributes on the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_vf_attr)
 * @vf_index:   VF index
 *	@macaddr:	mac address
 *	@vlanid:	vlan ID
 *	@maxrate:	max Tx rate in Mbps
 *	@spoofchk:	enable address spoof checking
 *	@trust:		enable VF trust
 *	@linkstate:	set link up or down
 *	@stats_pa:	set DMA address for VF stats
 */
struct ionic_vf_setattr_cmd {
	u8     opcode;
	u8     attr;
	__le16 vf_index;
	union {
		u8     macaddr[6];
		__le16 vlanid;
		__le32 maxrate;
		u8     spoofchk;
		u8     trust;
		u8     linkstate;
		__le64 stats_pa;
		u8     pad[60];
	} __attribute__((packed));
};

struct ionic_vf_setattr_comp {
	u8     status;
	u8     attr;
	__le16 vf_index;
	__le16 comp_index;
	u8     rsvd[9];
	u8     color;
};

/**
 * struct ionic_vf_getattr_cmd - Get VF attributes from the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_vf_attr)
 * @vf_index:   VF index
 */
struct ionic_vf_getattr_cmd {
	u8     opcode;
	u8     attr;
	__le16 vf_index;
	u8     rsvd[60];
};

struct ionic_vf_getattr_comp {
	u8     status;
	u8     attr;
	__le16 vf_index;
	union {
		u8     macaddr[6];
		__le16 vlanid;
		__le32 maxrate;
		u8     spoofchk;
		u8     trust;
		u8     linkstate;
		__le64 stats_pa;
		u8     pad[11];
	} __attribute__((packed));
	u8     color;
};

enum ionic_vf_ctrl_opcode {
	IONIC_VF_CTRL_START_ALL	= 0,
	IONIC_VF_CTRL_START	= 1,
};

/**
 * struct ionic_vf_ctrl_cmd - VF control command
 * @opcode:         Opcode for the command
 * @ctrl_opcode:    VF control operation type
 * @vf_index:       VF Index. It is unused if op START_ALL is used.
 */

struct ionic_vf_ctrl_cmd {
	u8	opcode;
	u8	ctrl_opcode;
	__le16	vf_index;
	u8	rsvd1[60];
};
IONIC_CHECK_CMD_LENGTH(ionic_vf_ctrl_cmd);

/**
 * struct ionic_vf_ctrl_comp - VF_CTRL command completion.
 * @status:     Status of the command (enum ionic_status_code)
 */
struct ionic_vf_ctrl_comp {
	u8	status;
	u8      rsvd[15];
};
IONIC_CHECK_COMP_LENGTH(ionic_vf_ctrl_comp);

/**
 * struct ionic_discover_cmb_cmd - CMB discovery command
 * @opcode: Opcode for the command
 * @rsvd:   Reserved bytes
 */
struct ionic_discover_cmb_cmd {
	u8	opcode;
	u8	rsvd[63];
};

IONIC_CHECK_CMD_LENGTH(ionic_discover_cmb_cmd);

/**
 * struct ionic_discover_cmb_comp - CMB discover command completion.
 * @status: Status of the command (enum ionic_status_code)
 * @rsvd:   Reserved bytes
 */
struct ionic_discover_cmb_comp {
	u8	status;
	u8	rsvd[15];
};

IONIC_CHECK_COMP_LENGTH(ionic_discover_cmb_comp);

#define IONIC_MAX_CMB_REGIONS	16
#define IONIC_CMB_REGION_64KB_SHIFT	16

enum ionic_cmb_type {
	IONIC_CMB_TYPE_DEVMEM	= 0,
	IONIC_CMB_TYPE_EXPDB64	= 1,
	IONIC_CMB_TYPE_EXPDB128	= 2,
	IONIC_CMB_TYPE_EXPDB256	= 3,
	IONIC_CMB_TYPE_EXPDB512	= 4,
};

/**
 * union ionic_cmb_region - Configuration for CMB region
 * @bar_num:		CMB mapping number from FW
 * @cmb_type:		Type of CMB this region describes (enum ionic_cmb_type)
 * @rsvd:		Reserved
 * @offset:		Offset within BAR in 64KB pages
 * @length:		Length of the CMB region
 * @words:		32-bit words for direct access to the entire region
 */
union ionic_cmb_region {
	struct {
		u8	bar_num;
		u8	cmb_type;
		u8	rsvd[6];
		__le32	offset;
		__le32	length;
	} __packed;
	__le32  words[4];
};

/**
 * union ionic_discover_cmb_identity - CMB layout identity structure
 * @num_regions:	Number of CMB regions, up to 16
 * @flags:		Feature and capability bits (0 for express doorbell, 1 for 4K
 *			alignment indicator, 31-24 for version information
 * @config:		CMB mappings config, entry 0 for regular mapping, entries 1-7
 *			for WQE sizes 64, 128, 256, 512, 1024, 2048 and 4096 bytes
 * @words		Full union buffer size
 */
union ionic_discover_cmb_identity {
	struct {
		__le32 num_regions;
#define IONIC_CMB_FLAG_EXPDB	BIT(0)
#define IONIC_CMB_FLAG_4KALIGN	BIT(1)
#define IONIC_CMB_FLAG_VERSION	0xff000000
		__le32 flags;
		union ionic_cmb_region region[IONIC_MAX_CMB_REGIONS];
	};
	__le32 words[478];
};

/**
 * struct ionic_qos_identify_cmd - QoS identify command
 * @opcode:  opcode
 * @ver:     Highest version of identify supported by driver
 *
 */
struct ionic_qos_identify_cmd {
	u8 opcode;
	u8 ver;
	u8 rsvd[62];
};

/**
 * struct ionic_qos_identify_comp - QoS identify command completion
 * @status: Status of the command (enum ionic_status_code)
 * @ver:    Version of identify returned by device
 */
struct ionic_qos_identify_comp {
	u8 status;
	u8 ver;
	u8 rsvd[14];
};

#define IONIC_QOS_TC_MAX		8
#define IONIC_QOS_ALL_TC		0xFF
/* Capri max supported, should be renamed. */
#define IONIC_QOS_CLASS_MAX		7
#define IONIC_QOS_PCP_MAX		8
#define IONIC_QOS_CLASS_NAME_SZ	32
#define IONIC_QOS_DSCP_MAX		64
#define IONIC_QOS_ALL_PCP		0xFF
#define IONIC_DSCP_BLOCK_SIZE		8

/**
 * enum ionic_qos_class
 */
enum ionic_qos_class {
	IONIC_QOS_CLASS_DEFAULT		= 0,
	IONIC_QOS_CLASS_USER_DEFINED_1	= 1,
	IONIC_QOS_CLASS_USER_DEFINED_2	= 2,
	IONIC_QOS_CLASS_USER_DEFINED_3	= 3,
	IONIC_QOS_CLASS_USER_DEFINED_4	= 4,
	IONIC_QOS_CLASS_USER_DEFINED_5	= 5,
	IONIC_QOS_CLASS_USER_DEFINED_6	= 6,
};

/**
 * enum ionic_qos_class_type - Traffic classification criteria
 * @IONIC_QOS_CLASS_TYPE_NONE:    No QoS
 * @IONIC_QOS_CLASS_TYPE_PCP:     Dot1Q PCP
 * @IONIC_QOS_CLASS_TYPE_DSCP:    IP DSCP
 */
enum ionic_qos_class_type {
	IONIC_QOS_CLASS_TYPE_NONE	= 0,
	IONIC_QOS_CLASS_TYPE_PCP	= 1,
	IONIC_QOS_CLASS_TYPE_DSCP	= 2,
};

/**
 * enum ionic_qos_sched_type - QoS class scheduling type
 * @IONIC_QOS_SCHED_TYPE_STRICT:  Strict priority
 * @IONIC_QOS_SCHED_TYPE_DWRR:    Deficit weighted round-robin
 */
enum ionic_qos_sched_type {
	IONIC_QOS_SCHED_TYPE_STRICT	= 0,
	IONIC_QOS_SCHED_TYPE_DWRR	= 1,
};

/**
 * union ionic_qos_config - QoS configuration structure
 * @flags:		Configuration flags
 *	IONIC_QOS_CONFIG_F_ENABLE		enable
 *	IONIC_QOS_CONFIG_F_NO_DROP		drop/nodrop
 *	IONIC_QOS_CONFIG_F_RW_DOT1Q_PCP		enable dot1q pcp rewrite
 *	IONIC_QOS_CONFIG_F_RW_IP_DSCP		enable ip dscp rewrite
 *	IONIC_QOS_CONFIG_F_NON_DISRUPTIVE	Non-disruptive TC update
 * @sched_type:		QoS class scheduling type (enum ionic_qos_sched_type)
 * @class_type:		QoS class type (enum ionic_qos_class_type)
 * @pause_type:		QoS pause type (enum ionic_qos_pause_type)
 * @name:		QoS class name
 * @mtu:		MTU of the class
 * @pfc_cos:		Priority-Flow Control class of service
 * @dwrr_weight:	QoS class scheduling weight
 * @strict_rlmt:	Rate limit for strict priority scheduling
 * @rw_dot1q_pcp:	Rewrite dot1q pcp to value (valid iff F_RW_DOT1Q_PCP)
 * @rw_ip_dscp:		Rewrite ip dscp to value (valid iff F_RW_IP_DSCP)
 * @dot1q_pcp:		Dot1q pcp value
 * @ndscp:		Number of valid dscp values in the ip_dscp field
 * @ip_dscp:		IP dscp values
 */
union ionic_qos_config {
	struct {
#define IONIC_QOS_CONFIG_F_ENABLE		BIT(0)
#define IONIC_QOS_CONFIG_F_NO_DROP		BIT(1)
/* Used to rewrite PCP or DSCP value. */
#define IONIC_QOS_CONFIG_F_RW_DOT1Q_PCP		BIT(2)
#define IONIC_QOS_CONFIG_F_RW_IP_DSCP		BIT(3)
/* Non-disruptive TC update */
#define IONIC_QOS_CONFIG_F_NON_DISRUPTIVE	BIT(4)
		u8      flags;
		u8      sched_type;
		u8      class_type;
		u8      pause_type;
		char    name[IONIC_QOS_CLASS_NAME_SZ];
		__le32  mtu;
		/* flow control */
		u8      pfc_cos;
		/* scheduler */
		union {
			u8      dwrr_weight;
			__le64  strict_rlmt;
		};
		/* marking */
		/* Used to rewrite PCP or DSCP value. */
		union {
			u8      rw_dot1q_pcp;
			u8      rw_ip_dscp;
		};
		/* classification */
		union {
			u8      dot1q_pcp;
			struct {
				u8      ndscp;
				u8      ip_dscp[IONIC_QOS_DSCP_MAX];
			};
		};
	} __attribute__((packed));
	__le32  words[64];
};

/**
 * union ionic_qos_identity - QoS identity structure
 * @version:	Version of the identify structure
 * @type:	QoS system type
 * @config:	Current configuration of classes
 */
union ionic_qos_identity {
	struct {
		u8     version;
		u8     type;
		u8     rsvd[62];
		union ionic_qos_config config[IONIC_QOS_CLASS_MAX];
	};
	__le32 words[478];
};

/**
 * struct ionic_qos_init_cmd - QoS config init command
 * @opcode:	Opcode
 * @group:	QoS class id
 * @info_pa:	destination address for qos info
 */
struct ionic_qos_init_cmd {
	u8     opcode;
	u8     group;
	u8     rsvd[6];
	__le64 info_pa;
	u8     rsvd1[48];
};

typedef struct ionic_admin_comp ionic_qos_init_comp;

/**
 * struct ionic_qos_reset_cmd - QoS config reset command
 * @opcode:	Opcode
 * @group:	QoS class id
 */
struct ionic_qos_reset_cmd {
	u8    opcode;
	u8    group;
	u8    rsvd[62];
};

/**
 * struct ionic_qos_clear_stats_cmd - Qos config reset command
 * @opcode:	Opcode
 */
struct ionic_qos_clear_stats_cmd {
	u8    opcode;
	u8    group_bitmap;
	u8    rsvd[62];
};

typedef struct ionic_admin_comp ionic_qos_reset_comp;

/**
 * struct ionic_fw_download_cmd - Firmware download command
 * @opcode:	opcode
 * @addr:	dma address of the firmware buffer
 * @offset:	offset of the firmware buffer within the full image
 * @length:	number of valid bytes in the firmware buffer
 */
struct ionic_fw_download_cmd {
	u8     opcode;
	u8     rsvd[3];
	__le32 offset;
	__le64 addr;
	__le32 length;
};

typedef struct ionic_admin_comp ionic_fw_download_comp;

/**
 * enum ionic_fw_control_oper - FW control operations
 * @IONIC_FW_RESET:		Reset firmware
 * @IONIC_FW_INSTALL:		Install firmware
 * @IONIC_FW_ACTIVATE:		Activate firmware
 * @IONIC_FW_INSTALL_ASYNC:	Install firmware asynchronously
 * @IONIC_FW_INSTALL_STATUS:	Firmware installation status
 * @IONIC_FW_ACTIVATE_ASYNC:	Activate firmware asynchronously
 * @IONIC_FW_ACTIVATE_STATUS:	Firmware activate status
 */
enum ionic_fw_control_oper {
	IONIC_FW_RESET			= 0,
	IONIC_FW_INSTALL		= 1,
	IONIC_FW_ACTIVATE		= 2,
	IONIC_FW_INSTALL_ASYNC		= 3,
	IONIC_FW_INSTALL_STATUS		= 4,
	IONIC_FW_ACTIVATE_ASYNC		= 5,
	IONIC_FW_ACTIVATE_STATUS	= 6,
	IONIC_FW_UPDATE_CLEANUP		= 7,
	IONIC_FW_GET_BOOT           = 8,
};

enum ionic_fw_slot {
	IONIC_FW_SLOT_INVALID   = 0,
	IONIC_FW_SLOT_A         = 1,
	IONIC_FW_SLOT_B         = 2,
	IONIC_FW_SLOT_GOLD      = 3,
};

/**
 * struct ionic_fw_control_cmd - Firmware control command
 * @opcode:    opcode
 * @oper:      firmware control operation (enum ionic_fw_control_oper)
 * @slot:      slot to activate
 */
struct ionic_fw_control_cmd {
	u8  opcode;
	u8  rsvd[3];
	u8  oper;
	u8  slot;
	u8  rsvd1[58];
};

/**
 * struct ionic_fw_control_comp - Firmware control copletion
 * @status:     Status of the command (enum ionic_status_code)
 * @comp_index: Index in the descriptor ring for which this is the completion
 * @slot:       Slot where the firmware was installed
 * @color:      Color bit
 */
struct ionic_fw_control_comp {
	u8     status;
	u8     rsvd;
	__le16 comp_index;
	u8     slot;
	u8     rsvd1[10];
	u8     color;
};

/******************************************************************
 ******************* RDMA Commands ********************************
 ******************************************************************/

/**
 * struct ionic_rdma_reset_cmd - Reset RDMA LIF cmd
 * @opcode:        opcode
 * @lif_index:     LIF index
 *
 * There is no RDMA specific dev command completion struct.  Completion uses
 * the common struct ionic_admin_comp.  Only the status is indicated.
 * Nonzero status means the LIF does not support RDMA.
 **/
struct ionic_rdma_reset_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	u8     rsvd2[60];
};

/**
 * struct ionic_rdma_queue_cmd - Create RDMA Queue command
 * @opcode:        opcode, 52, 53
 * @lif_index:     LIF index
 * @qid_ver:       (qid | (RDMA version << 24))
 * @cid:           intr, eq_id, or cq_id
 * @dbid:          doorbell page id
 * @depth_log2:    log base two of queue depth
 * @stride_log2:   log base two of queue stride
 * @dma_addr:      address of the queue memory
 *
 * The same command struct is used to create an RDMA event queue, completion
 * queue, or RDMA admin queue.  The cid is an interrupt number for an event
 * queue, an event queue id for a completion queue, or a completion queue id
 * for an RDMA admin queue.
 *
 * The queue created via a dev command must be contiguous in dma space.
 *
 * The dev commands are intended only to be used during driver initialization,
 * to create queues supporting the RDMA admin queue.  Other queues, and other
 * types of RDMA resources like memory regions, will be created and registered
 * via the RDMA admin queue, and will support a more complete interface
 * providing scatter gather lists for larger, scattered queue buffers and
 * memory registration.
 *
 * There is no RDMA specific dev command completion struct.  Completion uses
 * the common struct ionic_admin_comp.  Only the status is indicated.
 **/
struct ionic_rdma_queue_cmd {
	u8     opcode;
	u8     rsvd;
	__le16 lif_index;
	__le32 qid_ver;
	__le32 cid;
	__le16 dbid;
	u8     depth_log2;
	u8     stride_log2;
	__le64 dma_addr;
	u8     rsvd2[40];
};

/******************************************************************
 ******************* HII Commands *********************************
 ******************************************************************/
#define IONIC_HII_IDENTITY_VERSION	1

/**
 * struct ionic_hii_identify_cmd - HII identify command
 * @opcode:  opcode
 * @ver:     Highest version of identify supported by driver
 */
struct ionic_hii_identify_cmd {
	u8 opcode;
	u8 ver;
	u8 rsvd[62];
};

IONIC_CHECK_CMD_LENGTH(ionic_hii_identify_cmd);

/**
 * struct ionic_hii_identify_comp - HII identify command completion
 * @status: Status of the command (enum ionic_status_code)
 * @ver:    Version of identify returned by device
 */
struct ionic_hii_identify_comp {
	u8 status;
	u8 ver;
	u8 rsvd[14];
};

IONIC_CHECK_COMP_LENGTH(ionic_hii_identify_comp);

/**
 * enum ionic_hii_capabilities - Bitmap of HII capabilities
 * @IONIC_HII_CAPABILITY_NCSI:   NCSI is supported
 */
enum ionic_hii_capabilities {
	IONIC_HII_CAPABILITY_NCSI = 0,
	IONIC_HII_CAPABILITY_OOB  = 1,
};

/**
 * union ionic_hii_dev_identity - HII identity information
 * @ver:		HII Identify version
 * @oob_en:		Enable out of band management
 * @uid_led_on:		Turn on the UID led
 * @vlan_en:		Enable pxe vlan
 * @vlan:		Vlan id used for pxe
 * @capabilities:	Bitmap of capabilities supported by nic
 */
union ionic_hii_dev_identity {
	struct {
		u8	ver;
		u8	oob_en;
		u8	uid_led_on;
		u8	vlan_en;
		__le16	vlan;
		__le32	capabilities;
	};
	__le32 words[478];
};

IONIC_CHECK_CMD_DATA_LENGTH(ionic_hii_dev_identity);

/**
 * struct ionic_hii_init_cmd - HII initialization command
 * @opcode:		opcode
 * @oob_en:		Enable out of band management
 * @uid_led_on:		Turn on the UID led
 * @vlan_en:		Enable pxe vlan
 * @vlan:		Vlan id used for pxe
 */
struct ionic_hii_init_cmd {
	u8     opcode;
	u8     oob_en;
	u8     uid_led_on;
	u8     vlan_en;
	__le16 vlan;
	u8     rsvd[58];
};

IONIC_CHECK_CMD_LENGTH(ionic_hii_init_cmd);

/**
 * struct ionic_hii_init_comp - HII initialization command completion
 * @status:	Status of the command (enum ionic_status_code)
 */
struct ionic_hii_init_comp {
	u8 status;
	u8 rsvd[15];
};

IONIC_CHECK_COMP_LENGTH(ionic_hii_init_comp);

/**
 * enum ionic_hii_attr - List of HII attributes
 * @IONIC_HII_ATTR_OOB_EN:      HII OOB enable attribute
 * @IONIC_HII_ATTR_UID_LED:	HII set UID led attribute
 * @IONIC_HII_ATTR_VLAN:        HII PXE vlan attribute
 */
enum ionic_hii_attr {
	IONIC_HII_ATTR_OOB_EN	= 0,
	IONIC_HII_ATTR_UID_LED	= 1,
	IONIC_HII_ATTR_VLAN	= 2,
};

/**
 * struct ionic_hii_setattr_cmd - Set hii attributes on the NIC
 * @opcode:         Opcode
 * @attr:           Atrribute type (enum ionic_hii_attr)
 * @oob_en:         Enable out of band management
 * @uid_led_on:    Turn on the UID led
 * @vlan:           VLAN attributes
 *        @vlan.enable:    Enable pxe vlan
 *        @vlan.id:        Pxe vlan id
 */
struct ionic_hii_setattr_cmd {
	u8     opcode;
	u8     attr;
	union {
		u8     oob_en;
		u8     uid_led_on;
		struct {
			u8     enable;
			u8     rsvd;
			__le16 id;
		} vlan;
		u8      rsvd2[62];
	};
};

IONIC_CHECK_CMD_LENGTH(ionic_hii_setattr_cmd);

/**
 * struct ionic_hii_setattr_comp - Hii set attr command completion
 * @status:     Status of the command (enum ionic_status_code)
 * @color:      Color bit
 */
struct ionic_hii_setattr_comp {
	u8     status;
	u8     rsvd[14];
	u8     color;
};

IONIC_CHECK_COMP_LENGTH(ionic_hii_setattr_comp);

/**
 * struct ionic_hii_getattr_cmd - Get hii attributes from the NIC
 * @opcode:     Opcode
 * @attr:       Attribute type (enum ionic_hii_attr)
 */
struct ionic_hii_getattr_cmd {
	u8     opcode;
	u8     attr;
	u8     rsvd[62];
};

IONIC_CHECK_CMD_LENGTH(ionic_hii_getattr_cmd);

/**
 * struct ionic_hii_getattr_comp - Hii get attr command completion
 * @status:         Status of the command (enum ionic_status_code)
 * @oob_en:         Enable out of band management
 * @uid_led_on:     Turn on the UID led
 * @vlan:           VLAN attributes:
 *	@vlan.enable:    Enable pxe vlan
 *	@vlan.id:        Pxe vlan id
 * @color:          Color bit
 */
struct ionic_hii_getattr_comp {
	u8     status;
	u8     rsvd[3];
	union {
		u8     oob_en;
		u8     uid_led_on;
		struct {
			u8     enable;
			u8     rsvd2;
			__le16 id;
		} vlan;
		u8      rsvd3[11];
	} __attribute__((packed));
	u8     color;
};

#ifndef __CHECKER__
IONIC_CHECK_COMP_LENGTH(ionic_hii_getattr_comp);
#endif

/**
 * struct ionic_hii_reset_cmd - HII configuration reset command
 * @opcode:    opcode
 */
struct ionic_hii_reset_cmd {
	u8 opcode;
	u8 rsvd[63];
};

IONIC_CHECK_CMD_LENGTH(ionic_hii_reset_cmd);

/**
 * struct ionic_hii_reset_comp - HII reset command completion
 * @status: Status of the command (enum ionic_status_code)
 */
struct ionic_hii_reset_comp {
	u8 status;
	u8 rsvd[15];
};

IONIC_CHECK_COMP_LENGTH(ionic_hii_reset_comp);

/******************************************************************
 ******************* Notify Events ********************************
 ******************************************************************/

/**
 * struct ionic_notifyq_event - Generic event reporting structure
 * @eid:   event number
 * @ecode: event code
 * @data:  unspecified data about the event
 *
 * This is the generic event report struct from which the other
 * actual events will be formed.
 */
struct ionic_notifyq_event {
	__le64 eid;
	__le16 ecode;
	u8     data[54];
};

/**
 * struct ionic_link_change_event - Link change event notification
 * @eid:		event number
 * @ecode:		event code = IONIC_EVENT_LINK_CHANGE
 * @link_status:	link up/down, with error bits (enum ionic_port_status)
 * @link_speed:		speed of the network link
 *
 * Sent when the network link state changes between UP and DOWN
 */
struct ionic_link_change_event {
	__le64 eid;
	__le16 ecode;
	__le16 link_status;
	__le32 link_speed;	/* units of 1Mbps: e.g. 10000 = 10Gbps */
	u8     rsvd[48];
};

/**
 * struct ionic_reset_event - Reset event notification
 * @eid:		event number
 * @ecode:		event code = IONIC_EVENT_RESET
 * @reset_code:		reset type
 * @state:		0=pending, 1=complete, 2=error
 *
 * Sent when the NIC or some subsystem is going to be or
 * has been reset.
 */
struct ionic_reset_event {
	__le64 eid;
	__le16 ecode;
	u8     reset_code;
	u8     state;
	u8     rsvd[52];
};

/**
 * struct ionic_heartbeat_event - Sent periodically by NIC to indicate health
 * @eid:	event number
 * @ecode:	event code = IONIC_EVENT_HEARTBEAT
 */
struct ionic_heartbeat_event {
	__le64 eid;
	__le16 ecode;
	u8     rsvd[54];
};

/**
 * struct ionic_log_event - Sent to notify the driver of an internal error
 * @eid:	event number
 * @ecode:	event code = IONIC_EVENT_LOG
 * @data:	log data
 */
struct ionic_log_event {
	__le64 eid;
	__le16 ecode;
	u8     data[54];
};

/**
 * struct ionic_xcvr_event - Transceiver change event
 * @eid:	event number
 * @ecode:	event code = IONIC_EVENT_XCVR
 */
struct ionic_xcvr_event {
	__le64 eid;
	__le16 ecode;
	u8     rsvd[54];
};

/**
 * struct ionic_port_stats - Port statistics structure
 */
struct ionic_port_stats {
	__le64 frames_rx_ok;
	__le64 frames_rx_all;
	__le64 frames_rx_bad_fcs;
	__le64 frames_rx_bad_all;
	__le64 octets_rx_ok;
	__le64 octets_rx_all;
	__le64 frames_rx_unicast;
	__le64 frames_rx_multicast;
	__le64 frames_rx_broadcast;
	__le64 frames_rx_pause;
	__le64 frames_rx_bad_length;
	__le64 frames_rx_undersized;
	__le64 frames_rx_oversized;
	__le64 frames_rx_fragments;
	__le64 frames_rx_jabber;
	__le64 frames_rx_pripause;
	__le64 frames_rx_stomped_crc;
	__le64 frames_rx_too_long;
	__le64 frames_rx_vlan_good;
	__le64 frames_rx_dropped;
	__le64 frames_rx_less_than_64b;
	__le64 frames_rx_64b;
	__le64 frames_rx_65b_127b;
	__le64 frames_rx_128b_255b;
	__le64 frames_rx_256b_511b;
	__le64 frames_rx_512b_1023b;
	__le64 frames_rx_1024b_1518b;
	__le64 frames_rx_1519b_2047b;
	__le64 frames_rx_2048b_4095b;
	__le64 frames_rx_4096b_8191b;
	__le64 frames_rx_8192b_9215b;
	__le64 frames_rx_other;
	__le64 frames_tx_ok;
	__le64 frames_tx_all;
	__le64 frames_tx_bad;
	__le64 octets_tx_ok;
	__le64 octets_tx_total;
	__le64 frames_tx_unicast;
	__le64 frames_tx_multicast;
	__le64 frames_tx_broadcast;
	__le64 frames_tx_pause;
	__le64 frames_tx_pripause;
	__le64 frames_tx_vlan;
	__le64 frames_tx_less_than_64b;
	__le64 frames_tx_64b;
	__le64 frames_tx_65b_127b;
	__le64 frames_tx_128b_255b;
	__le64 frames_tx_256b_511b;
	__le64 frames_tx_512b_1023b;
	__le64 frames_tx_1024b_1518b;
	__le64 frames_tx_1519b_2047b;
	__le64 frames_tx_2048b_4095b;
	__le64 frames_tx_4096b_8191b;
	__le64 frames_tx_8192b_9215b;
	__le64 frames_tx_other;
	__le64 frames_tx_pri_0;
	__le64 frames_tx_pri_1;
	__le64 frames_tx_pri_2;
	__le64 frames_tx_pri_3;
	__le64 frames_tx_pri_4;
	__le64 frames_tx_pri_5;
	__le64 frames_tx_pri_6;
	__le64 frames_tx_pri_7;
	__le64 frames_rx_pri_0;
	__le64 frames_rx_pri_1;
	__le64 frames_rx_pri_2;
	__le64 frames_rx_pri_3;
	__le64 frames_rx_pri_4;
	__le64 frames_rx_pri_5;
	__le64 frames_rx_pri_6;
	__le64 frames_rx_pri_7;
	__le64 tx_pripause_0_1us_count;
	__le64 tx_pripause_1_1us_count;
	__le64 tx_pripause_2_1us_count;
	__le64 tx_pripause_3_1us_count;
	__le64 tx_pripause_4_1us_count;
	__le64 tx_pripause_5_1us_count;
	__le64 tx_pripause_6_1us_count;
	__le64 tx_pripause_7_1us_count;
	__le64 rx_pripause_0_1us_count;
	__le64 rx_pripause_1_1us_count;
	__le64 rx_pripause_2_1us_count;
	__le64 rx_pripause_3_1us_count;
	__le64 rx_pripause_4_1us_count;
	__le64 rx_pripause_5_1us_count;
	__le64 rx_pripause_6_1us_count;
	__le64 rx_pripause_7_1us_count;
	__le64 rx_pause_1us_count;
	__le64 frames_tx_truncated;
};

struct ionic_mgmt_port_stats {
	__le64 frames_rx_ok;
	__le64 frames_rx_all;
	__le64 frames_rx_bad_fcs;
	__le64 frames_rx_bad_all;
	__le64 octets_rx_ok;
	__le64 octets_rx_all;
	__le64 frames_rx_unicast;
	__le64 frames_rx_multicast;
	__le64 frames_rx_broadcast;
	__le64 frames_rx_pause;
	__le64 frames_rx_bad_length;
	__le64 frames_rx_undersized;
	__le64 frames_rx_oversized;
	__le64 frames_rx_fragments;
	__le64 frames_rx_jabber;
	__le64 frames_rx_64b;
	__le64 frames_rx_65b_127b;
	__le64 frames_rx_128b_255b;
	__le64 frames_rx_256b_511b;
	__le64 frames_rx_512b_1023b;
	__le64 frames_rx_1024b_1518b;
	__le64 frames_rx_gt_1518b;
	__le64 frames_rx_fifo_full;
	__le64 frames_tx_ok;
	__le64 frames_tx_all;
	__le64 frames_tx_bad;
	__le64 octets_tx_ok;
	__le64 octets_tx_total;
	__le64 frames_tx_unicast;
	__le64 frames_tx_multicast;
	__le64 frames_tx_broadcast;
	__le64 frames_tx_pause;
};

enum ionic_pb_buffer_drop_stats {
	IONIC_BUFFER_INTRINSIC_DROP = 0,
	IONIC_BUFFER_DISCARDED,
	IONIC_BUFFER_ADMITTED,
	IONIC_BUFFER_OUT_OF_CELLS_DROP,
	IONIC_BUFFER_OUT_OF_CELLS_DROP_2,
	IONIC_BUFFER_OUT_OF_CREDIT_DROP,
	IONIC_BUFFER_TRUNCATION_DROP,
	IONIC_BUFFER_PORT_DISABLED_DROP,
	IONIC_BUFFER_COPY_TO_CPU_TAIL_DROP,
	IONIC_BUFFER_SPAN_TAIL_DROP,
	IONIC_BUFFER_MIN_SIZE_VIOLATION_DROP,
	IONIC_BUFFER_ENQUEUE_ERROR_DROP,
	IONIC_BUFFER_INVALID_PORT_DROP,
	IONIC_BUFFER_INVALID_OUTPUT_QUEUE_DROP,
	IONIC_BUFFER_DROP_MAX,
};

enum ionic_oflow_drop_stats {
	IONIC_OFLOW_OCCUPANCY_DROP,
	IONIC_OFLOW_EMERGENCY_STOP_DROP,
	IONIC_OFLOW_WRITE_BUFFER_ACK_FILL_UP_DROP,
	IONIC_OFLOW_WRITE_BUFFER_ACK_FULL_DROP,
	IONIC_OFLOW_WRITE_BUFFER_FULL_DROP,
	IONIC_OFLOW_CONTROL_FIFO_FULL_DROP,
	IONIC_OFLOW_DROP_MAX,
};

/**
 * struct ionic_port_pb_stats - packet buffers system stats
 * uses ionic_pb_buffer_drop_stats for drop_counts[]
 */
struct ionic_port_pb_stats {
	__le64 sop_count_in;
	__le64 eop_count_in;
	__le64 sop_count_out;
	__le64 eop_count_out;
	__le64 drop_counts[IONIC_BUFFER_DROP_MAX];
	__le64 input_queue_buffer_occupancy[IONIC_QOS_TC_MAX];
	__le64 input_queue_port_monitor[IONIC_QOS_TC_MAX];
	__le64 output_queue_port_monitor[IONIC_QOS_TC_MAX];
	__le64 oflow_drop_counts[IONIC_OFLOW_DROP_MAX];
	__le64 input_queue_good_pkts_in[IONIC_QOS_TC_MAX];
	__le64 input_queue_good_pkts_out[IONIC_QOS_TC_MAX];
	__le64 input_queue_err_pkts_in[IONIC_QOS_TC_MAX];
	__le64 input_queue_fifo_depth[IONIC_QOS_TC_MAX];
	__le64 input_queue_max_fifo_depth[IONIC_QOS_TC_MAX];
	__le64 input_queue_peak_occupancy[IONIC_QOS_TC_MAX];
	__le64 output_queue_buffer_occupancy[IONIC_QOS_TC_MAX];
};

/**
 * enum ionic_port_type - Port types
 * @IONIC_ETH_UNKNOWN:             Port type not configured
 * @IONIC_ETH_HOST:                Port carries ethernet traffic (inband)
 * @IONIC_ETH_HOST_MGMT:           Port carries mgmt traffic (out-of-band)
 * @IONIC_ETH_MNIC_OOB_MGMT:
 * @IONIC_ETH_MNIC_INTERNAL_MGMT:
 * @IONIC_ETH_MNIC_INBAND_MGMT:
 * @IONIC_ETH_MNIC_CPU:
 * @IONIC_ETH_MNIC_LEARN:
 * @IONIC_ETH_MNIC_CONTROL:
 */
enum ionic_port_type {
	IONIC_ETH_UNKNOWN,
	IONIC_ETH_HOST,
	IONIC_ETH_HOST_MGMT,
	IONIC_ETH_MNIC_OOB_MGMT,
	IONIC_ETH_MNIC_INTERNAL_MGMT,
	IONIC_ETH_MNIC_INBAND_MGMT,
	IONIC_ETH_MNIC_CPU,
	IONIC_ETH_MNIC_LEARN,
	IONIC_ETH_MNIC_CONTROL,
};

/**
 * struct ionic_port_identity - port identity structure
 * @version:        identity structure version
 * @type:           type of port (enum ionic_port_type)
 * @num_lanes:      number of lanes for the port
 * @autoneg:        autoneg supported
 * @min_frame_size: minimum frame size supported
 * @max_frame_size: maximum frame size supported
 * @fec_type:       supported fec types
 * @pause_type:     supported pause types
 * @loopback_mode:  supported loopback mode
 * @speeds:         supported speeds
 * @config:         current port configuration
 */
union ionic_port_identity {
	struct {
		u8     version;
		u8     type;
		u8     num_lanes;
		u8     autoneg;
		__le32 min_frame_size;
		__le32 max_frame_size;
		u8     fec_type[4];
		u8     pause_type[2];
		u8     loopback_mode[2];
		__le32 speeds[16];
		u8     rsvd2[44];
		union ionic_port_config config;
	};
	__le32 words[478];
};

/**
 * struct ionic_port_info - port info structure
 * @config:          Port configuration data
 * @status:          Port status data
 * @stats:           Port statistics data
 * @mgmt_stats:      Port management statistics data
 * @sprom_epage:     Extended Transceiver sprom
 * @sprom_page1:     Extended Transceiver sprom, page 1
 * @sprom_page2:     Extended Transceiver sprom, page 2
 * @sprom_page3:     Extended Transceiver sprom, page 0x11 channel info
 * @pb_stats:        uplink pb drop stats
 */
struct ionic_port_info {
	union ionic_port_config config;
	struct ionic_port_status status;
	union {
		struct ionic_port_stats      stats;
		struct ionic_mgmt_port_stats mgmt_stats;
	};
	union {
		u8     sprom_epage[384];
		struct {
			u8 sprom_page1[128];
			u8 sprom_page2[128];
			u8 sprom_page17[128];
		};
	};
	u8     rsvd[376];

	/* pb_stats must start at 2k offset */
	struct ionic_port_pb_stats  pb_stats;
};

/**
 * struct ionic_lif_stats - LIF statistics structure
 */
struct ionic_lif_stats {
	/* RX */
	__le64 rx_ucast_bytes;
	__le64 rx_ucast_packets;
	__le64 rx_mcast_bytes;
	__le64 rx_mcast_packets;
	__le64 rx_bcast_bytes;
	__le64 rx_bcast_packets;
	__le64 rsvd0;
	__le64 rsvd1;
	/* RX drops */
	__le64 rx_ucast_drop_bytes;
	__le64 rx_ucast_drop_packets;
	__le64 rx_mcast_drop_bytes;
	__le64 rx_mcast_drop_packets;
	__le64 rx_bcast_drop_bytes;
	__le64 rx_bcast_drop_packets;
	__le64 rx_dma_error;
	__le64 rsvd2;
	/* TX */
	__le64 tx_ucast_bytes;
	__le64 tx_ucast_packets;
	__le64 tx_mcast_bytes;
	__le64 tx_mcast_packets;
	__le64 tx_bcast_bytes;
	__le64 tx_bcast_packets;
	__le64 rsvd3;
	__le64 rsvd4;
	/* TX drops */
	__le64 tx_ucast_drop_bytes;
	__le64 tx_ucast_drop_packets;
	__le64 tx_mcast_drop_bytes;
	__le64 tx_mcast_drop_packets;
	__le64 tx_bcast_drop_bytes;
	__le64 tx_bcast_drop_packets;
	__le64 tx_dma_error;
	__le64 rsvd5;
	/* Rx Queue/Ring drops */
	__le64 rx_queue_disabled;
	__le64 rx_queue_empty;
	__le64 rx_queue_error;
	__le64 rx_desc_fetch_error;
	__le64 rx_desc_data_error;
	__le64 rsvd6;
	__le64 rsvd7;
	__le64 rsvd8;
	/* Tx Queue/Ring drops */
	__le64 tx_queue_disabled;
	__le64 tx_queue_error;
	__le64 tx_desc_fetch_error;
	__le64 tx_desc_data_error;
	__le64 tx_queue_empty;
	__le64 rsvd10;
	__le64 rsvd11;
	__le64 rsvd12;

	/* RDMA/ROCE TX */
	__le64 tx_rdma_ucast_bytes;
	__le64 tx_rdma_ucast_packets;
	__le64 tx_rdma_mcast_bytes;
	__le64 tx_rdma_mcast_packets;
	__le64 tx_rdma_cnp_packets;
	__le64 rsvd13;
	__le64 rsvd14;
	__le64 rsvd15;

	/* RDMA/ROCE RX */
	__le64 rx_rdma_ucast_bytes;
	__le64 rx_rdma_ucast_packets;
	__le64 rx_rdma_mcast_bytes;
	__le64 rx_rdma_mcast_packets;
	__le64 rx_rdma_cnp_packets;
	__le64 rx_rdma_ecn_packets;
	__le64 rsvd16;
	__le64 rsvd17;

	__le64 rsvd18;
	__le64 rsvd19;
	__le64 rsvd20;
	__le64 rsvd21;
	__le64 rsvd22;
	__le64 rsvd23;
	__le64 rsvd24;
	__le64 rsvd25;

	__le64 rsvd26;
	__le64 rsvd27;
	__le64 rsvd28;
	__le64 rsvd29;
	__le64 rsvd30;
	__le64 rsvd31;
	__le64 rsvd32;
	__le64 rsvd33;

	__le64 rsvd34;
	__le64 rsvd35;
	__le64 rsvd36;
	__le64 rsvd37;
	__le64 rsvd38;
	__le64 rsvd39;
	__le64 rsvd40;
	__le64 rsvd41;

	__le64 rsvd42;
	__le64 rsvd43;
	__le64 rsvd44;
	__le64 rsvd45;
	__le64 rsvd46;
	__le64 rsvd47;
	__le64 rsvd48;
	__le64 rsvd49;

	/* RDMA/ROCE REQ Error/Debugs (768 - 895) */
	__le64 rdma_req_rx_pkt_seq_err;
	__le64 rdma_req_rx_rnr_retry_err;
	__le64 rdma_req_rx_remote_access_err;
	__le64 rdma_req_rx_remote_inv_req_err;
	__le64 rdma_req_rx_remote_oper_err;
	__le64 rdma_req_rx_implied_nak_seq_err;
	__le64 rdma_req_rx_cqe_err;
	__le64 rdma_req_rx_cqe_flush_err;

	__le64 rdma_req_rx_dup_responses;
	__le64 rdma_req_rx_invalid_packets;
	__le64 rdma_req_tx_local_access_err;
	__le64 rdma_req_tx_local_oper_err;
	__le64 rdma_req_tx_memory_mgmt_err;
	__le64 rsvd52;
	__le64 rsvd53;
	__le64 rsvd54;

	/* RDMA/ROCE RESP Error/Debugs (896 - 1023) */
	__le64 rdma_resp_rx_dup_requests;
	__le64 rdma_resp_rx_out_of_buffer;
	__le64 rdma_resp_rx_out_of_seq_pkts;
	__le64 rdma_resp_rx_cqe_err;
	__le64 rdma_resp_rx_cqe_flush_err;
	__le64 rdma_resp_rx_local_len_err;
	__le64 rdma_resp_rx_inv_request_err;
	__le64 rdma_resp_rx_local_qp_oper_err;

	__le64 rdma_resp_rx_out_of_atomic_resource;
	__le64 rdma_resp_tx_pkt_seq_err;
	__le64 rdma_resp_tx_remote_inv_req_err;
	__le64 rdma_resp_tx_remote_access_err;
	__le64 rdma_resp_tx_remote_oper_err;
	__le64 rdma_resp_tx_rnr_retry_err;
	__le64 rsvd57;
	__le64 rsvd58;
};

/**
 * struct ionic_lif_info - LIF info structure
 * @config:	LIF configuration structure
 * @status:	LIF status structure
 * @stats:	LIF statistics structure
 */
struct ionic_lif_info {
	union ionic_lif_config config;
	struct ionic_lif_status status;
	struct ionic_lif_stats stats;
};

union ionic_dev_cmd {
	u32 words[16];
	struct ionic_admin_cmd cmd;
	struct ionic_nop_cmd nop;

	struct ionic_dev_identify_cmd identify;
	struct ionic_dev_init_cmd init;
	struct ionic_dev_reset_cmd reset;
	struct ionic_dev_getattr_cmd getattr;
	struct ionic_dev_setattr_cmd setattr;
	struct ionic_dev_debug_cmd debug;

	struct ionic_port_identify_cmd port_identify;
	struct ionic_port_init_cmd port_init;
	struct ionic_port_reset_cmd port_reset;
	struct ionic_port_getattr_cmd port_getattr;
	struct ionic_port_setattr_cmd port_setattr;

	struct ionic_vf_setattr_cmd vf_setattr;
	struct ionic_vf_getattr_cmd vf_getattr;
	struct ionic_vf_ctrl_cmd vf_ctrl;

	struct ionic_discover_cmb_cmd discover_cmb;

	struct ionic_lif_identify_cmd lif_identify;
	struct ionic_lif_init_cmd lif_init;
	struct ionic_lif_reset_cmd lif_reset;

	struct ionic_qos_identify_cmd qos_identify;
	struct ionic_qos_init_cmd qos_init;
	struct ionic_qos_reset_cmd qos_reset;
	struct ionic_qos_clear_stats_cmd qos_clear_stats;

	struct ionic_q_identify_cmd q_identify;
	struct ionic_q_init_cmd q_init;
	struct ionic_q_control_cmd q_control;

	struct ionic_fw_download_cmd fw_download;
	struct ionic_fw_control_cmd fw_control;

	struct ionic_hii_identify_cmd hii_identify;
	struct ionic_hii_init_cmd hii_init;
	struct ionic_hii_setattr_cmd hii_setattr;
	struct ionic_hii_getattr_cmd hii_getattr;
	struct ionic_hii_reset_cmd hii_reset;

	struct ionic_upt_cmd upt_cmd;
};

union ionic_dev_cmd_comp {
	u32 words[4];
	u8 status;
	struct ionic_admin_comp comp;
	struct ionic_nop_comp nop;

	struct ionic_dev_identify_comp identify;
	struct ionic_dev_init_comp init;
	struct ionic_dev_reset_comp reset;
	struct ionic_dev_getattr_comp getattr;
	struct ionic_dev_setattr_comp setattr;
	struct ionic_dev_debug_comp debug;

	struct ionic_port_identify_comp port_identify;
	struct ionic_port_init_comp port_init;
	struct ionic_port_reset_comp port_reset;
	struct ionic_port_getattr_comp port_getattr;
	struct ionic_port_setattr_comp port_setattr;

	struct ionic_vf_setattr_comp vf_setattr;
	struct ionic_vf_getattr_comp vf_getattr;
	struct ionic_vf_ctrl_comp vf_ctrl;

	struct ionic_discover_cmb_comp discover_cmb;

	struct ionic_lif_identify_comp lif_identify;
	struct ionic_lif_init_comp lif_init;
	ionic_lif_reset_comp lif_reset;

	struct ionic_qos_identify_comp qos_identify;
	ionic_qos_init_comp qos_init;
	ionic_qos_reset_comp qos_reset;

	struct ionic_q_identify_comp q_identify;
	struct ionic_q_init_comp q_init;

	ionic_fw_download_comp fw_download;
	struct ionic_fw_control_comp fw_control;

	struct ionic_hii_identify_comp hii_identify;
	struct ionic_hii_init_comp hii_init;
	struct ionic_hii_setattr_comp hii_setattr;
	struct ionic_hii_getattr_comp hii_getattr;
	struct ionic_hii_reset_comp hii_reset;

	struct ionic_upt_comp upt_comp;
};

#define IONIC_DEVINFO_OPROM_RESERVED   31
/**
 * struct ionic_oprom_regs - Oprom debug/enable and bmp registers
 * @oprom_log_level: Variables indicates whether Oprom log to be printed or not
 * @oprom_reserved : Reserved for future use and make it as 32 byte alignment of oprom_regs.
 */
struct ionic_oprom_regs {
	u8    oprom_log_level;
	u8    oprom_reserved[IONIC_DEVINFO_OPROM_RESERVED];
};
IONIC_CHECK_OPROM_LENGTH(ionic_oprom_regs);

/**
 * struct ionic_hwstamp_regs - Hardware current timestamp registers
 * @tick_low:        Low 32 bits of hardware timestamp
 * @tick_high:       High 32 bits of hardware timestamp
 */
struct ionic_hwstamp_regs {
	u32    tick_low;
	u32    tick_high;
};

/**
 * union ionic_dev_info_regs - Device info register format (read-only)
 * @signature:       Signature value of 0x44455649 ('DEVI')
 * @version:         Current version of info
 * @asic_type:       Asic type
 * @asic_rev:        Asic revision
 * @fw_status:       Firmware status
 *			bit 0   - 1 = fw running
 *			bit 4-7 - 4 bit generation number, changes on fw restart
 * @fw_heartbeat:    Firmware heartbeat counter
 * @serial_num:      Serial number
 * @fw_version:      Firmware version
 * @oprom_regs:      oprom_regs to store oprom debug enable/disable and bmp
 * @int_mnic_ip:     Int mnic ip address 169.254.<port>.1, byte 3 is 169
 * @hwstamp:         Hardware current timestamp registers
 */
union ionic_dev_info_regs {
#define IONIC_DEVINFO_FWVERS_BUFLEN 32
#define IONIC_DEVINFO_SERIAL_BUFLEN 32
	struct {
		u32    signature;
		u8     version;
		u8     asic_type;
		u8     asic_rev;
#define IONIC_FW_STS_F_RUNNING		0x01
#define IONIC_FW_STS_F_GENERATION	0xF0
		u8     fw_status;
		u32    fw_heartbeat;
		char   fw_version[IONIC_DEVINFO_FWVERS_BUFLEN];
		char   serial_num[IONIC_DEVINFO_SERIAL_BUFLEN];
		struct ionic_oprom_regs oprom_regs;
		u8     int_mnic_ip[4];
		u8     rsvd_pad1024[912];
		struct ionic_hwstamp_regs hwstamp;
	};
	u32 words[512];
};
IONIC_CHECK_DEV_INFO_REGS_LENGTH(ionic_dev_info_regs);

/**
 * union ionic_dev_cmd_regs - Device command register format (read-write)
 * @doorbell:        Device Cmd Doorbell, write-only
 *                   Write a 1 to signal device to process cmd,
 *                   poll done for completion.
 * @done:            Done indicator, bit 0 == 1 when command is complete
 * @cmd:             Opcode-specific command bytes
 * @comp:            Opcode-specific response bytes
 * @data:            Opcode-specific side-data
 */
union ionic_dev_cmd_regs {
	struct {
		u32                   doorbell;
		u32                   done;
		union ionic_dev_cmd         cmd;
		union ionic_dev_cmd_comp    comp;
		u8                    rsvd[48];
		u32                   data[478];
	} __attribute__((packed));
	u32 words[512];
};

/**
 * union ionic_dev_regs - Device register format for bar 0 page 0
 * @info:            Device info registers
 * @devcmd:          Device command registers
 */
union ionic_dev_regs {
	struct {
		union ionic_dev_info_regs info;
		union ionic_dev_cmd_regs  devcmd;
	} __attribute__((packed));
	__le32 words[1024];
};

union ionic_adminq_cmd {
	struct ionic_admin_cmd cmd;
	struct ionic_nop_cmd nop;
	struct ionic_q_identify_cmd q_identify;
	struct ionic_q_init_cmd q_init;
	struct ionic_q_control_cmd q_control;
	struct ionic_lif_setattr_cmd lif_setattr;
	struct ionic_lif_getattr_cmd lif_getattr;
	struct ionic_lif_setphc_cmd lif_setphc;
	struct ionic_rx_mode_set_cmd rx_mode_set;
	struct ionic_rx_filter_add_cmd rx_filter_add;
	struct ionic_rx_filter_del_cmd rx_filter_del;
	struct ionic_rdma_reset_cmd rdma_reset;
	struct ionic_rdma_queue_cmd rdma_queue;
	struct ionic_fw_download_cmd fw_download;
	struct ionic_fw_control_cmd fw_control;
};

union ionic_adminq_comp {
	struct ionic_admin_comp comp;
	struct ionic_nop_comp nop;
	struct ionic_q_identify_comp q_identify;
	struct ionic_q_init_comp q_init;
	struct ionic_lif_setattr_comp lif_setattr;
	struct ionic_lif_getattr_comp lif_getattr;
	struct ionic_admin_comp lif_setphc;
	struct ionic_rx_filter_add_comp rx_filter_add;
	ionic_fw_download_comp fw_download;
	struct ionic_fw_control_comp fw_control;
};

#define IONIC_BARS_MAX			6
#define IONIC_PCI_BAR_DBELL		1
#define IONIC_PCI_BAR_CMB		2

/* BAR0 */
#define IONIC_BAR0_SIZE				0x8000
#define IONIC_BAR2_SIZE				0x800000

#define IONIC_BAR0_DEV_INFO_REGS_OFFSET		0x0000
#define IONIC_BAR0_DEV_CMD_REGS_OFFSET		0x0800
#define IONIC_BAR0_DEV_CMD_DATA_REGS_OFFSET	0x0c00
#define IONIC_BAR0_INTR_STATUS_OFFSET		0x1000
#define IONIC_BAR0_INTR_CTRL_OFFSET		0x2000

#define IONIC_DEV_CMD_DONE			0x00000001

#define IONIC_ASIC_TYPE_NONE			0
#define IONIC_ASIC_TYPE_CAPRI			1
#define IONIC_ASIC_TYPE_ELBA			2
#define IONIC_ASIC_TYPE_GIGLIO			3
#define IONIC_ASIC_TYPE_SALINA			4

/**
 * struct ionic_doorbell - Doorbell register layout
 * @p_index: Producer index
 * @ring:    Selects the specific ring of the queue to update
 *           Type-specific meaning:
 *              ring=0: Default producer/consumer queue
 *              ring=1: (CQ, EQ) Re-Arm queue.  RDMA CQs
 *              send events to EQs when armed.  EQs send
 *              interrupts when armed.
 * @qid_lo:  Queue destination for the producer index and flags (low bits)
 * @qid_hi:  Queue destination for the producer index and flags (high bits)
 */
struct ionic_doorbell {
	__le16 p_index;
	u8     ring;
	u8     qid_lo;
	__le16 qid_hi;
	u16    rsvd2;
};

/**
 * struct ionic_intr_ctrl - Interrupt control register
 * @coalescing_init:  Coalescing timer initial value, in
 *                    device units.  Use @identity->intr_coal_mult
 *                    and @identity->intr_coal_div to convert from
 *                    usecs to device units:
 *
 *                      coal_init = coal_usecs * coal_mutl / coal_div
 *
 *                    When an interrupt is sent the interrupt
 *                    coalescing timer current value
 *                    (@coalescing_curr) is initialized with this
 *                    value and begins counting down.  No more
 *                    interrupts are sent until the coalescing
 *                    timer reaches 0.  When @coalescing_init=0
 *                    interrupt coalescing is effectively disabled
 *                    and every interrupt assert results in an
 *                    interrupt.  Reset value: 0
 * @mask:             Interrupt mask.  When @mask=1 the interrupt
 *                    resource will not send an interrupt.  When
 *                    @mask=0 the interrupt resource will send an
 *                    interrupt if an interrupt event is pending
 *                    or on the next interrupt assertion event.
 *                    Reset value: 1
 * @int_credits:      Interrupt credits.  This register indicates
 *                    how many interrupt events the hardware has
 *                    sent.  When written by software this
 *                    register atomically decrements @int_credits
 *                    by the value written.  When @int_credits
 *                    becomes 0 then the "pending interrupt" bit
 *                    in the Interrupt Status register is cleared
 *                    by the hardware and any pending but unsent
 *                    interrupts are cleared.
 *                    !!!IMPORTANT!!! This is a signed register.
 * @flags:            Interrupt control flags
 *                       @unmask -- When this bit is written with a 1
 *                       the interrupt resource will set mask=0.
 *                       @coal_timer_reset -- When this
 *                       bit is written with a 1 the
 *                       @coalescing_curr will be reloaded with
 *                       @coalescing_init to reset the coalescing
 *                       timer.
 * @mask_on_assert:   Automatically mask on assertion.  When
 *                    @mask_on_assert=1 the interrupt resource
 *                    will set @mask=1 whenever an interrupt is
 *                    sent.  When using interrupts in Legacy
 *                    Interrupt mode the driver must select
 *                    @mask_on_assert=0 for proper interrupt
 *                    operation.
 * @coalescing_curr:  Coalescing timer current value, in
 *                    microseconds.  When this value reaches 0
 *                    the interrupt resource is again eligible to
 *                    send an interrupt.  If an interrupt event
 *                    is already pending when @coalescing_curr
 *                    reaches 0 the pending interrupt will be
 *                    sent, otherwise an interrupt will be sent
 *                    on the next interrupt assertion event.
 */
struct ionic_intr_ctrl {
	u8 coalescing_init;
	u8 rsvd[3];
	u8 mask;
	u8 rsvd2[3];
	u16 int_credits;
	u16 flags;
#define INTR_F_UNMASK		0x0001
#define INTR_F_TIMER_RESET	0x0002
	u8 mask_on_assert;
	u8 rsvd3[3];
	u8 coalescing_curr;
	u8 rsvd4[3];
	u32 rsvd6[3];
};

#define IONIC_INTR_CTRL_REGS_MAX	2048
#define IONIC_INTR_CTRL_COAL_MAX	0x3F

#define intr_to_coal(intr_ctrl)		\
		((void __iomem *)&(intr_ctrl)->coalescing_init)
#define intr_to_mask(intr_ctrl)		\
		((void __iomem *)&(intr_ctrl)->mask)
#define intr_to_credits(intr_ctrl)	\
		((void __iomem *)&(intr_ctrl)->int_credits)
#define intr_to_mask_on_assert(intr_ctrl)\
		((void __iomem *)&(intr_ctrl)->mask_on_assert)

struct ionic_intr_status {
	u32 status[2];
};

struct ionic_notifyq_cmd {
	__le32 data;	/* Not used but needed for qcq structure */
};

union ionic_notifyq_comp {
	struct ionic_notifyq_event event;
	struct ionic_link_change_event link_change;
	struct ionic_reset_event reset;
	struct ionic_heartbeat_event heartbeat;
	struct ionic_log_event log;
};
union ionic_debug_msg {
	struct {
		char string[128];
		u8   rsvd[128];
	};
	__le32 words[64];
};

/**
 * struct ionic_eq_comp - Event queue completion descriptor
 *
 * @code:	Event code, see enum ionic_eq_comp_code
 * @lif_index:	To which LIF the event pertains
 * @qid:	To which queue id the event pertains
 * @gen_color:	Event queue wrap counter, init 1, incr each wrap
 */
struct ionic_eq_comp {
	__le16 code;
	__le16 lif_index;
	__le32 qid;
	u8 rsvd[7];
	u8 gen_color;
};

enum ionic_eq_comp_code {
	IONIC_EQ_COMP_CODE_NONE = 0,
	IONIC_EQ_COMP_CODE_RX_COMP = 1,
	IONIC_EQ_COMP_CODE_TX_COMP = 2,
};

/* Deprecate */
struct ionic_identity {
	union ionic_drv_identity drv;
	union ionic_dev_identity dev;
	union ionic_lif_identity lif;
	union ionic_port_identity port;
	union ionic_qos_identity qos;
	union ionic_q_identity txq;
	union ionic_discover_cmb_identity cmb_layout;
};

#endif /* _IONIC_IF_H_ */
