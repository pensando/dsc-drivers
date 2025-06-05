/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022, Pensando Systems Inc.
 */
#ifndef __VIRTIO_SPEC_H__
#define __VIRTIO_SPEC_H__

#ifdef __cplusplus
extern "C" {
#if 0
} /* close to calm emacs autoindent */
#endif
#endif

#ifndef BIT
#define BIT(nr)                 (1UL << (nr))
#endif
#ifndef BIT_ULL
#define BIT_ULL(nr)             (1ULL << (nr))
#endif
#ifndef BIT_MASK
#define BIT_MASK(nr)            (1UL << (nr))
#endif
#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE           (8)
#endif

enum {
    VIRTIO_DEV_TYPE_NET = 1,
    VIRTIO_DEV_TYPE_BLK = 2,
};

/* 4.1.4.3 - common configuration structure layout */

/* upper bounds, non-inclusive, for indirect access via select registers */
enum {
    VIRTIO_PCI_FEATURE_SELECT_COUNT = 2,
    VIRTIO_PCI_QUEUE_SELECT_COUNT = 128,
};

/* feature config, for indirect access via select register */
typedef uint32_t virtio_pci_feature_cfg_t;

/* virtqueue config, for indirect access via select register */
typedef struct virtio_pci_queue_cfg {
    uint16_t                    queue_size;
    uint16_t                    queue_msix_vector;
    uint16_t                    queue_enable;
    uint16_t                    queue_notify_off;
    uint32_t                    queue_desc_lo;
    uint32_t                    queue_desc_hi;
    uint32_t                    queue_avail_lo;
    uint32_t                    queue_avail_hi;
    uint32_t                    queue_used_lo;
    uint32_t                    queue_used_hi;
    uint16_t                    queue_notify_data;
    uint16_t                    queue_reset;
} __attribute__((packed)) virtio_pci_queue_cfg_t;

/* common config, with dummy fields in place of indirect access */
typedef struct virtio_pci_common_cfg {
    uint32_t                    device_feature_select;
    virtio_pci_feature_cfg_t    device_feature; // indirect
    uint32_t                    driver_feature_select;
    virtio_pci_feature_cfg_t    driver_feature; // indirect
    uint16_t                    config_msix_vector;
    uint16_t                    num_queues;
    uint8_t                     device_status;
    uint8_t                     config_generation;
    uint16_t                    queue_select;
    union {
        virtio_pci_queue_cfg_t  queue_cfg; // indirect
        /* indirect features are hidden behind unused queue_cfg */
        struct {
            virtio_pci_feature_cfg_t device_feature_cfg[VIRTIO_PCI_FEATURE_SELECT_COUNT];
            union {
                virtio_pci_feature_cfg_t driver_feature_cfg[VIRTIO_PCI_FEATURE_SELECT_COUNT];
                /* source of truth for nicmgr feature checks */
                uint64_t active_features;
            };
            /* pciemgr observed device status nonzero -> zero */
            uint8_t need_reset;
            /* for checking status transitions */
            uint8_t device_status_prev;
            /* for VIRTIO_NET_F_MRG_RXBUF */
            uint16_t mtu_mrg_rxbuf;
            /* see VIRTIO_DEV_TYPE_* enum */
            uint8_t device_type;
        };
    };
} __attribute__((packed)) virtio_pci_common_cfg_t;

/* 5.1.4 - network device - configuration layout */
typedef struct virtio_net_config {
    /* The config defining mac address (if VIRTIO_NET_F_MAC) */
    uint8_t mac[6];

    /* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
    uint16_t status;

    /* Maximum number of each of transmit and receive queues;
     * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
     * Legal values are between 1 and 0x8000
     */
    uint16_t max_virtqueue_pairs;

    /* Default maximum transmit unit advice */
    uint16_t mtu;

    /* Speed, in units of 1Mb. All values 0 to INT_MAX are legal.
     * Any other value stands for unknown.
     */
    uint32_t speed;

    /* 0x00 - half duplex
     * 0x01 - full duplex
     * Any other value stands for unknown.
     */
    uint8_t duplex;

    /* maximum size of RSS key */
    uint8_t rss_max_key_size;

    /* maximum number of indirection table entries */
    uint16_t rss_max_indirection_table_length;

    /* bitmask of supported VIRTIO_NET_RSS_HASH_ types */
    uint32_t supported_hash_types;
} __attribute__((packed)) virtio_net_config_t;

/* 5.2.4 - block device - configuration layout */
typedef struct virtio_blk_config {
    /* Size in 512-byte sectors */
    uint64_t capacity;

    /* Maximum size in bytes of any segment in a request */
    uint32_t size_max;

    /* Maximum number of segments in a request */
    uint32_t seg_max;

    /* Obsolete */
    uint32_t geometry;

    /* Size in bytes; doesn't affect protocol; see VIRTIO_BLK_F_BLK_SIZE */
    uint32_t blk_size;

    /* Topology; doesn't affect protocol; see VIRTIO_BLK_F_TOPOLOGY */
    struct {
        /* Logical blocks per physical block */
        uint8_t physical_block_lg2;

        /* Offset of first aligned logical block */
        uint8_t alignment_offset;

        /* Suggested minimum I/O size in blocks */
        uint16_t min_io_size;

        /* Optimal (suggested maximum) I/O size in blocks */
        uint32_t opt_io_size;
    };

    /* 0x00 - writethrough
     * 0x01 - writeback
     * See VIRTIO_BLK_F_CONFIG_WCE */
    uint8_t writeback;

    uint8_t unused0;

    /* See VIRTIO_BLK_F_MQ */
    uint16_t num_queues;

    /* See VIRTIO_BLK_F_DISCARD */
    uint32_t max_discard_sectors;
    uint32_t max_discard_seg;
    uint32_t discard_sector_alignment;

    /* See VIRTIO_BLK_F_WRITE_ZEROES */
    uint32_t max_write_zeroes_sector;
    uint32_t max_write_zeroes_seg;
    uint8_t write_zeroes_may_unmap;

    uint8_t unused1[3];

    /* See VIRTIO_BLK_F_SECURE_ERASE */
    uint32_t max_secure_erase_sectors;
    uint32_t max_secure_erase_seg;
    uint32_t secure_erase_sector_alignment;
} __attribute__((packed)) virtio_blk_config_t;

/* 2.1 - device status field */
enum {
    VIRTIO_S_ACKNOWLEDGE                = (1u << 0),
    VIRTIO_S_DRIVER                     = (1u << 1),
    VIRTIO_S_DRIVER_OK                  = (1u << 2),
    VIRTIO_S_FEATURES_OK                = (1u << 3),
    VIRTIO_S_NEEDS_RESET                = (1u << 6),
    VIRTIO_S_FAILED                     = (1u << 7),
};

/* 5.1.3 - network device - feature bits */
enum {
    VIRTIO_NET_F_CSUM                   = (1ull << 0),
    VIRTIO_NET_F_GUEST_CSUM             = (1ull << 1),
    VIRTIO_NET_F_CTRL_GUEST_OFFLOADS    = (1ull << 2),
    VIRTIO_NET_F_MTU                    = (1ull << 3),
    VIRTIO_NET_F_MAC                    = (1ull << 5),
    VIRTIO_NET_F_GSO                    = (1ull << 6),
    VIRTIO_NET_F_GUEST_TSO4             = (1ull << 7),
    VIRTIO_NET_F_GUEST_TSO6             = (1ull << 8),
    VIRTIO_NET_F_GUEST_ECN              = (1ull << 9),
    VIRTIO_NET_F_GUEST_UFO              = (1ull << 10),
    VIRTIO_NET_F_HOST_TSO4              = (1ull << 11),
    VIRTIO_NET_F_HOST_TSO6              = (1ull << 12),
    VIRTIO_NET_F_HOST_ECN               = (1ull << 13),
    VIRTIO_NET_F_HOST_UFO               = (1ull << 14),
    VIRTIO_NET_F_MRG_RXBUF              = (1ull << 15),
    VIRTIO_NET_F_STATUS                 = (1ull << 16),
    VIRTIO_NET_F_CTRL_VQ                = (1ull << 17),
    VIRTIO_NET_F_CTRL_RX                = (1ull << 18),
    VIRTIO_NET_F_CTRL_VLAN              = (1ull << 19),
    VIRTIO_NET_F_CTRL_RX_EXTRA          = (1ull << 20),
    VIRTIO_NET_F_GUEST_ANNOUNCE         = (1ull << 21),
    VIRTIO_NET_F_MQ                     = (1ull << 22),
    VIRTIO_NET_F_CTRL_MAC_ADDR          = (1ull << 23),
    VIRTIO_NET_F_NOTF_COAL              = (1ull << 53),
    VIRTIO_NET_F_HASH_REPORT            = (1ull << 57),
    VIRTIO_NET_F_RSS                    = (1ull << 60),
    VIRTIO_NET_F_RSS_EXT                = (1ull << 61),
    VIRTIO_NET_F_STANDBY                = (1ull << 62),
    VIRTIO_NET_F_SPEED_DUPLEX           = (1ull << 63),
};

enum {
    VIRTIO_NET_S_LINK_UP                = 1,  // e.g. BIT(0)
    VIRTIO_NET_S_ANNOUNCE               = 2,  // e.g. BIT(1)
};

/* 5.2.3 - block device - feature bits */
enum {
    VIRTIO_BLK_F_BARRIER                = (1ull << 0),
    VIRTIO_BLK_F_SIZE_MAX               = (1ull << 1),
    VIRTIO_BLK_F_SEG_MAX                = (1ull << 2),
    VIRTIO_BLK_F_GEOMETRY               = (1ull << 4),
    VIRTIO_BLK_F_RO                     = (1ull << 5),
    VIRTIO_BLK_F_BLK_SIZE               = (1ull << 6),
    VIRTIO_BLK_F_SCSI                   = (1ull << 7),
    VIRTIO_BLK_F_FLUSH                  = (1ull << 9),
    VIRTIO_BLK_F_WCE                    = VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_TOPOLOGY               = (1ull << 10),
    VIRTIO_BLK_F_CONFIG_WCE             = (1ull << 11),
    VIRTIO_BLK_F_MQ                     = (1ull << 12),
    VIRTIO_BLK_F_DISCARD                = (1ull << 13),
    VIRTIO_BLK_F_WRITE_ZEROES           = (1ull << 14),
    VIRTIO_BLK_F_LIFETIME               = (1ull << 15),
    VIRTIO_BLK_F_SECURE_ERASE           = (1ull << 16),
};

/* 6 - reserved feature bits */
enum {
    VIRTIO_F_NOTIFY_ON_EMPTY            = (1ull << 24),
    VIRTIO_F_ANY_LAYOUT                 = (1ull << 27),
    VIRTIO_F_RING_INDIRECT_DESC         = (1ull << 28),
    VIRTIO_F_RING_EVENT_IDX             = (1ull << 29),
    VIRTIO_F_UNUSED                     = (1ull << 30),
    VIRTIO_F_VERSION_1                  = (1ull << 32),
    VIRTIO_F_ACCESS_PLATFORM            = (1ull << 33),
    VIRTIO_F_RING_PACKED                = (1ull << 34),
    VIRTIO_F_IN_ORDER                   = (1ull << 35),
    VIRTIO_F_ORDER_PLATFORM             = (1ull << 36),
    VIRTIO_F_SR_IOV                     = (1ull << 37),
    VIRTIO_F_NOTIFICATION_DATA          = (1ull << 38),
    VIRTIO_F_NOTIF_CONFIG_DATA          = (1ull << 39),
    VIRTIO_F_RING_RESET                 = (1ull << 40),
};

/* supported/enabled hash types */
enum {
    VIRTIO_NET_RSS_HASH_TYPE_IPv4       = (1u << 0),
    VIRTIO_NET_RSS_HASH_TYPE_TCPv4      = (1u << 1),
    VIRTIO_NET_RSS_HASH_TYPE_UDPv4      = (1u << 2),
    VIRTIO_NET_RSS_HASH_TYPE_IPv6       = (1u << 3),
    VIRTIO_NET_RSS_HASH_TYPE_TCPv6      = (1u << 4),
    VIRTIO_NET_RSS_HASH_TYPE_UDPv6      = (1u << 5),
    VIRTIO_NET_RSS_HASH_TYPE_IP_EX      = (1u << 6),
    VIRTIO_NET_RSS_HASH_TYPE_TCP_EX     = (1u << 7),
    VIRTIO_NET_RSS_HASH_TYPE_UDP_EX     = (1u << 8),
};

#define VIRTIO_ISR_STATUS_VQ_BIT        BIT(0)
#define VIRTIO_ISR_STATUS_CFG_BIT       BIT(1)

/* The first byte is read by the modern driver after a legacy interrupt.
 * The second byte is written by nicmgr when config change notification is
 * required.
 * The response to the driver read is a combination of the second byte
 * and the device's credits in the interrupt Pending Bit Array (PBA).
 */
struct virtio_isr_cfg_reg {
    uint8_t isr_status;    // indirect
    uint8_t cfg_status;    // hidden
};

#define VIRTIO_NOTIFY_MUL_SHIFT         2       // 2 ** 2 == 4 (bytes per dbell)
#define VIRTIO_NOTIFY_QID_SHIFT         6       // 2 ** 6 == 64 (qid per 1/4 region)
#define VIRTIO_NOTIFY_REG_SHIFT         10      // 2 ** 10 == 1024 (total bytes per region)
#define VIRTIO_NOTIFY_REG_BYTES         1024
#define VIRTIO_NOTIFY_MULTIPLIER        4

struct virtio_pci_notify_reg {
    uint8_t inc_pi_dbell[VIRTIO_NOTIFY_REG_BYTES];
    uint8_t set_pi_dbell[VIRTIO_NOTIFY_REG_BYTES];
};

// number of vqid supported by this notification doorbell layout (total rx + tx + cvq)
#define VIRTIO_VQID_NOTIFY_COUNT \
    (VIRTIO_NOTIFY_REG_BYTES / VIRTIO_NOTIFY_MULTIPLIER / 4)

// vqid offset within 1/2 of one notify region (two qtypes of four qtype region)
#define VIRTIO_VQID_NOTIFY_OFF_NET(vqid) \
    (((vqid) >> 1) | (((vqid) & 1) << VIRTIO_NOTIFY_QID_SHIFT))

#define VIRTIO_VQID_NOTIFY_OFF_BLK(vqid) \
    (vqid)

// offset the 1/2 notify region to use, depending on negotiated features
static inline uint16_t virtio_notify_offset_net(const uint64_t features)
{
    uint64_t off = 0;

    if (features & VIRTIO_F_RING_PACKED) {
        // packed: qtypes 0 and 1, first half of a 4-qtype region
        if (features & VIRTIO_F_NOTIFICATION_DATA) {
            off = offsetof(struct virtio_pci_notify_reg,
                           set_pi_dbell[0]);
        } else {
            off = offsetof(struct virtio_pci_notify_reg,
                           inc_pi_dbell[0]);
        }
    } else {
        // split: qtypes 2 and 3, second half of a 4-qtype region
        if (features & VIRTIO_F_NOTIFICATION_DATA) {
            off = offsetof(struct virtio_pci_notify_reg,
                           set_pi_dbell[VIRTIO_NOTIFY_REG_BYTES / 2]);
        } else {
            off = offsetof(struct virtio_pci_notify_reg,
                           inc_pi_dbell[VIRTIO_NOTIFY_REG_BYTES / 2]);
        }
    }

    return (uint16_t)(off / VIRTIO_NOTIFY_MULTIPLIER);
}

static inline uint16_t virtio_notify_offset_blk(const uint64_t features)
{
    uint64_t off = 0;

    if (features & VIRTIO_F_RING_PACKED) {
        // packed: qtype 0, first quarter of a 4-qtype region
        if (features & VIRTIO_F_NOTIFICATION_DATA) {
            off = offsetof(struct virtio_pci_notify_reg,
                           set_pi_dbell[0]);
        } else {
            off = offsetof(struct virtio_pci_notify_reg,
                           inc_pi_dbell[0]);
        }
    } else {
        // split: qtype 1, second quarter of a 4-qtype region
        if (features & VIRTIO_F_NOTIFICATION_DATA) {
            off = offsetof(struct virtio_pci_notify_reg,
                           set_pi_dbell[VIRTIO_NOTIFY_REG_BYTES / 4]);
        } else {
            off = offsetof(struct virtio_pci_notify_reg,
                           inc_pi_dbell[VIRTIO_NOTIFY_REG_BYTES / 4]);
        }
    }

    return (uint16_t)(off / VIRTIO_NOTIFY_MULTIPLIER);
}

struct virtio_ident_reg {
    uint64_t hw_features;
    uint16_t max_vqs;
    uint16_t max_qlen;
    uint16_t min_qlen;
};

/* Everything is discoverable via PCI_CAPs.
 */
struct virtio_dev_regs {
    union {
        uint8_t part0[256];
    };
    union {
        struct virtio_pci_common_cfg cmn_cfg;
        uint8_t part1[256];
    };
    union {
        struct virtio_net_config net_cfg;
        struct virtio_blk_config blk_cfg;
        uint8_t dev_cfg[256];
        uint8_t part2[256];
    };
    union {
        struct virtio_ident_reg ident;
        uint8_t part3[128];
    };
    union {
        struct virtio_isr_cfg_reg isr_cfg;
        uint8_t part4[128];
    };
    union {
        /* indirect queue configs */
        struct virtio_pci_queue_cfg queue_cfg[VIRTIO_PCI_QUEUE_SELECT_COUNT];
        uint8_t part5[5120];
    };
    union {
        struct virtio_pci_notify_reg notify_reg;
        uint8_t part6[2048];
    };
} __attribute__((packed));

#define VIRTIO_DEV_REG_OFF(fld) offsetof(struct virtio_dev_regs, fld)
#define VIRTIO_DEV_REG_SZ(fld) sizeof(((struct virtio_dev_regs *)0)->fld)
#define VIRTIO_DEV_REG_ADDR(base, fld) ((base) + VIRTIO_DEV_REG_OFF(fld))
#define VIRTIO_DEV_REG_QUEUE_CFG_ADDR(base, idx)                               \
    (VIRTIO_DEV_REG_ADDR(base, queue_cfg) +                                    \
     (idx * sizeof(struct virtio_pci_queue_cfg)))

struct pvirtq_desc {
    uint64_t addr;      /* Buffer Address. */
    uint32_t len;       /* Buffer Length. */
    uint16_t id;        /* Buffer ID. */
    uint16_t flags;     /* The flags depending on descriptor type. */
};

#ifdef __cplusplus
}
#endif

#endif /* __VIRTIO_SPEC_H__ */
