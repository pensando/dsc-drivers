/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Pensando Systems Inc.
 */
#include "pciesvc_impl.h"
#include "gve.h"

/* Fixed Configuration Registers */
struct gve_registers {
    u_int32_t	device_status;
    u_int32_t	driver_status;
    u_int32_t	max_tx_queues;
    u_int32_t	max_rx_queues;
    u_int32_t	adminq_pfn;
    u_int32_t	adminq_doorbell;
    u_int32_t	adminq_event_counter;
    u_int8_t	reserved[3];
    u_int8_t	driver_version;
};

#define GVE_REG_OFF(fld) offsetof(struct gve_registers, fld)
#define GVE_REG_SZ(fld) sizeof(((struct gve_registers *)0)->fld)
#define GVE_REG_ADDR(base, fld) ((base) + GVE_REG_OFF(fld))

#define FMT64X  "0x%" PRIx64
#define FMT64U "%" PRIu64
#define FMT64S "%lu"

#define GVE_REG_RD(fld)                                                 \
    case GVE_REG_OFF(fld):                                              \
        pciesvc_mem_rd(addr, &val, GVE_REG_SZ(fld));                    \
        pciesvc_logdebug("%s: read %s addr "FMT64X" off "FMT64U" size "FMT64S" val "FMT64X"", \
            pciehwdev_get_name(phwdev), #fld, addr, baroff, size, val); \
        break;

#define GVE_REG_WR(fld, notify)                                         \
    case GVE_REG_OFF(fld):                                              \
        pciesvc_logdebug("%s: write %s addr "FMT64X" off "FMT64U" size "FMT64S" val "FMT64X"",\
            pciehwdev_get_name(phwdev), #fld, addr, baroff, size, val); \
        pciesvc_mem_wr(addr, &val, GVE_REG_SZ(fld));                    \
        *do_notify = notify;                                            \
        break;

u_int64_t
gve_barrd(pciehwdev_t *phwdev, u_int64_t addr,
          const u_int64_t baroff, const size_t size,
          u_int8_t *do_notify)
{
    u_int64_t val = 0;

    switch (baroff) {
        GVE_REG_RD(device_status)
        GVE_REG_RD(max_tx_queues)
        GVE_REG_RD(max_rx_queues)
        GVE_REG_RD(adminq_event_counter)
        GVE_REG_RD(adminq_pfn)
    }

    return val;
}

void
gve_barwr(pciehwdev_t *phwdev, u_int64_t addr,
          const u_int64_t baroff, const size_t size, const u_int64_t val,
          u_int8_t *do_notify)
{
    if (baroff == GVE_REG_OFF(adminq_pfn) && val == 0) {
        // This is the reset case. We let nicmgr finish clean up and
        // write to the registers in this case
        *do_notify = 1;
        return;
    }
    switch (baroff) {
        GVE_REG_WR(driver_status, 1)
        GVE_REG_WR(adminq_pfn, 1)
        GVE_REG_WR(adminq_doorbell, 1)
        GVE_REG_WR(driver_version, 0)
    }
}
