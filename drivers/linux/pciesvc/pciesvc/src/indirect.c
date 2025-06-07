// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018,2021-2022, Pensando Systems Inc.
 */

#include "pciesvc_impl.h"
#include "pcietlp.h"
#include "req_int.h"
#include "indirect.h"
#include "intrutils.h"

static u_int64_t
ind_info_addr(const int port)
{
    return IND_INFO_BASE + (port * IND_INFO_STRIDE);
}

static u_int64_t
indirect_int_addr(void)
{
    return IND_INT_ADDR;
}

/*****************************************************************
 * indirect timer support
 *
 * sta_tgt_free_running_time_val:  free running count once we enable via
 *                                 cfg_tgt_ind_debug_rsp_enable
 * sta_tgt_ind_debug_rsp_pnd_time: This is the latched time when indirect
 *                                 started (start time)
 * sta_tgt_ind_debug_rsp_err_time: when error is crossed,
 *                                 it will store end time
 */

static uint32_t
indirect_timer_get_ticks(void)
{
#ifdef ASIC_SALINA
    return pciesvc_reg_rd32(PXBT_(STA_TGT_FREE_RUNNING));
#else
    return 0;
#endif
}

static uint32_t
indirect_timer_delta_from_now(const uint32_t ticks, const uint32_t now)
{
    if (now < ticks) {
        /* account for timer wrap */
        return (0x100000000ULL - ticks) + now;
    }
    return now - ticks;
}

static void
indirect_timer_get_rsp(uint32_t *pnd_time, uint32_t *err_time)
{
#ifdef ASIC_SALINA
    union {
        struct {
            uint32_t pnd_time;
            uint32_t err_time:16;
        } __attribute__((packed));
        uint32_t w[2];
    } sta_ind_debug_rsp;

    pciesvc_reg_rd32w(PXBT_(STA_TGT_IND_DEBUG_RSP), sta_ind_debug_rsp.w, 2);
    if (pnd_time) *pnd_time = sta_ind_debug_rsp.pnd_time;
    if (err_time) *err_time = sta_ind_debug_rsp.err_time;
#endif
}

#define CLOCK_FREQ      1100000000
#define IND_THRESHOLD   10000
#define ERR_UNIT        0
#define ERR_TM_UNIT_TO_TICKS(e) ((e) * 1024 * (1 << (ERR_UNIT * 2)))
/*
 * core clock frequency 11000000 MHz
 * one core clock cycle is 1 / 1100000000s, or 1 / 1100.000000us
 *
 * ticks to us:
 *     ticks to us: us = ticks * (1 / 1100.000000)
 *     ticks to us: us = ticks / 1100
 * us to ticks
 *     us to ticks: ticks = us / ( 1 / 1100)
 *     us to ticks: ticks = us * 1100
 */
uint32_t
pciehw_indirect_ticks_to_us(uint32_t ticks)
{
    return ticks / (CLOCK_FREQ / 1000000);
}

#ifdef ASIC_SALINA
static inline uint32_t
us_to_ticks(uint32_t usecs)
{
    return usecs * (CLOCK_FREQ/ 1000000);
}

/*
 * threshold - threshold that is allowed,
 *             once crosses HW will trigger interrupt,
 *              pxb_tgt_int_err_intreg.
 *                      tgt_indirect_rsp_cross_threshold_interrupt
 *             unit of 4k cycles, (reset_val=0x2FAF, size=20)
 * err_unit - clock unit for capturing sta_tgt_ind_debug_rsp err_time,
 *              0:  1k cycles, (reset_val=0, size=2)
 *              1 : 4k cycles,
 *              2 : 16k cycles,
 *              3 : 64k cycles",
 * tgt_port - select debug port, port values 0..7 (reset_val=0, size=3)
 * enable - enable indirect debug (reset_val=0, size=1)
 *              0 : disable,
 *              1 : enable",
 */
static void
indirect_timer_init(const int port)
{
    union {
        struct {
            uint32_t threshold:20;
            uint32_t err_unit:2;
            uint32_t tgt_port:3;
            uint32_t enable:1;
        } __attribute__((packed));
        uint32_t w;
    } cfg_ind_debug_rsp;
    const uint32_t threshold = us_to_ticks(IND_THRESHOLD) >> 12;

    cfg_ind_debug_rsp.w = pciesvc_reg_rd32(PXBT_(CFG_TGT_IND_DEBUG_RSP));
    cfg_ind_debug_rsp.tgt_port = port;
    cfg_ind_debug_rsp.threshold = threshold;
    cfg_ind_debug_rsp.enable = 1;
    cfg_ind_debug_rsp.err_unit = ERR_UNIT;
    pciesvc_reg_wr32(PXBT_(CFG_TGT_IND_DEBUG_RSP), cfg_ind_debug_rsp.w);
}
#endif

/*****************************************************************
 * aximst rams
 */

static u_int64_t
aximst_addr(const unsigned int port,
            const unsigned int idx,
            const unsigned int entry)
{
    return (AXIMST_BASE +
            ((u_int64_t)idx * AXIMST_STRIDE) +
            ((u_int64_t)port * AXIMST_PORT_STRIDE) +
            ((u_int64_t)entry * AXIMST_ENTRY_STRIDE));
}

static void
read_aximst(const unsigned int port,
            const unsigned int idx,
            const unsigned int entry,
            u_int32_t *buf)
{
    const u_int64_t pa = aximst_addr(port, idx, entry);

    pciesvc_reg_rd32w(pa, buf, AXIMST_NWORDS);
}

/*
 * Indirect info tlp format is reversed in srams:
 *
 *    15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
 * --------------------------------------------------
 * 0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * 1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * 2: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <= tlp[16]
 * 3: 00 00 00 00 60 02 00 3d 0f 00 00 3a 01 00 00 05 <= tlp[0]
 * 4: 24 48 00 00 00 04 c0 bc 05 78 02 00 40 0e 41 c4 <= indirect info
 */
static void
decode_indirect_info(u_int8_t *info, indirect_entry_t *ientry)
{
    u_int8_t *p;
    int i;

    /* copy the raw tlp data */
    p = (u_int8_t *)&ientry->rtlp;
    for (i = 0; i < sizeof(ientry->rtlp); i++) {
        p[i] = info[63 - i];
    }

    /* copy the tlp aux info */
    p = (u_int8_t *)&ientry->info;
    for (i = 0; i < sizeof(ientry->info); i++) {
        p[i] = info[64 + i];
    }
}

static void
read_ind_info(const unsigned int port, int *entryp, int *pendingp)
{
    union {
        struct {
            u_int32_t pending:1;
            u_int32_t entry:4;
            u_int32_t port:3;
        } __attribute__((packed));
        u_int32_t w[IND_INFO_NWORDS];
    } ind_info;

    pciesvc_reg_rd32w(ind_info_addr(port), ind_info.w, IND_INFO_NWORDS);

    /* pciesvc_assert(ind_info.port == port); */

    if (entryp) *entryp = ind_info.entry;
    if (pendingp) *pendingp = ind_info.pending;
}

/*
 * Fill the buffer with the raw indirect info data
 * from the aximst srams.
 */
static void
read_indirect_info(const unsigned int port,
                   const unsigned int entry,
                   u_int8_t *buf)
{
    u_int8_t *bp;
    int i;

    for (bp = buf, i = 0; i < 5; i++, bp += AXIS_INFO_BYTE_COUNT) {
        read_aximst(port, i, entry, (u_int32_t *)bp);
    }
}

static void
read_indirect_entry(const unsigned int port,
                    const unsigned int entry,
                    indirect_entry_t *ientry)
{
    u_int8_t buf[128];

    read_indirect_info(port, entry, buf);
    decode_indirect_info(buf, ientry);
    ientry->port = port;
}

static int
read_pending_indirect_entry(const unsigned int port,
                            indirect_entry_t *ientry)
{
    int entry, pending;

    read_ind_info(port, &entry, &pending);
    read_indirect_entry(port, entry, ientry);
    return pending;
}

void
pciehw_indirect_complete(indirect_entry_t *ientry)
{
    union {
        struct {
            u_int32_t data0;
            u_int32_t data1;
            u_int32_t data2;
            u_int32_t data3;
            u_int32_t cpl_stat:3;
            u_int32_t port_id:3;
            u_int32_t axi_id:7;
            u_int32_t fetch_rsp:1;
        } __attribute__((packed));
        u_int32_t w[IND_RSP_NWORDS];
    } ind_rsp;
    const u_int64_t pa = ientry->info.direct_addr;
    const size_t sz = ientry->info.direct_size;

    if (ientry->completed) return;

    /*
     * This indirect transaction was handled by software.
     * We might have written some memory that will be read
     * by subsequent direct transactions handled in hw.
     * Insert barrier here to be sure all memory writes have
     * landed so hw will always see the data we wrote.
     */
    pciesvc_mem_barrier();

    if (sz < 4 && (pa & 0x3)) {
        /*
         * If sub-dword read, shift return data to the correct
         * byte lanes expected for this transaction.
         *
         *     data0 = data0 << (address-dword-offset * 8);
         */
        ind_rsp.data0 = ientry->data[0] << ((pa & 0x3) << 3);
    } else {
        ind_rsp.data0 = ientry->data[0];
        ind_rsp.data1 = ientry->data[1];
        ind_rsp.data2 = ientry->data[2];
        ind_rsp.data3 = ientry->data[3];
    }
    ind_rsp.cpl_stat = ientry->cpl;
    ind_rsp.port_id = ientry->port;
    ind_rsp.axi_id = ientry->info.context_id;
    ind_rsp.fetch_rsp = 0;

    pciesvc_reg_wr32w(IND_RSP_ADDR, ind_rsp.w, IND_RSP_NWORDS);

#ifdef ASIC_SALINA
    if (ientry->pndtm) {
        const uint32_t now = indirect_timer_get_ticks();
        const uint32_t pnd_tm = ientry->pndtm;
        const uint32_t svc_tm =
            indirect_timer_delta_from_now(ientry->svc_start_tm, now);
        pciehw_port_t *p = pciesvc_port_get(ientry->port);
        uint32_t err_tm = 0;

        if (pnd_tm > p->stats.ind_rsp_pndmax)
            p->stats.ind_rsp_pndmax = pnd_tm;
        if (svc_tm > p->stats.ind_rsp_svcmax)
            p->stats.ind_rsp_svcmax = svc_tm;
        if ((pnd_tm + svc_tm) > us_to_ticks(IND_THRESHOLD)) {
            pciesvc_get_timestamp(&p->indtr_ring[p->indtr_idx].ts);
            p->indtr_ring[p->indtr_idx].pnd_tm = pnd_tm;
            p->indtr_ring[p->indtr_idx].svc_tm = svc_tm;
            indirect_timer_get_rsp(NULL, &err_tm);
            p->indtr_ring[p->indtr_idx].err_tm = ERR_TM_UNIT_TO_TICKS(err_tm);
            p->indtr_idx++;
            if (p->indtr_idx >= PCIEHW_NINDTR) p->indtr_idx = 0;
        }
    }
#endif

    ientry->completed = 1;
}

static void
handle_indirect(const int port, pciehw_port_t *p, indirect_entry_t *ientry)
{
    const u_int32_t pmti = ientry->info.pmti;
    pciehw_spmt_t *spmt = pciesvc_spmt_get(pmti);
    const pcie_tlp_common_hdr_t *hdr = (void *)ientry->rtlp;
    const u_int8_t tlp_type = hdr->type;

    switch (tlp_type) {
    case PCIE_TLP_TYPE_CFGRD0:
    case PCIE_TLP_TYPE_CFGRD1:
        pciehw_cfgrd_indirect(port, ientry);
        spmt->swrd++;
        p->stats.ind_cfgrd++;
        break;
    case PCIE_TLP_TYPE_CFGWR0:
    case PCIE_TLP_TYPE_CFGWR1:
        pciehw_cfgwr_indirect(port, ientry);
        spmt->swwr++;
        p->stats.ind_cfgwr++;
        break;
    case PCIE_TLP_TYPE_MEMRD:
    case PCIE_TLP_TYPE_MEMRD64:
        pciehw_barrd_indirect(port, ientry);
        spmt->swrd++;
        p->stats.ind_memrd++;
        break;
    case PCIE_TLP_TYPE_MEMWR:
    case PCIE_TLP_TYPE_MEMWR64:
        pciehw_barwr_indirect(port, ientry);
        spmt->swwr++;
        p->stats.ind_memwr++;
        break;
    case PCIE_TLP_TYPE_IORD:
        pciehw_barrd_indirect(port, ientry);
        spmt->swrd++;
        p->stats.ind_iord++;
        break;
    case PCIE_TLP_TYPE_IOWR:
        pciehw_barwr_indirect(port, ientry);
        spmt->swwr++;
        p->stats.ind_iowr++;
        break;
    default:
        ientry->cpl = PCIECPL_UR;
        pciehw_indirect_complete(ientry);
        p->stats.ind_unknown++;
        break;
    }

    pciesvc_spmt_put(spmt, DIRTY);
}

/******************************************************************
 * apis
 */

int
pciehw_indirect_global_init(const int active_port)
{
#ifdef ASIC_SALINA
    pciehw_port_t *p = pciesvc_port_get(active_port);

    p->indtimer = 1;    /* indirect timer enabled for this port */
    indirect_timer_init(active_port);
#endif
    return 0;
}

int
pciehw_indirect_intr_init(const int port,
                          const u_int64_t msgaddr, const u_int32_t msgdata)
{
    u_int64_t msgaddr0, msi_indirect_intr_base;
    u_int32_t msgdata0;
    int ret;
    pciehw_shmem_t *pshmem = pciesvc_shmem_get();

    msi_indirect_intr_base = PSHMEM_DATA_FIELD(pshmem, msi_intr_base);
    if (msi_indirect_intr_base > 0) {
        req_int_get(indirect_int_addr(), &msgaddr0, &msgdata0);

        if (port == 0 || msgaddr0 == 0) {
            req_int_set(indirect_int_addr(), intr_assert_addr(msi_indirect_intr_base), intr_assert_data());
        }

        ret = intr_config_local_msi(msi_indirect_intr_base + port, msgaddr, msgdata);
    } else {
        ret = req_int_init(indirect_int_addr(), port, msgaddr, MADDR_AS_IS, msgdata, MDATA_ADD_PORT);
    }
    return ret;
}

static int
pciehw_indirect_handle(const int port, const int polled)
{
    pciehw_port_t *p = pciesvc_port_get(port);
    indirect_entry_t ientrybuf, *ientry = &ientrybuf;
    int pending;
    int r = 0;

    pciesvc_memset(ientry, 0, sizeof(*ientry));
    pending = read_pending_indirect_entry(port, ientry);

    if (p->indtimer) {
        uint32_t quetm;
        const uint32_t now = indirect_timer_get_ticks();

        indirect_timer_get_rsp(&quetm, NULL);
        ientry->pndtm = indirect_timer_delta_from_now(quetm, now);
        ientry->svc_start_tm = now;
    }

    p->stats.ind_intr++;
    if (polled) p->stats.ind_polled++;
    if (!pending) {
        p->stats.ind_spurious++;
        goto out;
    }

    ientry->cpl = PCIECPL_SC; /* assume success */
    handle_indirect(port, p, ientry);
    r = 1;

 out:
    pciesvc_port_put(p, DIRTY);
    return r;
}

int
pciehw_indirect_intr(const int port)
{
    return pciehw_indirect_handle(port, 0);
}

/*
 * Arrange to have the notify interrupt written to memory,
 * then we can poll memory locations to see if there is work to do.
 */
int
pciehw_indirect_poll_init(const int port)
{
    const u_int64_t msgaddr = pciesvc_indirect_intr_dest_pa(port);
    const u_int32_t msgdata = 1;

    return req_int_init(indirect_int_addr(), port, msgaddr, MADDR_ADD_PORT,
                        msgdata, MDATA_AS_IS);
}

int
pciehw_indirect_poll(const int port)
{
    int pending;
    int r = 0;

    read_ind_info(port, NULL, &pending);
    if (pending) {
        r = pciehw_indirect_handle(port, 1);
    }
    return r;
}
