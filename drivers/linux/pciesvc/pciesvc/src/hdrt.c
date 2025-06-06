// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017,2021, Pensando Systems Inc.
 */

#include "pciesvc_impl.h"
#include "hdrt.h"

static int
hdrt_size(void)
{
    return HDRT_COUNT;
}

static u_int64_t
hdrt_addr(const u_int32_t lif)
{
    pciesvc_assert(lif < hdrt_size());
    return HDRT_BASE + (lif * HDRT_STRIDE);
}

static void
hdrt_set(const u_int32_t lif, const hdrt_t *hdrt)
{
    pciesvc_reg_wr32w(hdrt_addr(lif), hdrt->w, HDRT_NWORDS);
}

static void
hdrt_set_itr(const u_int32_t lif, const u_int16_t bdf,
             const u_int16_t rd_ro_en, const u_int16_t wr_ro_en)
{
    hdrt_t h = { 0 };

    h.valid = 1;
    h.bdf = bdf;
    h.attr2_1_rd = rd_ro_en; /* reads get Relaxed Ordering */
    h.attr2_1_wr = wr_ro_en; /* writes get Relaxed Ordering */
    hdrt_set(lif, &h);
}

static int
pciehw_hdrt_load(const u_int32_t lifb,
                 const u_int32_t lifc,
                 const u_int16_t bdf,
                 const u_int16_t rd_ro_en,
                 const u_int16_t wr_ro_en)
{
    u_int32_t lif;

    for (lif = lifb; lif < lifb + lifc; lif++) {
        hdrt_set_itr(lif, bdf, rd_ro_en, wr_ro_en);
    }
    return 0;
}

static int
pciehw_hdrt_unload(const u_int32_t lifb, const u_int32_t lifc)
{
    const hdrt_t h0 = { 0 };
    u_int32_t lif;

    for (lif = lifb; lif < lifb + lifc; lif++) {
        hdrt_set(lif, &h0);
    }
    return 0;
}

/******************************************************************
 * apis
 */

int
pciehw_hdrt_bus_master(pciehwdev_t *phwdev, const int on)
{
    if (phwdev->bm_en == on) {
        return 0;
    }

    phwdev->bm_en = on;
    if (phwdev->bm_en) {
        pciehw_hdrt_load(phwdev->lifb, phwdev->lifc, phwdev->bdf, phwdev->ro_en, 0);
        if (phwdev->ro_lif) {
            pciehw_hdrt_load(phwdev->ro_lif, 1, phwdev->bdf, 0, phwdev->ro_en);
        }
    } else {
        pciehw_hdrt_unload(phwdev->lifb, phwdev->lifc);
        if (phwdev->ro_lif) {
            pciehw_hdrt_unload(phwdev->ro_lif, 1);
        }
    }
    return 0;
}

int
pciehw_hdrt_set_relaxed_order(pciehwdev_t *phwdev, const int on)
{
    hdrt_t h = { 0 };
    u_int32_t lif;

    if (phwdev->ro_en == on) {
        return 0;
    }

    phwdev->ro_en = on;
    if (phwdev->bm_en) {
        for (lif = phwdev->lifb; lif < phwdev->lifb + phwdev->lifc; lif++) {
            pciesvc_reg_rd32w(hdrt_addr(lif), h.w, HDRT_NWORDS);
            h.attr2_1_rd = phwdev->ro_en;
            hdrt_set(lif, &h);
        }
        if (phwdev->ro_lif) {
            pciesvc_reg_rd32w(hdrt_addr(phwdev->ro_lif), h.w, HDRT_NWORDS);
            h.attr2_1_wr = phwdev->ro_en;
            hdrt_set(phwdev->ro_lif, &h);
        }
    }
    return 1;
}
