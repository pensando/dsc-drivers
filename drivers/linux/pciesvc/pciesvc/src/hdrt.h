/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2017,2021, Pensando Systems Inc.
 */

#ifndef __HDRT_H__
#define __HDRT_H__

#if defined(ASIC_SALINA) && defined(HW)

typedef union {
    struct {
        u_int64_t valid             :1;
        u_int64_t bdf               :16;
        u_int64_t td                :1;
        u_int64_t pasid_en          :1;
        u_int64_t pasid_sel         :3;
        u_int64_t pasid             :20;
        u_int64_t pasid_exe         :1;
        u_int64_t pasid_priv        :1;
        u_int64_t attr2_1_rd        :2;
        u_int64_t attr2_1_wr        :2;
        u_int64_t rc_cfg1           :1;
        u_int64_t attr0_rd          :1;
        u_int64_t attr0_wr          :1;
        u_int64_t ats_at_wr         :2;
        u_int64_t ats_at_rd         :2;
        u_int64_t tc                :3;
        u_int64_t ln_wr             :1;
        u_int64_t ln_rd             :1;
        u_int64_t tph_en            :1;
        u_int64_t tph_src           :3;
        u_int64_t tph_value         :18;
        u_int64_t tph_rsrd          :1;
        u_int64_t ide_en            :1;
        u_int64_t ide_flags         :4;
        u_int64_t ide_rsrd          :3;
        u_int64_t ide_strmid        :8;
        u_int64_t ide_msix_ide_en   :1;
        u_int64_t ide_msix_T_flag   :1;
        u_int64_t ide_msg_ide_en    :1;
        u_int64_t ide_msg_T_flag    :1;
        u_int64_t ats_wr_src        :2;
        u_int64_t ats_rd_src        :2;
        u_int64_t ats_msix_force_0  :1;
        u_int64_t rsrv              :10;
        u_int64_t ecc               :8;
        u_int64_t _pad              :3;
    } __attribute__((packed));
    u_int32_t w[HDRT_NWORDS];
} hdrt_t;

#else

typedef union {
    struct {
        u_int64_t valid     :1;
        u_int64_t bdf       :16;
        u_int64_t td        :1;
        u_int64_t pasid_en  :1;
        u_int64_t pasid_sel :2;
        u_int64_t pasid     :20;
        u_int64_t pasid_exe :1;
        u_int64_t pasid_priv:1;
        u_int64_t attr2_1_rd:2;
        u_int64_t attr2_1_wr:2;
        u_int64_t rc_cfg1   :1;
        u_int64_t attr0_rd  :1;
        u_int64_t attr0_wr  :1;
        u_int64_t ats_at_wr :1;
        u_int64_t ats_at_rd :1;
        u_int64_t tc        :3;
        u_int64_t ln_wr     :1;
        u_int64_t ln_rd     :1;
        u_int64_t rsrv      :13;
        u_int64_t ecc       :8;
        u_int64_t _pad      :16;
    } __attribute__((packed));
    u_int32_t w[HDRT_NWORDS];
} hdrt_t;

#endif

int pciehw_hdrt_bus_master(pciehwdev_t *phwdev, const int on);
int pciehw_hdrt_set_relaxed_order(pciehwdev_t *phwdev, const int on);

#endif /* __HDRT_H__ */
