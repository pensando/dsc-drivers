/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018,2020, Pensando Systems Inc.
 */

#ifndef __ELBA_TLPAUXINFO_PD_H__
#define __ELBA_TLPAUXINFO_PD_H__

/*
 * For indirect or notify transactions, the hardware delivers
 * this auxiliary information along with the pcie tlp.
 */
typedef struct tlpauxinfo_s {
    uint64_t spare              :3;
    uint64_t wqebpdbxen         :1;
    uint64_t wqebpsize          :2;
    uint64_t direct_blen        :4;
    uint64_t is_indirect        :1;
    uint64_t is_direct          :1;
    uint64_t is_ur              :1;
    uint64_t is_ca              :1;
    uint64_t romsksel           :7;
    uint64_t context_id         :7;
    uint64_t vfid               :11;
    uint64_t is_notify          :1;
    uint64_t direct_size        :9;
    uint64_t direct_addr        :52;
    uint64_t aspace             :1;
    uint64_t pmti               :10;
    uint64_t pmt_hit            :1;
    uint64_t indirect_reason    :5;
    uint64_t is_host            :1;
    uint64_t axilen             :4;
    uint64_t rsrv               :1;
    uint64_t wqetype            :1;     /* wqe type, 0=wqe, 1=doorbell */
    uint64_t wqebpdben          :1;     /* wqe bypass doorbell enable */
    uint64_t eop                :1;
    uint64_t sop                :1;
} __attribute__((packed)) tlpauxinfo_t;

#endif /* __ELBA_TLPAUXINFO_PD_H__ */
