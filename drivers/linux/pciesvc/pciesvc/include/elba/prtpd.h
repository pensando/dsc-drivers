/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Advanced Micro Devices Inc.
 */

#ifndef __PCIESVC_ELBA_PRTPD_H__
#define __PCIESVC_ELBA_PRTPD_H__

#ifdef __cplusplus
extern "C" {
#if 0
} /* close to calm emacs autoindent */
#endif
#endif

/******************************************************************
 * PCIe Resource Table (PRT)
 *
 * PRT entry is the table entry by PMT to describe
 * bar match table resources and handling.
 */

#ifdef RTOS
#define PRT_COUNT       CONFIG_PCIEHW_PRT_COUNT
#else
#define PRT_COUNT       4096
#endif
#define PRT_NWORDS      3

#define PRT_CMN_FIELDS                                      \
    u_int64_t valid     :1;     /* entry is valid */        \
    u_int64_t type      :2;     /* PRT_TYPE_* */            \
    u_int64_t indirect  :1;     /* sw handles tlp */        \
    u_int64_t notify    :1;     /* notify sw */             \
    u_int64_t vfstride  :5      /* power-of-2 stride added to addr */

/* common prt entry format */
typedef struct {
    PRT_CMN_FIELDS;
} __attribute__((packed)) prt_cmn_t;

/* resource prt entry format */
typedef struct {
    PRT_CMN_FIELDS;
    u_int64_t aspace    :1;     /* target address space, 1=external (pcie) */
    u_int64_t addrdw    :50;    /* target resource address */
    u_int64_t sizedw    :11;    /* encoded resource size */
    u_int64_t pmvdis    :1;     /* disable Programming Model Violation check */
    u_int64_t wqebpen   :1;     /* WQE bypass enable */
    u_int64_t wqebpsize :2;     /* WQE bypass entry size encoded */
    u_int64_t wqebpdben :1;     /* WQE bypass doorbell enable */
    u_int64_t spare     :8;     /* implemented but unused in hw */
    u_int64_t rsrv      :43;    /* unimplemented bits */
} __attribute__((packed)) prt_res_t;

/* db64/db32/db16 prt entry format */
typedef struct {
    PRT_CMN_FIELDS;
    u_int64_t lif       :11;    /* target LIF */
    u_int64_t updvec    :40;    /* 8x5-bit UPD field, indexed by qtype */
    u_int64_t stridesel :2;     /* selects vfstride, 0=VF, 1={VF,LIF} */
    u_int64_t idxshift  :2;     /* db16/32: index location in data */
    u_int64_t idxwidth  :4;     /* db16/32: index width    in data */
    u_int64_t qidshift  :2;     /* db16/32: qid   location in data */
    u_int64_t qidwidth  :4;     /* db16/32: qid   width    in data */
    u_int64_t qidsel    :1;     /* db16/32: qid source select, 0=data 1=addr */
    u_int64_t dbbussel  :1;     /* doorbell bus select, 0=prp, 1=express */
    u_int64_t spare     :8;     /* implemented but unused in hw */
    u_int64_t rsrv      :43;    /* unimplemented bits */
} __attribute__((packed)) prt_db_t;

#ifdef __cplusplus
}
#endif

#endif /* __PCIESVC_ELBA_PRTPD_H__ */
