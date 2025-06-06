/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2017-2018,2021, Pensando Systems Inc.
 */

#ifndef __PCIESVC_PRT_H__
#define __PCIESVC_PRT_H__

#ifdef ASIC_CAPRI
#include "capri/prtpd.h"
#endif
#ifdef ASIC_ELBA
#include "elba/prtpd.h"
#endif
#ifdef ASIC_SALINA
#include "salina/prtpd.h"
#endif

/* terminator index for chained prts */
#define PRT_INVALID     ((u_int16_t)-1)

/* for PRT.type */
#define PRT_TYPE_RES    0       /* resource */
#define PRT_TYPE_DB64   1       /* 64-bit doorbells */
#define PRT_TYPE_DB32   2       /* 32-bit doorbells */
#define PRT_TYPE_DB16   3       /* 16-bit doorbells */

/* for PRT.res.wqebpsize */
#define PRT_WQEBP_SZ64  0       /*  64B aligned WQEs */
#define PRT_WQEBP_SZ128 1       /* 128B aligned WQEs */
#define PRT_WQEBP_SZ256 2       /* 256B aligned WQEs */
#define PRT_WQEBP_SZ512 3       /* 512B aligned WQEs */

/* for PRT.db.updvec */
#define PRT_UPD_SCHED_NONE      0x00 /* no scheduler request */
#define PRT_UPD_SCHED_EVAL      0x01 /* scheduler eval pi/ci */
#define PRT_UPD_SCHED_CLEAR     0x02 /* scheduler clear */
#define PRT_UPD_SCHED_SET       0x03 /* scheduler set */
#define PRT_UPD_SCHED_MASK      0x03 /* sched bit mask */
#define PRT_UPD_PICI_CISET      0x04 /* set ci */
#define PRT_UPD_PICI_PISET      0x08 /* set pi */
#define PRT_UPD_PICI_PIINC      0x0c /* increment pi */
#define PRT_UPD_PICI_MASK       0x0c /* pici bit mask */
#define PRT_UPD_PID_CHECK       0x10 /* check pid */

/* PRT entry */
typedef union prt_u {
    prt_cmn_t cmn;
    prt_res_t res;
    prt_db_t db;
    u_int32_t w[PRT_NWORDS];
} prt_t;

static inline int
prt_is_valid(const prt_t *prt)
{
    return prt->cmn.valid;
}

static inline u_int32_t
prt_type(const prt_t *prt)
{
    return prt->cmn.type;
}

#endif /* __PCIESVC_PRT_H__ */
