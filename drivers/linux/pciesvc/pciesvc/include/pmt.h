/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2017-2018, Pensando Systems Inc.
 */

#ifndef __PCIESVC_PMT_H__
#define __PCIESVC_PMT_H__

#ifdef ASIC_CAPRI
#include "capri/pmtpd.h"
#endif
#ifdef ASIC_ELBA
#include "elba/pmtpd.h"
#endif
#ifdef ASIC_SALINA
#include "salina/pmtpd.h"
#endif

/* terminator index for chained pmts */
#define PMT_INVALID     ((u_int16_t)-1)

/*
 * pmt_alloc priority.
 * Lower pmtpri corresponds to lower index in tcam so higher priority.
 */
typedef enum pmtpri_e {
    PMTPRI_HIGH,                        /* high priority in tcam */
    PMTPRI_LOW,                         /* low priority in tcam */
    PMTPRI_VF0ADJ,                      /* vf0 adjust entry */

    PMTPRI_CFG = PMTPRI_HIGH,           /* cfg space pmt entry */
    PMTPRI_BAR = PMTPRI_HIGH,           /* bar pmt entry */
    PMTPRI_FLEXVF = PMTPRI_LOW,         /* flexvf bar pmt default entry */
    PMTPRI_FLEXVFOVRD = PMTPRI_HIGH,    /* flexvf bar pmt override entry */
} pmtpri_t;

/* defines for PMT.type and PMR.type fields */
#define PMT_TYPE_CFG    0       /* host cfg */
#define PMT_TYPE_MEM    1       /* host mem bar */
#define PMT_TYPE_RC     2       /* rc dma */
#define PMT_TYPE_IO     5       /* host I/O bar */

/* data and mask format used to describe pmt_tcam_t format */
typedef struct pmt_datamask_s {
    pmt_format_t data;
    pmt_format_t mask;
} pmt_datamask_t;

/* tcam entry as words for reading/writing to hw */
typedef union pmt_entry_u {
    pmt_tcam_t tcam;
    u_int32_t w[PMT_NWORDS];
} pmt_entry_t;

/* PMR entry format */
typedef union {
    pmr_cfg_entry_t cfg;
    pmr_bar_entry_t bar;
    u_int32_t w[PMR_NWORDS];
} pmr_entry_t;

/* full PMT/PMR entry */
typedef struct pmt_s {
    pmt_entry_t pmte;
    pmr_entry_t pmre;
} pmt_t;

#endif /* __PCIESVC_PMT_H__ */
