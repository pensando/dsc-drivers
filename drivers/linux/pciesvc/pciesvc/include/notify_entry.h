/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018,2021, Pensando Systems Inc.
 */

#ifndef __NOTIFY_ENTRY_H__
#define __NOTIFY_ENTRY_H__

#include "tlpauxinfo.h"

#if defined(ASIC_SALINA) && defined(HW)
#define NOTIFY_TLPSZ            44
#else
#define NOTIFY_TLPSZ            48
#endif

typedef struct notify_entry_s {
    uint8_t rtlp[NOTIFY_TLPSZ];
    tlpauxinfo_t info;
#ifdef ASIC_SALINA
    /* asic 18bit padding, 2bit in info and 16bit below */
    uint8_t reserved[2];
#endif
} __attribute__((packed)) notify_entry_t;

#endif /* __NOTIFY_ENTRY_H__ */
