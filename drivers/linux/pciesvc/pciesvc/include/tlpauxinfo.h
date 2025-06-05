/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018,2020, Pensando Systems Inc.
 */

#ifndef __TLPAUXINFO_H__
#define __TLPAUXINFO_H__

#ifdef ASIC_CAPRI
#include "capri/tlpauxinfopd.h"
#endif
#ifdef ASIC_ELBA
#include "elba/tlpauxinfopd.h"
#endif
#ifdef ASIC_SALINA
#include "salina/tlpauxinfopd.h"
#endif

#endif /* __TLPAUXINFO_H__ */
