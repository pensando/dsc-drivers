/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 * Copyright (c) 2023, Advanced Micro Devices Inc.
 */

#ifndef __ASIC_REGS_H__
#define __ASIC_REGS_H__

#ifdef ASIC_CAPRI
#include "asic_regs_capri.h"
#endif
#ifdef ASIC_ELBA
#include "asic_regs_elba.h"
#endif
#ifdef ASIC_SALINA
#include "asic_regs_salina.h"
#endif

#endif /* __ASIC_REGS_H__ */
