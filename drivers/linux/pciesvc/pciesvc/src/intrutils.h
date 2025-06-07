/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018-2019,2022, Pensando Systems Inc.
 */

#ifndef __INTRUTILS_H__
#define __INTRUTILS_H__

#ifdef __cplusplus
extern "C" {
#if 0
} /* close to calm emacs autoindent */
#endif
#endif

#ifdef ASIC_CAPRI
#include "capri/intrutilspd.h"
#endif
#ifdef ASIC_ELBA
#include "elba/intrutilspd.h"
#endif
#ifdef ASIC_SALINA
#include "salina/intrutilspd.h"
#endif

typedef struct intr_drvcfg_s {
    u_int32_t coal_init;
    u_int32_t mask;
    u_int32_t int_credits;
    u_int32_t mask_on_assert;
    u_int32_t coal_curr;
} __attribute__((packed)) intr_drvcfg_t;

typedef struct intr_msixcfg_s {
    u_int64_t msgaddr;
    u_int32_t msgdata;
    u_int32_t vector_ctrl;
} __attribute__((packed)) intr_msixcfg_t;

/* override these to avoid static link dups */
#define intr_assert_addr        _pciesvc_intr_assert_addr
#define intr_assert_data        _pciesvc_intr_assert_data
#define intr_assert             _pciesvc_intr_assert
#define intr_deassert           _pciesvc_intr_deassert
#define intr_drvcfg_mask        _pciesvc_intr_drvcfg_mask
#define intr_fwcfg_mode         _pciesvc_intr_fwcfg_mode
#define intr_reset_pci          _pciesvc_intr_reset_pci
#define intr_pba_clear          _pciesvc_intr_pba_clear
#define intr_config_local_msi   _pciesvc_intr_config_local_msi

u_int64_t intr_assert_addr(const int intr);
u_int32_t intr_assert_data(void);
void intr_assert(const int intr);
void intr_deassert(const int intr);
int intr_drvcfg_mask(const int intr, const int on);
void intr_fwcfg_mode(const int intr, const int legacy, const int fmask);
int intr_config_local_msi(const int intr, u_int64_t msgaddr, u_int32_t msgdata);

u_int32_t intr_pba_clear(const int intr);

/*
 * intr_reset_pci() - reset the pcie managed register groups to default values,
 *                    use for pcie block resets (FLR, bus reset).
 */
void intr_reset_pci(const int intrb, const int intrc, const int dmask);

#ifdef __cplusplus
}
#endif

#endif /* __INTRUTILS_H__ */
