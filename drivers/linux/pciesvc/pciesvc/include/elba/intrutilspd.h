/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Advanced Micro Devices Inc.
 */

#ifndef __PCIESVC_ELBA_INTRUTILSPD_H__
#define __PCIESVC_ELBA_INTRUTILSPD_H__

#ifdef __cplusplus
extern "C" {
#if 0
} /* close to calm emacs autoindent */
#endif
#endif

typedef union intr_fwcfg_u {
    struct {
        u_int32_t function_mask:1;
        u_int32_t rsrv:31;
        u_int32_t lif:11;
        u_int32_t port_id:3;
        u_int32_t local_int:1;
        u_int32_t legacy:1;
        u_int32_t int_pin:2;
        u_int32_t rsrv2:14;
    } __attribute__((packed));
    u_int32_t w[2];
} intr_fwcfg_t;

typedef union intr_state_s {
    struct {
        u_int64_t msixcfg_msg_addr:50;
        u_int64_t msixcfg_msg_data:32;
        u_int64_t msixcfg_vector_ctrl:1;
        u_int64_t fwcfg_function_mask:1;
        u_int64_t fwcfg_lif:11;
        u_int64_t fwcfg_local_int:1;
        u_int64_t fwcfg_legacy_int:1;
        u_int64_t fwcfg_legacy_pin:2;
        u_int64_t drvcfg_mask:1;
          int64_t drvcfg_int_credits:16; /* signed */
        u_int64_t drvcfg_mask_on_assert:1;
        u_int64_t fwcfg_port_id:3;
    } __attribute__((packed));
    u_int32_t w[4];
} intr_state_t;

#ifdef __cplusplus
}
#endif

#endif /* __PCIESVC_ELBA_INTRUTILSPD_H__ */
