/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, 2025, AMD and/or its affiliates.
 */
#include "kpcimgr_api.h"

void kpcimgr_init_intr(kstate_t *ks);
void kpcimgr_init_fn(kstate_t *ks);
void kpcimgr_version_fn(char **);
void kpcimgr_init_poll(kstate_t *);
void kpcimgr_poll(kstate_t *, int, int);
int kpcimgr_ind_intr(kstate_t *ks, int);
int kpcimgr_not_intr(kstate_t *ks, int);
void kpcimgr_undefined_entry(void);
void kpcimgr_features(long *, long, long, long);
void kpcimgr_reboot(long , long, long, long);
unsigned long kpcimgr_get_holding_pen(unsigned long old_entry,
				      unsigned int cpu, unsigned long ks_paddr);

int pciesvc_sysfs_cmd_read(kstate_t *ks, char *buf, loff_t off, size_t count, int *exists);
int pciesvc_sysfs_cmd_write(kstate_t *ks, char *buf, loff_t off, size_t count, int *exists);
