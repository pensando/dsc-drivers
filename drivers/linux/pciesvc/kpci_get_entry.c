//
// Copyright(C) Advanced Micro Devices, Inc. All rights reserved.
//
// You may not use this software and documentation (if any) (collectively,
// the "Materials") except in compliance with the terms and conditions of
// the Software License Agreement included with the Materials or otherwise as
// set forth in writing and signed by you and an authorized signatory of AMD.
// If you do not have a copy of the Software License Agreement, contact your
// AMD representative for a copy.
//
// You agree that you will not reverse engineer or decompile the Materials,
// in whole or in part, except as allowed by applicable law.
//
// THE MATERIALS ARE DISTRIBUTED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
// REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//


#include "kpcimgr_api.h"

struct kpcimgr_entry_points_t *kpci_get_entry_points(void);

extern char pciesvc_end;
extern void kpcimgr_init_intr(void *);
extern void kpcimgr_init_fn(void *);
extern void kpcimgr_version_fn(char **);
extern void kpcimgr_init_poll(void *);
extern void pciesvc_shut(int);
extern void kpcimgr_poll(kstate_t *, int, int);
extern unsigned long kpcimgr_get_holding_pen(unsigned long, unsigned int);
extern int kpcimgr_ind_intr(void *, int);
extern int kpcimgr_not_intr(void *, int);
extern void kpcimgr_undefined_entry(void);
extern int pciesvc_sysfs_cmd_read(void *, char *, int *);
extern int pciesvc_sysfs_cmd_write(void *, char *, unsigned long, int *);

extern int pciesvc_version_major;
extern int pciesvc_version_minor;

struct kpcimgr_entry_points_t ep;

struct kpcimgr_entry_points_t *kpci_get_entry_points(void)
{
	int i;

	/* initialize entry_points struct via executable code so that
	 * PC relative relocations are generated */
	ep.expected_mgr_version = 3;
	ep.lib_version_major = pciesvc_version_major;
	ep.lib_version_minor = pciesvc_version_minor;
	ep.code_end = &pciesvc_end;

	for (i=0; i<K_NUM_ENTRIES; i++)
		ep.entry_point[i] = kpcimgr_undefined_entry;

	ep.entry_point[K_ENTRY_INIT_INTR] = kpcimgr_init_intr;
	ep.entry_point[K_ENTRY_INIT_POLL] = kpcimgr_init_poll;
	ep.entry_point[K_ENTRY_SHUT] = pciesvc_shut;
	ep.entry_point[K_ENTRY_POLL] = kpcimgr_poll;
	ep.entry_point[K_ENTRY_HOLDING_PEN] = kpcimgr_get_holding_pen;
	ep.entry_point[K_ENTRY_INDIRECT_INTR] = kpcimgr_ind_intr;
	ep.entry_point[K_ENTRY_NOTIFY_INTR] = kpcimgr_not_intr;
	ep.entry_point[K_ENTRY_INIT_FN] = kpcimgr_init_fn;
	ep.entry_point[K_ENTRY_CMD_READ] = pciesvc_sysfs_cmd_read;
	ep.entry_point[K_ENTRY_CMD_WRITE] = pciesvc_sysfs_cmd_write;
	ep.entry_point[K_ENTRY_GET_VERSION] = kpcimgr_version_fn;

	return &ep;
}
