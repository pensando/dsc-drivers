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
#include "pciesvc_impl.h"
#include "version.h"

extern char pciesvc_end;
extern void kpcimgr_init_intr(void *);
extern void kpcimgr_init_fn(void *);
extern void kpcimgr_version_fn(char **);
extern void kpcimgr_init_poll(kstate_t *);
extern void pciesvc_shut(int);
extern void kpcimgr_poll(kstate_t *, int, int);
extern unsigned long kpcimgr_get_holding_pen(unsigned long, unsigned int);
extern int kpcimgr_ind_intr(void *, int);
extern int kpcimgr_not_intr(void *, int);
extern void kpcimgr_undefined_entry(void);
extern int pciesvc_sysfs_cmd_read(void *, char *, int *);
extern int pciesvc_sysfs_cmd_write(void *, char *, size_t, int *);
extern void kpcimgr_features(long *, long, long, long);
extern void kpcimgr_reboot(long , long, long, long);

extern int pciesvc_version_major;
extern int pciesvc_version_minor;

struct kpcimgr_entry_points_t ep;
#define EXPECTED_MGR_VERSION 3
int expected_mgr_version = EXPECTED_MGR_VERSION;

struct kpcimgr_entry_points_t *kpci_get_entry_points(void)
{
	int i;

	/* initialize entry_points struct via executable code so that
	 * PC relative relocations are generated */
	ep.expected_mgr_version = expected_mgr_version;
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
	ep.entry_point[K_ENTRY_FEATURES] = kpcimgr_features;
	ep.entry_point[K_ENTRY_REBOOT] = kpcimgr_reboot;

	return &ep;
}

#ifndef __KERNEL__

struct fw_info_t pciesvc_info_space __attribute__((section(".pciesvc_info"))) =
{
	.expected_mgr_version = EXPECTED_MGR_VERSION,
	.lib_version_major = PCIESVC_VERSION_MAJ,
	.lib_version_minor = PCIESVC_VERSION_MIN,
	.valid = FW_INFO_MAGIC_V1,
	.features = FLAG_PSCI | FLAG_GUEST,
	.build_time = PCIESVC_VERSION,
	.code_offsets = {
		kpcimgr_init_intr,
		kpcimgr_init_poll,
		pciesvc_shut,
		kpcimgr_poll,
		kpcimgr_get_holding_pen,
		kpcimgr_ind_intr,
		kpcimgr_not_intr,
		kpcimgr_init_fn,
		pciesvc_sysfs_cmd_read,
		pciesvc_sysfs_cmd_write,
		kpcimgr_version_fn,
		kpcimgr_features,
		kpcimgr_reboot,
		kpcimgr_undefined_entry,
		kpcimgr_undefined_entry,
		kpcimgr_undefined_entry,
	},
	.reserved = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};
#endif
