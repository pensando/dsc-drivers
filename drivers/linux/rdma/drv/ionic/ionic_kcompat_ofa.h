/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_KCOMPAT_OFA_H
#define IONIC_KCOMPAT_OFA_H

/* There is no semantic versioning for OFED kernel api.
 *
 * Instead, our makefile detects the presence of an ofed stack, and if present
 * it defines OFA_KERNEL with hash from the compat_version file at the top of
 * the ofa kernel, eg, /usr/src/ofa_kernel/default/compat_version.  That
 * compat_version is just a unique hash for that particular version of ofed,
 * not a semantic version number.
 *
 * Then below, we encode compatibility for each _specific_ version of ofed that
 * we support.  We will support a minimal number of ofed stacks as an
 * out-of-ofed driver.
 *
 *
 * This compatibility support is fragile, because ofed can be bugfixed by
 * vendor with no minor version change, but then ofed compat_version hash can
 * still change, breaking compatibility.  To resolve the new hash to compat
 * ofed configuration, add one more line like the following, to this file:
 *
 *	#define OFA_COMPAT_xxxxyyy		MLNX_OFED_4_5
 */

/* MLNX_OFED_LINUX-4.2-1.2.0.0-debian9.0-x86_64 */
#define OFA_COMPAT_f8de107		MLNX_OFED_4_2

#define MLNX_OFED_4_2__support		1
#define MLNX_OFED_4_2__umem_get		1
#define MLNX_OFED_4_2__4_14a		1
#define MLNX_OFED_4_2__4_14c		1
#define MLNX_OFED_4_2__4_15		1
#define MLNX_OFED_4_2__4_17		1
#define MLNX_OFED_4_2__4_19a		1
#define MLNX_OFED_4_2__4_19b		1
#define MLNX_OFED_4_2__4_19c		1
#define MLNX_OFED_4_2__4_20		1
#define MLNX_OFED_4_2__5_0		1
#define MLNX_OFED_4_2__5_1		1
#define MLNX_OFED_4_2__5_2a		1
#define MLNX_OFED_4_2__5_2b		1
#define MLNX_OFED_4_2__5_3		1
#define MLNX_OFED_4_2__5_5		1
#define MLNX_OFED_4_2__FUTURE		1

/* MLNX_OFED_LINUX-4.4-1.0.0.0-ubuntu18.04-x86_64 */
#define OFA_COMPAT_d647238		MLNX_OFED_4_4

#define MLNX_OFED_4_4__support		1
#define MLNX_OFED_4_4__umem_get		1
#define MLNX_OFED_4_4__reg_user_mr	1
#define MLNX_OFED_4_4__4_17		1
#define MLNX_OFED_4_4__4_19b		1
#define MLNX_OFED_4_4__4_19c		1
#define MLNX_OFED_4_4__4_20		1
#define MLNX_OFED_4_4__5_0		1
#define MLNX_OFED_4_4__5_1		1
#define MLNX_OFED_4_4__5_2a		1
#define MLNX_OFED_4_4__5_2b		1
#define MLNX_OFED_4_4__5_3		1
#define MLNX_OFED_4_4__5_5		1
#define MLNX_OFED_4_4__FUTURE		1

/* MLNX_OFED_LINUX-4.5-1.0.1.0-debian9.0-x86_64 */
/* MLNX_OFED_LINUX-4.5-1.0.1.0-ubuntu18.04-x86_64 */
#define OFA_COMPAT_b4fdfac		MLNX_OFED_4_5

#define MLNX_OFED_4_5__support		1
#define MLNX_OFED_4_5__umem_get		1
#define MLNX_OFED_4_5__reg_user_mr	1
#define MLNX_OFED_4_5__4_19b		1
#define MLNX_OFED_4_5__4_20		1
#define MLNX_OFED_4_5__5_0		1
#define MLNX_OFED_4_5__5_1		1
#define MLNX_OFED_4_5__5_2a		1
#define MLNX_OFED_4_5__5_2b		1
#define MLNX_OFED_4_5__5_3		1
#define MLNX_OFED_4_5__5_5		1
#define MLNX_OFED_4_5__FUTURE		1

/* MLNX_OFED_LINUX-4.6-1.0.1.1-ubuntu18.04-x86_64 */
#define OFA_COMPAT_a2cfe08		MLNX_OFED_4_6

#define MLNX_OFED_4_6__support		1
#define MLNX_OFED_4_6__umem_get		1
#define MLNX_OFED_4_6__reg_user_mr	1
#define MLNX_OFED_4_6__5_0		1
#define MLNX_OFED_4_6__5_1		1
#define MLNX_OFED_4_6__5_2a		1
#define MLNX_OFED_4_6__5_2b		1
#define MLNX_OFED_4_6__5_3		1
#define MLNX_OFED_4_6__FUTURE		1

/* MLNX_OFED_LINUX-4.7-3.2.9.0-rhel7.6-x86_64 */
#define OFA_COMPAT_457f064		MLNX_OFED_4_7

#define MLNX_OFED_4_7__support		1
#define MLNX_OFED_4_7__umem_get_udata	1
#define MLNX_OFED_4_7__reg_user_mr	1
#define MLNX_OFED_4_7__xarray		1
#define MLNX_OFED_4_7__5_2b		1
#define MLNX_OFED_4_7__5_3		1
#define MLNX_OFED_4_7__FUTURE		1

/* MLNX_OFED_LINUX-5.4-3.1.0.0-ubuntu20.04-x86_64 */
#define OFA_COMPAT_49f69b0		MLNX_OFED_5_4

#define MLNX_OFED_5_4__support		1
#define MLNX_OFED_5_4__xarray		1
#define MLNX_OFED_5_4__peermem		1
#define MLNX_OFED_5_4__FUTURE		1

/* MLNX_OFED_LINUX-23.10-1.1.9.0-ubuntu22.04-x86_64 */
#define OFA_COMPAT_a675be0		MLNX_OFED_23_10

#define MLNX_OFED_23_10__support	1
#define MLNX_OFED_23_10__xarray		1
#define MLNX_OFED_23_10__peermem	1
#define MLNX_OFED_23_10__FUTURE		1

/* MLNX_OFED_LINUX-24.04-0.6.6.0-ubuntu22.04-x86_64 */
#define OFA_COMPAT_7037b8d		MLNX_OFED_24_04

#define MLNX_OFED_24_04__support	1
#define MLNX_OFED_24_04__xarray		1
#define MLNX_OFED_24_04__peermem	1
#define MLNX_OFED_24_04__FUTURE		1


/* macro magic...
 * OFA_COMPAT_CHECK(OFA_KERNEL, OFA)
 * -> _OFA_COMPAT_CHECK(OFA_COMPAT_ ## f8de107, support)
 * -> __OFA_COMPAT_CHECK(OFA_COMPAT_f8de107, support)
 * -> ___OFA_COMPAT_CHECK(MLNX_OFED_4_2, support)
 * -> MLNX_OFED_4_2__support
 */
#define OFA_COMPAT_CHECK(OFA_KERNEL, OFA) \
	_OFA_COMPAT_CHECK(OFA_KERNEL, OFA)
#define _OFA_COMPAT_CHECK(OFA_KERNEL, OFA) \
	__OFA_COMPAT_CHECK(OFA_COMPAT_ ## OFA_KERNEL, OFA)
#define __OFA_COMPAT_CHECK(OFA_COMPAT, OFA) \
	___OFA_COMPAT_CHECK(OFA_COMPAT, OFA)
#define ___OFA_COMPAT_CHECK(OFA_COMPAT, OFA) \
	OFA_COMPAT ## __ ## OFA

#define BROKEN_IBDEV_PRINT

#endif /* IONIC_KCOMPAT_OFA_H */
