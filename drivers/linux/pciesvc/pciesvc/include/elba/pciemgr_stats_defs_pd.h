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

#ifndef PCIEMGR_STATS_DEF
#define PCIEMGR_STATS_DEF(st, desc)
#endif

PCIEMGR_STATS_DEF(not_intr, "total notify interrupts")
PCIEMGR_STATS_DEF(not_spurious, "notify spurious interrupts")
PCIEMGR_STATS_DEF(not_polled, "notify interrupts processed by polling")
PCIEMGR_STATS_DEF(not_cnt, "total notify messages processed")
PCIEMGR_STATS_DEF(not_max, "notify ring max pici delta")
PCIEMGR_STATS_DEF(not_cfgrd, "notify config reads")
PCIEMGR_STATS_DEF(not_cfgwr, "notify config writes")
PCIEMGR_STATS_DEF(not_memrd, "notify memory reads")
PCIEMGR_STATS_DEF(not_memwr, "notify memory writes")
PCIEMGR_STATS_DEF(not_iord, "notify io reads")
PCIEMGR_STATS_DEF(not_iowr, "notify io writes")
PCIEMGR_STATS_DEF(not_unknown, "notify unknown")

#define notify_reason_stats not_rsrv0
PCIEMGR_STATS_DEF(not_rsrv0, "notify reason - reserved 0")
PCIEMGR_STATS_DEF(not_rsrv1, "notify reason - reserved 1")
PCIEMGR_STATS_DEF(not_msg, "notify reason - pcie message")
PCIEMGR_STATS_DEF(not_unsupported, "notify reason - unsupported TLP type")
PCIEMGR_STATS_DEF(not_pmv, "notify reason - programming model violation")
PCIEMGR_STATS_DEF(not_dbpmv, "notify reason - doorbell PMV")
PCIEMGR_STATS_DEF(not_atomic, "notify reason - atomic request")
PCIEMGR_STATS_DEF(not_pmtmiss, "notify reason - PMT miss")
PCIEMGR_STATS_DEF(not_pmrmiss, "notify reason - PMR miss")
PCIEMGR_STATS_DEF(not_prtmiss, "notify reason - PRT miss")
PCIEMGR_STATS_DEF(not_bdf2vfidmiss, "notify reason - RC BDF2VFID table miss")
PCIEMGR_STATS_DEF(not_prtoor, "notify reason - PRT out of range")
PCIEMGR_STATS_DEF(not_vfidoor, "notify reason - VFID out of range")
PCIEMGR_STATS_DEF(not_bdfoor, "notify reason - BDF out of range")
PCIEMGR_STATS_DEF(not_pmrind, "notify reason - PMR force indirect")
PCIEMGR_STATS_DEF(not_prtind, "notify reason - PRT force indirect")
PCIEMGR_STATS_DEF(not_pmrecc, "notify reason - PMR ecc error")
PCIEMGR_STATS_DEF(not_prtecc, "notify reason - PRT ecc error")

PCIEMGR_STATS_DEF(ind_intr, "total indirect interrupts")
PCIEMGR_STATS_DEF(ind_spurious, "indirect spurios interrupts")
PCIEMGR_STATS_DEF(ind_polled, "indirect interrupts processed by polling")
PCIEMGR_STATS_DEF(ind_cfgrd, "indirect config reads")
PCIEMGR_STATS_DEF(ind_cfgwr, "indirect config writes")
PCIEMGR_STATS_DEF(ind_memrd, "indirect memory reads")
PCIEMGR_STATS_DEF(ind_memwr, "indirect memory writes")
PCIEMGR_STATS_DEF(ind_iord, "indirect io reads")
PCIEMGR_STATS_DEF(ind_iowr, "indirect io writes")
PCIEMGR_STATS_DEF(ind_unknown, "indirect unknown")

PCIEMGR_STATS_DEF(healthlog, "Healthlog events")

#undef PCIEMGR_STATS_DEF
