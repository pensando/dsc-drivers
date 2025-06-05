/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Pensando Systems Inc.
 */

#ifndef __GVE_H__
#define __GVE_H__

u_int64_t
gve_barrd(pciehwdev_t *phwdev, u_int64_t addr,
          const u_int64_t baroff, const size_t size,
          u_int8_t *do_notify);

void
gve_barwr(pciehwdev_t *phwdev, u_int64_t addr,
          const u_int64_t baroff, const size_t size, const u_int64_t val,
          u_int8_t *do_notify);

#endif /* __GVE_H__ */
