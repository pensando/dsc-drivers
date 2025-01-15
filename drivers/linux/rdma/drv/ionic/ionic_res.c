// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "ionic_res.h"

#ifndef ORDER_PER_LONG
/* Order of bits per long for 64 bit (2^6 is 64).
 *
 * On 32 bit, order should actually be 5, but here is still using the value 6.
 * This leads to a corner case that is not optmized, but has correct behavior.
 */
#define ORDER_PER_LONG 6
#endif

int ionic_resid_init(struct ionic_resid_bits *resid, int size)
{
	int size_bytes = sizeof(long) * BITS_TO_LONGS(size);

	resid->next_id = 0;
	resid->inuse_size = size;

	resid->inuse = kzalloc(size_bytes, GFP_KERNEL);
	if (!resid->inuse)
		return -ENOMEM;

	return 0;
}

int ionic_resid_get_shared(struct ionic_resid_bits *resid, int wrap_id,
			   int next_id, int size)
{
	int id;

	id = find_next_zero_bit(resid->inuse, size, next_id);
	if (id != size) {
		set_bit(id, resid->inuse);
		return id;
	}

	id = find_next_zero_bit(resid->inuse, next_id, wrap_id);
	if (id != next_id) {
		set_bit(id, resid->inuse);
		return id;
	}

	return -ENOMEM;
}

int ionic_buddy_init(struct ionic_buddy_bits *buddy, int size)
{
	buddy->inuse_size = size;
	buddy->inuse_longs = BITS_TO_LONGS(size);
	buddy->inuse = kcalloc(buddy->inuse_longs, sizeof(long), GFP_KERNEL);
	if (!buddy->inuse)
		goto err_inuse;

	buddy->order_max = ilog2(size);
	buddy->order_next = kcalloc(buddy->order_max + 1,
				    sizeof(*buddy->order_next),
				    GFP_KERNEL);
	if (!buddy->order_next)
		goto err_order;

	return 0;

err_order:
	kfree(buddy->inuse);
err_inuse:
	return -ENOMEM;
}

int ionic_buddy_get(struct ionic_buddy_bits *buddy, int order)
{
	int rc, i, pos, first_long, next_long, align_longs;

	/* order must fit in overall capacity */
	if (order > buddy->order_max)
		return -ENOMEM;

	first_long = buddy->order_next[order];

	/* capacity must be available at that order */
	if (first_long >= buddy->inuse_longs)
		return -ENOMEM;

	pos = first_long * BITS_PER_LONG;

	/* find, but skip ahead to first_long to speed up search */
	rc = bitmap_find_free_region(buddy->inuse + first_long,
				     buddy->inuse_size - pos,
				     order);
	if (rc < 0) {
		pos = buddy->inuse_size;
	} else {
		pos += rc;
		rc = pos;
	}

	/* On success and also on failure, update the next indices.
	 *
	 * If allocation at this order did not succeed, then neither will
	 * allocation at any larger order.  However, it may still be possible
	 * to allocate at a smaller order.
	 *
	 * If allocation did succeed, we know that this order and any larger
	 * order will not succeed at an earlier position than next_long.
	 * Likewise for any smaller order, if it would have come from the range
	 * just allocated.
	 */

	first_long = BIT_WORD(pos);
	next_long = BIT_WORD(pos + BIT(order));

	/* any smaller order after this starts at next_long */
	if (order >= ORDER_PER_LONG && rc >= 0) {
		for (i = 0; i < order; ++i) {
			if (buddy->order_next[i] >= first_long)
				buddy->order_next[i] = next_long;
		}
	}

	/* any larger order before this starts at later alignment */
	for (i = order; i <= buddy->order_max; ++i) {
		if (buddy->order_next[i] <= first_long) {
			/* min alignment of 1, align to order i */
			align_longs = BIT_WORD(BIT(i)) ?: 1;
			/* start at next_long aligned up to order i */
			buddy->order_next[i] = ALIGN(next_long, align_longs);
		}
	}

	return rc;
}

void ionic_buddy_put(struct ionic_buddy_bits *buddy, int pos, int order)
{
	int i, first_long, mask_longs;

	bitmap_release_region(buddy->inuse, pos, order);

	first_long = BIT_WORD(pos);

	/* any smaller order after this starts at first_long */
	for (i = 0; i < order; ++i) {
		if (buddy->order_next[i] >= first_long)
			buddy->order_next[i] = first_long;
	}

	/* any larger order starts at earlier alignment */
	for (i = order; i <= buddy->order_max; ++i) {
		if (buddy->order_next[i] >= first_long) {
			/* min alignment of 1, align to order i, and mask */
			mask_longs = ~((BIT_WORD(BIT(i)) ?: 1) - 1);
			/* start at first_long aligned down to order i */
			buddy->order_next[i] = first_long & mask_longs;
		}
	}
}
