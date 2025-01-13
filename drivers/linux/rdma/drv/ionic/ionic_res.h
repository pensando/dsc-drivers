/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_RES_H
#define IONIC_RES_H

/**
 * struct ionic_resid_bits - Number allocator based on find_first_zero_bit
 *
 * The allocator find_first_zero_bit suffers O(N^2) search time complexity,
 * for N allocations.  This is because it starts from the beginning of the
 * bitmap each time.  To find a free bit in the bitmap, the search time
 * increases for each allocation as the beginning of the bitmap is filled.  On
 * the other hand, it is desirable for O(1) memory size complexity, assuming
 * the capacity is constant.
 *
 * This allocator is intended to keep the desired memory size complexity, but
 * improve the search time complexity for typical workloads.  The search time
 * complexity is expected to be closer to O(N), for N allocations, although it
 * remains bounded by O(N^2) in the worst case.
 */
struct ionic_resid_bits {
	int next_id;
	int inuse_size;
	unsigned long *inuse;
};

/**
 * ionic_resid_init() - Initialize a resid allocator
 * @resid:	Uninitialized resid allocator
 * @size:	Capacity of the allocator
 *
 * Return: Zero on success, or negative error number
 */
int ionic_resid_init(struct ionic_resid_bits *resid, int size);

/**
 * ionic_resid_destroy() - Destroy a resid allocator
 * @resid:	Resid allocator
 */
static inline void ionic_resid_destroy(struct ionic_resid_bits *resid)
{
	kfree(resid->inuse);
}

/**
 * ionic_resid_get_shared() - Allocate an available shared resource id
 * @resid:	Resid allocator
 * @wrap_id:	Smallest valid resource id
 * @next_id:	Start the search at resource id
 * @size:	One after largest valid resource id
 *
 * This does not update the next_id.  Caller should update the next_id for for
 * the resource that shares the id space, and/or the shared resid->next_id as
 * appropriate.
 *
 * Return: Resource id, or negative error number
 */
int ionic_resid_get_shared(struct ionic_resid_bits *resid, int wrap_id,
			   int next_id, int size);

/**
 * ionic_resid_get_wrap() - Allocate an available resource id, wrap to nonzero
 * @resid:	Resid allocator
 * @wrap_id:	Smallest valid resource id
 *
 * Return: Resource id, or negative error number
 */
static inline int ionic_resid_get_wrap(struct ionic_resid_bits *resid,
				       int wrap_id)
{
	int rc;

	rc = ionic_resid_get_shared(resid, wrap_id,
				    resid->next_id,
				    resid->inuse_size);
	if (rc >= 0)
		resid->next_id = rc + 1;

	return rc;
}

/**
 * ionic_resid_get() - Allocate an available resource id
 * @resid:	Resid allocator
 *
 * Return: Resource id, or negative error number
 */
static inline int ionic_resid_get(struct ionic_resid_bits *resid)
{
	return ionic_resid_get_wrap(resid, 0);
}

/**
 * ionic_resid_put() - Free a resource id
 * @resid:	Resid allocator
 * @id:		Resource id
 */
static inline void ionic_resid_put(struct ionic_resid_bits *resid, int id)
{
	clear_bit(id, resid->inuse);
}

/**
 * ionic_bitid_to_qid() - Transform a resource bit index into a queue id
 * @bitid:	Bit index
 * @qgrp_shift	Log2 number of queues per queue group
 * @half_qid_shift Log2 of half the total number of queues
 *
 * Return: Queue id
 *
 * Udma-constrained queues (QPs and CQs) are associated with their udma by queue group.
 * Even queue groups are associated with udma0, and odd queue groups with udma1.
 *
 * For allocating queue ids, we want to arrange the bits into two halves, with the even
 * queue groups of udma0 in the lower half of the bitset, and the odd queue groups of
 * udma1 in the upper half of the bitset.  Then, one or two calls of find_next_zero_bit
 * can examine all the bits for queues of an entire udma.
 *
 * For example, assuming eight queue groups with qgrp qids per group:
 *
 * bitid 0*qgrp..1*qgrp-1 : qid 0*qgrp..1*qgrp-1
 * bitid 1*qgrp..2*qgrp-1 : qid 2*qgrp..3*qgrp-1
 * bitid 2*qgrp..3*qgrp-1 : qid 4*qgrp..5*qgrp-1
 * bitid 3*qgrp..4*qgrp-1 : qid 6*qgrp..7*qgrp-1
 * bitid 4*qgrp..5*qgrp-1 : qid 1*qgrp..2*qgrp-1
 * bitid 5*qgrp..6*qgrp-1 : qid 3*qgrp..4*qgrp-1
 * bitid 6*qgrp..7*qgrp-1 : qid 5*qgrp..6*qgrp-1
 * bitid 7*qgrp..8*qgrp-1 : qid 7*qgrp..8*qgrp-1
 *
 * There are three important ranges of bits in the qid.  There is the udma bit "U" at
 * qgrp_shift, which is the least significant bit of the group index, and determines
 * which udma a queue is associated with.  The bits of lesser significance we can call
 * the idx bits "I", which are the index of the queue within the group.  The bits of
 * greater significance we can call the grp bits "G", which are other bits of the group
 * index that do not determine the udma.  Those bits are just rearranged in the bit index
 * in the bitset.  A bitid has the udma bit in the most significant place, then the grp
 * bits, then the idx bits.
 *
 * bitid: 00000000000000 U GGG IIIIII
 * qid:   00000000000000 GGG U IIIIII
 *
 * Transforming from bit index to qid, or from qid to bit index, can be accomplished by
 * rearranging the bits by masking and shifting.
 */
static inline u32 ionic_bitid_to_qid(u32 bitid, u8 qgrp_shift, u8 half_qid_shift)
{
	u32 udma_bit = (bitid & BIT(half_qid_shift)) >> (half_qid_shift - qgrp_shift);
	u32 grp_bits = (bitid & GENMASK(half_qid_shift - 1, qgrp_shift)) << 1;
	u32 idx_bits = bitid & (BIT(qgrp_shift) - 1);

	return grp_bits | udma_bit | idx_bits;
}

/**
 * ionic_qid_to_bitid() - Transform a queue id into a resource bit index
 * @bitid:	Bit index
 * @qgrp_shift	Log2 number of queues per queue group
 * @half_qid_shift Log2 of half the total number of queues
 *
 * Return: Resource bit index
 *
 * This is the inverse of ionic_bitid_to_qid().
 */
static inline u32 ionic_qid_to_bitid(u32 qid, u8 qgrp_shift, u8 half_qid_shift)
{
	u32 udma_bit = (qid & BIT(qgrp_shift)) << (half_qid_shift - qgrp_shift);
	u32 grp_bits = (qid & GENMASK(half_qid_shift, qgrp_shift + 1)) >> 1;
	u32 idx_bits = qid & (BIT(qgrp_shift) - 1);

	return udma_bit | grp_bits | idx_bits;
}

/**
 * struct ionic_buddy_bits - Buddy allocator based on bitmap_find_free_region
 *
 * The allocator bitmap_find_free_region suffers O(N^2) search time complexity,
 * for N allocations.  This is because it starts from the beginning of the
 * bitmap each time.  To find a free range of bits in the bitmap, the search
 * time increases for each allocation as the beginning of the bitmap is filled.
 * On the other hand, it is desirable for O(1) memory size complexity, assuming
 * the capacity is constant.
 *
 * This allocator is intended to keep the desired memory size complexity, but
 * improve the search time complexity for typical workloads.  The search time
 * complexity is expected to be closer N, for N allocations, although it
 * remains bounded by O(N^2) in the worst case.
 */
struct ionic_buddy_bits {
	int inuse_size;
	int inuse_longs;
	unsigned long *inuse;
	int order_max;
	int *order_next;
};

/**
 * ionic_buddy_init() - Initialize a buddy allocator
 * @buddy:	Uninitialized buddy allocator
 * @size:	Capacity of the allocator
 *
 * Return: Zero on success, or negative error number
 */
int ionic_buddy_init(struct ionic_buddy_bits *buddy, int size);

/**
 * ionic_buddy_destroy() - Destroy a buddy allocator
 * @buddy:	Buddy allocator
 */
static inline void ionic_buddy_destroy(struct ionic_buddy_bits *buddy)
{
	kfree(buddy->order_next);
	kfree(buddy->inuse);
}

/**
 * ionic_buddy_get() - Allocate an order-sized range
 * @buddy:	Buddy allocator
 * @order:	Log size of the range to get
 *
 * Return: Position of the start of the range, or negative error number
 */
int ionic_buddy_get(struct ionic_buddy_bits *buddy, int order);

/**
 * ionic_buddy_put() - Free an order-sized range
 * @buddy:	Buddy allocator
 * @pos:	Position of the start of the range
 * @order:	Log size of the range to put
 */
void ionic_buddy_put(struct ionic_buddy_bits *buddy, int pos, int order);

#endif /* IONIC_RES_H */
