// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Pensando Systems, Inc */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <net/ip6_checksum.h>
#include <linux/skbuff.h>

#include "ionic.h"
#include "ionic_lif.h"
#include "ionic_txrx.h"

#define CREATE_TRACE_POINTS
#include "ionic_trace.h"

#define IONIC_RX_PAGE_FLAG_UNMAP	BIT(0)
#define IONIC_RX_PAGE_FLAG_FREE		BIT(1)
#define IONIC_RX_PAGE_FLAG_CLEAR	BIT(2)
#define IONIC_RX_PAGE_FLAGS_ALL		(IONIC_RX_PAGE_FLAG_UNMAP | \
					 IONIC_RX_PAGE_FLAG_FREE | \
					 IONIC_RX_PAGE_FLAG_CLEAR)

static int ionic_maybe_stop_tx(struct net_device *netdev, struct ionic_queue *q,
			       int ndescs);

static dma_addr_t ionic_tx_map_single(struct ionic_queue *q,
				      void *data, size_t len);

static dma_addr_t ionic_tx_map_frag(struct ionic_queue *q,
				    const skb_frag_t *frag,
				    size_t offset, size_t len);

static void ionic_tx_desc_unmap_bufs(struct ionic_queue *q,
				     struct ionic_tx_desc_info *desc_info);

static void ionic_tx_clean(struct ionic_queue *q,
			   struct ionic_tx_desc_info *desc_info,
			   struct ionic_txq_comp *comp,
			   bool in_napi);

static inline void ionic_txq_post(struct ionic_queue *q, bool ring_dbell)
{
	DEBUG_STATS_TXQ_POST(q, ring_dbell);

	ionic_q_post(q, ring_dbell);
}

static inline void ionic_rxq_post(struct ionic_queue *q, bool ring_dbell)
{
	ionic_q_post(q, ring_dbell);

	DEBUG_STATS_RX_BUFF_CNT(q);
}

bool ionic_txq_poke_doorbell(struct ionic_queue *q)
{
	struct netdev_queue *netdev_txq;
	unsigned long now, then, dif;
	struct net_device *netdev;

	netdev = q->lif->netdev;
	netdev_txq = netdev_get_tx_queue(netdev, q->index);

	HARD_TX_LOCK(netdev, netdev_txq, smp_processor_id());

	if (q->tail_idx == q->head_idx) {
		HARD_TX_UNLOCK(netdev, netdev_txq);
		return false;
	}

	now = READ_ONCE(jiffies);
	then = q->dbell_jiffies;
	dif = now - then;

	if (dif > q->dbell_deadline) {
		ionic_dbell_ring(q->lif->kern_dbpage, q->hw_type,
				 q->dbval | q->head_idx);

		q->dbell_jiffies = now;
	}

	HARD_TX_UNLOCK(netdev, netdev_txq);

	return true;
}

bool ionic_rxq_poke_doorbell(struct ionic_queue *q)
{
	unsigned long now, then, dif;

	/* no lock, called from rx napi or txrx napi, nothing else can fill */

	if (q->tail_idx == q->head_idx)
		return false;

	now = READ_ONCE(jiffies);
	then = q->dbell_jiffies;
	dif = now - then;

	if (dif > q->dbell_deadline) {
		ionic_dbell_ring(q->lif->kern_dbpage, q->hw_type,
				 q->dbval | q->head_idx);

		q->dbell_jiffies = now;

		dif = 2 * q->dbell_deadline;
		if (dif > IONIC_RX_MAX_DOORBELL_DEADLINE)
			dif = IONIC_RX_MAX_DOORBELL_DEADLINE;

		q->dbell_deadline = dif;
	}

	return true;
}

static inline struct ionic_txq_sg_elem *ionic_tx_sg_elems(struct ionic_queue *q)
{
	if (likely(q->sg_desc_size == sizeof(struct ionic_txq_sg_desc_v1)))
		return q->txq_sgl_v1[q->head_idx].elems;
	else
		return q->txq_sgl[q->head_idx].elems;
}

static inline struct netdev_queue *q_to_ndq(struct net_device *netdev,
					    struct ionic_queue *q)
{
	return netdev_get_tx_queue(netdev, q->index);
}

static void *ionic_rx_buf_va(struct ionic_buf_info *buf_info)
{
	return page_address(buf_info->page) + buf_info->page_offset;
}

static dma_addr_t ionic_rx_buf_pa(struct ionic_buf_info *buf_info)
{
	return buf_info->dma_addr + buf_info->page_offset;
}

static unsigned int ionic_rx_buf_size(struct ionic_buf_info *buf_info)
{
	return min_t(u32, IONIC_MAX_BUF_LEN, IONIC_PAGE_SIZE - buf_info->page_offset);
}

static bool ionic_rx_cache_put(struct ionic_queue *q,
			       struct ionic_buf_info *buf_info)
{
	struct ionic_rx_stats *stats = q_to_rx_stats(q);
	struct ionic_page_cache *cache = q->page_cache;
	u32 tail_next;

	tail_next = (cache->tail + 1) & (IONIC_PAGE_CACHE_SIZE - 1);
	if (tail_next == cache->head) {
		stats->cache_full++;
		return false;
	}

	get_page(buf_info->page);

	cache->ring[cache->tail] = *buf_info;
	cache->tail = tail_next;
	stats->cache_put++;

	return true;
}

static bool ionic_rx_cache_get(struct ionic_queue *q,
			       struct ionic_buf_info *buf_info)
{
	struct ionic_rx_stats *stats = q_to_rx_stats(q);
	struct ionic_page_cache *cache = q->page_cache;

	if (unlikely(cache->head == cache->tail)) {
		stats->cache_empty++;
		return false;
	}

	if (page_ref_count(cache->ring[cache->head].page) != 1) {
		stats->cache_busy++;
		return false;
	}

	*buf_info = cache->ring[cache->head];
	cache->head = (cache->head + 1) & (IONIC_PAGE_CACHE_SIZE - 1);
	stats->cache_get++;

	dma_sync_single_range_for_device(q->dev, buf_info->dma_addr,
					 0, IONIC_PAGE_SIZE, DMA_FROM_DEVICE);

	return true;
}

static void ionic_rx_cache_drain(struct ionic_queue *q)
{
	struct ionic_rx_stats *stats = q_to_rx_stats(q);
	struct ionic_page_cache *cache = q->page_cache;
	struct ionic_buf_info *buf_info;

	while (cache->head != cache->tail) {
		buf_info = &cache->ring[cache->head];
		dma_unmap_page(q->dev, buf_info->dma_addr, IONIC_PAGE_SIZE,
			       DMA_FROM_DEVICE);
		put_page(buf_info->page);
		cache->head = (cache->head + 1) & (IONIC_PAGE_CACHE_SIZE - 1);
	}

	cache->head = 0;
	cache->tail = 0;
	stats->cache_empty = 0;
	stats->cache_busy = 0;
	stats->cache_get = 0;
	stats->cache_put = 0;
	stats->cache_full = 0;
}

static bool ionic_rx_buf_reuse(struct ionic_queue *q,
			       struct ionic_buf_info *buf_info, u32 used)
{
	struct ionic_rx_stats *stats = q_to_rx_stats(q);
	u32 size;

	if (!dev_page_is_reusable(buf_info->page)) {
		stats->buf_not_reusable++;
		return false;
	}

	size = ALIGN(used, q->xdp_rxq_info ? IONIC_PAGE_SIZE : IONIC_PAGE_SPLIT_SZ);
	buf_info->page_offset += size;
	if (buf_info->page_offset >= IONIC_PAGE_SIZE) {
		buf_info->page_offset = 0;
		stats->buf_exhausted++;
		return false;
	}

	stats->buf_reused++;

	get_page(buf_info->page);

	return true;
}

static void ionic_rx_buf_complete(struct ionic_queue *q,
				  struct ionic_buf_info *buf_info, u32 used)
{
	if (ionic_rx_buf_reuse(q, buf_info, used))
		return;

	if (!ionic_rx_cache_put(q, buf_info)) {
#ifndef HAVE_STRUCT_DMA_ATTRS
		dma_unmap_page_attrs(q->dev, buf_info->dma_addr, IONIC_PAGE_SIZE,
				     DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
#else
		dma_unmap_page(q->dev, buf_info->dma_addr, IONIC_PAGE_SIZE, DMA_FROM_DEVICE);
#endif
	}

	buf_info->page = NULL;
}

static inline int ionic_rx_page_alloc(struct ionic_queue *q,
				      struct ionic_buf_info *buf_info)
{
	struct device *dev = q->dev;
	dma_addr_t dma_addr;
	struct page *page;

	if (ionic_rx_cache_get(q, buf_info))
		return 0;

	page = alloc_pages_node(dev_to_node(dev), IONIC_PAGE_GFP_MASK, IONIC_PAGE_ORDER);
	if (unlikely(!page)) {
		net_err_ratelimited("%s: %s page alloc failed\n",
				    dev_name(dev), q->name);
		q_to_rx_stats(q)->alloc_err++;
		return -ENOMEM;
	}

	dma_addr = dma_map_page(dev, page, 0,
				IONIC_PAGE_SIZE, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(dev, dma_addr))) {
		__free_pages(page, IONIC_PAGE_ORDER);
		net_err_ratelimited("%s: %s dma map failed\n",
				    dev_name(dev), q->name);
		q_to_rx_stats(q)->dma_map_err++;
		return -EIO;
	}

	buf_info->dma_addr = dma_addr;
	buf_info->page = page;
	buf_info->page_offset = 0;

	return 0;
}

static inline void ionic_rx_page_release(struct ionic_queue *q,
					 struct ionic_buf_info *buf_info,
					 u8 flags)
{
	struct device *dev = q->dev;

	if (unlikely(!buf_info)) {
		net_err_ratelimited("%s: %s invalid buf_info in free\n",
				    dev_name(dev), q->name);
		return;
	}

	if (flags & IONIC_RX_PAGE_FLAG_UNMAP)
		dma_unmap_page(dev, buf_info->dma_addr, IONIC_PAGE_SIZE, DMA_FROM_DEVICE);
	if (buf_info->page && (flags & IONIC_RX_PAGE_FLAG_FREE)) {
		__free_pages(buf_info->page, IONIC_PAGE_ORDER);
		buf_info->page = NULL;
	} else if (flags & IONIC_RX_PAGE_FLAG_CLEAR) {
		buf_info->page = NULL;
	}
}

static void ionic_rx_add_skb_frag(struct ionic_queue *q,
				  struct sk_buff *skb,
				  struct ionic_buf_info *buf_info,
				  u32 off, u32 len,
				  bool synced)
{
	if (!synced)
		dma_sync_single_range_for_cpu(q->dev, ionic_rx_buf_pa(buf_info),
					      off, len, DMA_FROM_DEVICE);

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			buf_info->page, buf_info->page_offset + off,
			len,
			IONIC_PAGE_SIZE);

	ionic_rx_buf_complete(q, buf_info, off + len);
}

static struct sk_buff *ionic_rx_build_skb(struct ionic_queue *q,
					  struct ionic_rx_desc_info *desc_info,
					  unsigned int headroom,
					  unsigned int len,
					  unsigned int num_sg_elems,
					  bool synced)
{
	struct ionic_buf_info *buf_info;
	struct sk_buff *skb;
	unsigned int i;
	u16 frag_len;

	buf_info = &desc_info->bufs[0];
	prefetchw(buf_info->page);

	skb = napi_get_frags(&q_to_qcq(q)->napi);
	if (unlikely(!skb)) {
		net_warn_ratelimited("%s: SKB alloc failed on %s!\n",
				     dev_name(q->dev), q->name);
		q_to_rx_stats(q)->alloc_err++;
		return NULL;
	}

	if (headroom)
		frag_len = min_t(u16, len,
				 IONIC_XDP_MAX_LINEAR_MTU + VLAN_ETH_HLEN);
	else
		frag_len = min_t(u16, len, ionic_rx_buf_size(buf_info));

	if (unlikely(!buf_info->page))
		goto err_bad_buf_page;
	ionic_rx_add_skb_frag(q, skb, buf_info, headroom, frag_len, synced);
	len -= frag_len;
	buf_info++;

	for (i = 0; i < num_sg_elems; i++, buf_info++) {
		if (unlikely(!buf_info->page))
			goto err_bad_buf_page;
		frag_len = min_t(u16, len, ionic_rx_buf_size(buf_info));
		ionic_rx_add_skb_frag(q, skb, buf_info, 0, frag_len, synced);
		len -= frag_len;
	}

	return skb;

err_bad_buf_page:
	dev_kfree_skb(skb);
	return NULL;

}

static struct sk_buff *ionic_rx_copybreak(struct net_device *netdev,
					  struct ionic_queue *q,
					  struct ionic_rx_desc_info *desc_info,
					  unsigned int headroom,
					  u16 len,
					  bool synced)
{
	struct ionic_buf_info *buf_info;
	struct device *dev = q->dev;
	struct sk_buff *skb;

	buf_info = &desc_info->bufs[0];

	skb = napi_alloc_skb(&q_to_qcq(q)->napi, len);
	if (unlikely(!skb)) {
		net_warn_ratelimited("%s: SKB alloc failed on %s!\n",
				     dev_name(dev), q->name);
		q_to_rx_stats(q)->alloc_err++;
		return NULL;
	}

	if (unlikely(!buf_info->page)) {
		dev_kfree_skb(skb);
		return NULL;
	}

	if (!synced)
		dma_sync_single_range_for_cpu(dev, ionic_rx_buf_pa(buf_info),
					      headroom, len, DMA_FROM_DEVICE);
	skb_copy_to_linear_data(skb, ionic_rx_buf_va(buf_info) + headroom, len);
	dma_sync_single_range_for_device(dev, ionic_rx_buf_pa(buf_info),
					 headroom, len, DMA_FROM_DEVICE);

	skb_put(skb, len);
	skb->protocol = eth_type_trans(skb, netdev);

	return skb;
}

#ifdef HAVE_NET_XDP
static void ionic_xdp_rx_page_release(struct ionic_queue *q,
				      struct ionic_buf_info *buf_info,
				      int nfrags, u8 flags)
{
	int i;

	for (i = 0; i < nfrags + 1; i++, buf_info++)
		ionic_rx_page_release(q, buf_info, flags);
}

static void ionic_xdp_tx_desc_clean(struct ionic_queue *q,
				    struct ionic_tx_desc_info *desc_info)
{
	unsigned int nbufs = desc_info->nbufs;
	struct ionic_buf_info *buf_info;
	struct device *dev = q->dev;
	int i;

	if (!nbufs)
		return;

	buf_info = desc_info->bufs;
	dma_unmap_single(dev, buf_info->dma_addr,
			 buf_info->len, DMA_TO_DEVICE);
	if (desc_info->act == XDP_TX)
		__free_pages(buf_info->page, IONIC_PAGE_ORDER);
	buf_info->page = NULL;

	buf_info++;
	for (i = 1; i < nbufs + 1 && buf_info->page; i++, buf_info++) {
		dma_unmap_page(dev, buf_info->dma_addr,
			       buf_info->len, DMA_TO_DEVICE);
		if (desc_info->act == XDP_TX)
			__free_pages(buf_info->page, IONIC_PAGE_ORDER);
		buf_info->page = NULL;
	}

	if (desc_info->act == XDP_REDIRECT)
		xdp_return_frame(desc_info->xdpf);

	desc_info->nbufs = 0;
	desc_info->xdpf = NULL;
	desc_info->act = 0;
}

static int ionic_xdp_post_frame(struct ionic_queue *q, struct xdp_frame *frame,
				enum xdp_action act, struct page *page, int off,
				bool ring_doorbell)
{
	struct ionic_tx_desc_info *desc_info;
	struct ionic_buf_info *buf_info;
	struct ionic_tx_stats *stats;
	struct ionic_txq_desc *desc;
	size_t len = frame->len;
	dma_addr_t dma_addr;
	u64 cmd;

	desc_info = &q->tx_info[q->head_idx];
	desc = &q->txq[q->head_idx];
	buf_info = desc_info->bufs;
	stats = q_to_tx_stats(q);

	dma_addr = ionic_tx_map_single(q, frame->data, len);
	if (!dma_addr)
		return -EIO;
	buf_info->dma_addr = dma_addr;
	buf_info->len = len;
	buf_info->page = page;
	buf_info->page_offset = off;

	desc_info->nbufs = 1;
	desc_info->xdpf = frame;
	desc_info->act = act;

#ifdef HAVE_NET_XDP_FRAGS
	if (xdp_frame_has_frags(frame)) {
		struct ionic_txq_sg_elem *elem;
		struct skb_shared_info *sinfo;
		struct ionic_buf_info *bi;
		skb_frag_t *frag;
		int i;

		bi = &buf_info[1];
		sinfo = xdp_get_shared_info_from_frame(frame);
		frag = sinfo->frags;
		elem = ionic_tx_sg_elems(q);
		for (i = 0; i < sinfo->nr_frags; i++, frag++, bi++) {
			dma_addr = ionic_tx_map_frag(q, frag, 0, skb_frag_size(frag));
			if (!dma_addr) {
				ionic_tx_desc_unmap_bufs(q, desc_info);
				return -EIO;
			}
			bi->dma_addr = dma_addr;
			bi->len = skb_frag_size(frag);
			bi->page = skb_frag_page(frag);

			elem->addr = cpu_to_le64(bi->dma_addr);
			elem->len = cpu_to_le16(bi->len);
			elem++;

			desc_info->nbufs++;
		}
	}
#endif
	cmd = encode_txq_desc_cmd(IONIC_TXQ_DESC_OPCODE_CSUM_NONE,
				  0, (desc_info->nbufs - 1), buf_info->dma_addr);
	desc->cmd = cpu_to_le64(cmd);
	desc->len = cpu_to_le16(len);
	desc->csum_start = 0;
	desc->csum_offset = 0;

	stats->xdp_frames++;
	stats->pkts++;
	stats->bytes += len;

	ionic_txq_post(q, ring_doorbell);

	return 0;
}

int ionic_xdp_xmit(struct net_device *netdev, int n,
		   struct xdp_frame **xdp_frames, u32 flags)
{
	struct ionic_lif *lif = netdev_priv(netdev);
	struct ionic_queue *txq;
	struct netdev_queue *nq;
	int nxmit;
	int space;
	int cpu;
	int qi;

	if (unlikely(!test_bit(IONIC_LIF_F_UP, lif->state)))
		return -ENETDOWN;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	/* AdminQ is assumed on cpu 0, while we attempt to affinitize the
	 * TxRx queue pairs 0..n-1 on cpus 1..n.  We try to keep with that
	 * affinitization here, but of course irqbalance and friends might
	 * have juggled things anyway, so we have to check for the 0 case.
	 */
	cpu = smp_processor_id();
	qi = cpu ? (cpu - 1) % lif->nxqs : cpu;

	txq = &lif->txqcqs[qi]->q;
	nq = netdev_get_tx_queue(netdev, txq->index);
	__netif_tx_lock(nq, cpu);
	txq_trans_cond_update(nq);

	if (netif_tx_queue_stopped(nq) ||
	    unlikely(ionic_maybe_stop_tx(netdev, txq, 1))) {
		__netif_tx_unlock(nq);
		return -EIO;
	}

	space = min_t(int, n, ionic_q_space_avail(txq));
	for (nxmit = 0; nxmit < space ; nxmit++) {
		if (ionic_xdp_post_frame(txq, xdp_frames[nxmit],
					 XDP_REDIRECT,
					 virt_to_page(xdp_frames[nxmit]->data),
					 0, false)) {
			nxmit--;
			break;
		}
	}

	if (flags & XDP_XMIT_FLUSH)
		ionic_dbell_ring(lif->kern_dbpage, txq->hw_type,
				 txq->dbval | txq->head_idx);

	ionic_maybe_stop_tx(netdev, txq, 4);
	__netif_tx_unlock(nq);

	return nxmit;
}

static bool ionic_run_xdp(struct ionic_rx_stats *stats,
			  struct net_device *netdev,
			  struct bpf_prog *xdp_prog,
			  struct ionic_queue *rxq,
			  struct ionic_buf_info *buf_info,
			  int len)
{
	/* unmap and free all buffers in most XDP abort cases */
	u8 rx_page_flags = IONIC_RX_PAGE_FLAGS_ALL;
	u32 xdp_action = XDP_ABORTED;
	struct xdp_buff xdp_buf;
	struct ionic_queue *txq;
	struct netdev_queue *nq;
	struct xdp_frame *xdpf;
	int remain_len;
	int nfrags = 0;
	int frag_len;
	int err = 0;

	xdp_init_buff(&xdp_buf, IONIC_PAGE_SIZE, rxq->xdp_rxq_info);
	frag_len = min_t(u16, len, IONIC_XDP_MAX_LINEAR_MTU + VLAN_ETH_HLEN);
	xdp_prepare_buff(&xdp_buf, ionic_rx_buf_va(buf_info),
			 XDP_PACKET_HEADROOM, frag_len, false);

	dma_sync_single_range_for_cpu(rxq->dev, ionic_rx_buf_pa(buf_info),
				      XDP_PACKET_HEADROOM, frag_len,
				      DMA_FROM_DEVICE);

	prefetchw(&xdp_buf.data_hard_start);

	/*  We limit MTU size to one buffer if !xdp_has_frags, so
	 *  if the recv len is bigger than one buffer
	 *     then we know we have frag info to gather
	 */
	remain_len = len - frag_len;
	if (remain_len) {
#ifdef HAVE_NET_XDP_FRAGS
		struct skb_shared_info *sinfo;
		struct ionic_buf_info *bi;
		skb_frag_t *frag;

		bi = buf_info;
		sinfo = xdp_get_shared_info_from_buff(&xdp_buf);
		sinfo->nr_frags = 0;
		sinfo->xdp_frags_size = 0;
		xdp_buff_set_frags_flag(&xdp_buf);

		do {
			if (unlikely(sinfo->nr_frags >= MAX_SKB_FRAGS)) {
				err = -ENOSPC;
				goto out_xdp_abort;
			}

			frag = &sinfo->frags[sinfo->nr_frags];
			sinfo->nr_frags++;
			nfrags++;
			bi++;
			frag_len = min_t(u16, remain_len, ionic_rx_buf_size(bi));
			dma_sync_single_range_for_cpu(rxq->dev, ionic_rx_buf_pa(bi),
						      0, frag_len, DMA_FROM_DEVICE);
			skb_frag_fill_page_desc(frag, bi->page, 0, frag_len);
			sinfo->xdp_frags_size += frag_len;
			remain_len -= frag_len;

			if (page_is_pfmemalloc(bi->page))
				xdp_buff_set_frag_pfmemalloc(&xdp_buf);
		} while (remain_len > 0);
#else
		netdev_dbg(netdev, "%s: len err remain_len %d\n",  __func__,
			   remain_len);
		goto out_xdp_abort;
#endif
	}

	xdp_action = bpf_prog_run_xdp(xdp_prog, &xdp_buf);

	switch (xdp_action) {
	case XDP_PASS:
		stats->xdp_pass++;
		return false;  /* false = we didn't consume the packet */

	case XDP_DROP:
		ionic_xdp_rx_page_release(rxq, buf_info, nfrags,
					  IONIC_RX_PAGE_FLAGS_ALL);
		stats->xdp_drop++;
		break;

	case XDP_TX:
		xdpf = xdp_convert_buff_to_frame(&xdp_buf);
		if (!xdpf)
			goto out_xdp_abort;

		txq = rxq->partner;
		nq = netdev_get_tx_queue(netdev, txq->index);
		__netif_tx_lock(nq, smp_processor_id());
		txq_trans_cond_update(nq);

		if (netif_tx_queue_stopped(nq) ||
		    unlikely(ionic_maybe_stop_tx(netdev, txq, 1))) {
			__netif_tx_unlock(nq);
			goto out_xdp_abort;
		}

		ionic_xdp_rx_page_release(rxq, buf_info, nfrags,
					  IONIC_RX_PAGE_FLAG_UNMAP);

		err = ionic_xdp_post_frame(txq, xdpf, XDP_TX,
					   buf_info->page,
					   buf_info->page_offset,
					   true);
		__netif_tx_unlock(nq);
		if (unlikely(err)) {
			netdev_dbg(netdev, "tx ionic_xdp_post_frame err %d\n", err);
			rx_page_flags = IONIC_RX_PAGE_FLAG_FREE;
			goto out_xdp_abort;
		}
		stats->xdp_tx++;

		/* the Tx completion will free the buffers */
		ionic_xdp_rx_page_release(rxq, buf_info, nfrags,
					  IONIC_RX_PAGE_FLAG_CLEAR);
		break;

	case XDP_REDIRECT:
		/* unmap the pages before handing them to a different device */
		ionic_xdp_rx_page_release(rxq, buf_info, nfrags,
					  IONIC_RX_PAGE_FLAG_UNMAP);

		err = xdp_do_redirect(netdev, &xdp_buf, xdp_prog);
		if (unlikely(err)) {
			netdev_dbg(netdev, "xdp_do_redirect err %d\n", err);
			rx_page_flags = IONIC_RX_PAGE_FLAG_FREE;
			goto out_xdp_abort;
		}
		ionic_xdp_rx_page_release(rxq, buf_info, nfrags,
					  IONIC_RX_PAGE_FLAG_CLEAR);
		rxq->xdp_flush = true;
		stats->xdp_redirect++;
		break;

	case XDP_ABORTED:
	default:
		goto out_xdp_abort;
	}

	return true;

out_xdp_abort:
	ionic_xdp_rx_page_release(rxq, buf_info, nfrags, rx_page_flags);
	trace_xdp_exception(netdev, xdp_prog, xdp_action);
	stats->xdp_aborted++;

	return true;
}
#endif

static void ionic_rx_clean(struct ionic_queue *q,
			   struct ionic_rx_desc_info *desc_info,
			   struct ionic_rxq_comp *comp)
{
	struct net_device *netdev = q->lif->netdev;
	struct ionic_qcq *qcq = q_to_qcq(q);
	struct ionic_rx_stats *stats;
#ifdef HAVE_NET_XDP
	struct bpf_prog *xdp_prog;
#endif
	unsigned int headroom;
	struct sk_buff *skb;
	bool synced = false;
	bool use_copybreak;
#ifdef CSUM_DEBUG
	__sum16 csum;
#endif
	u16 len;

	stats = q_to_rx_stats(q);

	if (comp->status) {
		stats->dropped++;
		return;
	}

	len = le16_to_cpu(comp->len);
	stats->pkts++;
	stats->bytes += len;

#ifdef HAVE_NET_XDP
	xdp_prog = READ_ONCE(q->lif->xdp_prog);
	if (xdp_prog) {
		if (ionic_run_xdp(stats, netdev, xdp_prog, q, desc_info->bufs, len))
			return;
		synced = true;
	}
#endif

	headroom = q->xdp_rxq_info ? XDP_PACKET_HEADROOM : 0;
	use_copybreak = len <= q->lif->rx_copybreak;
	if (use_copybreak)
		skb = ionic_rx_copybreak(netdev, q, desc_info,
					 headroom, len, synced);
	else
		skb = ionic_rx_build_skb(q, desc_info, headroom, len,
					 comp->num_sg_elems, synced);
	if (unlikely(!skb)) {
		stats->dropped++;
		return;
	}

#ifdef CSUM_DEBUG
	csum = ip_compute_csum(skb->data, skb->len);
#endif

	skb_record_rx_queue(skb, q->index);

	if (likely(netdev->features & NETIF_F_RXHASH)) {
		switch (comp->pkt_type_color & IONIC_RXQ_COMP_PKT_TYPE_MASK) {
		case IONIC_PKT_TYPE_IPV4:
		case IONIC_PKT_TYPE_IPV6:
			skb_set_hash(skb, le32_to_cpu(comp->rss_hash),
				     PKT_HASH_TYPE_L3);
			break;
		case IONIC_PKT_TYPE_IPV4_TCP:
		case IONIC_PKT_TYPE_IPV6_TCP:
		case IONIC_PKT_TYPE_IPV4_UDP:
		case IONIC_PKT_TYPE_IPV6_UDP:
			skb_set_hash(skb, le32_to_cpu(comp->rss_hash),
				     PKT_HASH_TYPE_L4);
			break;
		}
	}

	if (likely(netdev->features & NETIF_F_RXCSUM) &&
	    (comp->csum_flags & IONIC_RXQ_COMP_CSUM_F_CALC)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = (__force __wsum)le16_to_cpu(comp->csum);
#ifdef IONIC_DEBUG_STATS
		stats->csum_complete++;
#endif
#ifdef CSUM_DEBUG
		if (skb->csum != (u16)~csum)
			netdev_warn(netdev, "Rx CSUM incorrect. Want 0x%04x got 0x%04x, protocol 0x%04x\n",
				    (u16)~csum, skb->csum,
				    htons(skb->protocol));
#endif
	} else {
#ifdef IONIC_DEBUG_STATS
		stats->csum_none++;
#endif
		skb->ip_summed = CHECKSUM_NONE;
	}

	if (unlikely((comp->csum_flags & IONIC_RXQ_COMP_CSUM_F_TCP_BAD) ||
		     (comp->csum_flags & IONIC_RXQ_COMP_CSUM_F_UDP_BAD) ||
		     (comp->csum_flags & IONIC_RXQ_COMP_CSUM_F_IP_BAD)))
		stats->csum_error++;

	if (likely(netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    (comp->csum_flags & IONIC_RXQ_COMP_CSUM_F_VLAN)) {
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       le16_to_cpu(comp->vlan_tci));
#ifdef IONIC_DEBUG_STATS
		stats->vlan_stripped++;
#endif
	}

	if (unlikely(q->features & IONIC_RXQ_F_HWSTAMP)) {
		__le64 *cq_desc_hwstamp;
		u64 hwstamp;

		cq_desc_hwstamp =
			(void *)comp +
			qcq->cq.desc_size -
			sizeof(struct ionic_rxq_comp) -
			IONIC_HWSTAMP_CQ_NEGOFFSET;

		hwstamp = le64_to_cpu(*cq_desc_hwstamp);

		if (hwstamp != IONIC_HWSTAMP_INVALID) {
			skb_hwtstamps(skb)->hwtstamp = ionic_lif_phc_ktime(q->lif, hwstamp);
			stats->hwstamp_valid++;
		} else {
			stats->hwstamp_invalid++;
		}
	}

	if (use_copybreak)
		napi_gro_receive(&qcq->napi, skb);
	else
		napi_gro_frags(&qcq->napi);
}

bool ionic_rx_service(struct ionic_cq *cq)
{
	struct ionic_rx_desc_info *desc_info;
	struct ionic_queue *q = cq->bound_q;
	struct ionic_rxq_comp *comp;

	comp = &((struct ionic_rxq_comp *)cq->base)[cq->tail_idx];

	if (!color_match(comp->pkt_type_color, cq->done_color))
		return false;

	/* check for empty queue */
	if (q->tail_idx == q->head_idx)
		return false;

	if (q->tail_idx != le16_to_cpu(comp->comp_index))
		return false;

	desc_info = &q->rx_info[q->tail_idx];
	q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);

	/* clean the related q entry, only one per qc completion */
	ionic_rx_clean(q, desc_info, comp);

	return true;
}

static inline void ionic_write_cmb_desc(struct ionic_queue *q,
					void *desc)
{
	/* Since Rx and Tx descriptors are the same size, we can
	 * save an instruction or two and skip the qtype check.
	 */
	if (unlikely(q_to_qcq(q)->flags & IONIC_QCQ_F_CMB_RINGS))
		memcpy_toio(&q->cmb_txq[q->head_idx], desc, sizeof(q->cmb_txq[0]));
}

void ionic_rx_fill(struct ionic_queue *q)
{
	struct net_device *netdev = q->lif->netdev;
	struct ionic_rx_desc_info *desc_info;
	struct ionic_rxq_sg_elem *sg_elem;
	struct ionic_buf_info *buf_info;
	unsigned int fill_threshold;
	struct ionic_rxq_desc *desc;
	unsigned int remain_len;
	unsigned int frag_len;
	unsigned int nfrags;
	unsigned int n_fill;
	unsigned int len;
	unsigned int i;
	unsigned int j;

	n_fill = ionic_q_space_avail(q);

	fill_threshold = min_t(unsigned int, rx_fill_threshold,
			       q->num_descs / IONIC_RX_FILL_DIV);
	if (n_fill < fill_threshold)
		return;

	len = netdev->mtu + VLAN_ETH_HLEN;

	for (i = n_fill; i; i--) {
		unsigned int headroom;
		unsigned int buf_len;

		nfrags = 0;
		remain_len = len;
		desc = &q->rxq[q->head_idx];
		desc_info = &q->rx_info[q->head_idx];
		buf_info = &desc_info->bufs[0];

		if (!buf_info->page) { /* alloc a new buffer? */
			if (unlikely(ionic_rx_page_alloc(q, buf_info))) {
				desc->addr = 0;
				desc->len = 0;
				return;
			}
		}

		/* fill main descriptor - buf[0]
		 * XDP uses space in the first buffer, so account for
		 * head room, tail room, and ip header in the first frag size.
		 */
		headroom = q->xdp_rxq_info ? XDP_PACKET_HEADROOM : 0;
		if (q->xdp_rxq_info)
			buf_len = IONIC_XDP_MAX_LINEAR_MTU + VLAN_ETH_HLEN;
		else
			buf_len = ionic_rx_buf_size(buf_info);
		frag_len = min_t(u16, len, buf_len);

		desc->addr = cpu_to_le64(ionic_rx_buf_pa(buf_info) + headroom);
		desc->len = cpu_to_le16(frag_len);
		remain_len -= frag_len;
		buf_info++;
		nfrags++;

		/* fill sg descriptors - buf[1..n] */
		sg_elem = q->rxq_sgl[q->head_idx].elems;
		for (j = 0; remain_len > 0 && j < q->max_sg_elems; j++, sg_elem++) {
			if (!buf_info->page) { /* alloc a new sg buffer? */
				if (unlikely(ionic_rx_page_alloc(q, buf_info))) {
					sg_elem->addr = 0;
					sg_elem->len = 0;
					return;
				}
			}

			sg_elem->addr = cpu_to_le64(ionic_rx_buf_pa(buf_info));
			frag_len = min_t(u16, remain_len, ionic_rx_buf_size(buf_info));
			sg_elem->len = cpu_to_le16(frag_len);
			remain_len -= frag_len;
			buf_info++;
			nfrags++;
		}

		/* clear end sg element as a sentinel */
		if (j < q->max_sg_elems)
			memset(sg_elem, 0, sizeof(*sg_elem));

		desc->opcode = (nfrags > 1) ? IONIC_RXQ_DESC_OPCODE_SG :
					      IONIC_RXQ_DESC_OPCODE_SIMPLE;
		desc_info->nbufs = nfrags;

		ionic_write_cmb_desc(q, desc);

		ionic_rxq_post(q, false);
	}

	ionic_dbell_ring(q->lif->kern_dbpage, q->hw_type,
			 q->dbval | q->head_idx);

	q->dbell_deadline = IONIC_RX_MIN_DOORBELL_DEADLINE;
	q->dbell_jiffies = jiffies;
}

void ionic_rx_empty(struct ionic_queue *q)
{
	struct ionic_rx_desc_info *desc_info;
	struct ionic_buf_info *buf_info;
	unsigned int i, j;

	for (i = 0; i < q->num_descs; i++) {
		desc_info = &q->rx_info[i];
		for (j = 0; j < IONIC_RX_MAX_SG_ELEMS + 1; j++) {
			buf_info = &desc_info->bufs[j];
			if (buf_info->page)
				ionic_rx_page_release(q, buf_info,
						      IONIC_RX_PAGE_FLAGS_ALL);
		}

		desc_info->nbufs = 0;
	}

	q->head_idx = 0;
	q->tail_idx = 0;

	ionic_rx_cache_drain(q);
}

static void ionic_dim_update(struct ionic_qcq *qcq, int napi_mode)
{
	struct dim_sample dim_sample;
	struct ionic_lif *lif;
	unsigned int qi;
	u64 pkts, bytes;

	if (!qcq->intr.dim_coal_hw)
		return;

	lif = qcq->q.lif;
	qi = qcq->cq.bound_q->index;

	switch (napi_mode) {
	case IONIC_LIF_F_TX_DIM_INTR:
		pkts = lif->txqstats[qi].pkts;
		bytes = lif->txqstats[qi].bytes;
		break;
	case IONIC_LIF_F_RX_DIM_INTR:
		pkts = lif->rxqstats[qi].pkts;
		bytes = lif->rxqstats[qi].bytes;
		break;
	default:
		pkts = lif->txqstats[qi].pkts + lif->rxqstats[qi].pkts;
		bytes = lif->txqstats[qi].bytes + lif->rxqstats[qi].bytes;
		break;
	}

	dim_update_sample_with_comps(qcq->cq.bound_intr->rearm_count,
				     pkts, bytes, 0, &dim_sample);

#if defined(IONIC_HAVE_NET_DIM_SAMPLE_PTR) && IS_ENABLED(CONFIG_DIMLIB)
	net_dim(&qcq->dim, &dim_sample);
#else
	net_dim(&qcq->dim, dim_sample);
#endif
}
int ionic_tx_napi(struct napi_struct *napi, int budget)
{
	struct ionic_qcq *qcq = napi_to_qcq(napi);
	struct ionic_cq *cq = napi_to_cq(napi);
	u32 work_done = 0;
	u32 flags = 0;

	work_done = ionic_tx_cq_service(cq, budget, !!budget);

	if (unlikely(!budget))
		return budget;

	if (work_done < budget && napi_complete_done(napi, work_done)) {
		ionic_dim_update(qcq, IONIC_LIF_F_TX_DIM_INTR);
		flags |= IONIC_INTR_CRED_UNMASK;
		cq->bound_intr->rearm_count++;
	}

	if (work_done || flags) {
		flags |= IONIC_INTR_CRED_RESET_COALESCE;
		ionic_intr_credits(cq->idev->intr_ctrl,
				   cq->bound_intr->index,
				   work_done, flags);
	}

	if (!work_done && cq->bound_q->lif->doorbell_wa)
		ionic_rxq_poke_doorbell(&qcq->q);

	DEBUG_STATS_NAPI_POLL(qcq, work_done);

	return work_done;
}

static void ionic_xdp_do_flush(struct ionic_cq *cq)
{
#ifdef HAVE_NET_XDP
	if (cq->bound_q->xdp_flush) {
		xdp_do_flush();
		cq->bound_q->xdp_flush = false;
	}
#endif
}

int ionic_rx_napi(struct napi_struct *napi, int budget)
{
	struct ionic_qcq *qcq = napi_to_qcq(napi);
	struct ionic_cq *cq = napi_to_cq(napi);
	u32 work_done = 0;
	u32 flags = 0;

	if (unlikely(!budget))
		return budget;

	work_done = ionic_cq_service(cq, budget,
				     ionic_rx_service, NULL, NULL);

	ionic_rx_fill(cq->bound_q);

	ionic_xdp_do_flush(cq);
	if (work_done < budget && napi_complete_done(napi, work_done)) {
		ionic_dim_update(qcq, IONIC_LIF_F_RX_DIM_INTR);
		flags |= IONIC_INTR_CRED_UNMASK;
		cq->bound_intr->rearm_count++;
	}

	if (work_done || flags) {
		flags |= IONIC_INTR_CRED_RESET_COALESCE;
		ionic_intr_credits(cq->idev->intr_ctrl,
				   cq->bound_intr->index,
				   work_done, flags);
	}

	if (!work_done && cq->bound_q->lif->doorbell_wa)
		ionic_rxq_poke_doorbell(&qcq->q);

	DEBUG_STATS_NAPI_POLL(qcq, work_done);

	return work_done;
}

int ionic_txrx_napi(struct napi_struct *napi, int budget)
{
	struct ionic_qcq *rxqcq = napi_to_qcq(napi);
	struct ionic_cq *rxcq = napi_to_cq(napi);
	unsigned int qi = rxcq->bound_q->index;
	struct ionic_qcq *txqcq;
	struct ionic_lif *lif;
	struct ionic_cq *txcq;
	u32 rx_work_done = 0;
	u32 tx_work_done = 0;
	u32 flags = 0;

	lif = rxcq->bound_q->lif;
	txqcq = lif->txqcqs[qi];
	txcq = &lif->txqcqs[qi]->cq;

	tx_work_done = ionic_tx_cq_service(txcq, tx_budget, !!budget);

	if (unlikely(!budget))
		return budget;

	rx_work_done = ionic_cq_service(rxcq, budget,
					ionic_rx_service, NULL, NULL);

	ionic_rx_fill(rxcq->bound_q);

	ionic_xdp_do_flush(rxcq);
	if (rx_work_done < budget && napi_complete_done(napi, rx_work_done)) {
		ionic_dim_update(rxqcq, 0);
		flags |= IONIC_INTR_CRED_UNMASK;
		rxcq->bound_intr->rearm_count++;
	}

	if (rx_work_done || flags) {
		flags |= IONIC_INTR_CRED_RESET_COALESCE;
		ionic_intr_credits(rxcq->idev->intr_ctrl, rxcq->bound_intr->index,
				   tx_work_done + rx_work_done, flags);
	}

	DEBUG_STATS_NAPI_POLL(rxqcq, rx_work_done);
	DEBUG_STATS_NAPI_POLL(txqcq, tx_work_done);

	if (lif->doorbell_wa) {
		if (!rx_work_done)
			ionic_rxq_poke_doorbell(&rxqcq->q);
		if (!tx_work_done)
			ionic_txq_poke_doorbell(&txqcq->q);
	}

	return rx_work_done;
}

static dma_addr_t ionic_tx_map_single(struct ionic_queue *q,
				      void *data, size_t len)
{
	struct device *dev = q->dev;
	dma_addr_t dma_addr;

	dma_addr = dma_map_single(dev, data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, dma_addr))) {
		net_warn_ratelimited("%s: DMA single map failed on %s!\n",
				     dev_name(dev), q->name);
		q_to_tx_stats(q)->dma_map_err++;
		return 0;
	}
	return dma_addr;
}

static dma_addr_t ionic_tx_map_frag(struct ionic_queue *q,
				    const skb_frag_t *frag,
				    size_t offset, size_t len)
{
	struct device *dev = q->dev;
	dma_addr_t dma_addr;

	dma_addr = skb_frag_dma_map(dev, frag, offset, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, dma_addr))) {
		net_warn_ratelimited("%s: DMA frag map failed on %s!\n",
				     dev_name(dev), q->name);
		q_to_tx_stats(q)->dma_map_err++;
		return 0;
	}
	return dma_addr;
}

static int ionic_tx_map_skb(struct ionic_queue *q, struct sk_buff *skb,
			    struct ionic_tx_desc_info *desc_info)
{
	struct ionic_buf_info *buf_info = desc_info->bufs;
	struct device *dev = q->dev;
	dma_addr_t dma_addr;
	unsigned int nfrags;
	skb_frag_t *frag;
	int frag_idx;

	dma_addr = ionic_tx_map_single(q, skb->data, skb_headlen(skb));
	if (!dma_addr)
		return -EIO;
	buf_info->dma_addr = dma_addr;
	buf_info->len = skb_headlen(skb);
	buf_info++;

	frag = skb_shinfo(skb)->frags;
	nfrags = skb_shinfo(skb)->nr_frags;
	for (frag_idx = 0; frag_idx < nfrags; frag_idx++, frag++) {
		dma_addr = ionic_tx_map_frag(q, frag, 0, skb_frag_size(frag));
		if (!dma_addr)
			goto dma_fail;
		buf_info->dma_addr = dma_addr;
		buf_info->len = skb_frag_size(frag);
		buf_info++;
	}

	desc_info->nbufs = 1 + nfrags;

	return 0;

dma_fail:
	/* unwind the frag mappings and the head mapping */
	while (frag_idx > 0) {
		frag_idx--;
		buf_info--;
		dma_unmap_page(dev, buf_info->dma_addr,
			       buf_info->len, DMA_TO_DEVICE);
	}
	dma_unmap_single(dev, desc_info->bufs[0].dma_addr,
			 desc_info->bufs[0].len, DMA_TO_DEVICE);
	return -EIO;
}

static void ionic_tx_desc_unmap_bufs(struct ionic_queue *q,
				     struct ionic_tx_desc_info *desc_info)
{
	struct ionic_buf_info *buf_info = desc_info->bufs;
	struct device *dev = q->dev;
	unsigned int i;

	if (!desc_info->nbufs)
		return;

	dma_unmap_single(dev, buf_info->dma_addr,
			 buf_info->len, DMA_TO_DEVICE);
	buf_info++;
	for (i = 1; i < desc_info->nbufs; i++, buf_info++)
		dma_unmap_page(dev, buf_info->dma_addr,
			       buf_info->len, DMA_TO_DEVICE);

	desc_info->nbufs = 0;
}

static void ionic_tx_clean(struct ionic_queue *q,
			   struct ionic_tx_desc_info *desc_info,
			   struct ionic_txq_comp *comp,
			   bool in_napi)
{
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
	struct ionic_qcq *qcq = q_to_qcq(q);
	struct sk_buff *skb;

#ifdef HAVE_NET_XDP
	if (desc_info->xdpf) {
		ionic_xdp_tx_desc_clean(q->partner, desc_info);
		stats->clean++;

		if (unlikely(__netif_subqueue_stopped(q->lif->netdev, q->index))) {
			netif_wake_subqueue(q->lif->netdev, q->index);
			trace_ionic_q_start(q);
			q->wake++;
		}

		return;
	}
#endif

	ionic_tx_desc_unmap_bufs(q, desc_info);

	skb = desc_info->skb;
	if (!skb)
		return;

	if (unlikely(ionic_txq_hwstamp_enabled(q))) {
		if (comp) {
			struct skb_shared_hwtstamps hwts = {};
			__le64 *cq_desc_hwstamp;
			u64 hwstamp;

			cq_desc_hwstamp =
				(void *)comp +
				qcq->cq.desc_size -
				sizeof(struct ionic_txq_comp) -
				IONIC_HWSTAMP_CQ_NEGOFFSET;

			hwstamp = le64_to_cpu(*cq_desc_hwstamp);

			if (hwstamp != IONIC_HWSTAMP_INVALID) {
				hwts.hwtstamp = ionic_lif_phc_ktime(q->lif, hwstamp);

				skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
				skb_tstamp_tx(skb, &hwts);

				stats->hwstamp_valid++;
			} else {
				stats->hwstamp_invalid++;
			}
		}
	}

	desc_info->bytes = skb->len;
	stats->clean++;

	napi_consume_skb(skb, likely(in_napi) ? 1 : 0);
}

static bool ionic_tx_service(struct ionic_cq *cq,
			     unsigned int *total_pkts,
			     unsigned int *total_bytes,
			     bool in_napi)
{
	struct ionic_tx_desc_info *desc_info;
	struct ionic_queue *q = cq->bound_q;
	struct ionic_txq_comp *comp;
	unsigned int bytes = 0;
	unsigned int pkts = 0;
	u16 index;

	comp = &((struct ionic_txq_comp *)cq->base)[cq->tail_idx];

	if (!color_match(comp->color, cq->done_color))
		return false;

	/* clean the related q entries, there could be
	 * several q entries completed for each cq completion
	 */
	do {
		desc_info = &q->tx_info[q->tail_idx];
		desc_info->bytes = 0;
		index = q->tail_idx;
		q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);
		ionic_tx_clean(q, desc_info, comp, in_napi);
		if (desc_info->skb) {
			pkts++;
			bytes += desc_info->bytes;
			desc_info->skb = NULL;
		}
	} while (index != le16_to_cpu(comp->comp_index));

	(*total_pkts) += pkts;
	(*total_bytes) += bytes;

	return true;
}

unsigned int ionic_tx_cq_service(struct ionic_cq *cq,
				 unsigned int work_to_do,
				 bool in_napi)
{
	unsigned int work_done = 0;
	unsigned int bytes = 0;
	unsigned int pkts = 0;

	while (ionic_tx_service(cq, &pkts, &bytes, in_napi)) {
		if (cq->tail_idx == cq->num_descs - 1)
			cq->done_color = !cq->done_color;
		cq->tail_idx = (cq->tail_idx + 1) & (cq->num_descs - 1);
		DEBUG_STATS_CQE_CNT(cq);

		if (++work_done >= work_to_do)
			break;
	}

	if (work_done) {
		struct ionic_queue *q = cq->bound_q;
		struct netdev_queue *nd_txq;

		nd_txq = q_to_ndq(q->lif->netdev, q);

		if (likely(!ionic_txq_hwstamp_enabled(q)))
			netdev_tx_completed_queue(nd_txq, pkts, bytes);

		if (unlikely(netif_tx_queue_stopped(nd_txq)) &&
		    ionic_q_has_space(q, IONIC_TSO_DESCS_NEEDED)) {
			netif_tx_wake_queue(nd_txq);
			q->wake++;
		}
	}

	return work_done;
}

void ionic_tx_flush(struct ionic_cq *cq)
{
	u32 work_done;

	work_done = ionic_tx_cq_service(cq, cq->num_descs, false);
	if (work_done)
		ionic_intr_credits(cq->idev->intr_ctrl, cq->bound_intr->index,
				   work_done, IONIC_INTR_CRED_RESET_COALESCE);
}

void ionic_tx_empty(struct ionic_queue *q)
{
	struct ionic_tx_desc_info *desc_info;
	int bytes = 0;
	int pkts = 0;

	/* walk the not completed tx entries, if any */
	while (q->head_idx != q->tail_idx) {
		desc_info = &q->tx_info[q->tail_idx];
		desc_info->bytes = 0;
		q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);
		ionic_tx_clean(q, desc_info, NULL, false);
		if (desc_info->skb) {
			pkts++;
			bytes += desc_info->bytes;
			desc_info->skb = NULL;
		}
	}

	if (likely(!ionic_txq_hwstamp_enabled(q))) {
		struct netdev_queue *ndq = q_to_ndq(q->lif->netdev, q);

		netdev_tx_completed_queue(ndq, pkts, bytes);
		netdev_tx_reset_queue(ndq);
	}
}

static int ionic_tx_tcp_inner_pseudo_csum(struct sk_buff *skb)
{
	int err;

	err = skb_cow_head(skb, 0);
	if (unlikely(err))
		return err;

	if (skb->protocol == cpu_to_be16(ETH_P_IP)) {
		inner_ip_hdr(skb)->check = 0;
		inner_tcp_hdr(skb)->check =
			~csum_tcpudp_magic(inner_ip_hdr(skb)->saddr,
					   inner_ip_hdr(skb)->daddr,
					   0, IPPROTO_TCP, 0);
	} else if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
		inner_tcp_hdr(skb)->check =
			~csum_ipv6_magic(&inner_ipv6_hdr(skb)->saddr,
					 &inner_ipv6_hdr(skb)->daddr,
					 0, IPPROTO_TCP, 0);
	}

	return 0;
}

static int ionic_tx_tcp_pseudo_csum(struct sk_buff *skb)
{
	int err;

	err = skb_cow_head(skb, 0);
	if (unlikely(err))
		return err;

	if (skb->protocol == cpu_to_be16(ETH_P_IP)) {
		ip_hdr(skb)->check = 0;
		tcp_hdr(skb)->check =
			~csum_tcpudp_magic(ip_hdr(skb)->saddr,
					   ip_hdr(skb)->daddr,
					   0, IPPROTO_TCP, 0);
	} else if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
		tcp_hdr(skb)->check =
			~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
					 &ipv6_hdr(skb)->daddr,
					 0, IPPROTO_TCP, 0);
	}

	return 0;
}

static void ionic_tx_tso_post(struct net_device *netdev, struct ionic_queue *q,
			      struct ionic_txq_desc *desc,
			      struct sk_buff *skb,
			      dma_addr_t addr, u8 nsge, u16 len,
			      unsigned int hdrlen, unsigned int mss,
			      bool outer_csum,
			      u16 vlan_tci, bool has_vlan,
			      bool start, bool done)
{
	u8 flags = 0;
	u64 cmd;

	flags |= has_vlan ? IONIC_TXQ_DESC_FLAG_VLAN : 0;
	flags |= outer_csum ? IONIC_TXQ_DESC_FLAG_ENCAP : 0;
	flags |= start ? IONIC_TXQ_DESC_FLAG_TSO_SOT : 0;
	flags |= done ? IONIC_TXQ_DESC_FLAG_TSO_EOT : 0;

	cmd = encode_txq_desc_cmd(IONIC_TXQ_DESC_OPCODE_TSO, flags, nsge, addr);
	desc->cmd = cpu_to_le64(cmd);
	desc->len = cpu_to_le16(len);
	desc->vlan_tci = cpu_to_le16(vlan_tci);
	desc->hdr_len = cpu_to_le16(hdrlen);
	desc->mss = cpu_to_le16(mss);

	ionic_write_cmb_desc(q, desc);

	if (start) {
		skb_tx_timestamp(skb);
		if (likely(!ionic_txq_hwstamp_enabled(q)))
			netdev_tx_sent_queue(q_to_ndq(netdev, q), skb->len);
		ionic_txq_post(q, false);
	} else {
		ionic_txq_post(q, done);
	}
}

static int ionic_tx_tso(struct net_device *netdev, struct ionic_queue *q,
			struct sk_buff *skb)
{
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
	struct ionic_tx_desc_info *desc_info;
	struct ionic_buf_info *buf_info;
	struct ionic_txq_sg_elem *elem;
	struct ionic_txq_desc *desc;
	unsigned int chunk_len;
	unsigned int frag_rem;
	unsigned int tso_rem;
	unsigned int seg_rem;
	dma_addr_t desc_addr;
	dma_addr_t frag_addr;
	unsigned int hdrlen;
	unsigned int len;
	unsigned int mss;
	bool start, done;
	bool outer_csum;
	bool has_vlan;
	u16 desc_len;
	u8 desc_nsge;
	u16 vlan_tci;
	bool encap;
	int err;

	desc_info = &q->tx_info[q->head_idx];

	if (unlikely(ionic_tx_map_skb(q, skb, desc_info)))
		return -EIO;

	len = skb->len;
	mss = skb_shinfo(skb)->gso_size;
	outer_csum = (skb_shinfo(skb)->gso_type & (SKB_GSO_GRE |
						   SKB_GSO_GRE_CSUM |
#ifdef NETIF_F_GSO_IPXIP4
						   SKB_GSO_IPXIP4 |
#endif
#ifdef NETIF_F_GSO_IPXIP6
						   SKB_GSO_IPXIP6 |
#endif
#ifdef NETIF_F_GSO_IPIP
						   SKB_GSO_IPIP |
#endif
#ifdef NETIF_F_GSO_SIT
						   SKB_GSO_SIT |
#endif
						   SKB_GSO_UDP_TUNNEL |
						   SKB_GSO_UDP_TUNNEL_CSUM));
	has_vlan = !!skb_vlan_tag_present(skb);
	vlan_tci = skb_vlan_tag_get(skb);
	encap = skb->encapsulation;

	/* Preload inner-most TCP csum field with IP pseudo hdr
	 * calculated with IP length set to zero.  HW will later
	 * add in length to each TCP segment resulting from the TSO.
	 */

	if (encap)
		err = ionic_tx_tcp_inner_pseudo_csum(skb);
	else
		err = ionic_tx_tcp_pseudo_csum(skb);
	if (unlikely(err)) {
		/* clean up mapping from ionic_tx_map_skb */
		ionic_tx_desc_unmap_bufs(q, desc_info);
		return err;
	}

	if (encap)
		hdrlen = skb_inner_tcp_all_headers(skb);
	else
		hdrlen = skb_tcp_all_headers(skb);

	desc_info->skb = skb;
	buf_info = desc_info->bufs;
	tso_rem = len;
	seg_rem = min(tso_rem, hdrlen + mss);

	frag_addr = 0;
	frag_rem = 0;

	start = true;

	while (tso_rem > 0) {
		desc = NULL;
		elem = NULL;
		desc_addr = 0;
		desc_len = 0;
		desc_nsge = 0;
		/* use fragments until we have enough to post a single descriptor */
		while (seg_rem > 0) {
			/* if the fragment is exhausted then move to the next one */
			if (frag_rem == 0) {
				/* grab the next fragment */
				frag_addr = buf_info->dma_addr;
				frag_rem = buf_info->len;
				buf_info++;
			}
			chunk_len = min(frag_rem, seg_rem);
			if (!desc) {
				/* fill main descriptor */
				desc = &q->txq[q->head_idx];
				elem = ionic_tx_sg_elems(q);
				desc_addr = frag_addr;
				desc_len = chunk_len;
			} else {
				/* fill sg descriptor */
				elem->addr = cpu_to_le64(frag_addr);
				elem->len = cpu_to_le16(chunk_len);
				elem++;
				desc_nsge++;
			}
			frag_addr += chunk_len;
			frag_rem -= chunk_len;
			tso_rem -= chunk_len;
			seg_rem -= chunk_len;
		}
		seg_rem = min(tso_rem, mss);
		done = (tso_rem == 0);
		/* post descriptor */
		ionic_tx_tso_post(netdev, q, desc, skb, desc_addr, desc_nsge,
				  desc_len, hdrlen, mss, outer_csum, vlan_tci,
				  has_vlan, start, done);
		start = false;
		/* Buffer information is stored with the first tso descriptor */
		desc_info = &q->tx_info[q->head_idx];
		desc_info->nbufs = 0;
	}

	stats->pkts += DIV_ROUND_UP(len - hdrlen, mss);
	stats->bytes += len;
	stats->tso++;
	stats->tso_bytes = len;

	return 0;
}

static void ionic_tx_calc_csum(struct ionic_queue *q, struct sk_buff *skb,
			       struct ionic_tx_desc_info *desc_info)
{
	struct ionic_txq_desc *desc = &q->txq[q->head_idx];
	struct ionic_buf_info *buf_info = desc_info->bufs;
#ifdef IONIC_DEBUG_STATS
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
#endif
	bool has_vlan;
	u8 flags = 0;
	bool encap;
	u64 cmd;

	has_vlan = !!skb_vlan_tag_present(skb);
	encap = skb->encapsulation;

	flags |= has_vlan ? IONIC_TXQ_DESC_FLAG_VLAN : 0;
	flags |= encap ? IONIC_TXQ_DESC_FLAG_ENCAP : 0;

	cmd = encode_txq_desc_cmd(IONIC_TXQ_DESC_OPCODE_CSUM_PARTIAL,
				  flags, skb_shinfo(skb)->nr_frags,
				  buf_info->dma_addr);
	desc->cmd = cpu_to_le64(cmd);
	desc->len = cpu_to_le16(buf_info->len);
	if (has_vlan) {
		desc->vlan_tci = cpu_to_le16(skb_vlan_tag_get(skb));
#ifdef IONIC_DEBUG_STATS
		stats->vlan_inserted++;
#endif
	}
	desc->csum_start = cpu_to_le16(skb_checksum_start_offset(skb));
	desc->csum_offset = cpu_to_le16(skb->csum_offset);

	ionic_write_cmb_desc(q, desc);

#ifdef IONIC_DEBUG_STATS
#ifdef HAVE_CSUM_NOT_INET
	if (skb->csum_not_inet)
		stats->crc32_csum++;
	else
#endif
		stats->csum++;
#endif
}

static void ionic_tx_calc_no_csum(struct ionic_queue *q, struct sk_buff *skb,
				  struct ionic_tx_desc_info *desc_info)
{
	struct ionic_txq_desc *desc = &q->txq[q->head_idx];
	struct ionic_buf_info *buf_info = desc_info->bufs;
#ifdef IONIC_DEBUG_STATS
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
#endif
	bool has_vlan;
	u8 flags = 0;
	bool encap;
	u64 cmd;

	has_vlan = !!skb_vlan_tag_present(skb);
	encap = skb->encapsulation;

	flags |= has_vlan ? IONIC_TXQ_DESC_FLAG_VLAN : 0;
	flags |= encap ? IONIC_TXQ_DESC_FLAG_ENCAP : 0;

	cmd = encode_txq_desc_cmd(IONIC_TXQ_DESC_OPCODE_CSUM_NONE,
				  flags, skb_shinfo(skb)->nr_frags,
				  buf_info->dma_addr);
	desc->cmd = cpu_to_le64(cmd);
	desc->len = cpu_to_le16(buf_info->len);
	if (has_vlan) {
		desc->vlan_tci = cpu_to_le16(skb_vlan_tag_get(skb));
#ifdef IONIC_DEBUG_STATS
		stats->vlan_inserted++;
#endif
	}
	desc->csum_start = 0;
	desc->csum_offset = 0;

	ionic_write_cmb_desc(q, desc);

#ifdef IONIC_DEBUG_STATS
	stats->csum_none++;
#endif
}

static void ionic_tx_skb_frags(struct ionic_queue *q, struct sk_buff *skb,
			       struct ionic_tx_desc_info *desc_info)
{
	struct ionic_buf_info *buf_info = &desc_info->bufs[1];
#ifdef IONIC_DEBUG_STATS
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
#endif
	struct ionic_txq_sg_elem *elem;
	unsigned int i;

	elem = ionic_tx_sg_elems(q);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++, buf_info++, elem++) {
		elem->addr = cpu_to_le64(buf_info->dma_addr);
		elem->len = cpu_to_le16(buf_info->len);
	}

#ifdef IONIC_DEBUG_STATS
	stats->frags += skb_shinfo(skb)->nr_frags;
#endif
}

static void ionic_check_stop_tx(struct netdev_queue *ndq,
				struct ionic_queue *q, int ndescs)
{
	if (unlikely(!ionic_q_has_space(q, ndescs))) {
		netif_tx_stop_queue(ndq);
		trace_ionic_q_stop(q);
		q->stop++;
	}
}

static int ionic_tx(struct net_device *netdev, struct ionic_queue *q,
		    struct sk_buff *skb)
{
	struct ionic_tx_desc_info *desc_info = &q->tx_info[q->head_idx];
	struct ionic_tx_stats *stats = q_to_tx_stats(q);
	bool ring_dbell = true;

	if (unlikely(ionic_tx_map_skb(q, skb, desc_info)))
		return -EIO;

	desc_info->skb = skb;

	/* set up the initial descriptor */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		ionic_tx_calc_csum(q, skb, desc_info);
	else
		ionic_tx_calc_no_csum(q, skb, desc_info);

	/* add frags */
	ionic_tx_skb_frags(q, skb, desc_info);

	skb_tx_timestamp(skb);
	stats->pkts++;
	stats->bytes += skb->len;

	if (likely(!ionic_txq_hwstamp_enabled(q))) {
		struct netdev_queue *ndq = q_to_ndq(netdev, q);

#ifdef HAVE_SKB_XMIT_MORE
		ionic_check_stop_tx(ndq, q, MAX_SKB_FRAGS + 1);
		ring_dbell = __netdev_tx_sent_queue(ndq, skb->len,
						    netdev_xmit_more());
#else
		netdev_tx_sent_queue(ndq, skb->len);
#endif
	}

	ionic_txq_post(q, ring_dbell);

	return 0;
}

static int ionic_tx_descs_needed(struct ionic_queue *q, struct sk_buff *skb)
{
	int nr_frags = skb_shinfo(skb)->nr_frags;
	bool too_many_frags = false;
	skb_frag_t *frag;
	int desc_bufs;
	int chunk_len;
	int frag_rem;
	int tso_rem;
	int seg_rem;
	bool encap;
	int hdrlen;
	int ndescs;
	int err;

	/* Each desc is mss long max, so a descriptor for each gso_seg */
	if (skb_is_gso(skb)) {
		ndescs = skb_shinfo(skb)->gso_segs;
		if (!nr_frags)
			return ndescs;
	} else {
		ndescs = 1;
		if (!nr_frags)
			return ndescs;

		if (unlikely(nr_frags > q->max_sg_elems)) {
			too_many_frags = true;
			goto linearize;
		}

		return ndescs;
	}

	/* We need to scan the skb to be sure that none of the MTU sized
	 * packets in the TSO will require more sgs per descriptor than we
	 * can support.  We loop through the frags, add up the lengths for
	 * a packet, and count the number of sgs used per packet.
	 */
	tso_rem = skb->len;
	frag = skb_shinfo(skb)->frags;
	encap = skb->encapsulation;

	/* start with just hdr in first part of first descriptor */
	if (encap)
		hdrlen = skb_inner_tcp_all_headers(skb);
	else
		hdrlen = skb_tcp_all_headers(skb);
	seg_rem = min_t(int, tso_rem, hdrlen + skb_shinfo(skb)->gso_size);
	frag_rem = hdrlen;

	while (tso_rem > 0) {
		desc_bufs = 0;
		while (seg_rem > 0) {
			desc_bufs++;

			/* We add the +1 because we can take buffers for one
			 * more than we have SGs: one for the initial desc data
			 * in addition to the SG segments that might follow.
			 */
			if (desc_bufs > q->max_sg_elems + 1) {
				too_many_frags = true;
				goto linearize;
			}

			if (frag_rem == 0) {
				frag_rem = skb_frag_size(frag);
				frag++;
			}
			chunk_len = min(frag_rem, seg_rem);
			frag_rem -= chunk_len;
			tso_rem -= chunk_len;
			seg_rem -= chunk_len;
		}

		seg_rem = min_t(int, tso_rem, skb_shinfo(skb)->gso_size);
	}

linearize:
	if (too_many_frags) {
		err = skb_linearize(skb);
		if (unlikely(err))
			return err;
		q_to_tx_stats(q)->linearize++;
	}

	return ndescs;
}

static int ionic_maybe_stop_tx(struct net_device *netdev, struct ionic_queue *q,
			       int ndescs)
{
	int stopped = 0;

	if (unlikely(!ionic_q_has_space(q, ndescs))) {
		netif_stop_subqueue(netdev, q->index);
		stopped = 1;

		/* Might race with ionic_tx_clean, check again */
		smp_rmb();
		if (ionic_q_has_space(q, ndescs)) {
			netif_start_subqueue(netdev, q->index);
			stopped = 0;
		}

		if (stopped) {
			trace_ionic_q_stop(q);
			q->stop++;
		}
	}

	return stopped;
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
static netdev_tx_t ionic_start_hwstamp_xmit(struct sk_buff *skb,
					    struct net_device *netdev)
{
	struct ionic_lif *lif = netdev_priv(netdev);
	struct ionic_queue *q;
	int err, ndescs;

	/* Does not stop/start txq, because we post to a separate tx queue
	 * for timestamping, and if a packet can't be posted immediately to
	 * the timestamping queue, it is dropped.
	 */

	q = &lif->hwstamp_txq->q;
	ndescs = ionic_tx_descs_needed(q, skb);
	if (unlikely(ndescs < 0))
		goto err_out_drop;

	if (unlikely(!ionic_q_has_space(q, ndescs)))
		goto err_out_drop;

	skb_shinfo(skb)->tx_flags |= SKBTX_HW_TSTAMP;
	if (skb_is_gso(skb))
		err = ionic_tx_tso(netdev, q, skb);
	else
		err = ionic_tx(netdev, q, skb);

	if (unlikely(err))
		goto err_out_drop;

	return NETDEV_TX_OK;

err_out_drop:
	q->drop++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
#endif

netdev_tx_t ionic_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	u16 queue_index = skb_get_queue_mapping(skb);
	struct ionic_lif *lif = netdev_priv(netdev);
	struct ionic_queue *q;
	int ndescs;
	int err;

	if (unlikely(!test_bit(IONIC_LIF_F_UP, lif->state))) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		if (lif->hwstamp_txq && lif->phc->ts_config_tx_mode)
			return ionic_start_hwstamp_xmit(skb, netdev);
#endif

	if (unlikely(queue_index >= lif->nxqs))
		queue_index = 0;
	q = &lif->txqcqs[queue_index]->q;

	ndescs = ionic_tx_descs_needed(q, skb);
	if (ndescs < 0)
		goto err_out_drop;

	if (unlikely(ionic_maybe_stop_tx(netdev, q, ndescs)))
		return NETDEV_TX_BUSY;

	if (skb_is_gso(skb))
		err = ionic_tx_tso(netdev, q, skb);
	else
		err = ionic_tx(netdev, q, skb);

	if (unlikely(err))
		goto err_out_drop;

	return NETDEV_TX_OK;

err_out_drop:
	q->drop++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
