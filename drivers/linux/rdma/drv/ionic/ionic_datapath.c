// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_user_verbs.h>

#include "ionic_fw.h"
#include "ionic_ibdev.h"

#define IONIC_OP(version, opname) \
	((version) < 2 ? IONIC_V1_OP_##opname : IONIC_V2_OP_##opname)

#ifdef IONIC_NOT_UPSTREAM
/* Kernel module parameters are not to be upstreamed */
static bool ionic_qp_dbell = true;
module_param_named(qp_dbell, ionic_qp_dbell, bool, 0644);
MODULE_PARM_DESC(qp_dbell, "Enable ringing qp doorbell (to test handling of dev failure).");
#endif

static bool ionic_next_cqe(struct ionic_ibdev *dev, struct ionic_cq *cq,
			   struct ionic_v1_cqe **cqe)
{
	struct ionic_v1_cqe *qcqe = ionic_queue_at_prod(&cq->q);

	if (unlikely(cq->color != ionic_v1_cqe_color(qcqe)))
		return false;

	ionic_lat_enable(dev->lats, true);

	/* Prevent out-of-order reads of the CQE */
	rmb();

	ibdev_dbg(&dev->ibdev, "poll cq %u prod %u\n", cq->cqid, cq->q.prod);
	print_hex_dump_debug("cqe ", DUMP_PREFIX_OFFSET, 16, 1,
			     qcqe, BIT(cq->q.stride_log2), true);
	*cqe = qcqe;

	return true;
}

static int ionic_flush_recv(struct ionic_qp *qp, struct ib_wc *wc)
{
	struct ionic_v1_wqe *wqe;
	struct ionic_rq_meta *meta;

	if (!qp->rq_flush)
		return 0;

	if (ionic_queue_empty(&qp->rq))
		return 0;

	wqe = ionic_queue_at_cons(&qp->rq);

	/* wqe_id must be a valid queue index */
	if (unlikely(wqe->base.wqe_id >> qp->rq.depth_log2)) {
		ibdev_warn(qp->ibqp.device,
			   "flush qp %u recv index %llu invalid\n",
			   qp->qpid, (unsigned long long)wqe->base.wqe_id);
		return -EIO;
	}

	/* wqe_id must indicate a request that is outstanding */
	meta = &qp->rq_meta[wqe->base.wqe_id];
	if (unlikely(meta->next != IONIC_META_POSTED)) {
		ibdev_warn(qp->ibqp.device,
			   "flush qp %u recv index %llu not posted\n",
			   qp->qpid, (unsigned long long)wqe->base.wqe_id);
		return -EIO;
	}

	ionic_queue_consume(&qp->rq);

	memset(wc, 0, sizeof(*wc));

	wc->status = IB_WC_WR_FLUSH_ERR;
	wc->wr_id = meta->wrid;
	wc->qp = &qp->ibqp;

	meta->next = qp->rq_meta_head;
	qp->rq_meta_head = meta;

	return 1;
}

static int ionic_flush_recv_many(struct ionic_qp *qp,
				 struct ib_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_flush_recv(qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_flush_send(struct ionic_qp *qp, struct ib_wc *wc)
{
	struct ionic_sq_meta *meta;

	if (!qp->sq_flush)
		return 0;

	if (ionic_queue_empty(&qp->sq))
		return 0;

	meta = &qp->sq_meta[qp->sq.cons];

	ionic_queue_consume(&qp->sq);

	memset(wc, 0, sizeof(*wc));

	wc->status = IB_WC_WR_FLUSH_ERR;
	wc->wr_id = meta->wrid;
	wc->qp = &qp->ibqp;

	return 1;
}

static int ionic_flush_send_many(struct ionic_qp *qp,
				 struct ib_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_flush_send(qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_poll_recv(struct ionic_ibdev *dev, struct ionic_cq *cq,
			   struct ionic_qp *cqe_qp, struct ionic_v1_cqe *cqe,
			   struct ib_wc *wc)
{
	struct ionic_qp *qp = NULL;
	struct ionic_rq_meta *meta;
	u32 src_qpn, st_len;
	u16 vlan_tag;
	u8 op;

	if (cqe_qp->rq_flush)
		return 0;

	qp = cqe_qp;

	st_len = be32_to_cpu(cqe->status_length);

	/* ignore wqe_id in case of flush error */
	if (ionic_v1_cqe_error(cqe) && st_len == IONIC_STS_WQE_FLUSHED_ERR) {
		cqe_qp->rq_flush = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_rq, &cq->flush_rq);

		ionic_stat_incr(dev->stats, poll_cq_wc_err);

		/* posted recvs (if any) flushed by ionic_flush_recv */
		return 0;
	}

	/* there had better be something in the recv queue to complete */
	if (ionic_queue_empty(&qp->rq)) {
		ibdev_warn(&dev->ibdev, "qp %u is empty\n", qp->qpid);
		return -EIO;
	}

	/* wqe_id must be a valid queue index */
	if (unlikely(cqe->recv.wqe_id >> qp->rq.depth_log2)) {
		ibdev_warn(&dev->ibdev,
			   "qp %u recv index %llu invalid\n",
			   qp->qpid, (unsigned long long)cqe->recv.wqe_id);
		return -EIO;
	}

	/* wqe_id must indicate a request that is outstanding */
	meta = &qp->rq_meta[cqe->recv.wqe_id];
	if (unlikely(meta->next != IONIC_META_POSTED)) {
		ibdev_warn(&dev->ibdev,
			   "qp %u recv index %llu not posted\n",
			   qp->qpid, (unsigned long long)cqe->recv.wqe_id);
		return -EIO;
	}

	meta->next = qp->rq_meta_head;
	qp->rq_meta_head = meta;

	memset(wc, 0, sizeof(*wc));

	wc->wr_id = meta->wrid;

	wc->qp = &cqe_qp->ibqp;

	if (ionic_v1_cqe_error(cqe)) {
		wc->vendor_err = st_len;
		wc->status = ionic_to_ib_status(st_len);

		cqe_qp->rq_flush = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_rq, &cq->flush_rq);

		ionic_stat_incr(dev->stats, poll_cq_wc_err);
		ibdev_warn(&dev->ibdev,
			   "qp %d recv cqe with error\n", qp->qpid);
		print_hex_dump(KERN_WARNING, "cqe ", DUMP_PREFIX_OFFSET, 16, 1,
			       cqe, BIT(cq->q.stride_log2), true);
		goto out;
	}

	wc->vendor_err = 0;
	wc->status = IB_WC_SUCCESS;

	src_qpn = be32_to_cpu(cqe->recv.src_qpn_op);
	op = src_qpn >> IONIC_V1_CQE_RECV_OP_SHIFT;

	src_qpn &= IONIC_V1_CQE_RECV_QPN_MASK;
	op &= IONIC_V1_CQE_RECV_OP_MASK;

	wc->opcode = IB_WC_RECV;
	switch (op) {
	case IONIC_V1_CQE_RECV_OP_RDMA_IMM:
		wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags |= IB_WC_WITH_IMM;
		wc->ex.imm_data = cqe->recv.imm_data_rkey; /* be32 in wc */
		break;
	case IONIC_V1_CQE_RECV_OP_SEND_IMM:
		wc->wc_flags |= IB_WC_WITH_IMM;
		wc->ex.imm_data = cqe->recv.imm_data_rkey; /* be32 in wc */
		break;
	case IONIC_V1_CQE_RECV_OP_SEND_INV:
		wc->wc_flags |= IB_WC_WITH_INVALIDATE;
		wc->ex.invalidate_rkey = be32_to_cpu(cqe->recv.imm_data_rkey);
		break;
	}

	wc->byte_len = st_len;
	wc->src_qp = src_qpn;

	if (qp->ibqp.qp_type == IB_QPT_UD ||
	    qp->ibqp.qp_type == IB_QPT_GSI) {
		wc->wc_flags |= IB_WC_GRH | IB_WC_WITH_SMAC;
		ether_addr_copy(wc->smac, cqe->recv.src_mac);

		wc->wc_flags |= IB_WC_WITH_NETWORK_HDR_TYPE;
		if (ionic_v1_cqe_recv_is_ipv4(cqe))
			wc->network_hdr_type = RDMA_NETWORK_IPV4;
		else
			wc->network_hdr_type = RDMA_NETWORK_IPV6;

		if (ionic_v1_cqe_recv_is_vlan(cqe))
			wc->wc_flags |= IB_WC_WITH_VLAN;

		/* vlan_tag in cqe will be valid from dpath even if no vlan */
		vlan_tag = be16_to_cpu(cqe->recv.vlan_tag);
		wc->vlan_id = vlan_tag & 0xfff; /* 802.1q VID */
		wc->sl = vlan_tag >> 13; /* 802.1q PCP */
	}

	wc->pkey_index = 0;
	wc->port_num = 1;

out:
	ionic_queue_consume(&qp->rq);

	return 1;
}

static bool ionic_peek_send(struct ionic_qp *qp)
{
	struct ionic_sq_meta *meta;

	if (qp->sq_flush)
		return false;

	/* completed all send queue requests? */
	if (ionic_queue_empty(&qp->sq))
		return false;

	meta = &qp->sq_meta[qp->sq.cons];

	/* waiting for remote completion? */
	if (meta->remote && meta->seq == qp->sq_msn_cons)
		return false;

	/* waiting for local completion? */
	if (!meta->remote && !meta->local_comp)
		return false;

	return true;
}

static int ionic_poll_send(struct ionic_ibdev *dev, struct ionic_cq *cq,
			   struct ionic_qp *qp, struct ib_wc *wc)
{
	struct ionic_sq_meta *meta;

	if (qp->sq_flush)
		return 0;

	do {
		/* completed all send queue requests? */
		if (ionic_queue_empty(&qp->sq))
			goto out_empty;

		meta = &qp->sq_meta[qp->sq.cons];

		/* waiting for remote completion? */
		if (meta->remote && meta->seq == qp->sq_msn_cons)
			goto out_empty;

		/* waiting for local completion? */
		if (!meta->remote && !meta->local_comp)
			goto out_empty;

		ionic_queue_consume(&qp->sq);

		/* produce wc only if signaled or error status */
	} while (!meta->signal && meta->ibsts == IB_WC_SUCCESS);

	memset(wc, 0, sizeof(*wc));

	wc->status = meta->ibsts;
	wc->wr_id = meta->wrid;
	wc->qp = &qp->ibqp;

	if (meta->ibsts == IB_WC_SUCCESS) {
		wc->byte_len = meta->len;
		wc->opcode = meta->ibop;
	} else {
		wc->vendor_err = meta->len;

		qp->sq_flush = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_sq, &cq->flush_sq);

		ionic_stat_incr(dev->stats, poll_cq_wc_err);
	}

	return 1;

out_empty:
	if (qp->sq_flush_rcvd) {
		qp->sq_flush = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_sq, &cq->flush_sq);
	}
	return 0;
}

static int ionic_poll_send_many(struct ionic_ibdev *dev, struct ionic_cq *cq,
				struct ionic_qp *qp, struct ib_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_poll_send(dev, cq, qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_validate_cons(u16 prod, u16 cons,
			       u16 comp, u16 mask)
{
	if (((prod - cons) & mask) <= ((comp - cons) & mask))
		return -EIO;

	return 0;
}

static int ionic_comp_msn(struct ionic_qp *qp, struct ionic_v1_cqe *cqe)
{
	struct ionic_sq_meta *meta;
	u16 cqe_seq, cqe_idx;
	int rc;

	if (qp->sq_flush)
		return 0;

	cqe_seq = be32_to_cpu(cqe->send.msg_msn) & qp->sq.mask;

	rc = ionic_validate_cons(qp->sq_msn_prod,
				 qp->sq_msn_cons,
				 cqe_seq - 1,
				 qp->sq.mask);
	if (rc) {
		ibdev_warn(qp->ibqp.device,
			   "qp %u bad msn %#x seq %u for prod %u cons %u\n",
			   qp->qpid, be32_to_cpu(cqe->send.msg_msn),
			   cqe_seq, qp->sq_msn_prod, qp->sq_msn_cons);
		return rc;
	}

	qp->sq_msn_cons = cqe_seq;

	if (ionic_v1_cqe_error(cqe)) {
		cqe_idx = qp->sq_msn_idx[(cqe_seq - 1) & qp->sq.mask];

		meta = &qp->sq_meta[cqe_idx];
		meta->len = be32_to_cpu(cqe->status_length);
		meta->ibsts = ionic_to_ib_status(meta->len);

		ibdev_warn(qp->ibqp.device,
			   "qp %d msn cqe with error\n", qp->qpid);
		print_hex_dump(KERN_WARNING, "cqe ", DUMP_PREFIX_OFFSET, 16, 1,
			       cqe, sizeof(*cqe), true);
	}

	return 0;
}

static int ionic_comp_npg(struct ionic_qp *qp, struct ionic_v1_cqe *cqe)
{
	struct ionic_sq_meta *meta;
	u16 cqe_idx;
	u32 st_len;

	if (qp->sq_flush)
		return 0;

	st_len = be32_to_cpu(cqe->status_length);

	if (ionic_v1_cqe_error(cqe) && st_len == IONIC_STS_WQE_FLUSHED_ERR) {
		/* Flush cqe does not consume a wqe on the device, and maybe
		 * no such work request is posted.
		 *
		 * The driver should begin flushing after the last indicated
		 * normal or error completion.	Here, only set a hint that the
		 * flush request was indicated.	 In poll_send, if nothing more
		 * can be polled normally, then begin flushing.
		 */
		qp->sq_flush_rcvd = true;
		return 0;
	}

	cqe_idx = cqe->send.npg_wqe_id & qp->sq.mask;
	meta = &qp->sq_meta[cqe_idx];
	meta->local_comp = true;

	if (ionic_v1_cqe_error(cqe)) {
		meta->len = st_len;
		meta->ibsts = ionic_to_ib_status(st_len);
		meta->remote = false;
		ibdev_warn(qp->ibqp.device,
			   "qp %d npg cqe with error\n", qp->qpid);
		print_hex_dump(KERN_WARNING, "cqe ", DUMP_PREFIX_OFFSET, 16, 1,
			       cqe, sizeof(*cqe), true);
	}

	return 0;
}

static void ionic_reserve_sync_cq(struct ionic_ibdev *dev, struct ionic_cq *cq)
{
	if (!ionic_queue_empty(&cq->q)) {
		cq->reserve += ionic_queue_length(&cq->q);
		cq->q.cons = cq->q.prod;

		ionic_dbell_ring(dev->dbpage, dev->cq_qtype,
				 ionic_queue_dbell_val(&cq->q));

		ionic_stat_incr(dev->stats, ring_cq_dbell);
	}
}

static void ionic_reserve_cq(struct ionic_ibdev *dev, struct ionic_cq *cq,
			     int spend)
{
	cq->reserve -= spend;

	if (cq->reserve <= 0)
		ionic_reserve_sync_cq(dev, cq);
}

static int ionic_poll_vcq_cq(struct ionic_ibdev *dev,
			     struct ionic_cq *cq,
			     int nwc, struct ib_wc *wc)
{
	struct ionic_qp *qp, *qp_next;
	struct ionic_v1_cqe *cqe;
	u32 qtf, qid;
	u8 type;
	bool peek;
	int rc = 0, npolled = 0;
	unsigned long irqflags;
	u16 old_prod;

	ionic_lat_trace(dev->lats, application);
	ionic_stat_incr(dev->stats, poll_cq);

	if (nwc < 1)
		return 0;

	spin_lock_irqsave(&cq->lock, irqflags);

	old_prod = cq->q.prod;

	/* poll already indicated work completions for send queue */

	list_for_each_entry_safe(qp, qp_next, &cq->poll_sq, cq_poll_sq) {
		if (npolled == nwc)
			goto out;

		spin_lock(&qp->sq_lock);
		rc = ionic_poll_send_many(dev, cq, qp, wc + npolled, nwc - npolled);
		spin_unlock(&qp->sq_lock);

		if (rc > 0)
			npolled += rc;

		if (npolled < nwc)
			list_del_init(&qp->cq_poll_sq);
	}

	/* poll for more work completions */

	while (likely(ionic_next_cqe(dev, cq, &cqe))) {
		if (npolled == nwc)
			goto out;

		qtf = ionic_v1_cqe_qtf(cqe);
		qid = ionic_v1_cqe_qtf_qid(qtf);
		type = ionic_v1_cqe_qtf_type(qtf);

		qp = xa_load(&dev->qp_tbl, qid);
		if (unlikely(!qp)) {
			ibdev_dbg(&dev->ibdev, "missing qp for qid %u\n", qid);
			goto cq_next;
		}

		switch (type) {
		case IONIC_V1_CQE_TYPE_RECV:
			spin_lock(&qp->rq_lock);
			rc = ionic_poll_recv(dev, cq, qp, cqe, wc + npolled);
			spin_unlock(&qp->rq_lock);

			if (rc < 0)
				goto out;

			npolled += rc;

			break;

		case IONIC_V1_CQE_TYPE_SEND_MSN:
			spin_lock(&qp->sq_lock);
			rc = ionic_comp_msn(qp, cqe);
			if (!rc) {
				rc = ionic_poll_send_many(dev, cq, qp,
							  wc + npolled,
							  nwc - npolled);
				peek = ionic_peek_send(qp);
			}
			spin_unlock(&qp->sq_lock);

			if (rc < 0)
				goto out;

			npolled += rc;

			if (peek)
				list_move_tail(&qp->cq_poll_sq, &cq->poll_sq);
			break;

		case IONIC_V1_CQE_TYPE_SEND_NPG:
			spin_lock(&qp->sq_lock);
			rc = ionic_comp_npg(qp, cqe);
			if (!rc) {
				rc = ionic_poll_send_many(dev, cq, qp,
							  wc + npolled,
							  nwc - npolled);
				peek = ionic_peek_send(qp);
			}
			spin_unlock(&qp->sq_lock);

			if (rc < 0)
				goto out;

			npolled += rc;

			if (peek)
				list_move_tail(&qp->cq_poll_sq, &cq->poll_sq);
			break;

		default:
			ibdev_warn(&dev->ibdev,
				   "unexpected cqe type %u\n", type);
			rc = -EIO;
			goto out;
		}

cq_next:
		ionic_queue_produce(&cq->q);
		cq->color = ionic_color_wrap(cq->q.prod, cq->color);
	}

	/* lastly, flush send and recv queues */

	if (likely(!cq->flush))
		goto out;

	cq->flush = false;

	list_for_each_entry_safe(qp, qp_next, &cq->flush_sq, cq_flush_sq) {
		if (npolled == nwc)
			goto out;

		spin_lock(&qp->sq_lock);
		rc = ionic_flush_send_many(qp, wc + npolled, nwc - npolled);
		ionic_stat_add(dev->stats, poll_cq_wc_flush, rc);
		spin_unlock(&qp->sq_lock);

		if (rc > 0)
			npolled += rc;

		if (npolled < nwc)
			list_del_init(&qp->cq_flush_sq);
		else
			cq->flush = true;
	}

	list_for_each_entry_safe(qp, qp_next, &cq->flush_rq, cq_flush_rq) {
		if (npolled == nwc)
			goto out;

		spin_lock(&qp->rq_lock);
		rc = ionic_flush_recv_many(qp, wc + npolled, nwc - npolled);
		ionic_stat_add(dev->stats, poll_cq_wc_flush, rc);
		spin_unlock(&qp->rq_lock);

		if (rc > 0)
			npolled += rc;

		if (npolled < nwc)
			list_del_init(&qp->cq_flush_rq);
		else
			cq->flush = true;
	}

out:
	/* in case reserve was depleted (more work posted than cq depth) */
	if (cq->reserve <= 0)
		ionic_reserve_sync_cq(dev, cq);

	old_prod = (cq->q.prod - old_prod) & cq->q.mask;

	ionic_stat_add(dev->stats, poll_cq_cqe, old_prod);
	ionic_stat_incr_idx_fls(dev->stats, poll_cq_ncqe, old_prod);
	ionic_stat_add(dev->stats, poll_cq_wc, npolled);
	ionic_stat_incr_idx_fls(dev->stats, poll_cq_nwc, npolled);
	ionic_stat_add(dev->stats, poll_cq_err, (npolled ?: rc) < 0);

	spin_unlock_irqrestore(&cq->lock, irqflags);

	if (npolled) {
		ionic_lat_trace(dev->lats, poll_cq_compl);
	} else {
		ionic_lat_trace(dev->lats, poll_cq_empty);
		ionic_lat_enable(dev->lats, false);
	}

	return npolled ?: rc;
}

static int ionic_poll_cq(struct ib_cq *ibcq, int nwc, struct ib_wc *wc)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibcq->device);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);
	int rc_tmp, rc = 0, npolled = 0;
	int cq_i, cq_x, cq_ix;

	/* poll_idx is not protected by a lock, but a race is benign */
	cq_x = vcq->poll_idx;

	vcq->poll_idx ^= dev->udma_count - 1;

	for (cq_i = 0; npolled < nwc && cq_i < dev->udma_count; ++cq_i) {
		cq_ix = cq_i ^ cq_x;

		if (!(vcq->udma_mask & BIT(cq_ix)))
			continue;

		rc_tmp = ionic_poll_vcq_cq(dev, &vcq->cq[cq_ix],
					   nwc - npolled,
					   wc + npolled);

		if (rc_tmp >= 0)
			npolled += rc_tmp;
		else if (!rc)
			rc = rc_tmp;
	}

	return npolled ?: rc;
}

static int ionic_req_notify_vcq_cq(struct ionic_ibdev *dev, struct ionic_cq *cq,
				   enum ib_cq_notify_flags flags)
{
	u64 dbell_val = cq->q.dbell;

	if (flags & IB_CQ_SOLICITED) {
		cq->arm_sol_prod = ionic_queue_next(&cq->q, cq->arm_sol_prod);
		dbell_val |= cq->arm_sol_prod | IONIC_CQ_RING_SOL;

		ionic_stat_incr(dev->stats, arm_cq_sol);
	} else {
		cq->arm_any_prod = ionic_queue_next(&cq->q, cq->arm_any_prod);
		dbell_val |= cq->arm_any_prod | IONIC_CQ_RING_ARM;

		ionic_stat_incr(dev->stats, arm_cq_any);
	}

	ionic_reserve_sync_cq(dev, cq);

	ionic_dbell_ring(dev->dbpage, dev->cq_qtype, dbell_val);

	/* IB_CQ_REPORT_MISSED_EVENTS:
	 *
	 * The queue index in ring zero guarantees no missed events.
	 *
	 * Here, we check if the color bit in the next cqe is flipped.	If it
	 * is flipped, then progress can be made by immediately polling the cq.
	 * Still, the cq will be armed, and an event will be generated.	 The cq
	 * may be empty when polled after the event, because the next poll
	 * after arming the cq can empty it.
	 */
	return (flags & IB_CQ_REPORT_MISSED_EVENTS) &&
		cq->color == ionic_v1_cqe_color(ionic_queue_at_prod(&cq->q));
}

static int ionic_req_notify_cq(struct ib_cq *ibcq,
			       enum ib_cq_notify_flags flags)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibcq->device);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);
	int rc = 0, cq_i;

	for (cq_i = 0; cq_i < dev->udma_count; ++cq_i) {
		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;

		if (ionic_req_notify_vcq_cq(dev, &vcq->cq[cq_i], flags))
			rc = 1;
	}

	return rc;
}

static s64 ionic_prep_inline(void *data, u32 max_data,
			     const struct ib_sge *ib_sgl, int num_sge)
{
	static const s64 bit_31 = 1u << 31;
	s64 len = 0, sg_len;
	int sg_i;

	for (sg_i = 0; sg_i < num_sge; ++sg_i) {
		sg_len = ib_sgl[sg_i].length;

		/* sge length zero means 2GB */
		if (unlikely(sg_len == 0))
			sg_len = bit_31;

		/* greater than max inline data is invalid */
		if (unlikely(len + sg_len > max_data))
			return -EINVAL;

		memcpy(data + len, (void *)ib_sgl[sg_i].addr, sg_len);

		len += sg_len;
	}

	return len;
}

static s64 ionic_prep_pld(struct ionic_v1_wqe *wqe,
			  union ionic_v1_pld *pld,
			  int spec, u32 max_sge,
			  const struct ib_sge *ib_sgl,
			  int num_sge)
{
	static const s64 bit_31 = 1l << 31;
	struct ionic_sge *sgl;
	__be32 *spec32 = NULL;
	__be16 *spec16 = NULL;
	s64 len = 0, sg_len;
	int sg_i = 0;

	if (unlikely(num_sge < 0 || (u32)num_sge > max_sge))
		return -EINVAL;

	if (spec && num_sge > IONIC_V1_SPEC_FIRST_SGE) {
		sg_i = IONIC_V1_SPEC_FIRST_SGE;

		if (num_sge > 8) {
			wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_SPEC16);
			spec16 = pld->spec16;
		} else {
			wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_SPEC32);
			spec32 = pld->spec32;
		}
	}

	sgl = &pld->sgl[sg_i];

	for (sg_i = 0; sg_i < num_sge; ++sg_i) {
		sg_len = ib_sgl[sg_i].length;

		/* sge length zero means 2GB */
		if (unlikely(sg_len == 0))
			sg_len = bit_31;

		/* greater than 2GB data is invalid */
		if (unlikely(len + sg_len > bit_31))
			return -EINVAL;

		sgl[sg_i].va = cpu_to_be64(ib_sgl[sg_i].addr);
		sgl[sg_i].len = cpu_to_be32(sg_len);
		sgl[sg_i].lkey = cpu_to_be32(ib_sgl[sg_i].lkey);

		if (spec32) {
			spec32[sg_i] = sgl[sg_i].len;
		} else if (spec16) {
			if (unlikely(sg_len > U16_MAX))
				return -EINVAL;
			spec16[sg_i] = cpu_to_be16(sg_len);
		}

		len += sg_len;
	}

	return len;
}

static void ionic_prep_base(struct ionic_qp *qp,
			    const struct ib_send_wr *wr,
			    struct ionic_sq_meta *meta,
			    struct ionic_v1_wqe *wqe)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);

	meta->wrid = wr->wr_id;
	meta->ibsts = IB_WC_SUCCESS;
	meta->signal = false;
	meta->local_comp = false;

	wqe->base.wqe_id = qp->sq.prod;

	if (wr->send_flags & IB_SEND_FENCE)
		wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_FENCE);

	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_SOL);

	if (qp->sig_all || wr->send_flags & IB_SEND_SIGNALED) {
		wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_SIG);
		meta->signal = true;
	}

	meta->seq = qp->sq_msn_prod;
	meta->remote =
		qp->ibqp.qp_type != IB_QPT_UD &&
		qp->ibqp.qp_type != IB_QPT_GSI &&
		!ionic_ibop_is_local(wr->opcode);

	if (meta->remote) {
		qp->sq_msn_idx[meta->seq] = qp->sq.prod;
		qp->sq_msn_prod = ionic_queue_next(&qp->sq, qp->sq_msn_prod);
	}

	ionic_stat_incr_idx(dev->stats, post_send_op, wqe->base.op);
	ionic_stat_add(dev->stats, post_send_sig,
		       !!(wqe->base.flags & cpu_to_be16(IONIC_V1_FLAG_SIG)));
	ionic_stat_add(dev->stats, post_send_inl,
		       !!(wqe->base.flags & cpu_to_be16(IONIC_V1_FLAG_INL)));
	ibdev_dbg(&dev->ibdev,
		  "post send %u prod %u\n", qp->qpid, qp->sq.prod);
	print_hex_dump_debug("wqe ", DUMP_PREFIX_OFFSET, 16, 1,
			     wqe, BIT(qp->sq.stride_log2), true);
	ionic_queue_produce(&qp->sq);
}

static int ionic_prep_common(struct ionic_qp *qp,
			     const struct ib_send_wr *wr,
			     struct ionic_sq_meta *meta,
			     struct ionic_v1_wqe *wqe)
{
	s64 signed_len;
	u32 mval;
	u32 sg_i, len;

	if (ionic_stats_enable) {
		qp->sq_frag_cnt[wr->num_sge]++;
		for (sg_i = 0; sg_i < wr->num_sge; sg_i++) {
			len = wr->sg_list[sg_i].length;
			if (len == 0 || len >= 4096)
				qp->sq_frag_4096_plus++;
			else if (len >= 2048)
				qp->sq_frag_2048_4095++;
			else if (len >= 1024)
				qp->sq_frag_1024_2047++;
			else if (len >= 512)
				qp->sq_frag_512_1023++;
			else if (len >= 256)
				qp->sq_frag_256_511++;
			else if (len >= 192)
				qp->sq_frag_192_255++;
			else if (len >= 128)
				qp->sq_frag_128_191++;
			else if (len >= 64)
				qp->sq_frag_64_127++;
			else if (len >= 32)
				qp->sq_frag_32_63++;
			else
				qp->sq_frag_0_31++;
		}
	}

	if (wr->send_flags & IB_SEND_INLINE) {
		wqe->base.num_sge_key = 0;
		wqe->base.flags |= cpu_to_be16(IONIC_V1_FLAG_INL);
		mval = ionic_v1_send_wqe_max_data(qp->sq.stride_log2,
						  qp->sq_cmb & IONIC_CMB_EXPDB);
		signed_len = ionic_prep_inline(wqe->common.pld.data, mval,
					       wr->sg_list, wr->num_sge);
	} else {
		wqe->base.num_sge_key = wr->num_sge;
		mval = ionic_v1_send_wqe_max_sge(qp->sq.stride_log2, qp->sq_spec,
						 qp->sq_cmb & IONIC_CMB_EXPDB);
		signed_len = ionic_prep_pld(wqe, &wqe->common.pld,
					    qp->sq_spec, mval,
					    wr->sg_list, wr->num_sge);
	}

	if (unlikely(signed_len < 0))
		return signed_len;

	meta->len = signed_len;
	wqe->common.length = cpu_to_be32(signed_len);

	ionic_prep_base(qp, wr, meta, wqe);

	return 0;
}

static void ionic_prep_sq_wqe(struct ionic_qp *qp, void *wqe)
{
	memset(wqe, 0, 1u << qp->sq.stride_log2);
}

static void ionic_prep_rq_wqe(struct ionic_qp *qp, void *wqe)
{
	memset(wqe, 0, 1u << qp->rq.stride_log2);
}

static int ionic_prep_send(struct ionic_qp *qp,
			   const struct ib_send_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	meta->ibop = IB_WC_SEND;

	switch (wr->opcode) {
	case IB_WR_SEND:
		wqe->base.op = IONIC_OP(dev->rdma_version, SEND);
		break;
	case IB_WR_SEND_WITH_IMM:
		wqe->base.op = IONIC_OP(dev->rdma_version, SEND_IMM);
		wqe->base.imm_data_key = wr->ex.imm_data;
		break;
	case IB_WR_SEND_WITH_INV:
		wqe->base.op = IONIC_OP(dev->rdma_version, SEND_INV);
		wqe->base.imm_data_key =
			cpu_to_be32(wr->ex.invalidate_rkey);
		break;
	default:
		return -EINVAL;
	}

	return ionic_prep_common(qp, wr, meta, wqe);
}

static int ionic_prep_send_ud(struct ionic_qp *qp,
			      const struct ib_ud_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;
	struct ionic_ah *ah;

	if (unlikely(!wr->ah))
		return -EINVAL;

	ah = to_ionic_ah(wr->ah);

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	wqe->common.send.ah_id = cpu_to_be32(ah->ahid);
	wqe->common.send.dest_qpn = cpu_to_be32(wr->remote_qpn);
	wqe->common.send.dest_qkey = cpu_to_be32(wr->remote_qkey);

	meta->ibop = IB_WC_SEND;

	switch (wr->wr.opcode) {
	case IB_WR_SEND:
		wqe->base.op = IONIC_OP(dev->rdma_version, SEND);
		break;
	case IB_WR_SEND_WITH_IMM:
		wqe->base.op = IONIC_OP(dev->rdma_version, SEND_IMM);
		wqe->base.imm_data_key = wr->wr.ex.imm_data;
		break;
	default:
		return -EINVAL;
	}

	return ionic_prep_common(qp, &wr->wr, meta, wqe);
}

static int ionic_prep_rdma(struct ionic_qp *qp,
			   const struct ib_rdma_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	meta->ibop = IB_WC_RDMA_WRITE;

	switch (wr->wr.opcode) {
	case IB_WR_RDMA_READ:
		if (wr->wr.send_flags & (IB_SEND_SOLICITED | IB_SEND_INLINE))
			return -EINVAL;
		meta->ibop = IB_WC_RDMA_READ;
		wqe->base.op = IONIC_OP(dev->rdma_version, RDMA_READ);
		break;
	case IB_WR_RDMA_WRITE:
		if (wr->wr.send_flags & IB_SEND_SOLICITED)
			return -EINVAL;
		wqe->base.op = IONIC_OP(dev->rdma_version, RDMA_WRITE);
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		wqe->base.op = IONIC_OP(dev->rdma_version, RDMA_WRITE_IMM);
		wqe->base.imm_data_key = wr->wr.ex.imm_data;
		break;
	default:
		return -EINVAL;
	}

	wqe->common.rdma.remote_va_high = cpu_to_be32(wr->remote_addr >> 32);
	wqe->common.rdma.remote_va_low = cpu_to_be32(wr->remote_addr);
	wqe->common.rdma.remote_rkey = cpu_to_be32(wr->rkey);

	return ionic_prep_common(qp, &wr->wr, meta, wqe);
}

static int ionic_prep_atomic(struct ionic_qp *qp,
			     const struct ib_atomic_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	if (wr->wr.num_sge != 1 || wr->wr.sg_list[0].length != 8)
		return -EINVAL;

	if (wr->wr.send_flags & (IB_SEND_SOLICITED | IB_SEND_INLINE))
		return -EINVAL;

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	meta->ibop = IB_WC_RDMA_WRITE;

	switch (wr->wr.opcode) {
	case IB_WR_ATOMIC_CMP_AND_SWP:
		meta->ibop = IB_WC_COMP_SWAP;
		wqe->base.op = IONIC_OP(dev->rdma_version, ATOMIC_CS);
		wqe->atomic.swap_add_high = cpu_to_be32(wr->swap >> 32);
		wqe->atomic.swap_add_low = cpu_to_be32(wr->swap);
		wqe->atomic.compare_high = cpu_to_be32(wr->compare_add >> 32);
		wqe->atomic.compare_low = cpu_to_be32(wr->compare_add);
		break;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		meta->ibop = IB_WC_FETCH_ADD;
		wqe->base.op = IONIC_OP(dev->rdma_version, ATOMIC_FA);
		wqe->atomic.swap_add_high = cpu_to_be32(wr->compare_add >> 32);
		wqe->atomic.swap_add_low = cpu_to_be32(wr->compare_add);
		break;
	default:
		return -EINVAL;
	}

	wqe->atomic.remote_va_high = cpu_to_be32(wr->remote_addr >> 32);
	wqe->atomic.remote_va_low = cpu_to_be32(wr->remote_addr);
	wqe->atomic.remote_rkey = cpu_to_be32(wr->rkey);

	wqe->base.num_sge_key = 1;
	wqe->atomic.sge.va = cpu_to_be64(wr->wr.sg_list[0].addr);
	wqe->atomic.sge.len = cpu_to_be32(8);
	wqe->atomic.sge.lkey = cpu_to_be32(wr->wr.sg_list[0].lkey);

	return ionic_prep_common(qp, &wr->wr, meta, wqe);
}

static int ionic_prep_inv(struct ionic_qp *qp,
			  const struct ib_send_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	if (wr->send_flags & (IB_SEND_SOLICITED | IB_SEND_INLINE))
		return -EINVAL;

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	wqe->base.op = IONIC_OP(dev->rdma_version, LOCAL_INV);
	wqe->base.imm_data_key = cpu_to_be32(wr->ex.invalidate_rkey);

	meta->len = 0;
	meta->ibop = IB_WC_LOCAL_INV;

	ionic_prep_base(qp, wr, meta, wqe);

	return 0;
}

static int ionic_prep_reg(struct ionic_qp *qp,
			  const struct ib_reg_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_mr *mr = to_ionic_mr(wr->mr);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;
	__le64 dma_addr;
	int flags;

	if (wr->wr.send_flags & (IB_SEND_SOLICITED | IB_SEND_INLINE))
		return -EINVAL;

	/* must call ib_map_mr_sg before posting reg wr */
	if (!mr->buf.tbl_pages)
		return -EINVAL;

	meta = &qp->sq_meta[qp->sq.prod];
	wqe = ionic_queue_at_prod(&qp->sq);

	ionic_prep_sq_wqe(qp, wqe);

	flags = to_ionic_mr_flags(wr->access);

	wqe->base.op = IONIC_OP(dev->rdma_version, REG_MR);
	wqe->base.num_sge_key = wr->key;
	wqe->base.imm_data_key = cpu_to_be32(mr->ibmr.lkey);
	wqe->reg_mr.va = cpu_to_be64(mr->ibmr.iova);
	wqe->reg_mr.length = cpu_to_be64(mr->ibmr.length);
	wqe->reg_mr.offset = ionic_pgtbl_off(&mr->buf, mr->ibmr.iova);
	dma_addr = ionic_pgtbl_dma(&mr->buf, mr->ibmr.iova);
	wqe->reg_mr.dma_addr = cpu_to_be64(le64_to_cpu(dma_addr));

	wqe->reg_mr.map_count = cpu_to_be32(mr->buf.tbl_pages);
	wqe->reg_mr.flags = cpu_to_be16(flags);
	wqe->reg_mr.dir_size_log2 = 0;
	wqe->reg_mr.page_size_log2 = order_base_2(mr->ibmr.page_size);

	meta->len = 0;
	meta->ibop = IB_WC_REG_MR;

	ionic_prep_base(qp, &wr->wr, meta, wqe);

	return 0;
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_prep_one_rc(struct ionic_qp *qp,
			     const struct ib_send_wr *wr)
#else
static int ionic_prep_one_rc(struct ionic_qp *qp,
			     struct ib_send_wr *wr)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	int rc = 0;

	switch (wr->opcode) {
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND_WITH_INV:
		rc = ionic_prep_send(qp, wr);
		break;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		rc = ionic_prep_rdma(qp, rdma_wr(wr));
		break;
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		rc = ionic_prep_atomic(qp, atomic_wr(wr));
		break;
	case IB_WR_LOCAL_INV:
		rc = ionic_prep_inv(qp, wr);
		break;
	case IB_WR_REG_MR:
		rc = ionic_prep_reg(qp, reg_wr(wr));
		break;
	default:
		ibdev_dbg(&dev->ibdev, "invalid opcode %d\n", wr->opcode);
		rc = -EINVAL;
	}

	return rc;
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_prep_one_ud(struct ionic_qp *qp,
			     const struct ib_send_wr *wr)
#else
static int ionic_prep_one_ud(struct ionic_qp *qp,
			     struct ib_send_wr *wr)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	int rc = 0;

	switch (wr->opcode) {
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
		rc = ionic_prep_send_ud(qp, ud_wr(wr));
		break;
	default:
		ibdev_dbg(&dev->ibdev, "invalid opcode %d\n", wr->opcode);
		rc = -EINVAL;
	}

	return rc;
}

#define IONIC_EXPDB_BASE(qtype, qpid) (((u64)(qtype) << 48) |	\
					IONIC_DBELL_QID(qpid) |	\
					((0x03 | 0x8) << 19)) /* SCHED_SET | PICI_PISET */

// TODO: rework similar to libionic_rdma
static void ionic_post_send_cmb(struct ionic_ibdev *dev, struct ionic_qp *qp)
{
	void *wqe_ptr;
	void __iomem *cmb_ptr;
	u64 *db_ptr;
	u64 db_base;
	u32 stride;
	u16 pos, end;
	u8 stride_log2;

	stride_log2 = qp->sq.stride_log2;
	stride = BIT(stride_log2);

	pos = qp->sq_cmb_prod;
	end = qp->sq.prod;

	while (pos != end) {
		cmb_ptr = qp->sq_cmb_ptr + ((size_t)pos << stride_log2);
		wqe_ptr = ionic_queue_at(&qp->sq, pos);

		if (qp->sq_cmb & IONIC_CMB_EXPDB) {
			db_ptr = wqe_ptr + stride - IONIC_EXP_DBELL_SZ;

			/* Assume ring 0 */
			db_base = IONIC_EXPDB_BASE(dev->sq_qtype, qp->qpid);
			*db_ptr = db_base | ((pos + 1) & qp->sq.mask);
		}

		memcpy_toio(cmb_ptr, wqe_ptr, stride);

		pos = ionic_queue_next(&qp->sq, pos);

		if (!(qp->sq_cmb & IONIC_CMB_EXPDB)) {
#ifdef IONIC_NOT_UPSTREAM
			if (ionic_qp_dbell)
#endif
				ionic_dbell_ring(dev->dbpage, dev->sq_qtype,
						 qp->sq.dbell | pos);
		}
	}

	ionic_stat_add(dev->stats, post_send_cmb,
		       (end - qp->sq_cmb_prod) & qp->sq.mask);

	qp->sq_cmb_prod = end;
}

// TODO: rework similar to libionic_rdma
static void ionic_post_recv_cmb(struct ionic_ibdev *dev, struct ionic_qp *qp)
{
	void __iomem *cmb_ptr;
	void *wqe_ptr;
	u64 *db_ptr;
	u64 db_base;
	u32 stride;
	u16 pos, end;
	u8 stride_log2;

	stride_log2 = qp->rq.stride_log2;

	pos = qp->rq_cmb_prod;
	end = qp->rq.prod;

	if (pos > end) {
		cmb_ptr = qp->rq_cmb_ptr + ((size_t)pos << stride_log2);
		wqe_ptr = ionic_queue_at(&qp->rq, pos);

		stride = (u32)(qp->rq.mask - pos + 1) << stride_log2;
		if (qp->rq_cmb & IONIC_CMB_EXPDB) {
			db_ptr = wqe_ptr + stride - IONIC_EXP_DBELL_SZ;

			/* Assume ring 0 */
			db_base = IONIC_EXPDB_BASE(dev->rq_qtype, qp->qpid);
			*db_ptr = db_base | ((pos + 1) & qp->rq.mask);
		}

		memcpy_toio(cmb_ptr, wqe_ptr, stride);

		pos = 0;

		if (!(qp->rq_cmb & IONIC_CMB_EXPDB))
			ionic_dbell_ring(dev->dbpage, dev->rq_qtype,
					 qp->rq.dbell | pos);
	}

	if (pos < end) {
		cmb_ptr = qp->rq_cmb_ptr + ((size_t)pos << stride_log2);
		wqe_ptr = ionic_queue_at(&qp->rq, pos);
		stride = (u32)(end - pos) << stride_log2;
		if (qp->rq_cmb & IONIC_CMB_EXPDB) {
			db_ptr = wqe_ptr + stride - IONIC_EXP_DBELL_SZ;

			/* Assume ring 0 */
			db_base = IONIC_EXPDB_BASE(dev->rq_qtype, qp->qpid);
			*db_ptr = db_base | ((pos + 1) & qp->rq.mask);
		}

		memcpy_toio(cmb_ptr, wqe_ptr, stride);

		pos = end;

		if (!(qp->rq_cmb & IONIC_CMB_EXPDB))
			ionic_dbell_ring(dev->dbpage, dev->rq_qtype,
					 qp->rq.dbell | pos);
	}

	ionic_stat_add(dev->stats, post_recv_cmb,
		       (end - qp->rq_cmb_prod) & qp->rq.mask);

	qp->rq_cmb_prod = end;
}

static int ionic_prep_recv(struct ionic_qp *qp,
			   const struct ib_recv_wr *wr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(qp->ibqp.device);
	struct ionic_rq_meta *meta;
	struct ionic_v1_wqe *wqe;
	s64 signed_len;
	u32 mval;

	wqe = ionic_queue_at_prod(&qp->rq);

	/* if wqe is owned by device, caller can try posting again soon */
	if (wqe->base.flags & cpu_to_be16(IONIC_V1_FLAG_FENCE))
		return -EAGAIN;

	meta = qp->rq_meta_head;
	if (unlikely(meta == IONIC_META_LAST) ||
	    unlikely(meta == IONIC_META_POSTED))
		return -EIO;

	ionic_prep_rq_wqe(qp, wqe);

	mval = ionic_v1_recv_wqe_max_sge(qp->rq.stride_log2, qp->rq_spec,
					 qp->rq_cmb & IONIC_CMB_EXPDB);
	signed_len = ionic_prep_pld(wqe, &wqe->recv.pld,
				    qp->rq_spec, mval,
				    wr->sg_list, wr->num_sge);
	if (signed_len < 0)
		return signed_len;

	meta->wrid = wr->wr_id;

	wqe->base.wqe_id = meta - qp->rq_meta;
	wqe->base.num_sge_key = wr->num_sge;

	/* total length for recv goes in base imm_data_key */
	wqe->base.imm_data_key = cpu_to_be32(signed_len);

	ibdev_dbg(&dev->ibdev,
		  "post recv %u prod %u\n", qp->qpid, qp->rq.prod);
	print_hex_dump_debug("wqe ", DUMP_PREFIX_OFFSET, 16, 1,
			     wqe, BIT(qp->rq.stride_log2), true);
	ionic_queue_produce(&qp->rq);

	qp->rq_meta_head = meta->next;
	meta->next = IONIC_META_POSTED;

	return 0;
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_post_send_common(struct ionic_ibdev *dev,
				  struct ionic_vcq *vcq,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  const struct ib_send_wr *wr,
				  const struct ib_send_wr **bad)
#else
static int ionic_post_send_common(struct ionic_ibdev *dev,
				  struct ionic_vcq *vcq,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  struct ib_send_wr *wr,
				  struct ib_send_wr **bad)
#endif
{
	unsigned long irqflags;
	bool notify = false;
	int spend, rc = 0;
	u16 old_prod;

	ionic_lat_trace(dev->lats, application);
	ionic_stat_incr(dev->stats, post_send);

	if (!bad)
		return -EINVAL;

	if (!qp->has_sq) {
		*bad = wr;
		return -EINVAL;
	}

	if (qp->state < IB_QPS_RTS) {
		*bad = wr;
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->sq_lock, irqflags);

	old_prod = qp->sq.prod;
	ionic_stat_incr_idx_fls(dev->stats, post_send_qlen,
				ionic_queue_length(&qp->sq));

	while (wr) {
		if (ionic_queue_full(&qp->sq)) {
			ibdev_dbg(&dev->ibdev, "queue full");
			rc = -ENOMEM;
			goto out;
		}

		if (qp->ibqp.qp_type == IB_QPT_UD ||
		    qp->ibqp.qp_type == IB_QPT_GSI)
			rc = ionic_prep_one_ud(qp, wr);
		else
			rc = ionic_prep_one_rc(qp, wr);
		if (rc)
			goto out;

		wr = wr->next;
	}

out:
	old_prod = (qp->sq.prod - old_prod) & qp->sq.mask;
	ionic_stat_incr_idx_fls(dev->stats, post_send_nwr, old_prod);
	ionic_stat_add(dev->stats, post_send_wr, old_prod);

	/* irq remains saved here, not restored/saved again */
	if (!spin_trylock(&cq->lock)) {
		spin_unlock(&qp->sq_lock);
		spin_lock(&cq->lock);
		spin_lock(&qp->sq_lock);
	}

	if (likely(qp->sq.prod != qp->sq_old_prod)) {
		/* ring cq doorbell just in time */
		spend = (qp->sq.prod - qp->sq_old_prod) & qp->sq.mask;
		ionic_reserve_cq(dev, cq, spend);

		qp->sq_old_prod = qp->sq.prod;

		if (qp->sq_cmb_ptr)
			ionic_post_send_cmb(dev, qp);
		else
#ifdef IONIC_NOT_UPSTREAM
			if (ionic_qp_dbell)
#endif
				ionic_dbell_ring(dev->dbpage, dev->sq_qtype,
						 ionic_queue_dbell_val(&qp->sq));
	}

	if (qp->sq_flush) {
		notify = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_sq, &cq->flush_sq);
	}

	spin_unlock(&qp->sq_lock);
	spin_unlock_irqrestore(&cq->lock, irqflags);

	if (notify && vcq->ibcq.comp_handler)
		vcq->ibcq.comp_handler(&vcq->ibcq, vcq->ibcq.cq_context);

	ionic_stat_add(dev->stats, post_send_err, !!rc);
	ionic_lat_trace(dev->lats, post_send);

	*bad = wr;
	return rc;
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_post_recv_common(struct ionic_ibdev *dev,
				  struct ionic_vcq *vcq,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  const struct ib_recv_wr *wr,
				  const struct ib_recv_wr **bad)
#else
static int ionic_post_recv_common(struct ionic_ibdev *dev,
				  struct ionic_vcq *vcq,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  struct ib_recv_wr *wr,
				  struct ib_recv_wr **bad)
#endif
{
	unsigned long irqflags;
	bool notify = false;
	int spend, rc = 0;
	u16 old_prod;

	ionic_lat_trace(dev->lats, application);
	ionic_stat_incr(dev->stats, post_recv);

	if (!bad)
		return -EINVAL;

	if (!qp->has_rq) {
		*bad = wr;
		return -EINVAL;
	}

	if (qp->state < IB_QPS_INIT) {
		*bad = wr;
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->rq_lock, irqflags);

	old_prod = qp->rq.prod;
	ionic_stat_incr_idx_fls(dev->stats, post_recv_qlen,
				ionic_queue_length(&qp->rq));

	while (wr) {
		if (ionic_queue_full(&qp->rq)) {
			ibdev_dbg(&dev->ibdev, "queue full");
			rc = -ENOMEM;
			goto out;
		}

		rc = ionic_prep_recv(qp, wr);
		if (rc)
			goto out;

		wr = wr->next;
	}

out:
	old_prod = (qp->rq.prod - old_prod) & qp->rq.mask;
	ionic_stat_incr_idx_fls(dev->stats, post_recv_nwr, old_prod);
	ionic_stat_add(dev->stats, post_recv_wr, old_prod);

	if (!cq) {
		spin_unlock_irqrestore(&qp->rq_lock, irqflags);
		goto out_unlocked;
	}

	/* irq remains saved here, not restored/saved again */
	if (!spin_trylock(&cq->lock)) {
		spin_unlock(&qp->rq_lock);
		spin_lock(&cq->lock);
		spin_lock(&qp->rq_lock);
	}

	if (likely(qp->rq.prod != qp->rq_old_prod)) {
		/* ring cq doorbell just in time */
		spend = (qp->rq.prod - qp->rq_old_prod) & qp->rq.mask;
		ionic_reserve_cq(dev, cq, spend);

		qp->rq_old_prod = qp->rq.prod;

		if (qp->rq_cmb_ptr)
			ionic_post_recv_cmb(dev, qp);
		else
			ionic_dbell_ring(dev->dbpage, dev->rq_qtype,
					 ionic_queue_dbell_val(&qp->rq));
	}

	if (qp->rq_flush) {
		notify = true;
		cq->flush = true;
		list_move_tail(&qp->cq_flush_rq, &cq->flush_rq);
	}

	spin_unlock(&qp->rq_lock);
	spin_unlock_irqrestore(&cq->lock, irqflags);

	if (notify && vcq->ibcq.comp_handler)
		vcq->ibcq.comp_handler(&vcq->ibcq, vcq->ibcq.cq_context);

out_unlocked:
	ionic_lat_trace(dev->lats, post_recv);
	ionic_stat_add(dev->stats, post_recv_err, !!rc);

	*bad = wr;
	return rc;
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_post_send(struct ib_qp *ibqp,
			   const struct ib_send_wr *wr,
			   const struct ib_send_wr **bad)
#else
static int ionic_post_send(struct ib_qp *ibqp,
			   struct ib_send_wr *wr,
			   struct ib_send_wr **bad)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibqp->device);
	struct ionic_vcq *vcq = to_ionic_vcq(ibqp->send_cq);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq = to_ionic_vcq_cq(ibqp->send_cq, qp->udma_idx);

	return ionic_post_send_common(dev, vcq, cq, qp, wr, bad);
}

#ifdef IONIC_HAVE_CONST_IB_WR
static int ionic_post_recv(struct ib_qp *ibqp,
			   const struct ib_recv_wr *wr,
			   const struct ib_recv_wr **bad)
#else
static int ionic_post_recv(struct ib_qp *ibqp,
			   struct ib_recv_wr *wr,
			   struct ib_recv_wr **bad)
#endif
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibqp->device);
	struct ionic_vcq *vcq = to_ionic_vcq(ibqp->recv_cq);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq = to_ionic_vcq_cq(ibqp->recv_cq, qp->udma_idx);

	return ionic_post_recv_common(dev, vcq, cq, qp, wr, bad);
}

static const struct ib_device_ops ionic_datapath_ops = {
#ifdef IONIC_HAVE_RDMA_DEV_OPS_EXT
	.driver_id		= RDMA_DRIVER_IONIC,
#endif
	.post_send		= ionic_post_send,
	.post_recv		= ionic_post_recv,
	.poll_cq		= ionic_poll_cq,
	.req_notify_cq		= ionic_req_notify_cq,
};

void ionic_datapath_setops(struct ionic_ibdev *dev)
{
	ib_set_device_ops(&dev->ibdev, &ionic_datapath_ops);

	dev->ibdev.uverbs_cmd_mask |=
		BIT_ULL(IB_USER_VERBS_CMD_POST_SEND)		|
		BIT_ULL(IB_USER_VERBS_CMD_POST_RECV)		|
		BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ)		|
		BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)	|
		0;
}
