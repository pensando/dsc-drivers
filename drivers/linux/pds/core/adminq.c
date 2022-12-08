// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>

#include "core.h"
#include "pds_adminq.h"


struct pdsc_wait_context {
	struct pdsc_qcq *qcq;
	struct completion wait_completion;
};

static int pdsc_process_notifyq(struct pdsc_qcq *qcq)
{
	union pds_core_notifyq_comp *comp;
	struct pdsc *pdsc = qcq->pdsc;
	struct pdsc_cq *cq = &qcq->cq;
	struct pdsc_cq_info *cq_info;
	int n_work = 0;
	u64 eid;

	cq_info = &cq->info[cq->tail_idx];
	comp = cq_info->comp;
	eid = le64_to_cpu(comp->event.eid);
	while (eid > pdsc->last_eid) {
		u16 ecode = le16_to_cpu(comp->event.ecode);

		switch (ecode) {
		case PDS_EVENT_LINK_CHANGE:
			dev_info(pdsc->dev, "NotifyQ LINK_CHANGE ecode %d eid %lld\n",
				 ecode, eid);
			break;

		case PDS_EVENT_RESET:
			dev_info(pdsc->dev, "NotifyQ RESET ecode %d eid %lld\n",
				 ecode, eid);
			pdsc_auxbus_publish(pdsc, PDSC_ALL_CLIENT_IDS, comp);
			// TODO: call fw_down here or not?
			//	 don't want to race with health check
			//pdsc_fw_down(pdsc);
			break;

		case PDS_EVENT_XCVR:
			dev_info(pdsc->dev, "NotifyQ XCVR ecode %d eid %lld\n",
				 ecode, eid);
			break;

		case PDS_EVENT_CLIENT:
		{
			struct pds_core_client_event *ce;
			union pds_core_notifyq_comp *cc;
			u16 client_id;

			ce = (struct pds_core_client_event *)comp;
			cc = (union pds_core_notifyq_comp *)&ce->client_event;
			client_id = le16_to_cpu(ce->client_id);
			dev_info(pdsc->dev, "NotifyQ CLIENT %d ecode %d eid %lld cc->ecode %d\n",
				 client_id, ecode, eid, le16_to_cpu(cc->ecode));
			pdsc_auxbus_publish(pdsc, client_id, cc);
			break;
		}

		default:
			dev_info(pdsc->dev, "NotifyQ ecode %d eid %lld\n",
				 ecode, eid);
			break;
		}

		pdsc->last_eid = eid;
		cq->tail_idx = (cq->tail_idx + 1) & (cq->num_descs - 1);
		cq_info = &cq->info[cq->tail_idx];
		comp = cq_info->comp;
		eid = le64_to_cpu(comp->event.eid);

		n_work++;
	}

	qcq->accum_work += n_work;

	return n_work;
}

void pdsc_process_adminq(struct pdsc_qcq *qcq)
{
	union pds_core_adminq_comp *comp;
	struct pdsc_queue *q = &qcq->q;
	struct pdsc *pdsc = qcq->pdsc;
	struct pdsc_cq *cq = &qcq->cq;
	struct pdsc_q_info *q_info;
	unsigned long irqflags;
	int n_work = 0;
	int a_work = 0;
	pds_core_cb cb;
	void *cb_arg;
	int credits;
	u32 index;

	/* Only the core AdminQ has an accompanying NotifyQ */
	if (qcq->flags & PDS_CORE_QCQ_F_CORE)
		n_work = pdsc_process_notifyq(&pdsc->notifyqcq);

	/* Check for empty queue, which can happen if the interrupt was
	 * for a NotifyQ event and there are no new AdminQ completions.
	 */
	if (q->tail_idx == q->head_idx)
		goto credits;

	/* Find the first completion to clean,
	 * run the callback in the related q_info,
	 * and continue while we still match done color
	 */
	spin_lock_irqsave(&pdsc->adminq_lock, irqflags);
	comp = cq->info[cq->tail_idx].comp;
	while (pdsc_color_match(comp->color, cq->done_color)) {

		q_info = &q->info[q->tail_idx];
		index = q->tail_idx;
		q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);
		cb = q_info->cb;
		cb_arg = q_info->cb_arg;

		/* Copy out the completion data */
		memcpy(q_info->dest, comp, sizeof(*comp));

		q_info->cb = NULL;
		q_info->cb_arg = NULL;

		/* For synchronous AdminQ calls, the cb is NULL and the
		 * cb_arg is the wait context for the completion.
		 *
		 * For async AdminQ calls, this is the caller provided
		 * callback and argument.  Since we're holding the
		 * adminq_lock, the callback should take care
		 * not to try another AdminQ request.
		 */
		if (cb) {
			cb(cb_arg);
		} else {
			struct pdsc_wait_context *wc = cb_arg;

			complete_all(&wc->wait_completion);
		}

		if (cq->tail_idx == cq->num_descs - 1)
			cq->done_color = !cq->done_color;
		cq->tail_idx = (cq->tail_idx + 1) & (cq->num_descs - 1);
		comp = cq->info[cq->tail_idx].comp;

		a_work++;
	}
	spin_unlock_irqrestore(&pdsc->adminq_lock, irqflags);

	qcq->accum_work += a_work;

credits:
	/* Return the interrupt credits, one for each completion */
	credits = n_work + a_work;
	if (credits)
		pds_core_intr_credits(&pdsc->intr_ctrl[qcq->intx],
				      credits,
				      PDS_CORE_INTR_CRED_REARM);

}

void pdsc_work_thread(struct work_struct *work)
{
	struct pdsc_qcq *qcq = container_of(work, struct pdsc_qcq, work);

	pdsc_process_adminq(qcq);
}

irqreturn_t pdsc_adminq_isr(int irq, void *data)
{
	struct pdsc_qcq *qcq = data;
	struct pdsc *pdsc = qcq->pdsc;

	/* Don't process AdminQ when shutting down */
	if (pdsc->state & BIT_ULL(PDSC_S_STOPPING_DRIVER)) {
		pr_err("%s: called while PDSC_S_STOPPING_DRIVER\n", __func__);
		return IRQ_HANDLED;
	}

	queue_work(pdsc->wq, &qcq->work);

	//       we can safely re-enable the interrupt here
	//       more interrupts might come in while we're
	//       processing this work-queue event, but the
	//       queue_work() call will see that it is already
	//       queued and running, so won't enqueue another.
	//       meanwhile, our processing will see the new
	//       completions if it hasn't hit the end yet
	//       and process them accordingly.

	pds_core_intr_mask(&pdsc->intr_ctrl[irq], PDS_CORE_INTR_MASK_CLEAR);

	return IRQ_HANDLED;
}

static int __pdsc_adminq_post(struct pdsc *pdsc,
			      struct pdsc_qcq *qcq,
			      union pds_core_adminq_cmd *cmd,
			      union pds_core_adminq_comp *comp,
			      void (*comp_cb)(void *cb_arg),
			      void *cb_arg)
{
	struct pdsc_queue *q = &qcq->q;
	struct pdsc_q_info *q_info;
	unsigned long irqflags;
	unsigned int avail;
	int ret = 0;
	int index;

	spin_lock_irqsave(&pdsc->adminq_lock, irqflags);

	/* Check for space in the queue */
	avail = q->tail_idx;
	if (q->head_idx >= avail)
		avail += q->num_descs - q->head_idx - 1;
	else
		avail -= q->head_idx + 1;
	if (!avail) {
		ret = -ENOSPC;
		goto err_out;
	}

	/* Check that the FW is running */
	if (!pdsc_is_fw_running(pdsc)) {
		u8 fw_status = ioread8(&pdsc->info_regs->fw_status);

		dev_info(pdsc->dev, "%s: post failed - fw not running %#02x:\n",
			 __func__, fw_status);
		ret = -ENXIO;

		goto err_out;
	}

	/* Post the request */
	index = q->head_idx;
	q_info = &q->info[index];
	q_info->cb = comp_cb;
	q_info->cb_arg = cb_arg;
	q_info->dest = comp;
	memcpy(q_info->desc, cmd, sizeof(*cmd));

	dev_dbg(pdsc->dev, "head_idx %d tail_idx %d cb_arg %p\n",
		q->head_idx, q->tail_idx, cb_arg);
	dev_dbg(pdsc->dev, "post admin queue command:\n");
	dynamic_hex_dump("cmd ", DUMP_PREFIX_OFFSET, 16, 1,
			 cmd, sizeof(*cmd), true);

	q->head_idx = (q->head_idx + 1) & (q->num_descs - 1);

	pds_core_dbell_ring(pdsc->kern_dbpage, q->hw_type, q->dbval | q->head_idx);
	ret = index;

err_out:
	spin_unlock_irqrestore(&pdsc->adminq_lock, irqflags);
	return ret;
}

static void pdsc_adminq_flush(struct pdsc *pdsc, struct pdsc_qcq *qcq)
{
	struct pdsc_q_info *desc_info;
	unsigned long irqflags;
	struct pdsc_queue *q;

	spin_lock_irqsave(&pdsc->adminq_lock, irqflags);
	if (!qcq)
		goto out_unlock;

	q = &qcq->q;

	while (q->tail_idx != q->head_idx) {
		desc_info = &q->info[q->tail_idx];
		memset(desc_info->desc, 0, sizeof(union pds_core_adminq_cmd));
		desc_info->cb = NULL;
		desc_info->cb_arg = NULL;
		q->tail_idx = (q->tail_idx + 1) & (q->num_descs - 1);
	}

out_unlock:
	spin_unlock_irqrestore(&pdsc->adminq_lock, irqflags);
}

int pdsc_adminq_post_async(struct pdsc *pdsc,
			   struct pdsc_qcq *qcq,
			   union pds_core_adminq_cmd *cmd,
			   union pds_core_adminq_comp *comp,
			   void (*comp_cb)(void *cb_arg),
			   void *cb_arg)
{
	int err = 0;
	int index;

	index = __pdsc_adminq_post(pdsc, qcq, cmd, comp, comp_cb, cb_arg);
	if (index < 0)
		err = index;

	return err;
}

int pdsc_adminq_post(struct pdsc *pdsc,
		     struct pdsc_qcq *qcq,
		     union pds_core_adminq_cmd *cmd,
		     union pds_core_adminq_comp *comp,
		     bool fast_poll)
{
	struct pdsc_wait_context wc = {
		.wait_completion = COMPLETION_INITIALIZER_ONSTACK(wc.wait_completion),
		.qcq = qcq,
	};
	unsigned long poll_interval = 1;
	unsigned long time_limit;
	unsigned long time_start;
	unsigned long time_done;
	unsigned long remaining;
	int err = 0;
	int index;

	index = __pdsc_adminq_post(pdsc, qcq, cmd, comp, NULL, &wc);
	if (index < 0) {
		err = index;
		goto out;
	}

	time_start = jiffies;
	time_limit = time_start + HZ * pdsc->devcmd_timeout;
	do {
		/* Timeslice the actual wait to catch IO errors etc early */
		remaining = wait_for_completion_timeout(&wc.wait_completion,
							msecs_to_jiffies(poll_interval));
		if (remaining)
			break;

		if (!pdsc_is_fw_running(pdsc)) {
			u8 fw_status = ioread8(&pdsc->info_regs->fw_status);

			dev_dbg(pdsc->dev, "%s: post wait failed - fw not running %#02x:\n",
				__func__, fw_status);
			err = -ENXIO;
			break;
		}

		/* when fast_poll is not requested, prevent aggressive polling
		 * on failures due to timeouts by doing exponential back off
		 */
		if (!fast_poll && poll_interval < PDSC_ADMINQ_MAX_POLL_INTERVAL)
			poll_interval <<= 1;
	} while (time_before(jiffies, time_limit));
	time_done = jiffies;
	dev_dbg(pdsc->dev, "%s: elapsed %d msecs\n",
		__func__, jiffies_to_msecs(time_done - time_start));

	/* Check the results */
	if (time_after_eq(time_done, time_limit)) {
		err = -ETIMEDOUT;
		pdsc_adminq_flush(pdsc, qcq);
		// TODO: deal with waiting async requests
	}

	dev_dbg(pdsc->dev, "read admin queue completion idx %d:\n", index);
	dynamic_hex_dump("comp ", DUMP_PREFIX_OFFSET, 16, 1,
			 comp, sizeof(*comp), true);

	if (remaining && comp->status)
		err = pdsc_err_to_errno(comp->status);

out:
	if (err) {
		dev_dbg(pdsc->dev, "%s: opcode %d status %d err %pe\n",
			__func__, cmd->opcode, comp->status, ERR_PTR(err));
		if (err == -ENXIO || err == -ETIMEDOUT)
			pdsc_queue_health_check(pdsc);
	}

	return err;
}

