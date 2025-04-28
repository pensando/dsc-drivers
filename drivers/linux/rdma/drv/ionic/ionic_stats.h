/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_STATS_H
#define IONIC_STATS_H

#include <linux/types.h>

struct device;

extern bool ionic_stats_enable;
extern bool ionic_lats_enable;

/* Queue length can be 0..65535.  The histogram has 17 buckets.  There is one
 * bucket for zero, and one for each most significant bit set of 16 bits.
 */
#define IONIC_STATS_FLS	17

/* Valid opcodes are 0..255.  The histogram has 256 buckets. */
#define IONIC_STATS_OPS	256

/* Based on stats size, more than MAX_QPS_PER_COUNTER cannot fit into the socket
 * buffer (4K) size sent by the ioroute2/rdma application. There may be a need to
 * revisit max count if there are is increase in stats size.
 * To support more QPs per counter, changes are needed in application and/or the
 * kernel function res_get_common_dumpit to allow socket recvmsg to return with
 * MSG_TRUNC flag in case of socket buffer overflow case.
 */
#define IONIC_MAX_QPS_PER_COUNTER 180

struct ionic_counter_stats {
	int queue_stats_count;
	struct ionic_v1_stat *hdr;

#ifdef IONIC_HAVE_IB_HW_STAT_DESC
	struct rdma_stat_desc *stats_hdrs;
#else
	const char **stats_hdrs;
#endif
	struct xarray xa_counters;
};

struct ionic_counter {
	void *vals;
	struct list_head qp_list;
	int num_qps;
};

/**
 * struct ionic_stats: Counters incremented by driver.
 * @ring_cq_dbell:	Times rang cq doorbell to advance index.
 * @arm_cq_any:		Times rang cq doorbell to arm any event.
 * @arm_cq_sol:		Times rang cq doorbell to arm solicited only.
 * @poll_cq:		Times called poll_cq
 * @poll_cq_err:	Times returned error
 * @poll_cq_wc:		Total wc polled
 * @poll_cq_wc_err:	Total wc polled with error
 * @poll_cq_wc_flush:	Total wc flushed by driver
 * @poll_cq_cqe:	Total cqe (incl unsignaled)
 * @poll_cq_nwc:	Times polled batch of nwc (log)
 * @poll_cq_ncqe:	Times polled batch of ncqe (log)
 * @post_recv:		Timed called post_recv (or srq)
 * @post_recv_err:	Times returned error
 * @post_recv_wr:	Total recv wr posted
 * @post_recv_cmb:	Total posted to rq in cmb
 * @post_recv_nwr:	Times posted batch of nwr (log)
 * @post_recv_qlen:	Qlen when called post_send (log)
 * @post_send:		Times called post_send
 * @post_send_err:	Times returned error
 * @post_send_wr:	Total send wr posted
 * @post_send_inl:	Total posted with inline data
 * @post_send_sig:	Total posted with signaled flag
 * @post_send_cmb:	Total posted to sq in cmb
 * @post_send_nwr:	Times posted batch of nwr (log)
 * @post_send_qlen:	Qlen when called post_send (log)
 * @post_send_op:	Times posted send opcode
 */
struct ionic_stats {
	bool		histogram;
	atomic64_t	ring_cq_dbell;
	atomic64_t	arm_cq_any;
	atomic64_t	arm_cq_sol;
	atomic64_t	poll_cq;
	atomic64_t	poll_cq_err;
	atomic64_t	poll_cq_wc;
	atomic64_t	poll_cq_wc_err;
	atomic64_t	poll_cq_wc_flush;
	atomic64_t	poll_cq_cqe;
	atomic64_t	poll_cq_nwc[IONIC_STATS_FLS];
	atomic64_t	poll_cq_ncqe[IONIC_STATS_FLS];
	atomic64_t	post_recv;
	atomic64_t	post_recv_err;
	atomic64_t	post_recv_wr;
	atomic64_t	post_recv_cmb;
	atomic64_t	post_recv_nwr[IONIC_STATS_FLS];
	atomic64_t	post_recv_qlen[IONIC_STATS_FLS];
	atomic64_t	post_send;
	atomic64_t	post_send_err;
	atomic64_t	post_send_wr;
	atomic64_t	post_send_inl;
	atomic64_t	post_send_sig;
	atomic64_t	post_send_cmb;
	atomic64_t	post_send_nwr[IONIC_STATS_FLS];
	atomic64_t	post_send_qlen[IONIC_STATS_FLS];
	atomic64_t	post_send_op[IONIC_STATS_OPS];
};

/* Find the "last" or most significant bit that is set. */
static inline int ionic_fls(unsigned long val)
{
	/* Set all bits of lesser significance */
	val |= val >> 32;
	val |= val >> 16;
	val |= val >> 8;
	val |= val >> 4;
	val |= val >> 2;
	val |= val >> 1;
	/* Leave only the most significant bit set */
	val ^= val >> 1;
	/* The most significant is the least significant bit */
	return ffs(val);
}

#define _ionic_stat_add(stats, name, val)				\
	atomic64_add(val, &((stats)->name))

#define _ionic_stat_incr(stats, name)					\
	_ionic_stat_add(stats, name, 1)

#define ionic_stat_add(stats, name, val) do {				\
	if (ionic_stats_enable && stats)				\
		_ionic_stat_add(stats, name, val);			\
} while (0)

#define ionic_stat_incr(stats, name)					\
	ionic_stat_add(stats, name, 1)

#define ionic_stat_incr_idx(stats, name, idx)				\
	ionic_stat_incr(stats, name[(idx)])

#define ionic_stat_incr_idx_fls(stats, name, idx) do {			\
	if (ionic_stats_enable && stats && stats->histogram)		\
		_ionic_stat_incr(stats, name[ionic_fls((idx))]);	\
} while (0)

#define ionic_stat_print(dev, stats, name) do {				\
	const unsigned long long _val =					\
		atomic64_read(&(stats)->name);				\
	dev_info(dev, "%26s: %llu\n", #name, _val);			\
} while (0)

#define ionic_stat_print_idx(dev, stats, name, idx) do {		\
	const unsigned long long _val =					\
		atomic64_read(&(stats)->name[(idx)]);			\
	if (_val)							\
		dev_info(dev, "%21s[%3d]: %llu\n",			\
			 #name, idx, _val);				\
} while (0)

#define ionic_stat_print_idx_fls(dev, stats, name, idx) do {		\
	const unsigned long long _val =					\
		atomic64_read(&(stats)->name[idx]);			\
	const int _range = 1 << (idx);					\
	if (_val)							\
		dev_info(dev, "%16s[%3d..%3d]: %llu\n",			\
			 #name, _range >> 1, _range - 1, _val);		\
} while (0)

static inline void ionic_stats_print(struct device *dev,
				     struct ionic_stats *stats)
{
	int i;

	if (!stats || !ionic_stats_enable)
		return;

	dev_info(dev, "counter statistics:\n");

	ionic_stat_print(dev, stats, ring_cq_dbell);
	ionic_stat_print(dev, stats, arm_cq_any);
	ionic_stat_print(dev, stats, arm_cq_sol);
	ionic_stat_print(dev, stats, poll_cq);
	ionic_stat_print(dev, stats, poll_cq_err);
	ionic_stat_print(dev, stats, poll_cq_wc);
	ionic_stat_print(dev, stats, poll_cq_wc_err);
	ionic_stat_print(dev, stats, poll_cq_cqe);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, poll_cq_nwc, i);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, poll_cq_ncqe, i);
	ionic_stat_print(dev, stats, post_recv);
	ionic_stat_print(dev, stats, post_recv_err);
	ionic_stat_print(dev, stats, post_recv_wr);
	ionic_stat_print(dev, stats, post_recv_cmb);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, post_recv_nwr, i);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, post_recv_qlen, i);
	ionic_stat_print(dev, stats, post_send);
	ionic_stat_print(dev, stats, post_send_err);
	ionic_stat_print(dev, stats, post_send_wr);
	ionic_stat_print(dev, stats, post_send_inl);
	ionic_stat_print(dev, stats, post_send_sig);
	ionic_stat_print(dev, stats, post_send_cmb);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, post_send_nwr, i);
	for (i = 0; i < IONIC_STATS_FLS; ++i)
		ionic_stat_print_idx_fls(dev, stats, post_send_qlen, i);
	for (i = 0; i < IONIC_STATS_OPS; ++i)
		ionic_stat_print_idx(dev, stats, post_send_op, i);
}

/*
 * NB: The latency code assumes single-threaded usage.
 *     The results are meaningless when multiple threads access the device.
 */
//#define IONIC_LATS_TSC
#define IONIC_LATS_BINS		32
#define IONIC_LATS_OUTLIER	4

/**
 * struct ionic_latstat: One dimension of latency statistics.
 * @min:		Mininum latency seen.
 * @max:		Maximum latency seen after warmup.
 * @accum:		Accumulated latency after warmup.
 * @count:		Number of samples after warmup, for averaging.
 * @warmup:		Number of samples discarded for warmup.
 * @hist:		Histogram of samples, log scale.
 */
struct ionic_latstat {
	unsigned long		min;
	unsigned long		max;
	unsigned long		accum;
	unsigned int		count;
	unsigned int		warmup;
	unsigned long		hist[IONIC_LATS_BINS];
};

/**
 * struct ionic_latencies: Latency statistics.
 * @overhead:		Overhead per trace
 * @stamp:		Most recent timestamp
 * @application:	Duration between calls
 * @poll_cq_empty:	Duration of poll_cq empty cq
 * @poll_cq_compl:	Duration of poll_cq with completions
 * @post_send:		Duration of post_send
 * @post_recv:		Duration of post_recv
 *
 * Only single-thread supported to keep overhead low.
 */
struct ionic_latencies {
	unsigned long		overhead;
	unsigned long		stamp;
	bool			enable;
	bool			histogram;
	struct ionic_latstat	application;
	struct ionic_latstat	poll_cq_empty;
	struct ionic_latstat	poll_cq_compl;
	struct ionic_latstat	post_send;
	struct ionic_latstat	post_recv;
};

#ifdef IONIC_LATS_TSC
#define IONIC_LATS_UNITS "tsc"
static inline unsigned long ionic_lat_stamp(void) {
	unsigned int hi, lo;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));

	return (unsigned long)lo | ((unsigned long)hi << 32);
}
#else
#define IONIC_LATS_UNITS "ns"
static inline unsigned long ionic_lat_stamp(void) {
	struct timespec64 ts;

	ktime_get_ts64(&ts);

	return (unsigned long)ts.tv_sec * 1000000000 +
		(unsigned long)ts.tv_nsec;
}
#endif /* IONIC_LATS_TSC */

static inline void __ionic_lat_trace(struct ionic_latencies *lats,
				     struct ionic_latstat *stat)
{
	unsigned long now, dif;

	now = ionic_lat_stamp();
	dif = now - lats->stamp - lats->overhead;
	lats->stamp = now;

	if (unlikely(!lats->enable))
		return;

	/* adjust minimum */
	if (!stat->min || dif < stat->min) {
		stat->min = dif;
		/* continuation of warmup */
		if (!stat->count) {
			++stat->warmup;
			return;
		}
	}

	/* end of warmup */
	if (!stat->count) {
		stat->accum = stat->min;
		++stat->count;
		--stat->warmup;
		return;
	}

	/* average and max exclude outliers */
	if (likely(dif < stat->min * IONIC_LATS_OUTLIER)) {
		stat->accum += dif;
		++stat->count;
		if (unlikely(dif > stat->max))
			stat->max = dif;
	}

	if (!lats->histogram)
		return;

	/* convert to log scale */
	if (unlikely(dif >> (IONIC_LATS_BINS - 1)))
		++stat->hist[IONIC_LATS_BINS - 1];
	else
		++stat->hist[ionic_fls(dif)];
}

#define ionic_lat_trace(lats, name) do {				\
	if (ionic_lats_enable && lats)					\
		__ionic_lat_trace(lats, &(lats)->name);			\
} while (0)

static inline void ionic_lat_init(struct ionic_latencies *lats)
{
	unsigned long start, end;
	int i, count = 1000;

	if (!lats)
		return;

	lats->enable = true;
	/* warmup for measured loop */
	for (i = 0; i < count; ++i) {
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, poll_cq_compl);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, post_recv);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, post_send);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, poll_cq_empty);
	}
	/* measured to determine overhead of tracing */
	start = ionic_lat_stamp();
	for (i = 0; i < count; ++i) {
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, poll_cq_compl);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, post_recv);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, post_send);
		ionic_lat_trace(lats, application);
		ionic_lat_trace(lats, poll_cq_empty);
	}
	end = ionic_lat_stamp();

	memset(lats, 0, sizeof(*lats));

	/* There are eight traces in the body of the measured loop.
	 * Estimate the overhead more conservatively by dividing by 14.
	 */
	lats->overhead = (end - start) / count / 14;
	lats->stamp = end;
	lats->enable = false;
}

#define ionic_lat_enable(lats, v) do {					\
	if (lats)							\
		(lats)->enable = (v);					\
} while (0)

#define ionic_lat_print_idx(dev, lats, name, idx) do {			\
	const unsigned long _val = (lats)->name.hist[idx];		\
	const unsigned long _range = 1ul << (idx);			\
	if (_val)							\
		dev_info(dev, "%s[%lu..%lu%s]: %lu\n",			\
			 #name, _range >> 1, _range - 1,		\
			 IONIC_LATS_UNITS, _val);			\
} while (0)

#define ionic_lat_print_avg(dev, lats, name) do {			\
	const unsigned long _min = (lats)->name.min;			\
	const unsigned long _max = (lats)->name.max;			\
	const unsigned long _accum = (lats)->name.accum;		\
	const unsigned int _count = (lats)->name.count;			\
	const unsigned int _warmup = (lats)->name.warmup;		\
	const unsigned long _avg = _count ? _accum / _count : 0;	\
	dev_info(dev, "%26s: %u kept, %u discarded\n",			\
		 #name, _count, _warmup);				\
	dev_info(dev, "%26s: %lu%s min, %lu%s max, %lu%s avg\n",	\
		 #name, _min, IONIC_LATS_UNITS, _max, IONIC_LATS_UNITS,	\
		 _avg, IONIC_LATS_UNITS);				\
} while (0)

static inline void ionic_lats_print(struct device *dev,
				    struct ionic_latencies *lats)
{
	int i;

	if (!lats || !ionic_lats_enable)
		return;

	dev_info(dev, "latency statistics:\n");
	dev_info(dev, "%26s: %lu%s\n", "overhead",
		 lats->overhead, IONIC_LATS_UNITS);

	ionic_lat_print_avg(dev, lats, application);
	for (i = 0; i < IONIC_LATS_BINS; ++i)
		ionic_lat_print_idx(dev, lats, application, i);

	ionic_lat_print_avg(dev, lats, poll_cq_empty);
	for (i = 0; i < IONIC_LATS_BINS; ++i)
		ionic_lat_print_idx(dev, lats, poll_cq_empty, i);

	ionic_lat_print_avg(dev, lats, poll_cq_compl);
	for (i = 0; i < IONIC_LATS_BINS; ++i)
		ionic_lat_print_idx(dev, lats, poll_cq_compl, i);

	ionic_lat_print_avg(dev, lats, post_send);
	for (i = 0; i < IONIC_LATS_BINS; ++i)
		ionic_lat_print_idx(dev, lats, post_send, i);

	ionic_lat_print_avg(dev, lats, post_recv);
	for (i = 0; i < IONIC_LATS_BINS; ++i)
		ionic_lat_print_idx(dev, lats, post_recv, i);
}

#endif /* IONIC_STATS_H */
