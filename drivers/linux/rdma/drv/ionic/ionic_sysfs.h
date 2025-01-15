/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_SYSFS_H
#define IONIC_SYSFS_H

/* Ionic rdma sysfs/debugfs directory contents:
 *
 * The debugfs contents are an informative resource for debugging, only.  They
 * should not be relied on as a stable api from user space.  The location,
 * arrangement, names, internal formats and structures of these files may
 * change without warning.  Any documentation, including this, is very likely
 * to be incorrect or incomplete.  You have been warned.
 *
 * (parent dir: ionic lif)
 * - rdma
 *   |- info		- rdma device info
 *   |
 *   |- aq/N
 *   |  |- info		- admin queue info (id, prod, cons, mask, ...)
 *   |  `- q		- admin queue content (raw data)
 *   |
 *   |- cq/N
 *   |  |- info		- completion queue info (id, prod, cons, mask, ...)
 *   |  `- q		- (*) completion queue content (raw data)
 *   |
 *   |- eq/N
 *   |  |- info		- event queue info (id, prod, cons, mask, ...)
 *   |  `- q		- event queue content (raw data)
 *   |
 *   |- mr/N
 *   |  |- info		- memory region info (lkey, rkey, access, length, ...)
 *   |  |		- memory key info (lkey, rkey*, access*, length*, ...)
 *   |  `- umem		- (*) page and dma mapping infrmation
 *   |
 *   |- pd/N
 *   |  `- info		- protection domain info (id)
 *   |
 *   |- qp/N
 *   |  |- info		- queue pair info (id, type, sq/rq prod, cons, ...)
 *   |  |		- shared receive queue info (id, type, prod, cons, ...)
 *   |  |- rq		- (*) receive queue content (raw data)
 *   |  `- sq		- (*) send queue content (raw data)
 *   |
 *   `- srq/N
 *      `- rq		- (*) receive queue content (raw data)
 *
 * (*) - These files are only present if supported for the resource type.
 *       These files are not created for user space resources, only kernel.
 *       Some resources (eg, XRC QP) will not have a send and/or recv queue.
 *       Some memory window attributes are not shown for user space.
 */

struct ionic_ibdev;
struct ionic_eq;
struct ionic_cq;
struct ionic_aq;
struct ionic_mr;
struct ionic_qp;
struct dentry;

void ionic_dbg_add_dev(struct ionic_ibdev *dev, struct dentry *parent);
void ionic_dbg_rm_dev(struct ionic_ibdev *dev);

void ionic_dbg_add_eq(struct ionic_ibdev *dev, struct ionic_eq *eq);
void ionic_dbg_rm_eq(struct ionic_eq *eq);

void ionic_dbg_add_cq(struct ionic_ibdev *dev, struct ionic_cq *cq);
void ionic_dbg_rm_cq(struct ionic_cq *cq);

void ionic_dbg_add_aq(struct ionic_ibdev *dev, struct ionic_aq *aq);
void ionic_dbg_rm_aq(struct ionic_aq *aq);

void ionic_dbg_add_mr(struct ionic_ibdev *dev, struct ionic_mr *mr);
void ionic_dbg_rm_mr(struct ionic_mr *mr);

void ionic_dbg_add_qp(struct ionic_ibdev *dev, struct ionic_qp *qp);
void ionic_dbg_rm_qp(struct ionic_qp *qp);

int ionic_dbg_init(void);
void ionic_dbg_exit(void);

#endif /* IONIC_SYSFS_H */
