// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include "ionic_ibdev.h"

enum dcqcn_var {
	/* notification point */
	NP_ICNP_802P_PRIO,		/* 0..7 (prio) */
	NP_CNP_DSCP,			/* 0..63 (dscp) */

	RP_TOKEN_BUCKET_SIZE,		/* 100..200000000 (100kb - 200gb) */
	/* reaction point alpha update */
	RP_INITIAL_ALPHA_VALUE,		/* 0..1023 */
	RP_DCE_TCP_G,			/* 0..1023 */
	RP_DCE_TCP_RTT,			/* 1..131071 (us) */

	/* reaction point rate decrease */
	RP_RATE_REDUCE_MONITOR_PERIOD,	/* 1.. (us) */
	RP_RATE_TO_SET_ON_FIRST_CNP,	/* 0 disable, 1.. (Mbps) */
	RP_MIN_RATE,			/* 1.. (Mbps) */
	RP_GD,				/* 1..11 */
	RP_MIN_DEC_FAC,			/* 0..100 (%) */

	/* reaction point rate increase */
	RP_CLAMP_TGT_RATE,		/* 0..1 (bool) */
	RP_CLAMP_TGT_RATE_ATI,		/* 0..1 (bool) */
	RP_THRESHOLD,			/* 1..31 */
	RP_TIME_RESET,			/* 1..32767 (x RP_DCE_TCP_RTT) */
	RP_QP_RATE,			/* 1.. (Mbps) */
	RP_BYTE_RESET,			/* 1..4294967296 (B) */
	RP_AI_RATE,			/* 1.. (Mbps) */
	RP_HAI_RATE,			/* 1.. (Mbps) */

	DCQCN_VAR_COUNT
};

struct dcqcn_rule {
	bool			(*match)(struct rdma_ah_attr *attr, int cond);
	const char		*name;
	int			cond;
	int			prof;
};

struct dcqcn_vals {
	int			v[DCQCN_VAR_COUNT];
};

struct dcqcn_profile_attribute {
	struct kobj_attribute	kattr;

	enum dcqcn_var		var;

	int			min;
	int			max;
};

struct dcqcn_profile {
	struct kobject		kobj;

	struct ionic_ibdev	*dev;

	struct dcqcn_vals	vals;
};

struct dcqcn_root {
	struct kobject		kobj;
	struct kobject		prof_kobj;

	struct ionic_ibdev	*dev;

	int			profiles_default;
	int			profiles_count;
	struct dcqcn_profile	*profiles;

	spinlock_t		rules_lock;
	int			rules_count;
	struct dcqcn_rule	*rules;
};

#define to_dcqcn_root(_kobj) \
	container_of(_kobj, struct dcqcn_root, kobj)
#define to_dcqcn_prof(_kobj) \
	container_of(_kobj, struct dcqcn_profile, kobj)
#define to_dcqcn_prof_attr(_kattr) \
	container_of(_kattr, struct dcqcn_profile_attribute, kattr)

static const struct dcqcn_vals dcqcn_defaults[] = {
	{
		.v[NP_ICNP_802P_PRIO]			= 6,
		.v[NP_CNP_DSCP]				= 48,
		.v[RP_TOKEN_BUCKET_SIZE]		= 4000000,
		.v[RP_INITIAL_ALPHA_VALUE]		= 1023,
		.v[RP_DCE_TCP_G]			= 1019,
		.v[RP_DCE_TCP_RTT]			= 55,
		.v[RP_RATE_REDUCE_MONITOR_PERIOD]	= 4,
		.v[RP_MIN_RATE]				= 1,
		.v[RP_GD]				= 11,
		.v[RP_MIN_DEC_FAC]			= 50,
		.v[RP_CLAMP_TGT_RATE_ATI]		= 1,
		.v[RP_THRESHOLD]			= 5,
		.v[RP_TIME_RESET]			= 5,
		.v[RP_QP_RATE]				= 100000,
		.v[RP_BYTE_RESET]			= 131068,
		.v[RP_AI_RATE]				= 5,
		.v[RP_HAI_RATE]				= 50,
	},
};

static const struct dcqcn_vals *dcqcn_get_defaults(int prof_i)
{
	if (prof_i < 0 || prof_i >= ARRAY_SIZE(dcqcn_defaults))
		return &dcqcn_defaults[0];

	return &dcqcn_defaults[prof_i];
}

static void dcqcn_set_profile(struct dcqcn_profile *prof)
{
	struct ionic_ibdev *dev = prof->dev;
	int prof_i = prof - dev->dcqcn->profiles;
	struct ionic_admin_wr wr = {
		.work = COMPLETION_INITIALIZER_ONSTACK(wr.work),
		.wqe = {
			.op = IONIC_V1_ADMIN_MODIFY_DCQCN,
			.id_ver = cpu_to_le32(prof_i + 1),
		}
	};
	int rc;

	wr.wqe.mod_dcqcn.np_incp_802p_prio =
		prof->vals.v[NP_ICNP_802P_PRIO];

	wr.wqe.mod_dcqcn.np_cnp_dscp =
		prof->vals.v[NP_CNP_DSCP];

	wr.wqe.mod_dcqcn.rp_token_bucket_size =
		cpu_to_be64(prof->vals.v[RP_TOKEN_BUCKET_SIZE]);

	wr.wqe.mod_dcqcn.rp_initial_alpha_value =
		cpu_to_be16(prof->vals.v[RP_INITIAL_ALPHA_VALUE]);

	wr.wqe.mod_dcqcn.rp_dce_tcp_g =
		cpu_to_be16(prof->vals.v[RP_DCE_TCP_G]);

	wr.wqe.mod_dcqcn.rp_dce_tcp_rtt =
		cpu_to_be32(prof->vals.v[RP_DCE_TCP_RTT]);

	wr.wqe.mod_dcqcn.rp_rate_reduce_monitor_period =
		cpu_to_be32(prof->vals.v[RP_RATE_REDUCE_MONITOR_PERIOD]);

	wr.wqe.mod_dcqcn.rp_rate_to_set_on_first_cnp =
		cpu_to_be32(prof->vals.v[RP_RATE_TO_SET_ON_FIRST_CNP]);

	wr.wqe.mod_dcqcn.rp_min_rate =
		cpu_to_be32(prof->vals.v[RP_MIN_RATE]);

	wr.wqe.mod_dcqcn.rp_gd =
		prof->vals.v[RP_GD];

	wr.wqe.mod_dcqcn.rp_min_dec_fac =
		prof->vals.v[RP_MIN_DEC_FAC];

	if (prof->vals.v[RP_CLAMP_TGT_RATE])
		wr.wqe.mod_dcqcn.rp_clamp_flags |= IONIC_RPF_CLAMP_TGT_RATE;

	if (prof->vals.v[RP_CLAMP_TGT_RATE_ATI])
		wr.wqe.mod_dcqcn.rp_clamp_flags |=
			IONIC_RPF_CLAMP_TGT_RATE_ATI;

	wr.wqe.mod_dcqcn.rp_threshold =
		prof->vals.v[RP_THRESHOLD];

	wr.wqe.mod_dcqcn.rp_time_reset =
		cpu_to_be32(prof->vals.v[RP_TIME_RESET]);

	wr.wqe.mod_dcqcn.rp_qp_rate =
		cpu_to_be32(prof->vals.v[RP_QP_RATE]);

	wr.wqe.mod_dcqcn.rp_byte_reset =
		cpu_to_be32(prof->vals.v[RP_BYTE_RESET]);

	wr.wqe.mod_dcqcn.rp_ai_rate =
		cpu_to_be32(prof->vals.v[RP_AI_RATE]);

	wr.wqe.mod_dcqcn.rp_hai_rate =
		cpu_to_be32(prof->vals.v[RP_HAI_RATE]);

	ionic_admin_post(dev, &wr);

	rc = ionic_admin_wait(dev, &wr, IONIC_ADMIN_F_INTERRUPT);
	if (rc)
		ibdev_warn(&dev->ibdev, "dcqcn profile %d not set, error %d\n",
			   1 + prof_i, rc);
}

static ssize_t dcqcn_show_int(struct kobject *kobj,
			      struct kobj_attribute *kattr,
			      char *buf)
{
	struct dcqcn_profile_attribute *attr = to_dcqcn_prof_attr(kattr);
	struct dcqcn_profile *prof = to_dcqcn_prof(kobj);
	int val = prof->vals.v[attr->var];

	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t dcqcn_store_int(struct kobject *kobj,
			       struct kobj_attribute *kattr,
			       const char *buf, size_t size)
{
	struct dcqcn_profile_attribute *attr = to_dcqcn_prof_attr(kattr);
	struct dcqcn_profile *prof = to_dcqcn_prof(kobj);
	int rc, val;

	rc = kstrtoint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val < attr->min || val > attr->max)
		return -EINVAL;

	prof->vals.v[attr->var] = val;

	dcqcn_set_profile(prof);

	return size;
}

#define DCQCN_INT_ATTR(_name, _min, _max, _var) \
	struct dcqcn_profile_attribute dcqcn_profile_attr_##_name = { \
		.kattr = __ATTR(_name, 0644, \
				dcqcn_show_int, \
				dcqcn_store_int), \
		.min = (_min), .max = (_max), .var = (_var) \
	}

#define DCQCN_BOOL_ATTR(_name, _var) \
	DCQCN_INT_ATTR(_name, 0, 1, _var)

static DCQCN_INT_ATTR(icnp_802p_prio,
		      0, 7, NP_ICNP_802P_PRIO);

static DCQCN_INT_ATTR(cnp_dscp,
		      0, 63, NP_CNP_DSCP);

static struct attribute *dcqcn_profile_np_attrs[] = {
	&dcqcn_profile_attr_icnp_802p_prio.kattr.attr,
	&dcqcn_profile_attr_cnp_dscp.kattr.attr,
	NULL
};

static const struct attribute_group dcqcn_profile_np_group = {
	.name = "roce_np",
	.attrs = dcqcn_profile_np_attrs,
};

static DCQCN_INT_ATTR(token_bucket_size,
		      100, 200000000, RP_TOKEN_BUCKET_SIZE);

static DCQCN_INT_ATTR(initial_alpha_value,
		      0, 1023, RP_INITIAL_ALPHA_VALUE);

static DCQCN_INT_ATTR(dce_tcp_g,
		      0, 1023, RP_DCE_TCP_G);

static DCQCN_INT_ATTR(dce_tcp_rtt,
		      1, 131071, RP_DCE_TCP_RTT);

static DCQCN_INT_ATTR(rate_reduce_monitor_period,
		      1, INT_MAX, RP_RATE_REDUCE_MONITOR_PERIOD);

static DCQCN_INT_ATTR(rate_to_set_on_first_cnp,
		      1, INT_MAX, RP_RATE_TO_SET_ON_FIRST_CNP);

static DCQCN_INT_ATTR(min_rate,
		      1, INT_MAX, RP_MIN_RATE);

static DCQCN_INT_ATTR(gd,
		      1, 11, RP_GD);

static DCQCN_INT_ATTR(min_dec_fac,
		      0, 100, RP_MIN_DEC_FAC);

static DCQCN_BOOL_ATTR(clamp_tgt_rate, RP_CLAMP_TGT_RATE);

static DCQCN_BOOL_ATTR(clamp_tgt_rate_ati, RP_CLAMP_TGT_RATE_ATI);

static DCQCN_INT_ATTR(threshold,
		      1, 31, RP_THRESHOLD);

static DCQCN_INT_ATTR(time_reset,
		      1, 32767, RP_TIME_RESET);

static DCQCN_INT_ATTR(qp_rate,
		      1, INT_MAX, RP_QP_RATE);

static DCQCN_INT_ATTR(byte_reset,
		      1, INT_MAX, RP_BYTE_RESET);

static DCQCN_INT_ATTR(ai_rate,
		      1, INT_MAX, RP_AI_RATE);

static DCQCN_INT_ATTR(hai_rate,
		      1, INT_MAX, RP_HAI_RATE);

static struct attribute *dcqcn_profile_rp_attrs[] = {
	&dcqcn_profile_attr_token_bucket_size.kattr.attr,
	&dcqcn_profile_attr_initial_alpha_value.kattr.attr,
	&dcqcn_profile_attr_dce_tcp_g.kattr.attr,
	&dcqcn_profile_attr_dce_tcp_rtt.kattr.attr,
	&dcqcn_profile_attr_rate_reduce_monitor_period.kattr.attr,
	&dcqcn_profile_attr_rate_to_set_on_first_cnp.kattr.attr,
	&dcqcn_profile_attr_min_rate.kattr.attr,
	&dcqcn_profile_attr_gd.kattr.attr,
	&dcqcn_profile_attr_min_dec_fac.kattr.attr,
	&dcqcn_profile_attr_clamp_tgt_rate.kattr.attr,
	&dcqcn_profile_attr_clamp_tgt_rate_ati.kattr.attr,
	&dcqcn_profile_attr_threshold.kattr.attr,
	&dcqcn_profile_attr_time_reset.kattr.attr,
	&dcqcn_profile_attr_qp_rate.kattr.attr,
	&dcqcn_profile_attr_byte_reset.kattr.attr,
	&dcqcn_profile_attr_ai_rate.kattr.attr,
	&dcqcn_profile_attr_hai_rate.kattr.attr,
	NULL
};

static const struct attribute_group dcqcn_profile_rp_group = {
	.name = "roce_rp",
	.attrs = dcqcn_profile_rp_attrs,
};

static ssize_t dcqcn_profile_reset(struct kobject *kobj,
				   struct kobj_attribute *kattr,
				   const char *buf, size_t count)
{
	struct dcqcn_profile *prof = to_dcqcn_prof(kobj);
	struct ionic_ibdev *dev = prof->dev;
	int prof_i = prof - dev->dcqcn->profiles;

	if (strcmp(buf, "1") && strcmp(buf, "1\n"))
		return -EINVAL;

	prof->vals = *dcqcn_get_defaults(prof_i);
	dcqcn_set_profile(prof);
	return count;
}

static struct kobj_attribute dcqcn_profile_attr_reset =
	__ATTR(reset, 0200, NULL, dcqcn_profile_reset);

static struct attribute *dcqcn_profile_attrs[] = {
	&dcqcn_profile_attr_reset.attr,
	NULL
};

static const struct attribute_group dcqcn_profile_group = {
	.attrs = dcqcn_profile_attrs,
};

static const struct attribute_group *dcqcn_profile_groups[] = {
	&dcqcn_profile_group,
	&dcqcn_profile_np_group,
	&dcqcn_profile_rp_group,
	NULL
};

static ssize_t dcqcn_show_default(struct kobject *kobj,
				  struct kobj_attribute *kattr,
				  char *buf)
{
	struct dcqcn_root *dcqcn = to_dcqcn_root(kobj);
	int val = dcqcn->profiles_default;

	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t dcqcn_store_default(struct kobject *kobj,
				   struct kobj_attribute *kattr,
				   const char *buf, size_t count)
{
	struct dcqcn_root *dcqcn = to_dcqcn_root(kobj);
	int rc, val;

	rc = kstrtoint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val < 0 ||
	    val > dcqcn->profiles_count)
		return -EINVAL;

	dcqcn->profiles_default = val;

	return count;
}

static struct kobj_attribute dcqcn_attr_default =
	__ATTR(match_default, 0644, dcqcn_show_default, dcqcn_store_default);

static ssize_t dcqcn_show_rules(struct kobject *kobj,
				struct kobj_attribute *kattr,
				char *buf)
{
	struct dcqcn_root *dcqcn = to_dcqcn_root(kobj);
	struct dcqcn_rule *rule, *rules;
	int rule_i, rules_count;
	unsigned long irqflags;
	ssize_t rc, off = 0, size = PAGE_SIZE;

	spin_lock_irqsave(&dcqcn->rules_lock, irqflags);

	rules = dcqcn->rules;
	rules_count = dcqcn->rules_count;
	for (rule_i = 0; rule_i < rules_count; ++rule_i) {
		rule = &rules[rule_i];

		rc = snprintf(buf, size, "%s %d %d\n",
			      rule->name, rule->cond, rule->prof);
		if (rc < 0)
			goto out;

		off += rc;

		if (rc >= size) {
			buf = NULL;
			size = 0;
		} else {
			buf += rc;
			size -= rc;
		}
	}

	rc = off;

out:
	spin_unlock_irqrestore(&dcqcn->rules_lock, irqflags);

	return rc;
}

static bool match_prio(struct rdma_ah_attr *attr, int cond)
{
	int prio = attr->sl;

	return prio >= 0 && prio < 8 && (cond & BIT(prio));
}

static bool match_gid(struct rdma_ah_attr *attr, int cond)
{
	int gid = rdma_ah_read_grh(attr)->sgid_index;

	return gid == cond;
}

static bool dcqcn_parse_name(const char *name, const char *buf, int count)
{
	return !strncmp(name, buf, count) && !name[count];
}

static int dcqcn_parse_rules(const char *buf, size_t count,
			     int prof_count, int rules_count,
			     struct dcqcn_rule *rules)
{
	bool (*match)(struct rdma_ah_attr *attr, int cond);
	const char *name;
	struct dcqcn_rule *rule;
	int cmd, cond, prof, end;
	int rc, rule_i = 0;

	for (;; ++rule_i) {
		/* skip leading whitespace */

		rc = sscanf(buf, " %n", &end);
		if (rc != 0)
			return -EINVAL;

		buf += end;
		count -= end;

		/* break at end of buffer */

		if (!count)
			break;

		/* Parse one rule, as:
		 * <name> <condition> <profile>
		 *
		 * Name and condition determine when a rule will be a match.
		 * If a rule is a match, then use the inidcated DCQCN profile.
		 *
		 * If name eq "gid":
		 * then condition is a gid index.
		 *
		 * eg: gid 5 3 -> for gid index 5, use profile 3.
		 *
		 * If name eq "prio":
		 * then condition is a bitmask of 802.1p priorities.
		 *
		 * eg: prio 0xc 1 -> for 802.1p priority 2 or 3, use profile 1.
		 */

		rc = sscanf(buf, "%*s%n%i%i%n", &cmd, &cond, &prof, &end);
		if (rc != 2)
			return -EINVAL;

		/* rule name in first `cmd` chars of `buf` */

		if (dcqcn_parse_name("gid", buf, cmd)) {
			match = match_gid;
			name = "gid";
		} else if (dcqcn_parse_name("prio", buf, cmd)) {
			match = match_prio;
			name = "prio";
		} else {
			return -EINVAL;
		}

		if (prof < 0 || prof > prof_count)
			return -EINVAL;

		if (rule_i < rules_count) {
			rule = &rules[rule_i];
			rule->match = match;
			rule->name = name;
			rule->cond = cond;
			rule->prof = prof;
		}

		buf += end;
		count -= end;
	}

	return rule_i;
}

static ssize_t dcqcn_store_rules(struct kobject *kobj,
				 struct kobj_attribute *kattr,
				 const char *buf, size_t count)
{
	struct dcqcn_root *dcqcn =
		container_of(kobj, struct dcqcn_root, kobj);
	unsigned long irqflags;
	int rc, rules_count;

	/* validate and count rules */

	rc = dcqcn_parse_rules(buf, count, dcqcn->profiles_count, 0, NULL);
	if (rc < 0)
		return rc;

	rules_count = rc;

	/* clear previous rules */

	spin_lock_irqsave(&dcqcn->rules_lock, irqflags);
	dcqcn->rules_count = 0;
	spin_unlock_irqrestore(&dcqcn->rules_lock, irqflags);

	kfree(dcqcn->rules);
	dcqcn->rules = NULL;

	/* assign new rules */

	if (rules_count) {
		dcqcn->rules = kmalloc_array(rules_count,
					     sizeof(*dcqcn->rules),
					     GFP_KERNEL);
		if (!dcqcn->rules)
			return -ENOMEM;

		dcqcn_parse_rules(buf, count, dcqcn->profiles_count,
				  rules_count, dcqcn->rules);

		spin_lock_irqsave(&dcqcn->rules_lock, irqflags);
		dcqcn->rules_count = rules_count;
		spin_unlock_irqrestore(&dcqcn->rules_lock, irqflags);
	}

	return count;
}

static struct kobj_attribute dcqcn_attr_rules =
	__ATTR(match_rules, 0644, dcqcn_show_rules, dcqcn_store_rules);

static struct attribute *dcqcn_root_attrs[] = {
	&dcqcn_attr_rules.attr,
	&dcqcn_attr_default.attr,
	NULL
};

static const struct attribute_group dcqcn_root_group = {
	.attrs = dcqcn_root_attrs,
};

static const struct attribute_group *dcqcn_root_groups[] = {
	&dcqcn_root_group,
	NULL
};

static void dcqcn_root_release(struct kobject *kobj)
{
	struct dcqcn_root *dcqcn =
		container_of(kobj, struct dcqcn_root, kobj);

	kfree(dcqcn->rules);
	kfree(dcqcn->profiles);
	kfree(dcqcn);
}

static struct kobj_type dcqcn_root_type = {
	.release		= dcqcn_root_release,
	.sysfs_ops		= &kobj_sysfs_ops,
};

static void dcqcn_nonroot_release(struct kobject *kobj)
{
	/* stuff under root will be released by root itself */
}

static struct kobj_type dcqcn_nonroot_type = {
	.release		= dcqcn_nonroot_release,
	.sysfs_ops		= &kobj_sysfs_ops,
};

int ionic_dcqcn_select_profile(struct ionic_ibdev *dev,
			       struct rdma_ah_attr *attr)
{
	struct dcqcn_rule *rule, *rules;
	int rule_i, rules_count, prof;
	unsigned long irqflags;

	if (!dev->dcqcn)
		return 0;

	spin_lock_irqsave(&dev->dcqcn->rules_lock, irqflags);

	prof = dev->dcqcn->profiles_default;
	rules = dev->dcqcn->rules;
	rules_count = dev->dcqcn->rules_count;

	for (rule_i = 0; rule_i < rules_count; ++rule_i) {
		rule = &rules[rule_i];
		if (rule->match(attr, rule->cond)) {
			prof = rule->prof;
			break;
		}
	}

	spin_unlock_irqrestore(&dev->dcqcn->rules_lock, irqflags);

	return prof;
}

void ionic_dcqcn_destroy(struct ionic_ibdev *dev)
{
	struct dcqcn_profile *prof;
	int prof_i, prof_count;

	if (!dev->dcqcn)
		return;

	prof_count = dev->dcqcn->profiles_count;
	for (prof_i = 0; prof_i < prof_count; ++prof_i) {
		prof = &dev->dcqcn->profiles[prof_i];

		sysfs_remove_groups(&prof->kobj, dcqcn_profile_groups);
		kobject_put(&prof->kobj);
	}

	kobject_put(&dev->dcqcn->prof_kobj);

	sysfs_remove_groups(&dev->dcqcn->kobj, dcqcn_root_groups);
	kobject_put(&dev->dcqcn->kobj);

	dev->dcqcn = NULL;
}

int ionic_dcqcn_init(struct ionic_ibdev *dev, int prof_count)
{
	struct dcqcn_profile *prof;
	int rc, prof_i;

	if (!prof_count)
		return 0;

	dev->dcqcn = kzalloc(sizeof(*dev->dcqcn), GFP_KERNEL);
	if (!dev->dcqcn) {
		rc = -ENOMEM;
		goto err_cb_alloc;
	}

	spin_lock_init(&dev->dcqcn->rules_lock);

	rc = kobject_init_and_add(&dev->dcqcn->kobj,
				  &dcqcn_root_type,
				  &dev->ibdev.dev.kobj,
				  "dcqcn");
	if (rc) {
		/*
		 * Free dev->dcqcn here. In other error paths, kfree() is
		 * handled by the put() of the root object.
		 */
		kfree(dev->dcqcn);
		goto err_cb_kobj;
	}

	rc = sysfs_create_groups(&dev->dcqcn->kobj,
				 dcqcn_root_groups);
	if (rc)
		goto err_cb_groups;

	rc = kobject_init_and_add(&dev->dcqcn->prof_kobj,
				  &dcqcn_nonroot_type,
				  &dev->dcqcn->kobj,
				  "profiles");
	if (rc)
		goto err_prof_kobj;

	dev->dcqcn->profiles = kcalloc(prof_count,
				       sizeof(*dev->dcqcn->profiles),
				       GFP_KERNEL);
	if (!dev->dcqcn->profiles) {
		rc = -ENOMEM;
		goto err_prof_alloc;
	}

	for (prof_i = 0; prof_i < prof_count; ++prof_i) {
		prof = &dev->dcqcn->profiles[prof_i];

		prof->dev = dev;
		prof->vals = *dcqcn_get_defaults(prof_i);

		dcqcn_set_profile(prof);

		rc = kobject_init_and_add(&prof->kobj,
					  &dcqcn_nonroot_type,
					  &dev->dcqcn->prof_kobj,
					  "%d", 1 + prof_i);
		if (rc)
			break;

		rc = sysfs_create_groups(&prof->kobj,
					 dcqcn_profile_groups);
		if (rc) {
			kobject_put(&prof->kobj);
			break;
		}
	}

	if (!prof_i)
		goto err_no_prof;

	dev->dcqcn->profiles_count = prof_i;
	if (prof_i != prof_count) {
		ibdev_warn(&dev->ibdev,
			   "dcqcn initialized %d out of %d profiles\n",
			   prof_i, prof_count);
	}

	return 0;

err_no_prof:
	/* kfree(dev->dcqcn->profiles) handled by put() of root object */
err_prof_alloc:
	kobject_put(&dev->dcqcn->prof_kobj);
err_prof_kobj:
	sysfs_remove_groups(&dev->dcqcn->kobj, dcqcn_root_groups);
err_cb_groups:
	kobject_put(&dev->dcqcn->kobj);
err_cb_kobj:
	/* kfree(dev->dcqcn) handled by put() of root object */
	dev->dcqcn = NULL;
err_cb_alloc:
	ibdev_warn(&dev->ibdev, "dcqcn failed init, error %d\n", rc);
	return rc;
}
