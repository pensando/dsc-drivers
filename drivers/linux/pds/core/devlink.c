// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Pensando Systems, Inc */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>

#include "core.h"

static struct pdsc_viftype *pdsc_dl_find_viftype_by_id(struct pdsc *pdsc,
						enum devlink_param_type dl_id)
{
	int vt;

	for (vt = 0; vt < PDS_DEV_TYPE_MAX; vt++) {
		if (pdsc->viftype_status[vt].dl_id == dl_id)
			return &pdsc->viftype_status[vt];
	}

	return NULL;
}

static int pdsc_dl_enable_get(struct devlink *dl, u32 id,
			      struct devlink_param_gset_ctx *ctx)
{
	struct pdsc *pdsc = devlink_priv(dl);
	struct pdsc_viftype *vt_entry;

	vt_entry = pdsc_dl_find_viftype_by_id(pdsc, id);
	if (!vt_entry)
		return -ENOENT;

	ctx->val.vbool = vt_entry->enabled;

	return 0;
}

static int pdsc_dl_enable_set(struct devlink *dl, u32 id,
			      struct devlink_param_gset_ctx *ctx)
{
	struct pdsc *pdsc = devlink_priv(dl);
	struct pdsc_viftype *vt_entry;
	int err;
	int vf;

	vt_entry = pdsc_dl_find_viftype_by_id(pdsc, id);
	if (!vt_entry || !vt_entry->max_devs)
		return -EOPNOTSUPP;

	if (vt_entry->enabled == ctx->val.vbool)
		return 0;

	vt_entry->enabled = ctx->val.vbool;
	if (vt_entry->is_pf) {
		err = ctx->val.vbool ? pdsc_auxbus_dev_add_pf_device(pdsc, vt_entry->vif_id) :
				       pdsc_auxbus_dev_del_pf_device(pdsc, vt_entry->vif_id);
	} else {
		for (vf = 0; vf < pdsc->num_vfs; vf++) {
			err = ctx->val.vbool ? pdsc_auxbus_dev_add_vf(pdsc, vf) :
					       pdsc_auxbus_dev_del_vf(pdsc, vf);
		}
	}

	return err;
}

static int pdsc_dl_enable_validate(struct devlink *dl, u32 id,
				   union devlink_param_value val,
				   struct netlink_ext_ack *extack)
{
	struct pdsc *pdsc = devlink_priv(dl);
	struct pdsc_viftype *vt_entry;
	int err;

	vt_entry = pdsc_dl_find_viftype_by_id(pdsc, id);
	if (!vt_entry || !vt_entry->max_devs)
		return -EOPNOTSUPP;

	if (!pdsc->viftype_status[vt_entry->vif_id].max_devs)
		err = -ENODEV;
	else
		err = 0;

	return err;
}

char *slot_labels[] = { "fw.gold", "fw.mainfwa", "fw.mainfwb" };

static int pdsc_dl_fw_boot_get(struct devlink *dl, u32 id,
			       struct devlink_param_gset_ctx *ctx)
{
	struct pdsc *pdsc = devlink_priv(dl);
	union pds_core_dev_cmd cmd = {
		.fw_control.opcode = PDS_CORE_CMD_FW_CONTROL,
		.fw_control.oper = PDS_CORE_FW_GET_BOOT,
	};
	union pds_core_dev_comp comp;
	int err;

	err = pdsc_devcmd(pdsc, &cmd, &comp, pdsc->devcmd_timeout);
	if (err) {
		if (err == -EIO) {
			snprintf(ctx->val.vstr, sizeof(ctx->val.vstr), "(unknown)");
			return 0;
		} else {
			return err;
		}
	}

	if (comp.fw_control.slot >= ARRAY_SIZE(slot_labels))
		snprintf(ctx->val.vstr, sizeof(ctx->val.vstr),
			 "fw.slot%02d", comp.fw_control.slot);
	else
		snprintf(ctx->val.vstr, sizeof(ctx->val.vstr),
			 "%s", slot_labels[comp.fw_control.slot]);

	return 0;
}

static int pdsc_dl_fw_boot_set(struct devlink *dl, u32 id,
			       struct devlink_param_gset_ctx *ctx)
{
	struct pdsc *pdsc = devlink_priv(dl);
	union pds_core_dev_cmd cmd = {
		.fw_control.opcode = PDS_CORE_CMD_FW_CONTROL,
		.fw_control.oper = PDS_CORE_FW_SET_BOOT,
	};
	union pds_core_dev_comp comp;
	enum pds_core_fw_slot slot;
	int timeout;

	for (slot = 0; slot < ARRAY_SIZE(slot_labels); slot++)
		if (!strcmp(ctx->val.vstr, slot_labels[slot]))
			break;

	if (slot >= ARRAY_SIZE(slot_labels))
		return -EINVAL;

	cmd.fw_control.slot = slot;

	/* This is known to be a longer running command, so be sure
	 * to use a larger timeout on the command than usual
	 */
#define PDSC_SET_BOOT_TIMEOUT	10
	timeout = max_t(int, PDSC_SET_BOOT_TIMEOUT, pdsc->devcmd_timeout);
	return pdsc_devcmd(pdsc, &cmd, &comp, timeout);
}

static int pdsc_dl_fw_boot_validate(struct devlink *dl, u32 id,
				    union devlink_param_value val,
				    struct netlink_ext_ack *extack)
{
	enum pds_core_fw_slot slot;

	for (slot = 0; slot < ARRAY_SIZE(slot_labels); slot++)
		if (!strcmp(val.vstr, slot_labels[slot]))
			return 0;

	return -EINVAL;
}

static const struct devlink_param pdsc_dl_params[] = {
	DEVLINK_PARAM_GENERIC(ENABLE_ETH,
			      BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      pdsc_dl_enable_get,
			      pdsc_dl_enable_set,
			      pdsc_dl_enable_validate),
	DEVLINK_PARAM_GENERIC(ENABLE_VNET,
			      BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      pdsc_dl_enable_get,
			      pdsc_dl_enable_set,
			      pdsc_dl_enable_validate),
	DEVLINK_PARAM_DRIVER(PDSC_DEVLINK_PARAM_ID_CORE,
			     "enable_core",
			     DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     pdsc_dl_enable_get,
			     pdsc_dl_enable_set,
			     pdsc_dl_enable_validate),
	DEVLINK_PARAM_DRIVER(PDSC_DEVLINK_PARAM_ID_LM,
			     "enable_lm",
			     DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     pdsc_dl_enable_get,
			     pdsc_dl_enable_set,
			     pdsc_dl_enable_validate),
	DEVLINK_PARAM_DRIVER(PDSC_DEVLINK_PARAM_ID_FW_BOOT,
			     "boot_fw",
			     DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     pdsc_dl_fw_boot_get,
			     pdsc_dl_fw_boot_set,
			     pdsc_dl_fw_boot_validate),
};

static void pdsc_dl_set_params_init_values(struct devlink *dl)
{
	struct pdsc *pdsc = devlink_priv(dl);
	union devlink_param_value value;
	int vt;

	for (vt = 0; vt < PDS_DEV_TYPE_MAX; vt++) {
		if (!pdsc->viftype_status[vt].dl_id)
			continue;

		value.vbool = pdsc->viftype_status[vt].enabled;
		devlink_param_driverinit_value_set(dl,
						pdsc->viftype_status[vt].dl_id,
						value);
	}

}

static int pdsc_dl_flash_update(struct devlink *dl,
				struct devlink_flash_update_params *params,
				struct netlink_ext_ack *extack)
{
	struct pdsc *pdsc = devlink_priv(dl);

	return pdsc_firmware_update(pdsc, params->fw, extack);
}

static int pdsc_dl_info_get(struct devlink *dl, struct devlink_info_req *req,
			     struct netlink_ext_ack *extack)
{
	union pds_core_dev_cmd cmd = {
		.fw_control.opcode = PDS_CORE_CMD_FW_CONTROL,
		.fw_control.oper = PDS_CORE_FW_GET_LIST,
	};
	struct pds_core_fw_list_info *fw_list;
	struct pdsc *pdsc = devlink_priv(dl);
	union pds_core_dev_comp comp;
	char *fwprefix = "fw.";
	char buf[16];
	int listlen;
	int err = 0;
	size_t sz;
	int i;

	err = devlink_info_driver_name_put(req, pdsc->pdev->driver->name);
	if (err)
		return err;

	sz = min_t(size_t, sizeof(buf),
		   sizeof(fw_list->fw_names[0].slotname) + strlen(fwprefix));
	fw_list = (struct pds_core_fw_list_info *)pdsc->cmd_regs->data;

	mutex_lock(&pdsc->devcmd_lock);
	err = pdsc_devcmd_locked(pdsc, &cmd, &comp, pdsc->devcmd_timeout * 2);
	listlen = fw_list->num_fw_slots;
	for (i = 0; !err && i < listlen; i++) {
		snprintf(buf, sz, "%s%s",
			 fwprefix, fw_list->fw_names[i].slotname);
		err = devlink_info_version_stored_put(req, buf,
						      fw_list->fw_names[i].fw_version);
	}
	mutex_unlock(&pdsc->devcmd_lock);
	if (err && err != -EIO)
		return err;

	err = devlink_info_version_running_put(req,
					       DEVLINK_INFO_VERSION_GENERIC_FW,
					       pdsc->dev_info.fw_version);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", pdsc->dev_info.asic_type);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_ID,
					     buf);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", pdsc->dev_info.asic_rev);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_REV,
					     buf);
	if (err)
		return err;

	err = devlink_info_serial_number_put(req, pdsc->dev_info.serial_num);

	return err;
}

static const struct devlink_ops pdsc_dl_ops = {
	.info_get	= pdsc_dl_info_get,
	.flash_update	= pdsc_dl_flash_update,
};

struct pdsc *pdsc_dl_alloc(struct device *dev)
{
	struct devlink *dl;

	dl = devlink_alloc(&pdsc_dl_ops, sizeof(struct pdsc), dev);
	if (!dl)
		return NULL;

	return devlink_priv(dl);
}

void pdsc_dl_free(struct pdsc *pdsc)
{
	struct devlink *dl = priv_to_devlink(pdsc);

	devlink_free(dl);
}

int pdsc_dl_register(struct pdsc *pdsc)
{
	struct devlink *dl = priv_to_devlink(pdsc);
	int err;

	err = devlink_params_register(dl, pdsc_dl_params,
				      ARRAY_SIZE(pdsc_dl_params));
	if (err)
		return err;
	pdsc_dl_set_params_init_values(dl);
	devlink_register(dl);

	return 0;
}

void pdsc_dl_unregister(struct pdsc *pdsc)
{
	struct devlink *dl = priv_to_devlink(pdsc);

	devlink_unregister(dl);
	devlink_params_unregister(dl, pdsc_dl_params,
				  ARRAY_SIZE(pdsc_dl_params));
}
