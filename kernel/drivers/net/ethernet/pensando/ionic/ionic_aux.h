/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023-2024, Advanced Micro Devices, Inc. */

#ifndef _IONIC_AUX_H_
#define _IONIC_AUX_H_

#ifdef CONFIG_AUXILIARY_BUS
int ionic_auxbus_register(struct ionic_lif *lif);
void ionic_auxbus_unregister(struct ionic_lif *lif);
#else
static inline int ionic_auxbus_register(struct ionic_lif *lif __always_unused)
{
	return 0;
}

static inline void ionic_auxbus_unregister(struct ionic_lif *lif __always_unused)
{
}

#endif
#endif /* _IONIC_AUX_H_ */
