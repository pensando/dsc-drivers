/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, Oracle and/or its affiliates.
 */

/* uart constants */

/* NS16550 defines */
#define NS16550_UART		0x4800
#define NS16550_LSR		0x14
#define NS16550_DATA_READY	0x01
#define NS16550_THRE		0x20

/* PL011 defines */
#define UART_PL011_FR		0x18
#define UART011_FR_TXFE		0x080
#define UART011_FR_RXFF		0x040
#define UART01x_FR_TXFF		0x020
#define UART01x_FR_RXFE		0x010
