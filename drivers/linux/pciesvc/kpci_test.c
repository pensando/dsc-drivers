/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, 2025 Oracle and/or its affiliates.
 */

/*
 * Kernel PCIE Manager - test/serial/debug code
 *
 * Author: rob.gardner@oracle.com
 */

#include "pciesvc_impl.h"

#define TICKS_PER_US 200
#define TICKS_PER_MS  (1000*TICKS_PER_US)
#define TICKS_PER_SEC (1000*TICKS_PER_MS)

/*
 * kp_udelay
 *
 * Like kernel udelay(), but avoids an external call.
 */
void kp_udelay(unsigned long us)
{
	unsigned long last = read_sysreg(cntvct_el0);
	unsigned long now, elapsed = 0;
	unsigned long limit = us * TICKS_PER_US;

	while (elapsed < limit) {
		now = read_sysreg(cntvct_el0);
		if (now > last)
			elapsed += now - last;
		last = now;
	}
}

int time_elapsed(unsigned long start, unsigned long elapsed)
{
	unsigned long now = read_sysreg(cntvct_el0);

	if (now > start + elapsed)
		return 1;

	if (now < start && now > elapsed) /* good enough */
		return 1;

	return 0;
}

/*
 * Mini serial output driver
 *
 * We want to avoid a potential infinite loop if something
 * goes wrong with the uart, so let's wait no more than 1ms
 * for the transmitter shift register to become empty. The
 * baud rate is 115200, so theoretically, the shift register
 * should never take longer than 100us to become empty.
 */
void uart_write(char c)
{
	extern void uart_putc_nowait(char);
	extern int uart_canwrite(void);
	int i;

	/* reg should equal uart_reg */
	for (i=0; i<10; i++) {
		if (uart_canwrite())
			break;
		kp_udelay(100);
	}
	uart_putc_nowait(c);
	for (i=0; i<10; i++) {
		if (uart_canwrite())
			break;
		kp_udelay(100);
	}
}

int uart_read(char *c)
{
	extern long uart_data_reg, *uart_status_reg;
	extern int uart_canread(void), uart_getc_nowait(void);

	if (uart_data_reg == 0)
		return 0;
	if (uart_status_reg == 0)
		return 0;

	if (uart_canread()) {
		*c = uart_getc_nowait();
		return 1;
	}
	return 0;
}

void uart_write_debug(kstate_t *ks, char c)
{
	if (ks->debug)
		uart_write(c);
}

void kdbg_puts(const char *s)
{
	kstate_t *ks = get_kstate();

	if (ks == NULL || ks->uart_addr == NULL)
		return;

	for ( ; *s; s++) {
		uart_write(*s);
		if (*s == '\n')
			uart_write('\r');
	}
}

/*
 * For testing, this causes an SERR to be generated
 */
void trigger_serr(int val)
{
	const uint64_t good_bad_pa = 0x20141000;
	uint32_t dummy;

	kpr_err("pciesvc: triggering serr\n");
	if (val == 0x100)
		dummy = pciesvc_reg_rd32(good_bad_pa);
	else
		pciesvc_pciepreg_rd32(good_bad_pa, &dummy);
}

void kpcimgr_report_stats(kstate_t *ks, int phase, int always, int rightnow)
{
	pciehw_shmem_t *pshmem = pciesvc_shmem_get();
	unsigned long now = read_sysreg(cntvct_el0);
	uint64_t cfgrd, cfgwr, memrd, memwr;
	static unsigned long last_call = 0;
	pciemgr_stats_t *s;
	pciehw_port_t *p;

	if (!always && (now - last_call) < 5 * TICKS_PER_SEC)
		return;

	p = PSHMEM_ADDR_FIELD(pshmem, port[0]);
	s = &p->stats;
	cfgrd = s->ind_cfgrd - ks->ind_cfgrd;
	cfgwr = s->ind_cfgwr - ks->ind_cfgwr;
	memrd = s->ind_memrd - ks->ind_memrd;
	memwr = s->ind_memwr - ks->ind_memwr;

	if (!always && (cfgrd + cfgwr + memrd + memwr) == 0)
		return;

	if (rightnow || ks->debug) {
		kpr_err("pciesvc: called %d times during %s phase: %lld cfgrd, %lld cfgwr, %lld memrd, %lld memwr\n",
			ks->ncalls, (phase == NOMMU) ? "nommu" : "normal",
			cfgrd, cfgwr, memrd, memwr);
		kpr_err("         %d ind_intr, %d not_intr, %d event_intr\n", ks->ind_intr, ks->not_intr, ks->event_intr);
	}

	ks->ind_cfgrd = s->ind_cfgrd;
	ks->ind_cfgwr = s->ind_cfgwr;
	ks->ind_memrd = s->ind_memrd;
	ks->ind_memwr = s->ind_memwr;

	last_call = read_sysreg(cntvct_el0);
}

