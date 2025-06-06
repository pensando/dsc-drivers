/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, 2025, Oracle and/or its affiliates.
 */

/*
 * Kernel PCIE Manager - kexec related code
 *
 * Author: rob.gardner@oracle.com
 */

#include "kpcimgr_api.h"
#include "pciesvc_impl.h"
#include "pciesvc.h"
#include "pciesvc_system.h"
#include "kpci_uart.h"

#define TICKS_PER_US 200LL
#define TICKS_PER_MS  (1000*TICKS_PER_US)
#define TICKS_PER_SEC (1000*TICKS_PER_MS)

int holding_pen_idx;
unsigned long kstate_paddr;
kstate_t *kstate = NULL;
long spin_table_start_addr;

void set_kstate(kstate_t *ks)
{
	kstate = ks;
}

int virtual(void)
{
	return ((long)kstate) < 0 ;
}

/* called in physical mode */
void kpcimgr_nommu_poll(kstate_t *ks)
{
	kpcimgr_poll(ks, 0, NOMMU);
	ks->trace_data[NOMMU][LAST_CALL_TIME] = read_sysreg(cntvct_el0);

}

/*
 * release
 *
 * Called to determine if we should complete the missions and
 * return the borrowed cpu. Handles both PSCI and SPIN TABLE
 */
unsigned long release(void)
{
	kstate_t *ks = get_kstate();

	if (ks->features & FLAG_PSCI)
		return ks->features & FLAG_PSCI_CPU_RELEASE;

/*
 * Could release spin table the same way as psci, but this
 * is simpler and preserves compatibility with older kernels.
 */
	return *(long *)(spin_table_start_addr + 0x10);
}

/* This indicates to new kernel that we got the message to quit */
void released(void)
{
	kstate_t *ks = get_kstate();
	ks->features |= FLAG_PSCI_CPU_RELEASED;
}
	

/*
 * Main polling thread, call in no-mmu mode from a borrowed cpu
 */
void kpcimgr_cpu_polling_loop(kstate_t *ks)
{
#ifdef KPCI_DEVEL
	unsigned long start = read_sysreg(cntvct_el0);
#endif
	extern void pciesvc_quit(void);
	void serial_input(char c);
	int i, npolls = 0;
	char c;

	set_kstate(ks);
	uart_write_debug(ks, 'C');
	kpcimgr_init_poll(ks);

	ks->running = cpuid();
	kpr_err("\r\npciesvc: %s with EL%ld on cpu%d\n", __func__, read_el(), ks->running);

	holding_pen_idx = 0;

	while (1) {
		uart_write_debug(ks, 'S');
                if (uart_read(&c))
			serial_input(c);

		kpcimgr_nommu_poll(ks);
		npolls++;

		for (i=0; i<10; i++) {
			if (release()) {
				kpr_err("pciesvc: did %d polls\n", npolls+1);
				kpcimgr_nommu_poll(ks);
				return;
			}
			kp_udelay(1*1000); /* 1ms */
		}
#ifdef KPCI_DEVEL
		if (time_elapsed(start, 60*TICKS_PER_SEC)) {
			kpr_err("pciesvc: polling thread running for >60s, quitting.\n");
			pciesvc_quit();
		}
#endif
	}
}

void serial_help(void)
{
	kpr_err("Commands:\n");
	kpr_err(" a      Show addresses and parameters\n");
	kpr_err(" c      Cpu id\n");
	kpr_err(" e      Event queue\n");
	kpr_err(" f      Show/set cfgval\n");
	kpr_err(" h      Show help message\n");
	kpr_err(" m      Memory ranges\n");
	kpr_err(" q      Quit thread\n");
	kpr_err(" r      Reboot\n");
	kpr_err(" s      Serror trigger\n");
	kpr_err(" t      Report Stats\n");
#ifdef KPCI_DEVEL
	kpr_err(" u      Unstick kernel (testing only)\n");
#endif
}

#define WDOG_REGS (void *)0x1400
#define WDOG_CONTROL_REG_OFFSET             0x00
#define WDOG_CONTROL_REG_WDT_EN_MASK        0x01
#define WDOG_CONTROL_REG_RESP_MODE_MASK     0x02
void watchdog_reboot(void)
{
        u32 val = readl(WDOG_REGS + WDOG_CONTROL_REG_OFFSET);

	kpr_err("Rebooting...\n");
        /* Disable interrupt mode; always perform system reset. */
        val &= ~WDOG_CONTROL_REG_RESP_MODE_MASK;
        /* Enable watchdog. */
        val |= WDOG_CONTROL_REG_WDT_EN_MASK;
        writel(val, WDOG_REGS + WDOG_CONTROL_REG_OFFSET);
}

#define NORMAL_INPUT 1
#define CFGVAL_INPUT 2

/*
 * is_hexdigit
 *
 * if char c is a valid hex digit, then set *val to the
 * numerical value of that digit
 */
int is_hexdigit(char c, int *val)
{
	if (c >= '0' && c <= '9')
		*val = c - '0';
	else if (c >= 'a' && c <= 'f')
		*val = 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')
		*val = 10 + c - 'A';
	else
		return 0;
	return 1;
}

/*
 * cfgval_process
 *
 * Implement a tiny state machine to build up a hex value
 * gathered from reading characters from the uart. This
 * allows to basically read a bunch of characters from the
 * serial port without waiting, thus allowing us to get by
 * with just one thread.
 *
 * Return value of 1 indicates that we've processed the
 * character, otherwise the caller should process it.
 */
int cfgval_process(char c)
{
	static int cfgval = 0, modify = 0;
	static int state = NORMAL_INPUT;
	kstate_t *ks = get_kstate();
	int nibble;

	if (state == NORMAL_INPUT) {
		if (c == 'f' || c == 'F') {
			kpr_err("cfgval = %x\n", ks->cfgval);
			kpr_err("New cfgval: ");
			state = CFGVAL_INPUT;
			return 1;	/* swallow character */
		}
		return 0;	/* ignore character */
	}

	/* at this point we are in CFGVAL_INPUT state */
	uart_write(c);	/* echo typed character */
	if (is_hexdigit(c, &nibble)) {
		cfgval = (cfgval << 4) + nibble;
		modify = 1;
		return 1;
	}		

	/*
 	 * at this point, input has complete, so possibly
 	 * modify the actual cfgval, then clean up
 	 */
	if (modify) {
		kpr_err("\r\ncfgval set to %x\n", cfgval);
		ks->cfgval = cfgval;
	}
	else {
		kpr_err("\r\ncfgval not modified\n");
	}

	cfgval = 0;
	modify = 0;
	state = NORMAL_INPUT;

	return 1;
}

/*
 * serial_input
 *
 * Simple menu of options presented during the kexec reboot.
 * Normally, you'd only have a few hundred milliseconds to
 * interact with this, but if something goes wrong (ie, system
 * never reboots) then there will be additional time.
 *
 * A testing strategy is to insert code into the kernel at
 * arch/arm64/kernel/relocate_kernel.S that spins waiting for
 * notification. The 'u'nstick command below sets a byte
 * in ks->lib_version_major that is examined by relocate_kernel:

   ldr  x16, hardcoded_kstate_addr
1: ldrb w0, [x16, #0x15]
   cbz  w0, 1b
   ...
.align 3
hardcoded_kstate_addr: .quad 0xc5f8d000

*/
void serial_input(char c)
{
	extern int pciesvc_version_major, pciesvc_version_minor;   
	extern long uart_data_reg, uart_status_reg;
	void kpcimgr_version_fn(char **);
	extern void pciesvc_quit(void);
	extern long using_psci, using_xen;
	extern long protected_read;
	kstate_t *ks = get_kstate();
	char *version;
	int n;

	if (cfgval_process(c))
		return;

	switch (c) {
	case 'a': case 'A':
		kpcimgr_version_fn(&version);
		kpr_err("Library version %d.%d, %s\n",
			pciesvc_version_major, pciesvc_version_minor, version);
		kpr_err("kstate_paddr= %lx, xen=%d, psci=%d, uart_data=%lx, uart_status=%lx\n",
			kstate_paddr, using_xen, using_psci,
			uart_data_reg, uart_status_reg);
		kpr_err("protected_read=%d, debug progress=%x\n",
			protected_read, ks->lib_version_major);
		break;
	case 'c': case 'C':
		kpr_err("thread running on cpu#%d\n", cpuid());
		break;
	case 'e': case 'E':
		n = ks->evq_head - ks->evq_tail;
		if (n < 0)
			n += EVENT_QUEUE_LENGTH;
		kpr_err("event queue contains %d records\n", n);
		break;
	case '?':
	case 'h':
	case 'H':
		serial_help();
		break;
	case 'm': case 'M':
		for (n=0; n<ks->nranges; n++) {
			struct mem_range_t *mr = &ks->mem_ranges[n];
			kpr_err("range [%lx..%lx] mapped at %lx\n",
				mr->base, mr->end, mr->vaddr);
		}
		break;
	case 'q': case 'Q':
		ks->features |= FLAG_PSCI_CPU_RELEASE;
		pciesvc_quit();
		break;
	case 'r': case 'R':
		watchdog_reboot();
		break;
	case 's':
	case 'S':
		trigger_serr(0);
		break;
	case 't':
	case 'T':
		kpcimgr_report_stats(ks, NOMMU, 1, 1);
		break;
	case 'u':
	case 'U':
		ks->lib_version_major |= 0xee00;
		break;
	default:
		kpr_err("'%c' unknown command\n", c);
		break;
	}
}

/*
 * serial thread is not used anymore, but leaving
 * it here as an example
 */
void kpcimgr_serial_thread(kstate_t *ks)
{
	unsigned long start = read_sysreg(cntvct_el0);
	int warning_printed = 0;

	set_kstate(ks);

	kpr_err("pciesvc: %s el%d on cpu%d\n", __func__, read_el(), cpuid());
	while (!release()) {
		char c;
		if (uart_read(&c))
			serial_input(c);
		if (!warning_printed && time_elapsed(start, 2*TICKS_PER_SEC)) {
			kpr_err("pciesvc: serial thread running for >2s, 'H' for help\n");
			warning_printed = 1;
		}
	}
	kpr_err("pciesvc: %s done\n", __func__);
}


/*
 * Called from kpcimgr when the secondary CPUs are being taken
 * offline.  We return a physical address which the secondary CPU will
 * jump to.  The global 'holding_pen_idx' keeps a count of how many
 * times we've been called so that we can return the appropriate
 * function pointer for a given cpu. It would seem that there are some
 * very dangerous race conditions here:
 *
 * 1. Can't this function be called concurrently on multiple CPUs?
 *    No, it cannot, because we are called by kpcimgr_get_entry(),
 *    which protects against this with a spinlock.
 *
 * 2. holding_pen_idx is reset to zero in kpcimgr_cpu_polling_loop(),
 *    and can't that execute on CPU1 while this function executes
 *    concurrently on CPU2?
 *    Good question! The answer is yes, they can execute
 *    simultaneously, but it is not a race because they will operate
 *    on different memory.  When this function is called, it is in
 *    virtual mode, with the code and data in normal module_alloc'ed
 *    memory. But when kpcimgr_cpu_polling_loop() executes, it is
 *    running in physical mode from a copy of the code and data that
 *    has been relocated to persistent memory. Thus, references to
 *    'holding_pen_idx' in these two functions refer to different
 *    memory locations.
 */

unsigned long kpcimgr_get_holding_pen(unsigned long old_entry,
				      unsigned int cpu, unsigned long ks_paddr)
{
	kstate_t *ks = get_kstate();
	unsigned long offset, entry;
	extern void __kpcimgr_cpu_holding_pen(void);
	extern void __kpcimgr_serial_thread(void);
	extern long uart_data_reg, uart_status_reg;

	if (ks == NULL || ks->valid != KSTATE_MAGIC || !ks->running || !ks->have_persistent_mem)
		return old_entry;

	if (cpu == 0)
		return old_entry;

	holding_pen_idx++;
	switch (holding_pen_idx) {
	case 1:
		offset = (unsigned long) __kpcimgr_cpu_holding_pen - (unsigned long) ks->code_base;
		break;
#if 0
	case 2:
		offset = (unsigned long) __kpcimgr_serial_thread - (unsigned long) ks->code_base;
		break;
#endif
	default:
		return old_entry;
	}

#if 1
	/* temp: stay compatible with old kernel */
	if ((ks_paddr >> 24) != 0xc5)
		ks_paddr = ks->shmembase + COMPAT_SHMEM_KSTATE_OFFSET;
#endif
	entry = ks_paddr + KSTATE_CODE_OFFSET + offset;
	kpr_err("pciesvc: %s(cpu%d) entry = %lx; ks_paddr=%lx\n", __func__, cpu, entry, ks_paddr);

	/* In old kernel, propagate values of various phys addresses to persistent memory */
#define PROPAGATE(TARGET, SOURCE) \
	offset = ((unsigned long) &TARGET) - (unsigned long) ks->code_base; \
	*(unsigned long *)(ks->persistent_base + offset) = SOURCE;

	if (ks->features_valid != KSTATE_MAGIC) {
		PROPAGATE(kstate_paddr, ks_paddr);
		PROPAGATE(uart_data_reg, NS16550_UART);
		PROPAGATE(uart_status_reg, NS16550_UART + NS16550_LSR);
	}

	return entry;
}
