/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, 2025, Oracle and/or its affiliates.
 */

/*
 *  Low Level Functions for kpcimgr (a.k.a. pciesvc glue layer)
 *
 *  Author: rob.gardner@oracle.com
 */
	
#include "kpci_constants.h"
#include "kpci_uart.h"
#include "kpci_macros.h"

/* C callable uart read/write and can-read/write functions */

/*
 * uart_putc_nowait: writes one character and does not wait
 */
SYM_CODE_START(uart_putc_nowait)
	mov	x17, x0
	putc0_nowait
	ret
SYM_CODE_END(uart_putc_nowait)

/*
 * uart_canwrite: returns true if another char can be written
 */
SYM_CODE_START(uart_canwrite)
	uart_canwrite	w0
	ret
SYM_CODE_END(uart_canwrite)

/*
 * uart_getc_nowait: reads one character from the uart.
 * The caller must ascertain that a character is actually available.
 */
SYM_CODE_START(uart_getc_nowait)
	ldr	x16, uart_data_reg
	ldrb	w0, [x16]
	ret
SYM_CODE_END(uart_getc_nowait)

/*
 * uart_canread: returns true if a char is available to read
 * (x9 is caller saved)
 */
SYM_CODE_START(uart_canread)
	ldr	x16, uart_status_reg
	ldrb	w0, [x16]
	ldr	w9, using_xen
	cbnz	x9, 122f
	/* non-xen case */
	and	x0, x0, #NS16550_DATA_READY
	ret
122:	/* xen case */
	and	x0, x0, #UART01x_FR_RXFE
	eor	x0, x0, #UART01x_FR_RXFE
	ret
SYM_CODE_END(uart_canread)

/*
 * read_el, cpuid - C callable functions
 *
 *  long read_el(void);
 *  int cpuid(void);
 */
SYM_CODE_START(read_el)
	mrs	x0, CurrentEL
	lsr	x0, x0, #2
	ret
SYM_CODE_END(read_el)
	
SYM_CODE_START(cpuid)
	mrs	x0, cpuidreg
	ret
SYM_CODE_END(cpuid)

	
/*
 * This is the entry point for the first
 * cpu to be hijacked. After dropping to EL1,
 * we just need to set up a stack and then
 * jump to C code to do the real work.
 */
SYM_CODE_START(__kpcimgr_cpu_holding_pen)
	delineate '>'
	msr	cpuidreg, x2	/* save cpu number */
	print_el

	/* find out what EL we're currently at */
	mrs	x29, CurrentEL
	asr	x29, x29, 2
	cmp	x29, #1
	b.eq	213f		/* already at EL1 */
	putc	'2'
	
	/* we're at EL2, so set up EL2 exception vectors and drop to EL1 */
	adr	x29, xcpt_vectors
	msr	vbar_el2, x29
	isb

	/* do the actual drop to EL1 */
	putc	'#'
	adr	x29, 213f
	msr	elr_el2, x29
	eret
213:	
	/* at this point we are at EL1, set up EL1 exception vectors */
	putc	'1'
	adr	x29, xcpt_vectors
	msr	vbar_el1, x29
	isb
	putc	'V'

	/* save original address of spin table */
	adr	x29, spin_table_start_addr
	str	x0, [x29]
	
	/* set limit on number of times the exception handler runs */
	mov	x16, 2
	msr	ex_count, x16
	putc	'!'

	/* unmask Serror */
	msr	daifclr, #(1|4|8)
	putc	'D'

	/* load kstate base and set initial stack pointer */
	ldr	x0, kstate_paddr
	add	x3, x0, KSTATE_STACK_OFFSET
	mov	sp, x3

	/* execute the polling loop */
	bl	kpcimgr_cpu_polling_loop

	/* when C returns control here, we're done */
	putc	'='
	b	.exit
SYM_CODE_END(__kpcimgr_cpu_holding_pen)

/*
 * Exception handler
 *
 * Mainly used to deal with Serror
 *
 * EL2 exceptions are fatal, but exceptions that arrive here
 * at EL1 cause some useful output to the console, and return.
 * The number of exceptions handled this way is limited to a few.
 * The Serror exception is an exception to this rule.
 */
SYM_CODE_START(exception_handler)
	thre_wait
	print_el
	mrs	x17, CurrentEL
	cmp	x17, #8
	b.ne	400f

	/* EL2 (fatal) */
	printsr elr_el2
	b	.exit_final

	/* EL1 */
400:	printsr	elr_el1
	printsr far_el1
	printsr	spsr_el1
	printsr esr_el1
	printsr sctlr_el1
	printr	x0
	printr	x30
	printsp

	print_ex_count

	/* during a protected read, just retry */
	ldr	x15, protected_read
	cbnz	x15, 406f	/* skip counting */

	/* limit number of times we go through this code */
	/* to avoid an infinite stream of exceptions */
	mrs	x15, ex_count
	cbz	x15, .exit
	sub	x15, x15, 1
	msr	ex_count, x15
406:
	print	"\r\n"
	eret

	/*
	 * Finish by jumping back to the original
	 * spin table or psci.cpu_die()
	 */
SYM_CODE_START(pciesvc_quit)
.exit:	
	ldr	x0, using_xen
	cbnz	x0, .exit_final

/* already at EL2? skip the hvc */
	mrs	x17, CurrentEL
	cmp	x17, #8
	b.eq	.exit_final

	/* trap to EL2 and continue on to exit_final */
	mov	x0, #1
	hvc	#0

.exit_final:
	thre_wait
	ldr	x1, using_psci
	cbnz	x1, .exit_psci

	print	"pciesvc: rebooting cpu via spin table\r\n"
	ldr	x0, spin_table_start_addr
	br	x0

.exit_psci:
	print	"pciesvc: reboot via psci\r\n"
	bl	released
	mov 	x0, 0x84000000
	add	x0, x0, 2
	mov	x1, 0x10000	/* PSCI_POWER_STATE_TYPE_POWER_DOWN << PSCI_0_2_POWER_STATE_TYPE_SHIFT */
	mov	x2, 0
	mov	x3, 0
	mov	x4, 0
	mov	x5, 0
	mov	x6, 0
	mov	x7, 0
	mov	x8, 0
	smc	#0	/* psci.cpu_off() */
	print   "pciesvc: SHOULD NOT RETURN HERE!\r\n"
452:	/* loop here forever */
	b	452

SYM_CODE_END(exception_handler)

	/* The actual Exception Vector table, used for both EL1 and EL2 */
	.align 11
xcpt_vectors:
/* Current exception level with SP_EL0 */
	exlog	'A'	/* Sync */	
	exlog	'B'	/* IRQ/vIRQ */
	exlog	'C'	/* FIQ/cFIQ */
	exlog	'D'	/* SError/vSError */
/* Current exception level with SP_ELx, x>0 */
	hyper	'H'	/* Sync */
	exlog	'I'	/* IRQ/vIRQ */
	exlog	'Q'	/* FIQ/cFIQ */
	exlog	'S'	/* SError/vSError */
