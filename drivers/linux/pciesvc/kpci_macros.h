/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, 2025, Oracle and/or its affiliates.
 */

/*
 *  Macros for kpcimgr (a.k.a. pciesvc glue layer)
 *
 *  Author: rob.gardner@oracle.com
 */

#ifndef SYM_CODE_START	
#define SYM_CODE_START(name) \
	.globl name		;\
        name:			;
	
#define SYM_CODE_END(name) \
	.size name, .-name
#endif

/*
 * Calling conventions for internal function(s)
 *
 * We use x12 as the branch link register and x13
 * as the first function argument
 *
 * Currently the only internal callable function is 'printl'
 */
#define	return_addr 	x12
#define arg0 		x13

/* defines for exception count and cpuid */
#define ex_count	tpidr_el0
#define cpuidreg	tpidr_el1

.macro	CALL, target
	adr	return_addr, 34f
	b	\target
34:
.endm

.macro	RETURN
	br	return_addr
.endm

/*
 * putc0_nowait
 *
 * Writes a character to the UART, and handles both
 * types: ns16550a and PL011
 * Does not check to see if it's actually ok to write
 * the character. It is the caller's responsibility to do this.
 *
 * Registers: x16, x17
 */
.macro putc0_nowait
	ldr	x16, uart_data_reg
	strb	w17, [x16]	/* write char to data register */	
.endm

/*
 * uart_canwrite
 *
 * reg will be non-zero if it is safe to write a character
 */
.macro uart_canwrite, reg
	ldr	x16, uart_status_reg
	ldr	w9, using_xen
	ldrb	\reg, [x16]
	and	w16, \reg, #NS16550_THRE
	cbz	w9, 71f
	/* xen case */
	and	w16, \reg, #UART01x_FR_TXFF
	eor	w16, w16,  #UART01x_FR_TXFF
71:	mov	\reg, w16
.endm

/*
 * thre_wait
 *
 * Wait for uart transmitter to empty
 *
 * Registers: x16, x17
 */
.macro thre_wait
80:
	uart_canwrite w17	
	cbz	x17, 80b
.endm

	/* macro to print a char given in x17 */
/*
 * putc0
 *
 * Write a character and waits for it to be transmitted
 */
.macro putc0
	putc0_nowait
	thre_wait
.endm

/*
 * putc
 *
 * writes the given literal character and waits
 */
.macro putc, c
	mov	x17, \c
	putc0
.endm

/*
 * putc_nowait
 *
 * writes the given literal character and doesn't wait
 */
.macro putc_nowait, c
	mov	x17, \c
	putc0_nowait
.endm

/*
 * print
 *
 * print a literal string, ie, print "hello, world"
 *
 * Registers: x18
 */
.macro print, msg
	adr	x18, 147f
143:	ldrb	w17, [x18], #1
	cbz	x17, 149f
	putc0
	b	143b
147:	.asciz "\msg"
	.align	2
149:
.endm

/*
 * print various values, used mainly by exception
 * handler to produce something that vaguely resembles
 * a minimal panic message
 */

/*
 * printr - print the value in a register
 */
.macro	printr, reg
	print	"\reg"
	putc	':'
	mov	arg0, \reg
	CALL(printl)
.endm

/*
 * printsp - print sp
 */
.macro	printsp
	print	"SP: "
	mov	arg0, sp
	CALL(printl)
.endm

/*
 * printsr - print a system register
 */
.macro	printsr, reg
	print	"\reg"
	putc	':'
	mrs	arg0, \reg
	CALL(printl)
.endm


/*
 * delineate - print a group of 4 characters (for output visibility)
 */
.macro	delineate, c
	mov	x10, #4
184:	putc	\c
	sub	x10, x10, 1
	cbnz	x10, 184b
.endm


/*
 * print_ex_count - print the exception count value
 */
.macro	print_ex_count
	putc	'('
	print	"ex_count:"
	mrs	x15, ex_count
	add	x17, x15, '0'
	putc0
	putc	')'
.endm
	
/*
 * print_cpuid - print the cpu number
 */
.macro	print_cpuid
	putc	'<'
	print	"CPU"
	mrs	x17, cpuidreg
	add	x17, x17, '0'
	putc0
	putc	'>'
.endm

/*
 * print_el - print exception level
 */
.macro	print_el
	putc	'['
	print	"EL"
	mrs	x17, CurrentEL
	asr	x17, x17, 2
	add	x17, x17, '0'
	putc0
	putc	']'
.endm


/*
 * printl, basically performs a printf("[%lx]")
 *
 * We use a few registers, but they are not used elsewhere
 */
#define shiftval 	x14
#define nchars 		x15
#define nibble 		x17
	
SYM_CODE_START(printl)
	putc	'['
	mov	nchars, #0	/* number of characters actually printed */
	mov	shiftval, #64
.loop_top:
	sub	shiftval, shiftval, 4
	lsr	nibble, arg0, shiftval
	and	nibble, nibble, #0xf

	cbnz	nibble, .print		/* always print a non-zero nibble */
	cbz	shiftval, .print	/* always print the last nibble, even if zero */
	cbz	nchars, .loop_bottom	/* don't print leading zeros */
	
.print:	
	add	nchars, nchars, 1
	add	nibble, nibble, #'0'
	cmp	nibble, #'0'+0xA
	b.lt	368f
	add	nibble, nibble, #-0xA-'0'+'A'
368:	putc0
.loop_bottom:
	cbnz	shiftval, .loop_top
	
	putc	']'
	RETURN
SYM_CODE_END(printl)


/*
 * hyper, exlog - macros used in vector table
 */
.macro	hyper, c
	.align	7
	putc_nowait	\c
	b	.exit_final
.endm
	
.macro	exlog, c
	.align	7
	putc_nowait	\c
	b	exception_handler
.endm
