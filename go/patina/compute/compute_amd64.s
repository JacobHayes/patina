//go:build linux

#include "textflag.h"

// The cell's address: ·boot until the first event's hello, then the cell Patina mapped, or 0
// (inert) outside Patina. A uintptr in NOPTR data: storing it needs no write barrier.
GLOBL ·boot(SB), NOPTR, $8
DATA ·cell+0(SB)/8, $·boot(SB)
GLOBL ·cell(SB), NOPTR, $8

// The reserved system call and its compute operations (proto::sdk): COMPUTE_HELLO's argument
// is version 1 with kind COMPARE (4) in bits 8..16.
#define SYS_PATINA 0x7061
#define OP_HELLO 8
#define OP_POINT 9
#define HELLO_ARG 0x401

// The runtime's preemption mark in a goroutine's stack guard (runtime.stackPreempt), and the
// guard's offset in runtime.g (the offset every function prologue uses).
#define STACK_PREEMPT $0xfffffffffffffade
#define G_STACKGUARD0 16

// func event() bool
// Fast path: load the cell's address, decrement the cell, return false while it stays above 0.
// R14 is the goroutine (g) on entry: the caller is Go code (ABIInternal).
// Clobbers AX, CX, DX, SI, DI, R11 (caller-saved in both Go ABIs).
TEXT ·event(SB), NOSPLIT|NOFRAME, $0-1
	MOVB	$0, ret+0(FP)
	MOVQ	·cell(SB), AX
	TESTQ	AX, AX
	JZ	done
	DECQ	(AX)
	JLE	slow
done:
	RET
slow:
	LEAQ	·boot(SB), CX
	CMPQ	AX, CX
	JEQ	hello
	// The cell ran out: a compute point. The runtime refills the cell before it returns.
	MOVQ	$SYS_PATINA, AX
	MOVQ	$OP_POINT, DI
	XORL	SI, SI
	XORL	DX, DX
	SYSCALL
	MOVQ	STACK_PREEMPT, CX
	CMPQ	CX, G_STACKGUARD0(R14)
	SETEQ	ret+0(FP)
	RET
hello:
	// The first event: ask for the cell. Any error (ENOSYS outside Patina): stay inert.
	MOVQ	$SYS_PATINA, AX
	MOVQ	$OP_HELLO, DI
	MOVQ	$HELLO_ARG, SI
	XORL	DX, DX
	SYSCALL
	TESTQ	AX, AX
	JGT	store
	XORL	AX, AX
store:
	MOVQ	AX, ·cell(SB)
	RET
