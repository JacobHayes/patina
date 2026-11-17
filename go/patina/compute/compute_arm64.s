//go:build linux

#include "textflag.h"

// The arm64 twin of compute_amd64.s: the same cell, wire and preemption check.

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
// Fast path: load the cell's address, decrement the cell (a load, a subtract and a store:
// one thread runs at a time under Patina), return false while it stays above 0.
// g (R28) is the goroutine in every Go ABI on arm64. The system call takes its number in R8
// and its arguments in R0-R2, and the kernel (and Patina) preserve every register but R0.
// Clobbers R0-R3 and R8 (caller-saved in both Go ABIs).
TEXT ·event(SB), NOSPLIT|NOFRAME, $0-1
	MOVB	ZR, ret+0(FP)
	MOVD	·cell(SB), R0
	CBZ	R0, done
	MOVD	(R0), R1
	SUBS	$1, R1, R1
	MOVD	R1, (R0)
	BLE	slow
done:
	RET
slow:
	MOVD	$·boot(SB), R2
	CMP	R2, R0
	BEQ	hello
	// The cell ran out: a compute point. The runtime refills the cell before it returns.
	MOVD	$SYS_PATINA, R8
	MOVD	$OP_POINT, R0
	MOVD	ZR, R1
	MOVD	ZR, R2
	SVC
	MOVD	G_STACKGUARD0(g), R1
	MOVD	STACK_PREEMPT, R2
	CMP	R2, R1
	CSET	EQ, R3
	MOVB	R3, ret+0(FP)
	RET
hello:
	// The first event: ask for the cell. Any error (ENOSYS outside Patina): stay inert.
	MOVD	$SYS_PATINA, R8
	MOVD	$OP_HELLO, R0
	MOVD	$HELLO_ARG, R1
	MOVD	ZR, R2
	SVC
	CMP	$0, R0
	BGT	store
	MOVD	ZR, R0
store:
	MOVD	R0, ·cell(SB)
	RET
