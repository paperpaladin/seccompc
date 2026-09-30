/*
 * try - the oracle's probe. Make exactly one syscall and report what the
 * kernel said, by errno, numerically.
 *
 *   try call NAME            make the call
 *   try neg NAME             make syscall number -1 (NAME ignored)
 *   try x32 NAME             make it with the x32 bit set in rax
 *   try trap NAME            catch SIGSYS first, then make it
 *   try escape NAME          try every way out of the filter, then make it
 *   try fork NAME            make it in a child, relay the child's fate
 *   try thread NAME          make it in a sibling THREAD, report who survived
 *   try threadx32 NAME       the same, with the x32 bit, for the arch check
 *   try exec PROG ARGS...    execve PROG, which inherits the filter
 *
 * Exit status is the point: 0 if the syscall succeeded, otherwise the errno as
 * a number, so "denied with EPERM" can never be confused with "denied with
 * ENOSYS" or with "the call failed for its own ordinary reasons". 99 means a
 * SIGSYS handler ran, 97 that a sibling thread died while this one lived, 98
 * that a sibling neither died nor reported. A relayed death by signal comes
 * back as 128+signal, the same number a shell would report.
 *
 * Freestanding: no libc, no dynamic loader, its own _start, every syscall by
 * hand. That is not minimalism for its own sake. A probe linked against glibc
 * needs a startup sequence -- brk, arch_prctl, set_tid_address, set_robust_list,
 * rseq, mmap, ... -- which every test policy would then have to allow, so
 * "the allowed calls still work" would be partly an accident of a broad
 * allowlist and a glibc upgrade could change the set underneath the suite.
 * Here the only syscalls that happen are write, exit_group, and the one under
 * test.
 *
 * Built twice from this file: x86-64, and i386 via -m32, which is the only way
 * to drive the 32-bit entry point and prove the arch check closes the bypass
 * rather than merely containing an instruction that looks like it should. The
 * i386 half is a separate program with no arguments; see the bottom.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#include <asm/unistd.h>

#ifndef __i386__

#include <linux/filter.h>
#include <linux/seccomp.h>

#define SIGSYS 31
#define SA_RESTORER 0x04000000UL
#define SA_SIGINFO 0x00000004UL
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_SECCOMP 21
#define PR_SET_SECCOMP 22
#define SECCOMP_MODE_DISABLED 0
#define X32_BIT 0x40000000L

/*
 * x32 compiles through this half of the file, not the i386 half: pointers are
 * 32 bits under -mx32 but the syscall instruction and the registers it uses
 * are the 64-bit ones. The assert is most of the reason to build it at all.
 * X32_BIT is a constant the 64-bit probe uses to RECONSTRUCT what an x32
 * caller puts in rax, and the kernel's own uapi header, read by the compiler
 * in x32 mode, is the only authority outside this repository for it. Under
 * -mx32 the whole x32 table is biased by that bit, so getuid is 0x40000066
 * and the reconstruction is either exactly right or this does not build.
 */
#ifdef __ILP32__
_Static_assert(__NR_getuid == (X32_BIT | 102),
    "the x32 syscall bit is not what the 64-bit probe reconstructs");
#endif

/*
 * Raw syscalls. The return value is the kernel's: negative errno on failure,
 * with no errno variable and no libc wrapper between us and the number. That
 * is what makes the exit status trustworthy as an assertion.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f) {
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall"
	    : "=a"(ret)
	    : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
	    : "rcx", "r11", "memory");
	return ret;
}
#define sys3(n, a, b, c) sys6((n), (a), (b), (c), 0, 0, 0)

static void xexit(int code) {
	sys3(__NR_exit_group, code, 0, 0);
	__builtin_unreachable();
}

static unsigned slen(const char *s) {
	unsigned n = 0;
	while (s[n]) n++;
	return n;
}

static void out(const char *s) {
	sys3(__NR_write, 1, (long)s, slen(s));
}

/* Decimal, into a caller-supplied buffer, right-aligned at the end. */
static const char *num(long v, char *buf, unsigned size) {
	unsigned i = size - 1;
	int neg = v < 0;
	unsigned long u = neg ? (unsigned long)-v : (unsigned long)v;
	buf[i] = 0;
	do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u && i);
	if (neg && i) buf[--i] = '-';
	return buf + i;
}

static void outnum(long v) {
	char buf[24];
	out(num(v, buf, sizeof buf));
}

static int streq(const char *a, const char *b) {
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

/*
 * The syscalls worth probing, with arguments chosen so that "it worked" is
 * unambiguous. getuid is the important one: it has no arguments, no side
 * effect, and cannot fail, so a nonzero exit from it is the filter and nothing
 * else. It is also x86-64 number 102, which is i386's socketcall -- the
 * collision the arch check exists to stop.
 *
 * shortcut: seven calls, all of them argument-free or nearly so. The ceiling is
 * a policy worth testing against a syscall whose success is only observable
 * through its side effects -- openat, mmap, ptrace. Upgrade path: give the
 * table a verifier function per entry rather than widening it with arguments
 * whose meaning the harness would then have to know.
 */
static const struct { const char *name; long nr, a, b, c; } calls[] = {
	{ "getuid",      __NR_getuid,      0, 0, 0 },
	{ "geteuid",     __NR_geteuid,     0, 0, 0 },
	{ "getgid",      __NR_getgid,      0, 0, 0 },
	{ "getpid",      __NR_getpid,      0, 0, 0 },
	{ "gettid",      __NR_gettid,      0, 0, 0 },
	{ "sched_yield", __NR_sched_yield, 0, 0, 0 },
	/* AF_INET, SOCK_STREAM: returns a descriptor, so >= 0 means a real
	 * socket exists and the policy failed to stop it. */
	{ "socket",      __NR_socket,      2, 1, 0 },
};
#define NCALLS ((int)(sizeof calls / sizeof *calls))

static int lookup(const char *name) {
	for (int i = 0; i < NCALLS; i++)
		if (streq(calls[i].name, name)) return i;
	out("try: unknown call name: ");
	out(name);
	out("\n");
	xexit(2);
	return -1;
}

/* Report, and turn the kernel's answer into an exit status. */
static void report(const char *op, const char *name, long r) {
	out(r >= 0 ? "OK " : "FAIL ");
	out(op);
	out(" ");
	out(name);
	out(r >= 0 ? " ret=" : " errno=");
	outnum(r >= 0 ? r : -r);
	out("\n");
	xexit(r >= 0 ? 0 : (int)(-r & 0xff));
}

static long do_call(int i, long nrbias) {
	return sys3(calls[i].nr + nrbias, calls[i].a, calls[i].b, calls[i].c);
}

/* ------------------------------------------------------------ SIGSYS ----- */

/*
 * x86-64 requires SA_RESTORER and a restorer address; glibc normally supplies
 * one. Ours is never actually reached, because the handler exits rather than
 * returning, but rt_sigaction rejects the call without it.
 */
__asm__(".globl try_sigreturn\n"
        "try_sigreturn:\n"
        "\tmov $" "15" ", %eax\n"   /* __NR_rt_sigreturn */
        "\tsyscall\n");
extern void try_sigreturn(void);

struct ksigaction {
	void (*handler)(int);
	unsigned long flags;
	void (*restorer)(void);
	unsigned long mask;
};

static void on_sigsys(int signo) {
	(void)signo;
	out("note: SIGSYS was delivered and caught, so TRAP is catchable\n");
	xexit(99);
}

/* ------------------------------------------------------------ escape ----- */

/*
 * Every unprivileged way out, in order of how plausible it looks.
 *
 * None of them work, and the third one is the interesting one because it
 * SUCCEEDS: a process may install another filter at any time. Filters do not
 * replace each other, they accumulate -- every filter in the task's list runs
 * on every syscall and the most restrictive return value wins. So adding a
 * ret-ALLOW filter is permitted and changes nothing. There is no
 * seccomp_release(), no way to shorten the list, and the only thing that
 * clears it is the task exiting.
 */
static const struct sock_filter permissive[] = {
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static void note(const char *what, long r) {
	out("note: ");
	out(what);
	out(r == 0 ? " -> success" : " -> errno ");
	if (r != 0) outnum(-r);
	out("\n");
}

static void escape(int i, const char *name) {
	struct sock_fprog fprog;

	note("prctl(PR_SET_NO_NEW_PRIVS, 0)",
	    sys3(__NR_prctl, PR_SET_NO_NEW_PRIVS, 0, 0));
	note("prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED)",
	    sys3(__NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_DISABLED, 0));

	out("note: prctl(PR_GET_SECCOMP) reports mode ");
	outnum(sys3(__NR_prctl, PR_GET_SECCOMP, 0, 0));
	out(" (2 = filter)\n");

	fprog.len = 1;
	fprog.filter = (struct sock_filter *)permissive;
	note("seccomp(SET_MODE_FILTER, ret ALLOW) -- a filter of its own",
	    sys3(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, (long)&fprog));

	report("escape-then-call", name, do_call(i, 0));
}

/* ------------------------------------------------------------- fork ------ */

/*
 * clone(SIGCHLD, 0) is fork: no CLONE_VM, so the child gets a copy-on-write
 * copy of this stack. The child is its own thread group, which matters --
 * SECCOMP_RET_KILL_PROCESS kills the caller's thread group, so it takes the
 * child and leaves us to report what happened to it.
 */
static void relay(long status) {
	if ((status & 0x7f) == 0) xexit((int)((status >> 8) & 0xff));
	if ((status & 0x7f) != 0x7f) {
		out("note: child died on signal ");
		outnum(status & 0x7f);
		out("\n");
		xexit(128 + (int)(status & 0x7f));
	}
	xexit(125); /* stopped: nothing in this suite can produce it */
}

static void forked(int i, const char *name) {
	long pid = sys6(__NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
	int status = 0;

	if (pid < 0) report("clone", name, pid);
	if (pid == 0) report("call-in-child", name, do_call(i, 0));
	if (sys6(__NR_wait4, pid, (long)&status, 0, 0, 0, 0) < 0)
		report("wait4", name, -1);
	relay(status);
}

/* ------------------------------------------------------------ thread ----- */

/*
 * KILL_PROCESS and KILL_THREAD are the same death for a process with one
 * thread, which is why the suite reported the difference as a skip for as long
 * as the probe had only one. A sibling thread makes them tell apart:
 *
 *   KILL_THREAD   the sibling dies, this thread lives on and exits 97
 *   KILL_PROCESS  the whole thread group goes, and the harness sees 159
 *
 * The kernel's own distinction, at the bottom of __seccomp_filter, is
 * do_exit(SIGSYS) against do_group_exit(SIGSYS). Nothing here reads it; the
 * two outcomes are observed from outside, and the pair is the assertion. One
 * line alone says nothing, since a filter that killed everything would satisfy
 * the second for free.
 *
 * CLONE_CHILD_CLEARTID is the channel, and it is chosen because it is the
 * kernel's and not ours: mm_release zeroes the word and wakes anyone on it,
 * for every exit path including a fatal signal. A dying thread cannot report
 * its own death, so the report has to come from somewhere it does not run.
 */
#define CLONE_VM_F              0x00000100
#define CLONE_SIGHAND_F         0x00000800
#define CLONE_THREAD_F          0x00010000
#define CLONE_CHILD_CLEARTID_F  0x00200000

static volatile int sib_tid;
static int sib_call;
static long sib_bias;
static char sib_stack[8192] __attribute__((aligned(16)));

void sibling_main(void);

void sibling_main(void) {
	/* If the call is permitted this reports and exits the group, which is
	 * the control: it proves the sibling really runs and really calls. */
	report("call-in-sibling", calls[sib_call].name,
	    do_call(sib_call, sib_bias));
}

/*
 * The child cannot enter a C function through the ordinary return path of a
 * syscall wrapper. clone gives it a new stack pointer and the compiler is
 * entitled to address the caller's locals through that register, so the switch
 * happens here and the child's first C frame is a function taking nothing and
 * returning nowhere.
 */
__asm__(".globl try_clone_thread\n"
        "try_clone_thread:\n"            /* rdi flags, rsi stacktop, rdx ctid */
        "\tmov %rdx, %r10\n"             /* child_tidptr is clone's 4th arg */
        "\txor %edx, %edx\n"             /* parent_tidptr: not wanted */
        "\tmov $56, %eax\n"              /* __NR_clone */
        "\tsyscall\n"
        "\ttest %eax, %eax\n"
        "\tjnz 1f\n"
        "\txor %rbp, %rbp\n"
        "\tand $-16, %rsp\n"
        "\tcall sibling_main\n"
        "\thlt\n"
        "1:\tret\n");
extern long try_clone_thread(long flags, void *stacktop, volatile int *ctid);

static void threaded(int i, const char *name, long bias) {
	long tid;

	sib_call = i;
	sib_bias = bias;
	sib_tid = -1;
	tid = try_clone_thread(CLONE_VM_F | CLONE_SIGHAND_F | CLONE_THREAD_F |
	    CLONE_CHILD_CLEARTID_F, sib_stack + sizeof sib_stack, &sib_tid);
	if (tid < 0) report("clone-thread", name, tid);

	/*
	 * Bounded, because the alternative to a bound is a harness that hangs
	 * when this is wrong. sched_yield is a syscall, so every policy using
	 * this op has to permit it, and the permitted-call control is what
	 * shows that it does.
	 */
	for (long spins = 0; spins < 200000; spins++) {
		if (sib_tid == 0) {
			out("note: the sibling thread died and this one did "
			    "not, so the kill was per-thread\n");
			xexit(97);
		}
		sys3(__NR_sched_yield, 0, 0, 0);
	}
	out("FAIL thread: the sibling neither died nor reported\n");
	xexit(98);
}

/* -------------------------------------------------------------- main ----- */

void probe_main(long argc, char **argv);

void probe_main(long argc, char **argv) {
	const char *op, *name;
	int i;

	if (argc < 3) {
		out("usage: try call|neg|x32|trap|escape|fork|thread|threadx32 NAME | try exec PROG ARGS...\n");
		xexit(2);
	}
	op = argv[1];
	name = argv[2];

	if (streq(op, "exec")) {
		/* Deliberately a NULL environment: the filter is inherited
		 * across exec whatever the environment says, and an empty one
		 * keeps the exec'd program's own startup minimal. */
		long r = sys3(__NR_execve, (long)argv[2], (long)&argv[2], 0);
		report("exec", argv[2], r);
	}

	i = lookup(name);

	if (streq(op, "call"))   report("call", name, do_call(i, 0));
	if (streq(op, "x32"))    report("x32", name, do_call(i, X32_BIT));
	/* NAME is ignored: the point is the number, not the call. nr is a
	 * signed int in seccomp_data, so -1 reaches the filter as 0xffffffff
	 * and is caught by the same unsigned range check as the x32 bit.
	 * Unfiltered the kernel answers ENOSYS; under a filter it is a kill,
	 * and that difference is deliberate. */
	if (streq(op, "neg"))    report("neg", "nr=-1", sys3(-1, 0, 0, 0));
	if (streq(op, "escape")) escape(i, name);
	if (streq(op, "fork"))   forked(i, name);
	if (streq(op, "thread")) threaded(i, name, 0);
	/* The same sibling, calling through the x32 bit, so the action the
	 * arch range check returns is observable as a scope and not only as a
	 * death. KILL_THREAD there instead of KILL_PROCESS used to be a mutant
	 * only the structural check could see. */
	if (streq(op, "threadx32")) threaded(i, name, X32_BIT);
	if (streq(op, "trap")) {
		struct ksigaction act;
		act.handler = on_sigsys;
		act.flags = SA_RESTORER;
		act.restorer = try_sigreturn;
		act.mask = 0;
		if (sys6(__NR_rt_sigaction, SIGSYS, (long)&act, 0, 8, 0, 0) < 0)
			report("rt_sigaction", name, -1);
		report("trap", name, do_call(i, 0));
	}

	out("try: unknown op: ");
	out(op);
	out("\n");
	xexit(2);
}

/*
 * No libc, so no crt1.o and no __libc_start_main. argc and argv are where the
 * kernel left them, on the stack. The `and` keeps the ABI's 16-byte alignment
 * promise, which gcc is entitled to rely on; `hlt` is a tripwire, since
 * probe_main never returns.
 */
__asm__(".globl _start\n"
        "_start:\n"
        "\txor %rbp, %rbp\n"
        "\tmov (%rsp), %rdi\n"
        "\tlea 8(%rsp), %rsi\n"
        "\tand $-16, %rsp\n"
        "\tcall probe_main\n"
        "\thlt\n");

#else /* __i386__ */

/*
 * The i386 probe. One job, no arguments: reach the 32-bit syscall entry point
 * and ask for syscall number 102.
 *
 * On i386 that is socketcall, the multiplexer through which socket(), bind(),
 * connect() and the rest are reached. On x86-64 the same number is getuid.
 * A seccomp filter that compares seccomp_data.nr without first pinning
 * seccomp_data.arch therefore cannot tell them apart: a policy saying "getuid
 * is fine" has, on an x86-64 kernel, also said "any 32-bit caller may open a
 * socket". Nothing exotic is needed to use it -- `int $0x80` with eax=102 is
 * the whole technique, and it is right here.
 *
 * Exit status matches the 64-bit probe: 0 if the socket was created, otherwise
 * the errno. Unfiltered it exits 0, which is the control that stops the
 * filtered assertion from passing for some unrelated reason.
 *
 * shortcut: no argument parsing and one hardcoded call, where the 64-bit half
 * has six ops and a table. The ceiling is that only this one collision can be
 * driven through the i386 door, so a future assertion about, say, i386 nr 4
 * (write on i386, stat on x86-64) needs code rather than a flag. Upgrade path:
 * an i386 call table and the same argv dispatch as above, which is maybe thirty
 * lines and buys nothing until there is a second i386 assertion to write.
 */
#define SYS_SOCKET 1

static long sys3_32(long n, long a, long b, long c) {
	long ret;
	__asm__ volatile("int $0x80"
	    : "=a"(ret)
	    : "a"(n), "b"(a), "c"(b), "d"(c)
	    : "memory");
	return ret;
}

void probe_main(void);

void probe_main(void) {
	/* AF_INET, SOCK_STREAM, 0 */
	unsigned long args[3];
	long r;

	args[0] = 2;
	args[1] = 1;
	args[2] = 0;
	r = sys3_32(__NR_socketcall, SYS_SOCKET, (long)args, 0);

	/*
	 * No write(): reporting would need another syscall through the same
	 * 32-bit door, and under a filter that kills on foreign arch the
	 * report would be the thing that died. The exit status carries it.
	 *
	 * Leaving by i386 exit (number 1) rather than exit_group (252), and
	 * that choice is what makes the status unambiguous. 1 is write on
	 * x86-64 -- the second half of the same collision -- so a filter that
	 * allows write and has no arch check lets this exit through, and the
	 * process leaves with status 0 to say the bypass worked. Through
	 * exit_group the mutant would instead be denied its exit and die of
	 * something incidental, which proves nothing.
	 */
	sys3_32(__NR_exit, r >= 0 ? 0 : -r & 0xff, 0, 0);
	__builtin_unreachable();
}

__asm__(".globl _start\n"
        "_start:\n"
        "\txor %ebp, %ebp\n"
        "\tand $-16, %esp\n"
        "\tcall probe_main\n"
        "\thlt\n");

#endif
