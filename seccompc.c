/*
 * seccompc - compile a tiny textual policy into a seccomp-BPF filter.
 *
 *   seccompc -a POLICY -- CMD [ARGS...]   install the filter, then exec CMD
 *   seccompc -c POLICY -o FILE            compile the policy to a filter file
 *   seccompc -d FILE                      disassemble a filter file
 *   seccompc --actions                    print the actions this kernel has
 *
 * No libseccomp. Emitting the classic-BPF program by hand is the project; a
 * dependency that did it for us would leave nothing to be right or wrong
 * about.
 *
 * Unprivileged: PR_SET_NO_NEW_PRIVS lets a process without CAP_SYS_ADMIN
 * install a filter on itself, which is the only reason this is usable without
 * root.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Distro headers lag running kernels, and these values are ABI: the kernel
 * froze them when the action was introduced and cannot change them.
 */
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_THREAD 0x00000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP 0x00030000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE 0x7ff00000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif
#ifndef SECCOMP_RET_ACTION_FULL
#define SECCOMP_RET_ACTION_FULL 0xffff0000U
#endif
#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif

/*
 * The x32 ABI reuses AUDIT_ARCH_X86_64 and distinguishes itself by setting
 * bit 30 of the syscall number. Checking the arch alone therefore does not
 * pin down the syscall table; see emit().
 */
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000UL
#endif

/* The kernel clamps SECCOMP_RET_ERRNO data to this (include/linux/errno.h). */
#define SECCOMP_MAX_ERRNO 4095

static const char *prog = "seccompc";

/* 125 is seccompc's own failure, never a status that came from CMD. 126/127
 * are reserved for exec failure, exactly as in jail. */
static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void die(const char *fmt, ...) {
	va_list ap;
	fprintf(stderr, "%s: ", prog);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(125);
}

static void *xmalloc(size_t n) {
	void *p = malloc(n);
	if (!p) die("out of memory");
	return p;
}

static void usage(FILE *f) {
	fprintf(f,
	    "usage: %s -a POLICY -- CMD [ARGS...]   install filter, exec CMD\n"
	    "       %s -c POLICY -o FILE            compile policy to FILE\n"
	    "       %s -d FILE                      disassemble FILE\n"
	    "       %s --actions                    actions this kernel offers\n"
	    "\n"
	    "POLICY is ';'-separated clauses:\n"
	    "  default=ACTION            required; what every unlisted call gets\n"
	    "  allow=NAME,NAME,...       let these through\n"
	    "  kill=NAME,...             SIGSYS, whole process, uncatchable\n"
	    "  kill_thread=NAME,...      SIGSYS, calling thread only\n"
	    "  trap=NAME,...             SIGSYS, catchable\n"
	    "  log=NAME,...              allow, and log to the audit subsystem\n"
	    "  errno=ERRNO:NAME,...      fail with that errno\n"
	    "\n"
	    "ACTION is allow, kill, kill_thread, trap, log or errno:ERRNO.\n"
	    "NAME is a syscall name or a decimal syscall number.\n"
	    "ERRNO is a name such as ENOSYS or a decimal number.\n"
	    "\n"
	    "  %s -a 'default=kill; allow=write,exit_group,execve' -- ./prog\n",
	    prog, prog, prog, prog, prog);
}

/*
 * The only feature detection seccomp offers. A kernel can be missing an
 * action entirely (SECCOMP_RET_KILL_PROCESS and LOG arrived in 4.14,
 * USER_NOTIF in 5.0), and -- this is the part that makes it mandatory rather
 * than polite -- the kernel does not reject a filter that returns an action
 * it does not know. It treats the unknown value as the *lowest* action it
 * recognises, which is KILL_THREAD. So on a 4.13 kernel a filter asking for
 * KILL_PROCESS silently becomes KILL_THREAD, and `errno=ENOSYS:x` on a
 * kernel without RET_ERRNO silently becomes a kill. Asking first is the
 * difference between degrading and lying.
 *
 * /proc/sys/kernel/seccomp/actions_avail is the readable form of the same
 * answer, but it does not exist on a kernel without CONFIG_SECCOMP_FILTER,
 * which is where the answer matters most, so we ask the syscall.
 */
static const struct { const char *name; unsigned long ret; } actions[] = {
	{ "kill_process", SECCOMP_RET_KILL_PROCESS },
	{ "kill_thread",  SECCOMP_RET_KILL_THREAD },
	{ "trap",         SECCOMP_RET_TRAP },
	{ "errno",        SECCOMP_RET_ERRNO },
	{ "user_notif",   SECCOMP_RET_USER_NOTIF },
	{ "trace",        SECCOMP_RET_TRACE },
	{ "log",          SECCOMP_RET_LOG },
	{ "allow",        SECCOMP_RET_ALLOW },
};
#define NACTIONS ((int)(sizeof actions / sizeof *actions))

static int action_avail(unsigned long ret) {
	uint32_t r = (uint32_t)ret;
	return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &r) == 0;
}

/* Exits 0 if filters are usable at all, 1 if not, so a harness can skip. */
static int print_actions(void) {
	int ok = 0;
	for (int i = 0; i < NACTIONS; i++) {
		if (!action_avail(actions[i].ret)) continue;
		printf("%s%s", ok ? " " : "", actions[i].name);
		ok = 1;
	}
	putchar('\n');
	if (!ok)
		fprintf(stderr,
		    "%s: this kernel reports no seccomp actions at all "
		    "(CONFIG_SECCOMP_FILTER=n, or no SYS_seccomp: %s)\n",
		    prog, strerror(errno));
	return ok ? 0 : 1;
}

static const char *action_name(uint32_t ret) {
	for (int i = 0; i < NACTIONS; i++)
		if ((uint32_t)actions[i].ret == (ret & SECCOMP_RET_ACTION_FULL))
			return actions[i].name;
	return "UNKNOWN";
}

/*
 * Syscall names. The numbers come from the kernel's own uapi header through
 * __NR_*, so there is not one integer here to mistranscribe -- which is the
 * single bug a hand-written syscall table is famous for, and it is silent:
 * the wrong number produces a filter that confines the wrong call.
 *
 * shortcut: a curated set, not all ~360 x86-64 syscalls. The ceiling is a
 * policy naming one that is absent; the escape hatch is that a decimal number
 * is accepted wherever a name is, so no policy is inexpressible, only
 * uglier. Upgrade path: generate the list from <asm/unistd_64.h> in the
 * Makefile, which buys completeness for the price of a generated file.
 */
#define SYSCALL_NAMES(X) \
	X(read) X(write) X(open) X(close) X(stat) X(fstat) X(lstat) \
	X(poll) X(lseek) X(mmap) X(mprotect) X(munmap) X(brk) \
	X(rt_sigaction) X(rt_sigprocmask) X(rt_sigreturn) X(ioctl) \
	X(pread64) X(pwrite64) X(readv) X(writev) X(access) X(pipe) \
	X(select) X(sched_yield) X(mremap) X(msync) X(madvise) X(dup) \
	X(dup2) X(nanosleep) X(getpid) X(sendfile) X(socket) X(connect) \
	X(accept) X(sendto) X(recvfrom) X(sendmsg) X(recvmsg) X(shutdown) \
	X(bind) X(listen) X(getsockname) X(getpeername) X(socketpair) \
	X(setsockopt) X(getsockopt) X(clone) X(fork) X(vfork) X(execve) \
	X(exit) X(wait4) X(kill) X(uname) X(fcntl) X(flock) X(fsync) \
	X(ftruncate) X(getdents) X(getdents64) X(getcwd) X(chdir) \
	X(rename) X(mkdir) X(rmdir) X(creat) X(link) X(unlink) X(symlink) \
	X(readlink) X(chmod) X(fchmod) X(chown) X(umask) X(gettimeofday) \
	X(getrlimit) X(setrlimit) X(getrusage) X(getuid) X(getgid) \
	X(setuid) X(setgid) X(geteuid) X(getegid) X(getppid) X(setsid) \
	X(sched_setaffinity) X(sched_getaffinity) X(ptrace) X(capget) \
	X(capset) X(sigaltstack) X(prctl) X(arch_prctl) X(chroot) \
	X(mount) X(umount2) X(reboot) X(sethostname) X(init_module) \
	X(delete_module) X(gettid) X(futex) X(set_tid_address) \
	X(clock_gettime) X(clock_nanosleep) X(exit_group) X(epoll_create) \
	X(openat) X(mkdirat) X(newfstatat) X(unlinkat) X(renameat) \
	X(readlinkat) X(fchmodat) X(faccessat) X(pselect6) X(ppoll) \
	X(set_robust_list) X(get_robust_list) X(splice) X(tee) \
	X(sync_file_range) X(utimensat) X(epoll_pwait) X(signalfd) \
	X(timerfd_create) X(eventfd) X(fallocate) X(accept4) X(dup3) \
	X(pipe2) X(inotify_init1) X(preadv) X(pwritev) X(prlimit64) \
	X(sendmmsg) X(getcpu) X(kcmp) X(finit_module) X(sched_setattr) \
	X(renameat2) X(seccomp) X(getrandom) X(memfd_create) X(bpf) \
	X(execveat) X(userfaultfd) X(membarrier) X(mlock2) \
	X(copy_file_range) X(preadv2) X(pwritev2) X(pkey_mprotect) \
	X(statx) X(io_uring_setup) X(io_uring_enter) X(io_uring_register) \
	X(openat2) X(pidfd_open) X(clone3) X(close_range) X(faccessat2) \
	X(process_madvise) X(epoll_pwait2) X(mount_setattr) X(rseq) \
	X(landlock_create_ruleset) X(landlock_add_rule) \
	X(landlock_restrict_self)

static const struct { const char *name; int nr; } syscall_tab[] = {
#define SC_ENTRY(n) { #n, __NR_##n },
	SYSCALL_NAMES(SC_ENTRY)
#undef SC_ENTRY
};
#define NSYSCALL ((int)(sizeof syscall_tab / sizeof *syscall_tab))

/*
 * shortcut: curated too, for the same reason and with the same escape hatch
 * (a decimal number works anywhere an ERRNO name does). These are the ones a
 * policy actually reaches for: "pretend the call does not exist", "pretend it
 * is forbidden", "pretend the network is not there".
 */
#define ERRNO_NAMES(X) \
	X(EPERM) X(ENOENT) X(EINTR) X(EIO) X(ENXIO) X(EBADF) X(EAGAIN) \
	X(ENOMEM) X(EACCES) X(EFAULT) X(EBUSY) X(EEXIST) X(ENODEV) \
	X(ENOTDIR) X(EISDIR) X(EINVAL) X(ENFILE) X(EMFILE) X(ENOSPC) \
	X(EROFS) X(EPIPE) X(ENOSYS) X(ELOOP) X(EOPNOTSUPP) \
	X(EAFNOSUPPORT) X(ECONNREFUSED) X(ENETUNREACH) X(ETIMEDOUT) \
	X(EADDRINUSE) X(ENOTTY)

static const struct { const char *name; int val; } errno_tab[] = {
#define ERRNO_ENTRY(n) { #n, n },
	ERRNO_NAMES(ERRNO_ENTRY)
#undef ERRNO_ENTRY
};
#define NERRNO ((int)(sizeof errno_tab / sizeof *errno_tab))

/* Decimal only. strtol would accept "0x10" and " 12", and a syscall number
 * that silently means something else is exactly what we are guarding
 * against. */
static int all_digits(const char *s) {
	if (!*s) return 0;
	for (const char *p = s; *p; p++)
		if (*p < '0' || *p > '9') return 0;
	return 1;
}

static int lookup_errno(const char *s) {
	long v;
	if (all_digits(s)) {
		v = strtol(s, NULL, 10);
	} else {
		for (int i = 0; i < NERRNO; i++)
			if (!strcmp(errno_tab[i].name, s)) return errno_tab[i].val;
		die("unknown errno name: %s (use a decimal number if it is not "
		    "in the table)", s);
		return 0;
	}
	/*
	 * 0 would make the syscall report success without doing anything,
	 * which is a real technique but not one this policy language should
	 * express by accident; above MAX_ERRNO the kernel clamps, so the
	 * caller would get a different errno than they asked for.
	 */
	if (v < 1 || v > SECCOMP_MAX_ERRNO)
		die("errno %ld out of range: the kernel clamps "
		    "SECCOMP_RET_ERRNO data to 1..%d", v, SECCOMP_MAX_ERRNO);
	return (int)v;
}

static int lookup_syscall(const char *s) {
	if (all_digits(s)) {
		long v = strtol(s, NULL, 10);
		/* Above this the x32 bit is set and emit()'s range check would
		 * kill the call before the comparison could ever match. */
		if (v < 0 || v > 0x3fffffff)
			die("syscall number %ld out of range (0..%d)", v,
			    0x3fffffff);
		return (int)v;
	}
	for (int i = 0; i < NSYSCALL; i++)
		if (!strcmp(syscall_tab[i].name, s)) return syscall_tab[i].nr;
	die("unknown syscall name: %s (use a decimal number if it is not in "
	    "the table)", s);
	return -1;
}

/* ---------------------------------------------------------------- policy -- */

typedef struct { int nr; uint32_t act; const char *name; } Rule;

static Rule *rules;
static int nrule, rulecap;
static uint32_t def_act;
static int have_default;

static void rule_add(const char *name, int nr, uint32_t act) {
	for (int i = 0; i < nrule; i++)
		if (rules[i].nr == nr)
			die("%s (syscall %d) is assigned twice, as %s and %s; "
			    "refusing rather than picking one",
			    name, nr, action_name(rules[i].act),
			    action_name(act));
	if (nrule == rulecap) {
		rulecap = rulecap ? rulecap * 2 : 16;
		Rule *p = realloc(rules, (size_t)rulecap * sizeof *p);
		if (!p) die("out of memory for %d rules", rulecap);
		rules = p;
	}
	rules[nrule].nr = nr;
	rules[nrule].act = act;
	rules[nrule].name = name;
	nrule++;
}

static char *trim(char *s) {
	while (*s == ' ' || *s == '\t' || *s == '\n') s++;
	char *e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n')) e--;
	*e = 0;
	return s;
}

static int parse_action(const char *s, uint32_t *out) {
	if (!strcmp(s, "allow"))        { *out = SECCOMP_RET_ALLOW; return 0; }
	if (!strcmp(s, "log"))          { *out = SECCOMP_RET_LOG; return 0; }
	if (!strcmp(s, "trap"))         { *out = SECCOMP_RET_TRAP; return 0; }
	if (!strcmp(s, "kill") || !strcmp(s, "kill_process"))
	                                { *out = SECCOMP_RET_KILL_PROCESS; return 0; }
	if (!strcmp(s, "kill_thread"))  { *out = SECCOMP_RET_KILL_THREAD; return 0; }
	if (!strncmp(s, "errno:", 6)) {
		*out = SECCOMP_RET_ERRNO | (uint32_t)lookup_errno(s + 6);
		return 0;
	}
	return -1;
}

static void parse_list(char *list, uint32_t act) {
	char *save, *tok;
	int n = 0;
	for (tok = strtok_r(list, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		tok = trim(tok);
		if (!*tok) die("empty syscall name in list");
		rule_add(tok, lookup_syscall(tok), act);
		n++;
	}
	if (!n) die("clause with an empty syscall list");
}

/*
 * The policy string is kept, not freed: rule names point into it and they are
 * used in diagnostics right up to exec. A short-lived process can hold one
 * copy of its own argument.
 */
static void parse_policy(const char *policy) {
	char *buf = xmalloc(strlen(policy) + 1);
	char *save, *clause;
	strcpy(buf, policy);

	for (clause = strtok_r(buf, ";", &save); clause;
	     clause = strtok_r(NULL, ";", &save)) {
		clause = trim(clause);
		if (!*clause) continue;

		char *eq = strchr(clause, '=');
		if (!eq) die("clause has no '=': %s", clause);
		*eq = 0;
		char *lhs = trim(clause), *rhs = trim(eq + 1);
		uint32_t act;

		if (!strcmp(lhs, "default")) {
			if (have_default) die("default given more than once");
			if (parse_action(rhs, &act) < 0)
				die("unknown action: %s", rhs);
			def_act = act;
			have_default = 1;
			continue;
		}
		if (!strcmp(lhs, "errno")) {
			char *colon = strchr(rhs, ':');
			if (!colon)
				die("errno= wants ERRNO:NAME,... but got '%s'", rhs);
			*colon = 0;
			act = SECCOMP_RET_ERRNO |
			      (uint32_t)lookup_errno(trim(rhs));
			rhs = trim(colon + 1);
		} else if (!strncmp(lhs, "errno", 5)) {
			die("write 'errno=%s:NAME,...' rather than '%s=...'",
			    lhs + 6, lhs);
		} else if (parse_action(lhs, &act) < 0) {
			die("unknown clause '%s'", lhs);
		}
		parse_list(rhs, act);
	}
	if (!have_default)
		die("policy has no 'default=ACTION'; refusing to guess what "
		    "every unlisted syscall should do");

	/*
	 * Refuse an action this kernel does not implement, because the kernel
	 * will not: an unrecognised return value is treated as the lowest
	 * action, KILL_THREAD, so the filter would be installed and would do
	 * something other than what the policy says.
	 */
	if (!action_avail(def_act & SECCOMP_RET_ACTION_FULL))
		die("this kernel has no %s action (see --actions)",
		    action_name(def_act));
	for (int i = 0; i < nrule; i++)
		if (!action_avail(rules[i].act & SECCOMP_RET_ACTION_FULL))
			die("this kernel has no %s action, wanted for %s "
			    "(see --actions)",
			    action_name(rules[i].act), rules[i].name);
}

/* ----------------------------------------------------------------- emit --- */

/*
 * The filter. Fixed shape, and the order of the first two instructions is the
 * entire security of the thing:
 *
 *   ld   [arch]
 *   jeq  AUDIT_ARCH_X86_64 -> on past the kill
 *   ret  KILL_PROCESS
 *   ld   [nr]
 *   jgt  0x3fffffff -> fall into the kill
 *   ret  KILL_PROCESS
 *   (per rule)  jeq nr -> fall into its ret ; ret ACTION
 *   ret  DEFAULT
 *
 * Why the arch check comes first, and why a filter without it is broken
 * rather than merely sloppy: seccomp_data.nr is a number in the syscall table
 * of whichever entry point the process used, and x86-64 kernels keep three of
 * those. The numbers do not agree. x86-64 nr 102 is getuid; i386 nr 102 is
 * socketcall, through which every socket operation is reachable. So a filter
 * that matches nr without pinning arch and which allows getuid has also
 * allowed any 32-bit process to open a socket -- by doing nothing more exotic
 * than `int $0x80` with eax=102. That is not theoretical here: t/try32 does
 * exactly that, and the suite drives it.
 *
 * The second check exists because pinning arch is not sufficient on its own.
 * The x32 ABI reports AUDIT_ARCH_X86_64 as well, and marks itself by setting
 * bit 30 of nr, so after the arch check an x32 call still arrives with a
 * number from a third table. One unsigned compare handles that and a second
 * problem at the same time: nr is a signed int, so a negative syscall number
 * loads as a huge unsigned value and is also caught. Anything at or above
 * 0x40000000 is killed rather than defaulted, because we cannot say what it
 * means.
 *
 * Two instructions per rule, with every jump offset 0 or 1, rather than one
 * comparison per rule jumping forward to a shared return. The offsets in
 * classic BPF are 8-bit, so the shared-return layout has a maximum distance
 * and needs a check that the program did not outgrow it. This layout cannot
 * overflow a jump by construction, and 2N+7 <= BPF_MAXINSNS leaves room for
 * 2044 rules against the ~360 syscalls that exist -- so the shorter encoding
 * could never pay for the arithmetic it would need.
 */
static struct sock_filter *emit(int *out_n) {
	int n = 0, cap = 2 * nrule + 7;
	struct sock_filter *f = xmalloc((size_t)cap * sizeof *f);

	f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    (uint32_t)offsetof(struct seccomp_data, arch));
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
	    AUDIT_ARCH_X86_64, 1, 0);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);

	f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    (uint32_t)offsetof(struct seccomp_data, nr));
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K,
	    (uint32_t)(__X32_SYSCALL_BIT - 1), 0, 1);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);

	for (int i = 0; i < nrule; i++) {
		f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		    (uint32_t)rules[i].nr, 0, 1);
		f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
		    rules[i].act);
	}
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, def_act);

	if (n > BPF_MAXINSNS)
		die("filter is %d instructions, over the kernel's limit of %d",
		    n, BPF_MAXINSNS);
	*out_n = n;
	return f;
}

/*
 * The on-disk form is the in-memory form: a bare array of struct sock_filter,
 * native byte order, nothing else. No header and no magic, on purpose -- it
 * is the exact buffer that goes to the kernel, so there is no step between
 * "what -c wrote" and "what -a installs" that could differ. A file is valid
 * if and only if its size is a whole number of instructions.
 */
static void write_filter(const char *path, const struct sock_filter *f, int n) {
	FILE *fp = fopen(path, "wb");
	if (!fp) die("%s: %s", path, strerror(errno));
	if (fwrite(f, sizeof *f, (size_t)n, fp) != (size_t)n)
		die("%s: short write", path);
	if (fclose(fp) != 0) die("%s: %s", path, strerror(errno));
}

int main(int argc, char **argv) {
	if (argv[0]) prog = argv[0];

	if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage(stdout);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--actions")) return print_actions();

	if (argc >= 2 && !strcmp(argv[1], "-c")) {
		struct sock_filter *f;
		int n;
		if (argc != 5 || strcmp(argv[3], "-o"))
			die("usage: %s -c POLICY -o FILE", prog);
		parse_policy(argv[2]);
		f = emit(&n);
		write_filter(argv[4], f, n);
		free(f);
		return 0;
	}

	usage(stderr);
	return 125;
}
