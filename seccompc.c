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

static const char *prog = "seccompc";

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
 * action entirely (SECCOMP_RET_KILL_PROCESS arrived in 4.14, LOG in 4.14,
 * USER_NOTIF in 5.0), and asking is the difference between a tool that
 * degrades and one that installs a filter whose verdict is not what the
 * caller asked for. /proc/sys/kernel/seccomp/actions_avail is the readable
 * form of the same answer, but it is absent on a kernel without
 * CONFIG_SECCOMP_FILTER at all, so we ask the syscall.
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

int main(int argc, char **argv) {
	if (argv[0]) prog = argv[0];

	if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage(stdout);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--actions")) return print_actions();

	usage(stderr);
	return 125;
}
