CC      ?= gcc
# -ffile-prefix-map is not a style choice: with -g and without it, gcc writes
# $(CURDIR) into .debug_line_str and two builds in two directories differ.
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -ffile-prefix-map=$(CURDIR)=.
LDFLAGS ?=

# The probe is freestanding: no libc, no dynamic loader, its own _start, every
# syscall by hand. That is the whole reason the oracle is sharp. A probe linked
# against glibc drags in a startup sequence (brk, arch_prctl, set_tid_address,
# rseq, mmap, ...) that every test policy would then have to allow, so "the
# allowed syscalls still work" would be partly an accident of a broad
# allowlist, and a glibc upgrade could change the set under us.
PCFLAGS = -std=c11 -O1 -Wall -Wextra -nostdlib -nostartfiles -static -no-pie \
          -ffreestanding -fno-stack-protector -fno-builtin \
          -ffile-prefix-map=$(CURDIR)=.

all: seccompc t/try t/try32 t/tryx32

seccompc: seccompc.c syscalls.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# The syscall name table, from the kernel's own uapi header rather than
# curated by hand. The curated version had 177 of the 375 names this header
# knows, and the escape hatch for the rest was a decimal number, so no policy
# was inexpressible, only "unknown syscall name: fchown" for a real syscall.
#
# LC_ALL=C on the sort is load-bearing, not caution: a locale-dependent
# collation makes two builds of the same tree differ, which is what
# unrepro/unrepro.py checks for across the collection.
#
# shortcut: no prerequisite, so the file is generated once and `make clean`
# is what regenerates it. The ceiling is an upgrade of kernel-headers while a
# built tree is lying around, which then keeps yesterday's names. Upgrade
# path: ask the compiler where asm/unistd.h actually is and depend on that,
# which is `echo '#include <asm/unistd.h>' | $(CC) -M -` and some trimming.
syscalls.h:
	@printf '#include <asm/unistd.h>\n' | $(CC) -E -dM - \
	  | sed -n 's/^#define __NR_\([a-z0-9_]*\)[ \t].*/X(\1)/p' \
	  | LC_ALL=C sort -u > $@
	@echo "generated $@: $$(grep -c '^X(' $@) syscall names from asm/unistd.h"

t/try: t/try.c
	$(CC) $(PCFLAGS) -o $@ $<

# The i386 probe drives the 32-bit entry point for real, which is the only way
# to prove the arch check closes the bypass rather than merely containing an
# instruction that looks like it should. Best effort: a machine with no -m32
# assembler support still builds everything else, and t/run.sh then SKIPS those
# assertions loudly instead of pretending to have made them.
t/try32: t/try.c
	@$(CC) -m32 $(PCFLAGS) -o $@ $< 2>/dev/null \
	  && echo "$(CC) -m32 ... -o $@ $<" \
	  || echo "note: no -m32 toolchain; 32-bit bypass tests will be SKIPPED" >&2

# The x32 twin. There is no x32 libc on any distribution in common use, which
# is why the README used to call an x32 toolchain the blocker here; a
# freestanding build needs none, so this compiles with the ordinary x86-64 gcc.
# Whether it can RUN is the kernel's answer: CONFIG_X86_X32_ABI=n makes execve
# return ENOEXEC and t/run.sh says so and skips, loudly. The _Static_assert in
# t/try.c is what this target buys even when the binary cannot run: it checks
# the x32 syscall bit against the kernel's uapi header, in x32 mode, rather
# than against our own belief about it.
t/tryx32: t/try.c
	@$(CC) -mx32 $(PCFLAGS) -o $@ $< 2>/dev/null \
	  && echo "$(CC) -mx32 ... -o $@ $<" \
	  || echo "note: no -mx32 toolchain; the x32 binary tests will be SKIPPED" >&2

# overread is a prerequisite, not a separate chore, because it is the only
# witness to its own property: with the shrink in read_filter reverted the
# suite below still prints 0 failed.
test: all overread
	@t/run.sh ./seccompc

# A policy parser and a filter-file reader both chew on bytes someone else
# wrote, so the same suite has to pass with the sanitizers on.
#
# exitcode=86 is load-bearing. A sanitizer abort exits 1 by default, and the
# reject tests assert a specific nonzero status -- so without this the asan
# target could report green while printing a heap overflow to stderr. That
# exact hole existed in a sibling repo (inflate) and is why this line is a
# copy of its comment rather than an invention. UBSan additionally needs
# halt_on_error, because otherwise it prints and carries on.
SANOPT = ASAN_OPTIONS=exitcode=86 \
	 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86

test-asan: t/try t/try32 t/tryx32 syscalls.h
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=. \
		-o seccompc-asan seccompc.c
	@$(SANOPT) t/run.sh ./seccompc-asan

# A buffer larger than its data turns the sanitizer off, and `-d` holds the one
# buffer here filled with bytes someone else wrote. Before the shrink in
# read_filter, a 72-byte filter file sat in a 32776-byte allocation, so a read
# one instruction past the program landed 32 KB inside a live object and ASan
# reported nothing. This target plants that read and demands a diagnostic.
#
# exitcode=86 again, for the same reason as test-asan: `-d` can exit 0 or 125
# by its own ordinary routes, so a number it cannot otherwise produce is the
# only unambiguous evidence that the sanitizer, and not the program, spoke.
overread: seccompc syscalls.h
	@mkdir -p t/tmp
	@./seccompc -c 'default=kill; allow=read,write,exit_group,execve' \
	    -o t/tmp/overread.bpf
	@$(CC) -std=c11 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		-DSECCOMPC_OVERREAD -ffile-prefix-map=$(CURDIR)=. \
		-o t/tmp/seccompc-overread seccompc.c
	@ASAN_OPTIONS=exitcode=86 t/tmp/seccompc-overread -d t/tmp/overread.bpf \
	    >/dev/null 2>t/tmp/overread.log; \
	 st=$$?; \
	 if [ $$st -eq 86 ] && grep -q heap-buffer-overflow t/tmp/overread.log; \
	 then echo "ok    overread: ASan reported the planted read"; \
	 else echo "FAIL  overread: exit $$st, no heap-buffer-overflow reported"; \
	      sed 's/^/      | /' t/tmp/overread.log | head -20; exit 1; fi

clean:
	rm -f seccompc seccompc-asan t/try t/try32 t/tryx32 syscalls.h
	rm -rf t/tmp

.PHONY: all test test-asan overread clean
