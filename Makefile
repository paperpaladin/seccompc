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

all: seccompc t/try t/try32

seccompc: seccompc.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

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

test: all
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

test-asan: t/try t/try32
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=. \
		-o seccompc-asan seccompc.c
	@$(SANOPT) t/run.sh ./seccompc-asan

clean:
	rm -f seccompc seccompc-asan t/try t/try32
	rm -rf t/tmp

.PHONY: all test test-asan clean
