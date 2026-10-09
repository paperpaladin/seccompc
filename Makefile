CC      ?= gcc
# -ffile-prefix-map is not a style choice: with -g and without it, gcc writes
# $(CURDIR) into .debug_line_str and two builds in two directories differ.
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -ffile-prefix-map=$(CURDIR)=.
LDFLAGS ?=

all: seccompc

seccompc: seccompc.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

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

test-asan:
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=. \
		-o seccompc-asan seccompc.c
	@$(SANOPT) t/run.sh ./seccompc-asan

clean:
	rm -f seccompc seccompc-asan
	rm -rf t/tmp

.PHONY: all test test-asan clean
