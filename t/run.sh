#!/bin/sh
# The oracle. Every assertion below is a real syscall made by a real process
# under a real filter, and the thing asserted is the kernel's own verdict:
# exit 0 means the call succeeded, any other number is the errno the kernel
# returned, and 159 means it died of SIGSYS. strace is a second witness where
# one is available. Nothing here reads seccompc's internal state, and the two
# places that read its output say so.
#
# Usage: t/run.sh [./seccompc]   (test-asan passes the sanitized binary)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SC=${1:-$ROOT/seccompc}
TRY=$ROOT/t/try
TRY32=$ROOT/t/try32

# A denied syscall under kill/trap dumps core by default, and this suite
# produces dozens of them. Nothing here reads a core file.
ulimit -c 0 2>/dev/null

# Nothing in this suite should take seconds, but other work may be running on
# this machine, so the bound is generous. It is a safety net against a wedged
# child, never an assertion about speed.
TO="timeout 60"

pass=0; fail=0; skip=0

ok()   { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"
         shift; printf '%s\n' "$@" | sed 's/^/      | /'; }
skipt(){ skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }

# Dozens of assertions below expect death by SIGSYS, and the shell announces
# every one of them ("Bad system call") on ITS stderr, not the command's. The
# trailing 2>/dev/null on the assignment silences the announcement while the
# inner redirection still captures the command's own output.

# t NAME WANT_STATUS -- CMD...  assert the exit status of CMD
t() {
	_n=$1; _w=$2; shift 3
	_o=$( { "$@" ; } 2>&1 ) 2>/dev/null; _s=$?
	if [ "$_s" -eq "$_w" ]; then ok "$_n"
	else bad "$_n" "want status $_w, got $_s" "$_o"; fi
}

# tout NAME WANT_STATUS WANT_STDOUT -- CMD...  assert status AND exact stdout
tout() {
	_n=$1; _w=$2; _e=$3; shift 4
	_o=$( { "$@" ; } 2>/dev/null ) 2>/dev/null; _s=$?
	if [ "$_s" -eq "$_w" ] && [ "$_o" = "$_e" ]; then ok "$_n"
	else bad "$_n" "want status $_w stdout [$_e]" \
	              "got  status $_s stdout [$_o]"; fi
}

# grepped NAME PATTERN FILE   assert PATTERN appears in FILE
grepped() {
	if grep -qF "$2" "$3"; then ok "$1"
	else bad "$1" "no line matching: $2" "$(sed -n '1,8p' "$3")"; fi
}

[ -x "$SC" ] && [ -x "$TRY" ] || { echo "run 'make' first" >&2; exit 2; }

# --- is seccomp filtering actually here? skip loudly, never silently pass ---
avail=$("$SC" --actions 2>/dev/null)
if [ -z "$avail" ]; then
	echo "seccomp filtering is not available on this kernel ($(uname -r))."
	echo "Either CONFIG_SECCOMP_FILTER=n or there is no seccomp(2) at all."
	echo "Every assertion in this suite needs the kernel as the oracle, so"
	echo "they are SKIPPED, not passed."
	for n in allowed-works denied-errno kill-sigsys trap-sigsys \
	         trap-catchable log-allows inherit-fork inherit-exec \
	         cannot-unsandbox arch-bypass-closed x32-closed \
	         transparency malformed-refused; do
		skipt "$n" "no seccomp filtering"
	done
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 0
fi
echo "seccomp actions: $avail"
echo "on $(uname -r), filter binary $SC"
echo

TD=$(mktemp -d) || exit 2
trap 'rm -rf "$TD"' EXIT INT TERM

# The probe is freestanding, so these three are the entire cost of running it:
# exec itself, write its one report line, and leave.
BASE=execve,write,exit_group

# ===========================================================================
# 0. --actions against the kernel's own readable copy of the same answer
# ===========================================================================
# Independent in the only sense available: the proc file is produced by a
# different piece of kernel code than SECCOMP_GET_ACTION_AVAIL, and nothing in
# seccompc reads it.
PROCAV=/proc/sys/kernel/seccomp/actions_avail
if [ -r "$PROCAV" ]; then
	want=$(cat "$PROCAV")
	if [ "$avail" = "$want" ]; then ok '--actions agrees with the proc file'
	else bad '--actions agrees with the proc file' \
	         "ours [$avail]" "kernel [$want]"; fi
else
	skipt '--actions agrees with the proc file' "no $PROCAV"
fi

# ===========================================================================
# 1. allowed syscalls still work
# ===========================================================================
# This group is the floor under every "is it denied" assertion below. A filter
# that denies everything makes denial trivially true, so each denial has to sit
# next to a call that still goes through on the same kernel under a policy of
# the same shape.
P_OK="default=errno:ENOSYS; allow=$BASE,getuid,geteuid,getgid,getpid,gettid,sched_yield"
t 'allowed getuid works'       0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call getuid
t 'allowed geteuid works'      0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call geteuid
t 'allowed getgid works'       0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call getgid
t 'allowed getpid works'       0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call getpid
t 'allowed gettid works'       0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call gettid
t 'allowed sched_yield works'  0  -- $TO "$SC" -a "$P_OK" -- "$TRY" call sched_yield
# And the same policy denies the one call it did not list.
t 'unlisted socket gets the default' 38 -- $TO "$SC" -a "$P_OK" -- "$TRY" call socket

# ===========================================================================
# 2. a denied syscall fails with EXACTLY the errno the policy named
# ===========================================================================
# socket() with these arguments cannot fail on this machine -- unfiltered it
# returns a descriptor -- so the errno observed is the filter's and nothing
# else's. "It failed" would be a far weaker claim than any line here.
for pair in EPERM:1 EACCES:13 ENOSYS:38 ENETUNREACH:101 EOPNOTSUPP:95; do
	e=${pair%:*}; v=${pair#*:}
	t "errno=$e:socket gives errno $v" "$v" -- $TO "$SC" \
	    -a "default=allow; errno=$e:socket" -- "$TRY" call socket
done
# A decimal errno, for anything the name table does not carry.
t 'errno=7:socket gives errno 7'  7 -- $TO "$SC" \
    -a "default=allow; errno=7:socket" -- "$TRY" call socket
# The default action reaches an unlisted call just as a clause does.
t 'default=errno:EPERM reaches socket'  1 -- $TO "$SC" \
    -a "default=errno:EPERM; allow=$BASE" -- "$TRY" call socket
# Two different errnos in one policy, to show the per-rule return is per rule
# and not one value shared by the whole filter.
P_TWO="default=errno:ENOSYS; allow=$BASE,getuid; errno=EPERM:socket; errno=EACCES:geteuid"
t 'two errnos in one filter: EPERM'   1 -- $TO "$SC" -a "$P_TWO" -- "$TRY" call socket
t 'two errnos in one filter: EACCES' 13 -- $TO "$SC" -a "$P_TWO" -- "$TRY" call geteuid
t 'two errnos in one filter: default' 38 -- $TO "$SC" -a "$P_TWO" -- "$TRY" call getgid
t 'two errnos in one filter: allowed'  0 -- $TO "$SC" -a "$P_TWO" -- "$TRY" call getuid

# ===========================================================================
# 3. kill means SIGSYS, which is 128+31 = 159
# ===========================================================================
t 'default=kill: dies of SIGSYS'    159 -- $TO "$SC" \
    -a "default=kill; allow=$BASE,getuid" -- "$TRY" call socket
t 'default=kill: allowed still runs'  0 -- $TO "$SC" \
    -a "default=kill; allow=$BASE,getuid" -- "$TRY" call getuid
t 'kill= clause: dies of SIGSYS'    159 -- $TO "$SC" \
    -a "default=allow; kill=socket" -- "$TRY" call socket
t 'kill_thread= clause: SIGSYS'     159 -- $TO "$SC" \
    -a "default=allow; kill_thread=socket" -- "$TRY" call socket
# kill_process and kill_thread differ only in how much of a multi-threaded
# process they take down. The probe has one thread, so this suite cannot tell
# them apart, and says so rather than inventing an assertion.
skipt 'kill_process differs from kill_thread' \
      'the probe is single-threaded, so both are the same death'

# ===========================================================================
# 4. trap raises SIGSYS too, and unlike kill it is catchable
# ===========================================================================
# The pair is the assertion. Same action, same syscall, same kernel: without a
# handler the process dies, with one it does not. Neither line alone says
# anything about SIGSYS being deliverable to userspace.
P_TRAP="default=errno:ENOSYS; allow=$BASE,rt_sigaction; trap=socket"
t 'trap with no handler: SIGSYS'    159 -- $TO "$SC" -a "$P_TRAP" -- "$TRY" call socket
t 'trap with a handler: caught'      99 -- $TO "$SC" -a "$P_TRAP" -- "$TRY" trap socket
# And the part that makes kill different from trap rather than just louder:
# the identical handler cannot catch a kill.
P_KILLH="default=errno:ENOSYS; allow=$BASE,rt_sigaction; kill=socket"
t 'kill is not catchable'           159 -- $TO "$SC" -a "$P_KILLH" -- "$TRY" trap socket

# ===========================================================================
# 5. log allows the call; it is not a quiet denial
# ===========================================================================
t 'log= lets the call through'        0 -- $TO "$SC" \
    -a "default=errno:ENOSYS; allow=$BASE; log=socket" -- "$TRY" call socket
t 'default=log lets everything through' 0 -- $TO "$SC" \
    -a "default=log" -- "$TRY" call socket

# ===========================================================================
# 6. strace as an independent witness
# ===========================================================================
# Where strace and this program disagree about what the kernel did, this
# program is wrong. strace sees the syscall and its return value through
# ptrace, with no knowledge of the policy.
if command -v strace >/dev/null 2>&1; then
	strace -f -o "$TD/s1" $TO "$SC" \
	    -a "default=allow; errno=EPERM:socket" -- "$TRY" call socket \
	    >/dev/null 2>&1
	grepped 'strace sees socket return EPERM' \
	    'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = -1 EPERM' "$TD/s1"
	strace -f -o "$TD/s2" $TO "$SC" \
	    -a "default=allow; errno=ENOSYS:socket" -- "$TRY" call socket \
	    >/dev/null 2>&1
	grepped 'strace sees the errno change to ENOSYS' \
	    'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = -1 ENOSYS' "$TD/s2"
	# The install sequence itself, witnessed rather than claimed.
	grepped 'strace sees PR_SET_NO_NEW_PRIVS first' \
	    'prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0' "$TD/s2"
	grepped 'strace sees SECCOMP_SET_MODE_FILTER' \
	    'seccomp(SECCOMP_SET_MODE_FILTER, 0,' "$TD/s2"
	# Anti-vacuity, measured rather than assumed: a filtered run has to have
	# actually executed syscalls. A filter that stopped the process before it
	# made any would satisfy every denial assertion above for free.
	nsys=$(grep -cE '[a-z_0-9]+\(.*\) +=' "$TD/s2")
	if [ "$nsys" -gt 10 ]; then
		ok "strace counted $nsys syscalls under the filter"
	else
		bad 'strace counted syscalls under the filter' \
		    "only $nsys syscall lines; the denials above may be vacuous"
	fi
	# The kernel echoes the program length back to strace, which is an
	# outside check on the instruction count -d reports.
	klen=$(sed -n 's/.*SECCOMP_SET_MODE_FILTER, 0, {len=\([0-9]*\),.*/\1/p' \
	       "$TD/s2" | head -1)
	"$SC" -c "default=allow; errno=ENOSYS:socket" -o "$TD/len.bpf" 2>/dev/null
	dlen=$("$SC" -d "$TD/len.bpf" 2>/dev/null | wc -l | tr -d ' ')
	if [ -n "$klen" ] && [ "$klen" = "$dlen" ]; then
		ok "kernel and -d agree the filter is $klen instructions"
	else
		bad 'kernel and -d agree on the instruction count' \
		    "kernel said [$klen], -d printed [$dlen] lines"
	fi
else
	for n in 'strace sees socket return EPERM' \
	         'strace sees the errno change to ENOSYS' \
	         'strace sees PR_SET_NO_NEW_PRIVS first' \
	         'strace sees SECCOMP_SET_MODE_FILTER' \
	         'strace counted syscalls under the filter' \
	         'kernel and -d agree on the instruction count'; do
		skipt "$n" 'strace not installed'
	done
fi

# ===========================================================================
# 7. the filter is inherited, by children and by exec
# ===========================================================================
P_INH="default=errno:ENOSYS; allow=$BASE,getuid,clone,wait4"
t 'forked child is still filtered'   38 -- $TO "$SC" -a "$P_INH" -- "$TRY" fork socket
t 'forked child keeps what is allowed' 0 -- $TO "$SC" -a "$P_INH" -- "$TRY" fork getuid
t 'exec inherits the filter'         38 -- $TO "$SC" -a "$P_INH" -- \
    "$TRY" exec "$TRY" call socket
t 'exec keeps what is allowed'        0 -- $TO "$SC" -a "$P_INH" -- \
    "$TRY" exec "$TRY" call getuid
t 'grandchild via exec then fork'    38 -- $TO "$SC" -a "$P_INH" -- \
    "$TRY" exec "$TRY" fork socket

# ===========================================================================
# 8. the filtered process cannot remove or widen its own filter
# ===========================================================================
# The escape policy deliberately ALLOWS prctl and seccomp, so every attempt
# below is really made rather than denied at the door. If any of them worked,
# this tool would be worthless.
P_ESC="default=errno:ENOSYS; allow=$BASE,getuid,prctl,seccomp"
t 'cannot unsandbox itself'          38 -- $TO "$SC" -a "$P_ESC" -- \
    "$TRY" escape socket
t 'and allowed calls still work after trying' 0 -- $TO "$SC" -a "$P_ESC" -- \
    "$TRY" escape getuid
$TO "$SC" -a "$P_ESC" -- "$TRY" escape socket > "$TD/esc" 2>&1
# The transcript is proof the attempts happened: installing a permissive filter
# of its own must SUCCEED. If that line said errno, the escape test would be
# passing because the attempt was blocked rather than because it was futile.
grepped 'the permissive self-filter really installed' \
    'ret ALLOW) -- a filter of its own -> success' "$TD/esc"
grepped 'and PR_GET_SECCOMP still reports mode 2' \
    'PR_GET_SECCOMP) reports mode 2' "$TD/esc"
printf '      --- escape attempt transcript ---\n'
sed 's/^/      | /' "$TD/esc"

# ===========================================================================
# 9. the 32-bit bypass is closed, driven through the real i386 entry point
# ===========================================================================
# x86-64 syscall 102 is getuid. i386 syscall 102 is socketcall, through which
# every socket operation is reachable. A filter that compares seccomp_data.nr
# without first pinning seccomp_data.arch cannot tell those apart, so a policy
# permitting getuid would also permit any 32-bit caller to open a socket.
P_102="default=errno:ENOSYS; allow=$BASE,getuid"
if [ -x "$TRY32" ]; then
	# The control. Unfiltered, the 32-bit probe really does get a socket;
	# without this line the assertion below could pass because -m32 produced
	# something that cannot run at all.
	t 'control: i386 socketcall works unfiltered'  0 -- $TO "$TRY32"
	# Native nr 102 is permitted by this very policy, on this very kernel.
	t 'control: nr 102 is allowed natively'        0 -- $TO "$SC" \
	    -a "$P_102" -- "$TRY" call getuid
	# And through the i386 door the same number is killed, not allowed.
	t 'i386 nr 102 is killed, not allowed'       159 -- $TO "$SC" \
	    -a "$P_102" -- "$TRY32"
	# Even a policy that allows everything: a foreign arch is not something
	# the policy gets a say in, because its numbers mean something else.
	t 'default=allow still kills a foreign arch' 159 -- $TO "$SC" \
	    -a 'default=allow' -- "$TRY32"
else
	for n in 'control: i386 socketcall works unfiltered' \
	         'control: nr 102 is allowed natively' \
	         'i386 nr 102 is killed, not allowed' \
	         'default=allow still kills a foreign arch'; do
		skipt "$n" 'no -m32 toolchain, so t/try32 was not built'
	done
fi

# The x32 ABI reports AUDIT_ARCH_X86_64 and marks itself with bit 30 of nr, so
# it slips through an arch check alone. Driven from the 64-bit probe by setting
# the bit in rax, which is what an x32 binary's calls look like to seccomp.
t 'the x32 bit is killed, not defaulted'    159 -- $TO "$SC" \
    -a 'default=allow' -- "$TRY" x32 getuid
t 'and allowed without the bit, same policy'  0 -- $TO "$SC" \
    -a 'default=allow' -- "$TRY" call getuid
# A negative syscall number loads as a huge unsigned word, which the same
# compare catches. Unfiltered the kernel answers ENOSYS; filtered it is a kill,
# which is the deliberate difference.
t 'control: nr -1 is ENOSYS unfiltered'      38 -- $TO "$TRY" neg getuid
t 'nr -1 is killed under a filter'          159 -- $TO "$SC" \
    -a 'default=allow' -- "$TRY" neg getuid

# ===========================================================================
# 10. transparency: the filter changes nothing a policy did not name
# ===========================================================================
# A real dynamically linked program, so the loader runs under the filter too.
# The policy names fchmodat as well as chmod, and the next-but-one assertion is
# why: see the pair at the end of this section.
P_SH='default=allow; errno=EPERM:chmod,fchmodat'
tout 'exit status 0 passes through'   0 'hi' -- $TO "$SC" -a "$P_SH" -- \
    /bin/sh -c 'echo hi'
tout 'exit status 42 passes through' 42 ''   -- $TO "$SC" -a "$P_SH" -- \
    /bin/sh -c 'exit 42'
tout 'stdout exact, no seccompc noise' 0 'a
b' -- $TO "$SC" -a "$P_SH" -- /bin/sh -c 'echo a; echo b'
tout 'stderr is not merged into stdout' 0 'O' -- $TO "$SC" -a "$P_SH" -- \
    /bin/sh -c 'echo O; echo E >&2'
_o=$(printf 'abc' | $TO "$SC" -a "$P_SH" -- /bin/cat 2>/dev/null)
[ "$_o" = abc ] && ok 'stdin passes through' \
	|| bad 'stdin passes through' "got [$_o]"
{ $TO "$SC" -a "$P_SH" -- /bin/sh -c 'kill -TERM $$'; } 2>/dev/null
_s=$?
[ "$_s" -eq 143 ] && ok 'signal death passes through' \
	|| bad 'signal death passes through' "got $_s"
# The one operation this policy does name, reported by a program that has never
# heard of seccompc, in its own words.
tout 'a real program reports the errno we chose' 0 'rc=1' -- \
    $TO "$SC" -a "$P_SH" -- /bin/sh -c \
    "chmod 700 $TD 2>/dev/null; echo rc=\$?"
# And the same command unfiltered, so the line above is about the policy rather
# than about chmod being unable to work here at all.
tout 'and succeeds when the policy allows it'    0 'rc=0' -- \
    $TO "$SC" -a 'default=allow' -- /bin/sh -c \
    "chmod 700 $TD 2>/dev/null; echo rc=\$?"
# The trap that caught this harness first time round, now an assertion rather
# than a comment. A policy names SYSCALLS, not libc functions, and coreutils
# chmod(1) does not use the chmod(2) syscall -- glibc routes it through
# fchmodat(2). So denying 'chmod' alone changes nothing, and a reader who
# believes otherwise has a policy full of holes shaped exactly like this.
tout 'denying chmod alone does NOT stop chmod(1)' 0 'rc=0' -- \
    $TO "$SC" -a 'default=allow; errno=EPERM:chmod' -- /bin/sh -c \
    "chmod 700 $TD 2>/dev/null; echo rc=\$?"

# ===========================================================================
# 11. the emitted filter has the arch check before the nr comparison
# ===========================================================================
# WEAKEST ORACLE IN THIS FILE. Both the emitter and the disassembler are ours,
# so a shared misunderstanding passes. It is here to catch a regression in the
# instruction order, and the thing that actually establishes the arch check
# works is section 9, where the kernel decides.
checkorder() {
	"$SC" -c "$1" -o "$TD/o.bpf" 2>"$TD/o.err" || {
		bad "$2" "compile failed" "$(cat "$TD/o.err")"; return
	}
	"$SC" -d "$TD/o.bpf" > "$TD/o.txt" 2>&1 || {
		bad "$2" "disassembly failed" "$(cat "$TD/o.txt")"; return
	}
	_r=$(awk '
	  NR == 1 && ($2 != "ld" || $3 != "[4]") {
	    print "insn 0 is [" $2 " " $3 "], not a load of seccomp_data.arch"; exit }
	  NR == 2 && ($2 != "jeq" || $3 != "#0xc000003e") {
	    print "insn 1 does not compare against AUDIT_ARCH_X86_64"; exit }
	  NR == 3 && ($2 != "ret" || $3 != "#0x80000000") {
	    print "an arch mismatch does not return KILL_PROCESS"; exit }
	  $3 == "[0]" && !nrld { nrld = NR }
	  $2 == "jgt" && $3 == "#0x3fffffff" && !x32 { x32 = NR }
	  END {
	    if (!nrld) { print "nothing ever loads seccomp_data.nr"; exit }
	    if (nrld < 4) { print "seccomp_data.nr is loaded at insn " (nrld-1) \
	                          ", before the arch check is complete"; exit }
	    if (!x32) { print "no range check on nr, so the x32 bit is unguarded"; exit }
	    if (x32 != nrld + 1) { print "the nr range check is not adjacent to the nr load"; exit }
	  }' "$TD/o.txt")
	[ -z "$_r" ] && ok "$2" || bad "$2" "$_r" "$(sed -n '1,6p' "$TD/o.txt")"
}
checkorder "default=kill; allow=$BASE" 'arch check precedes nr (small policy)'
checkorder 'default=allow' 'arch check precedes nr (no rules at all)'
checkorder "default=errno:EPERM; allow=$BASE,getuid; kill=socket; trap=chmod" \
    'arch check precedes nr (mixed actions)'

# A round trip, labelled for what it is worth: both sides are ours, so this
# catches regressions and establishes nothing.
"$SC" -c "default=kill; allow=$BASE,read,getuid" -o "$TD/r1.bpf"
t 'round trip: -d accepts what -c emits'  0 -- "$SC" -d "$TD/r1.bpf"
"$SC" -d "$TD/r1.bpf" > "$TD/r1.txt"
grepped 'round trip: the syscall names come back' '; getuid' "$TD/r1.txt"
grepped 'round trip: the default action is named' \
    '; kill_process' "$TD/r1.txt"
# Determinism, which is what makes the build reproducible and the file
# diffable.
"$SC" -c "default=kill; allow=$BASE,read,getuid" -o "$TD/r2.bpf"
cmp -s "$TD/r1.bpf" "$TD/r2.bpf" && ok 'the same policy compiles to the same bytes' \
	|| bad 'the same policy compiles to the same bytes' 'files differ'

# ===========================================================================
# 12. a malformed filter file is refused, never crashed on
# ===========================================================================
# -d reads bytes someone else wrote. Each of these exits 125 with a message on
# stderr, and under test-asan each of them also has to not read out of bounds.
printf '' > "$TD/m-empty.bpf"
head -c 12 "$TD/r1.bpf" > "$TD/m-trunc.bpf"
head -c 1  "$TD/r1.bpf" > "$TD/m-byte.bpf"
# 4097 instructions' worth of bytes, one past BPF_MAXINSNS. The content does
# not matter: the length is checked before anything is decoded, which is the
# order that keeps a huge file from being read into memory first.
head -c 32776 /dev/zero > "$TD/m-long.bpf"
# jeq k=41 with jt=80, in a two-instruction program: a jump past the end.
printf '\025\000\120\000\051\000\000\000\006\000\000\000\000\000\377\177' \
	> "$TD/m-jump.bpf"
# ends with a comparison rather than a return
printf '\040\000\000\000\004\000\000\000\025\000\000\000\001\000\000\000' > "$TD/m-noret.bpf"
# opcode 0x00ff is not a classic-BPF instruction
printf '\377\000\000\000\000\000\000\000\006\000\000\000\000\000\377\177' > "$TD/m-op.bpf"
# absolute load at offset 9999, far outside seccomp_data
printf '\040\000\000\000\017\047\000\000\006\000\000\000\000\000\377\177' > "$TD/m-oob.bpf"
# store into scratch slot 99, of which there are BPF_MEMWORDS = 16
printf '\002\000\000\000\143\000\000\000\006\000\000\000\000\000\377\177' > "$TD/m-mem.bpf"
# divide by the constant zero, which the kernel refuses outright
printf '\064\000\000\000\000\000\000\000\006\000\000\000\000\000\377\177' > "$TD/m-div.bpf"

t 'reject: zero-length file'         125 -- "$SC" -d "$TD/m-empty.bpf"
t 'reject: one stray byte'           125 -- "$SC" -d "$TD/m-byte.bpf"
t 'reject: truncated instruction'    125 -- "$SC" -d "$TD/m-trunc.bpf"
t 'reject: past BPF_MAXINSNS'        125 -- "$SC" -d "$TD/m-long.bpf"
t 'reject: jump past the end'        125 -- "$SC" -d "$TD/m-jump.bpf"
t 'reject: no terminating return'    125 -- "$SC" -d "$TD/m-noret.bpf"
t 'reject: unknown opcode'           125 -- "$SC" -d "$TD/m-op.bpf"
t 'reject: load outside seccomp_data' 125 -- "$SC" -d "$TD/m-oob.bpf"
t 'reject: scratch slot out of range' 125 -- "$SC" -d "$TD/m-mem.bpf"
t 'reject: divide by constant zero'  125 -- "$SC" -d "$TD/m-div.bpf"
t 'reject: file does not exist'      125 -- "$SC" -d "$TD/nosuch.bpf"
t 'reject: a directory is not a filter' 125 -- "$SC" -d "$TD"
# Each refusal has to say something. A silent nonzero exit is not a diagnostic,
# and a refusal whose message does not name the problem sends the reader to the
# wrong place.
silent=
for f in m-empty m-byte m-trunc m-long m-jump m-noret m-op m-oob m-mem m-div; do
	_e=$("$SC" -d "$TD/$f.bpf" 2>&1 >/dev/null)
	[ -n "$_e" ] || silent="$silent $f"
done
[ -z "$silent" ] && ok 'every refusal prints a reason' \
	|| bad 'every refusal prints a reason' "silent for:$silent"
# One message checked for content rather than existence, since "too long" is
# the refusal most likely to be mistaken for "truncated".
case $("$SC" -d "$TD/m-long.bpf" 2>&1 >/dev/null) in
*limit*4096*) ok 'reject: the length message names the kernel limit' ;;
*) bad 'reject: the length message names the kernel limit' \
       "got: $("$SC" -d "$TD/m-long.bpf" 2>&1 >/dev/null)" ;;
esac
# And the positive control: a valid filter of exactly one instruction.
printf '\006\000\000\000\000\000\377\177' > "$TD/one.bpf"
t 'accept: a one-instruction ret ALLOW' 0 -- "$SC" -d "$TD/one.bpf"

# ===========================================================================
# 13. seccompc fails closed on its own mistakes, always with 125
# ===========================================================================
t 'no default= is refused'       125 -- "$SC" -c "allow=$BASE" -o "$TD/z"
t 'unknown action is refused'    125 -- "$SC" -c 'default=bogus' -o "$TD/z"
t 'unknown clause is refused'    125 -- "$SC" -c 'default=kill; nope=read' -o "$TD/z"
t 'clause with no = is refused'  125 -- "$SC" -c 'default=kill; allow' -o "$TD/z"
t 'unknown syscall is refused'   125 -- "$SC" -c 'default=kill; allow=frobnicate' \
                                         -o "$TD/z"
t 'unknown errno is refused'     125 -- "$SC" -c 'default=errno:EWOBBLE' -o "$TD/z"
t 'errno 0 is refused'           125 -- "$SC" -c 'default=errno:0' -o "$TD/z"
t 'errno past MAX_ERRNO refused' 125 -- "$SC" -c 'default=errno:4096' -o "$TD/z"
t 'the same syscall twice is refused' 125 -- "$SC" \
    -c 'default=kill; allow=read; errno=EPERM:read' -o "$TD/z"
t 'empty syscall list is refused' 125 -- "$SC" -c 'default=kill; allow=' -o "$TD/z"
t 'errno= without a colon refused' 125 -- "$SC" -c 'default=kill; errno=EPERM' \
                                          -o "$TD/z"
t 'syscall number out of range refused' 125 -- "$SC" \
    -c 'default=kill; allow=1073741824' -o "$TD/z"
t 'errno:NAME= on the left is refused' 125 -- "$SC" \
    -c 'default=kill; errno:EPERM=read' -o "$TD/z"
t '-c without -o is refused'     125 -- "$SC" -c 'default=kill'
t '-d with no file is refused'   125 -- "$SC" -d
t 'no -- before CMD is refused'  125 -- "$SC" -a 'default=allow' /bin/true
t 'no CMD after -- is refused'   125 -- "$SC" -a 'default=allow' --
t 'unknown mode is refused'      125 -- "$SC" --frobnicate
# Fail closed in the direction that matters: a policy that cannot start the
# command must not start it unconfined.
t 'a policy denying execve is refused' 125 -- "$SC" \
    -a "default=kill; allow=write" -- /bin/true
t 'exec of a missing command is 127'   127 -- "$SC" \
    -a "default=allow" -- /nonexistent-aaaa
t 'exec of a non-PATH name is 127'     127 -- "$SC" \
    -a "default=allow" -- zzz-not-a-command
t 'exec of a non-executable is 126'    126 -- "$SC" \
    -a "default=allow" -- "$TD/r1.bpf"
# A decimal syscall number is accepted where a name would be, which is the
# escape hatch for anything outside the name table. 102 is getuid.
t 'a decimal syscall number works'       0 -- $TO "$SC" \
    -a "default=errno:ENOSYS; allow=$BASE,102" -- "$TRY" call getuid
# ... and 102 is not a magic word: the same number under a denying policy.
t 'and the same number can be denied'   38 -- $TO "$SC" \
    -a "default=errno:ENOSYS; allow=$BASE; errno=ENOSYS:102" -- "$TRY" call getuid
# Whitespace and a trailing separator are tolerated, because a policy is
# something people type.
t 'whitespace and a trailing ; are fine'  0 -- $TO "$SC" \
    -a " default = errno:ENOSYS ; allow = execve , write , exit_group , getuid ; " \
    -- "$TRY" call getuid

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
