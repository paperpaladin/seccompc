# seccompc

Compile a one-line policy into a seccomp-BPF filter, install it, and run a
command under it. No root, no libseccomp, no container.

```
seccompc -a 'default=kill; allow=read,write,exit_group,execve' -- ./prog
```

Everything not permitted is decided by the kernel, the filter is inherited by
every descendant, and the command cannot take it off.

## Build

```
make            # seccompc, plus the test probes t/try and t/try32
make test
make test-asan  # the same suite under -fsanitize=address,undefined
make clean
```

Pure C11, gcc, no libraries. `seccomp(2)` and `prctl(2)` are called through
`syscall(2)` directly. `strace` is used by the test harness only, and the suite
skips those assertions loudly if it is absent.

## Usage

```
seccompc -a POLICY -- CMD [ARGS...]   install the filter, then exec CMD
seccompc -c POLICY -o FILE            compile POLICY to a filter file
seccompc -d FILE                      disassemble a filter file
seccompc --actions                    the seccomp actions this kernel has
```

A POLICY is `;`-separated clauses. One of them must be `default=`.

| clause | meaning |
|---|---|
| `default=ACTION` | required: what every syscall not named below gets |
| `allow=NAME,...` | let these through |
| `kill=NAME,...` | `SIGSYS`, whole process, uncatchable |
| `kill_thread=NAME,...` | `SIGSYS`, calling thread only |
| `trap=NAME,...` | `SIGSYS`, catchable by a handler |
| `log=NAME,...` | allow, and log to the audit subsystem |
| `errno=ERRNO:NAME,...` | fail with exactly that errno |

ACTION is `allow`, `kill` (= `kill_process`), `kill_thread`, `trap`, `log` or
`errno:ERRNO`. A NAME is a syscall name or a decimal syscall number. An ERRNO
is a name such as `ENOSYS` or a decimal number in 1..4095.

```
seccompc -a 'default=errno:ENOSYS; allow=execve,write,exit_group;
             errno=EACCES:socket,connect,bind' -- ./untrusted
```

The policy **must allow `execve`**, and seccompc refuses to run if it does not.
See "what does not work". It is structural.

## What it emits

```
$ seccompc -c 'default=kill; allow=read,write,exit_group,execve;
               errno=ENOSYS:socket' -o f.bpf
$ seccompc -d f.bpf
0000  ld [4]                                       ; seccomp_data.arch
0001  jeq #0xc000003e             jt 0003 jf 0002  ; AUDIT_ARCH_X86_64
0002  ret #0x80000000                              ; kill_process
0003  ld [0]                                       ; seccomp_data.nr
0004  jgt #0x3fffffff             jt 0005 jf 0006  ; x32 bit, or a negative nr
0005  ret #0x80000000                              ; kill_process
0006  jeq #0x00000000             jt 0007 jf 0008  ; read
0007  ret #0x7fff0000                              ; allow
0008  jeq #0x00000001             jt 0009 jf 0010  ; write
0009  ret #0x7fff0000                              ; allow
0010  jeq #0x000000e7             jt 0011 jf 0012  ; exit_group
0011  ret #0x7fff0000                              ; allow
0012  jeq #0x0000003b             jt 0013 jf 0014  ; execve
0013  ret #0x7fff0000                              ; allow
0014  jeq #0x00000029             jt 0015 jf 0016  ; socket
0015  ret #0x00050026                              ; errno 38 (ENOSYS)
0016  ret #0x80000000                              ; kill_process
```

## The one line that matters

Instructions 0 to 2 are the whole security of this program, and a seccomp
filter without them is broken, not merely sloppy.

`seccomp_data.nr` is an index into the syscall table of whichever entry point
the process used, and an x86-64 kernel keeps three of those. The tables
disagree:

| number | x86-64 | i386 |
|---|---|---|
| 1 | `write` | `exit` |
| 4 | `stat` | `write` |
| 102 | `getuid` | `socketcall` |

`socketcall` is the i386 multiplexer through which `socket`, `bind`, `connect`
and the rest are reached. So a filter that compares `nr` without first pinning
`arch`, and which permits `getuid`, has thereby permitted **any 32-bit caller
to open a socket**, using nothing more exotic than `int $0x80` with
`eax=102`.

That is not a story here. `t/try32` is built from the same source with `-m32`
and does exactly that call. Unfiltered it gets a socket; under
`default=errno:ENOSYS; allow=...,getuid` it dies of `SIGSYS`. Change the arch
comparison's `jf` from 0 to 1: the one-byte version of forgetting the check,
and the same probe exits 0 with a socket in hand.

Instruction 4 exists because pinning `arch` is necessary and **not sufficient**,
which is the part usually left out. The x32 ABI reports `AUDIT_ARCH_X86_64`
too, and marks itself by setting bit 30 of `nr`, so a third syscall table
arrives through a check that looks complete. One unsigned compare handles that
and, because `nr` is a signed `int` loaded as a 32-bit word, catches a negative
syscall number at the same time. Both are driven by the suite.

## The oracle

The kernel is the authority. No mock, no stub, and nothing in the suite that
inspects seccompc's internals, with one labelled exception, below.

Every assertion is a real process making a real syscall under a real filter,
and the thing asserted is the kernel's verdict. `t/try` is a freestanding
probe: no libc, no dynamic loader, its own `_start`, every syscall through
inline asm with the kernel's negative-errno return handed straight to the exit
status. That is not minimalism for its own sake. A probe linked against glibc
drags in a startup sequence: `brk`, `arch_prctl`, `set_tid_address`,
`set_robust_list`, `rseq`, `mmap`, which every test policy would then have to
allow, so "the allowed syscalls still work" would be partly an accident of a
broad allowlist, and a glibc upgrade could change the set under the suite
without anyone touching it. Here the only syscalls that occur are `write`,
`exit_group`, and the one under test.

Ranked by how little we control them:

1. The 32-bit entry point, driven for real. Four assertions, two of them
   controls, because without them the test would pass for a `-m32` binary that
   could not run at all, or for a policy that denied 102 outright.
2. The filtered process cannot get out. Four attempts, then the denied
   syscall again. The transcript is asserted to show the permissive
   self-install *succeeding*, or this group would pass for the wrong reason.
3. The exact errno, not merely failure. `socket(AF_INET, SOCK_STREAM)`
   cannot fail on this machine, so any errno seen is the filter's.
4. `kill` / `trap` / `log` are the mechanisms claimed. `kill` is wait
   status 159 and is *not* caught by a handler that does catch `trap`.
5. `strace` as an independent witness. Where strace and this program
   disagree, this program is wrong.
6. Allowed syscalls still work, and strace counts the syscalls actually
   executed under a filter, which must exceed ten.
7. Inheritance by fork, by exec, and by a grandchild.
8. Transparency, through a real dynamically linked program.
9. Malformed filter files, twelve refusals, each also under ASan+UBSan.
10. `--actions` against `/proc/sys/kernel/seccomp/actions_avail`.
11. Disassembly round trip: the weakest oracle here, and labelled so in
    `t/run.sh` itself. Both the emitter and the disassembler are ours, so a
    shared misunderstanding passes. It catches regressions in instruction
    order and establishes nothing about correctness; item 1 is what does that.

### `make test`

```
    seccomp actions: kill_process kill_thread trap errno user_notif trace log allow
    on 7.2.8-200.fc44.x86_64, filter binary ./seccompc
    
    ok    --actions agrees with the proc file
    ok    allowed getuid works
    ok    allowed geteuid works
    ok    allowed getgid works
    ok    allowed getpid works
    ok    allowed gettid works
    ok    allowed sched_yield works
    ok    unlisted socket gets the default
    ok    errno=EPERM:socket gives errno 1
    ok    errno=EACCES:socket gives errno 13
    ok    errno=ENOSYS:socket gives errno 38
    ok    errno=ENETUNREACH:socket gives errno 101
    ok    errno=EOPNOTSUPP:socket gives errno 95
    ok    errno=7:socket gives errno 7
    ok    default=errno:EPERM reaches socket
    ok    two errnos in one filter: EPERM
    ok    two errnos in one filter: EACCES
    ok    two errnos in one filter: default
    ok    two errnos in one filter: allowed
    ok    default=kill: dies of SIGSYS
    ok    default=kill: allowed still runs
    ok    kill= clause: dies of SIGSYS
    ok    kill_thread= clause: SIGSYS
    skip  kill_process differs from kill_thread  (the probe is single-threaded, so both are the same death)
    ok    trap with no handler: SIGSYS
    ok    trap with a handler: caught
    ok    kill is not catchable
    ok    log= lets the call through
    ok    default=log lets everything through
    ok    strace sees socket return EPERM
    ok    strace sees the errno change to ENOSYS
    ok    strace sees PR_SET_NO_NEW_PRIVS first
    ok    strace sees SECCOMP_SET_MODE_FILTER
    ok    strace counted 105 syscalls under the filter
    ok    kernel and -d agree the filter is 9 instructions
    ok    forked child is still filtered
    ok    forked child keeps what is allowed
    ok    exec inherits the filter
    ok    exec keeps what is allowed
    ok    grandchild via exec then fork
    ok    cannot unsandbox itself
    ok    and allowed calls still work after trying
    ok    the permissive self-filter really installed
    ok    and PR_GET_SECCOMP still reports mode 2
          --- escape attempt transcript ---
          | note: prctl(PR_SET_NO_NEW_PRIVS, 0) -> errno 22
          | note: prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED) -> errno 22
          | note: prctl(PR_GET_SECCOMP) reports mode 2 (2 = filter)
          | note: seccomp(SET_MODE_FILTER, ret ALLOW) -- a filter of its own -> success
          | FAIL escape-then-call socket errno=38
    ok    control: i386 socketcall works unfiltered
    ok    control: nr 102 is allowed natively
    ok    i386 nr 102 is killed, not allowed
    ok    default=allow still kills a foreign arch
    ok    the x32 bit is killed, not defaulted
    ok    and allowed without the bit, same policy
    ok    control: nr -1 is ENOSYS unfiltered
    ok    nr -1 is killed under a filter
    ok    exit status 0 passes through
    ok    exit status 42 passes through
    ok    stdout exact, no seccompc noise
    ok    stderr is not merged into stdout
    ok    stdin passes through
    ok    signal death passes through
    ok    a real program reports the errno we chose
    ok    and succeeds when the policy allows it
    ok    denying chmod alone does NOT stop chmod(1)
    ok    EPERM on statx stops stat(1)
    ok    ENOSYS on statx does not: glibc falls back
    ok    naming statx and newfstatat closes it
    ok    arch check precedes nr (small policy)
    ok    arch check precedes nr (no rules at all)
    ok    arch check precedes nr (mixed actions)
    ok    round trip: -d accepts what -c emits
    ok    round trip: the syscall names come back
    ok    round trip: the default action is named
    ok    the same policy compiles to the same bytes
    ok    reject: zero-length file
    ok    reject: one stray byte
    ok    reject: truncated instruction
    ok    reject: past BPF_MAXINSNS
    ok    reject: jump past the end
    ok    reject: no terminating return
    ok    reject: unknown opcode
    ok    reject: load outside seccomp_data
    ok    reject: scratch slot out of range
    ok    reject: divide by constant zero
    ok    reject: file does not exist
    ok    reject: a directory is not a filter
    ok    every refusal prints a reason
    ok    reject: the length message names the kernel limit
    ok    accept: a one-instruction ret ALLOW
    ok    no default= is refused
    ok    unknown action is refused
    ok    unknown clause is refused
    ok    clause with no = is refused
    ok    unknown syscall is refused
    ok    unknown errno is refused
    ok    errno 0 is refused
    ok    errno past MAX_ERRNO refused
    ok    the same syscall twice is refused
    ok    empty syscall list is refused
    ok    errno= without a colon refused
    ok    syscall number out of range refused
    ok    errno:NAME= on the left is refused
    ok    -c without -o is refused
    ok    -d with no file is refused
    ok    no -- before CMD is refused
    ok    no CMD after -- is refused
    ok    unknown mode is refused
    ok    a policy denying execve is refused
    ok    exec of a missing command is 127
    ok    exec of a non-PATH name is 127
    ok    exec of a non-executable is 126
    ok    missing command is 127 even under default=kill
    ok    non-executable is 126 even under default=kill
    ok    a decimal syscall number works
    ok    and the same number can be denied
    ok    whitespace and a trailing ; are fine
    ok    control: kill_process compiles when available
    ok    a missing kill_process action is refused
    ok    control: kill_thread compiles when available
    ok    a missing kill_thread action is refused
    ok    control: trap compiles when available
    ok    a missing trap action is refused
    ok    control: errno compiles when available
    ok    a missing errno action is refused
    ok    control: log compiles when available
    ok    a missing log action is refused
    ok    control: allow compiles when available
    ok    a missing allow action is refused
    ok    --actions honours the clamp
    
    130 passed, 0 failed, 1 skipped
```

The escape transcript is the interesting one. Clearing `no_new_privs` is
`EINVAL`. It is one-way. `PR_SET_SECCOMP` with `SECCOMP_MODE_DISABLED` is
`EINVAL`. There is no way to turn a filter off. And installing a maximally
permissive filter of its own succeeds, and changes nothing. Filters do not
replace each other, they accumulate. Every filter in the task's list runs on
every syscall and the most restrictive answer wins. There is no
`seccomp_release()`, by design. The policy for that test deliberately allows
`prctl` and `seccomp` so the attempts are really made.

If seccomp filtering is unavailable the harness prints the kernel version and
the two likely reasons and reports every assertion as skipped. If there is
no `-m32` toolchain the four i386 assertions skip loudly and say why. A skip is
never dressed up as a pass.

## Mutation testing

The question is not whether the tests pass. Twenty-seven deliberate defects,
twenty-six caught by a named assertion:

| mutation | caught by |
|---|---|
| remove the arch check entirely | 5, incl. both i386 assertions |
| invert the arch jump (`jf` 0 -> 1) | 5 |
| compare arch against `AUDIT_ARCH_I386` | 50 |
| load `nr` where `arch` belongs | 50 |
| remove the x32 / negative-`nr` range check | 5 |
| `jgt` -> `jge` in that range check | 3 (structural only) |
| per-rule errno off by one | 11 |
| default action forced to `ALLOW` | 8 |
| per-rule action forced to `ALLOW` | 17 |
| invert the per-rule jump | 30 |
| per-rule `jeq` compares `nr+1` | 43 |
| `KILL_THREAD` instead of `KILL_PROCESS` for a foreign arch | 3 (structural only) |
| drop `PR_SET_NO_NEW_PRIVS` | 57 |
| validator ignores out-of-range jumps | 2 |
| validator ignores a partial instruction | 2 |
| validator ignores `BPF_MAXINSNS` | 1 |
| validator drops the terminating-return check | 2 |
| validator accepts loads outside `seccomp_data` | 2 |
| duplicate rules silently first-wins | 1 |
| missing `default=` silently becomes `allow` | 1 |
| drop the `execve` requirement | 1 |
| drop the errno range check | 2 |
| drop the PATH preflight | 2 |
| disassembler prints `jt` and `jf` swapped | 3 |
| install via `prctl` instead of `seccomp(2)` | 2 (strace sees it) |
| availability check gutted entirely | 7 |
| **`SECCOMP_GET_ACTION_AVAIL` query replaced by `return 1`** | **nothing** |

The one survivor is recorded, not patched, because on this kernel it is
provably equivalent: all eight seccomp actions are available: a fact the
suite asserts against `/proc/sys/kernel/seccomp/actions_avail`, so asking the
kernel and answering "yes" are the same function here. Only a kernel missing an
action could tell them apart, and `SECCOMPC_NO_ACTION` drives the surrounding
logic instead.

Three mutations are caught only by the structural check, the weakest
oracle in the suite, and all three are observationally identical to a
single-threaded probe making real syscalls: `jgt` -> `jge` differs only at
`nr == 0x3fffffff`, a number that is no syscall; `KILL_THREAD` and `KILL_PROCESS`
are the same death for a process with one thread, and swapped `jt`/`jf` in the
disassembler changes no filter. The structural check earning its place on those
three is the argument for keeping it, and the reason it is still ranked last.

Four mutations survived the first sweep and three of them were real holes, all
of the same shape, a fixture that was being refused for the wrong reason:

- `reject: truncated instruction` used the first 12 bytes of a valid filter.
  Delete the size check and 12/8 truncates to one instruction, that instruction
  is a load, not a return, and the file is still refused, by a
  different check. The fixture is now a complete program plus four stray bytes.
  A sanitizer run caught that mutation anyway, by a route nobody designed:
  with the check gone a one-byte file yields zero instructions and the
  terminating-return check reads `f[-1]`.
- `reject: no terminating return` ended its program on a comparison, which is
  also a jump past the end, so the fixture had two faults and deleting either
  check left the other to refuse it.
- Both 126/127 assertions used `default=allow`, where `write` is permitted, so
  deleting the PATH preflight was invisible. The preflight exists precisely for
  the policy that denies `write`. There are now assertions under
  `default=kill`.

## What works

- `-a POLICY: CMD` installs the filter and execs CMD. Inherited by every
  descendant across `fork` and `exec`, forever, and irrevocable.
- Six clause kinds and seven actions, with the action validated against the
  running kernel before anything is installed.
- The arch check and the `nr` range check, both driven against the kernel.
- `errno=` gives exactly the errno named, 1..4095, by name or by number.
- `trap` is catchable and `kill` is not, both asserted.
- Fully transparent: seccompc `exec`s, so exit status, signal death and all
  three standard streams are the command's own by construction.
- Fails closed: a malformed policy, an unknown syscall name, an action this
  kernel lacks, or a command that cannot be executed all exit without running
  anything unfiltered. `125` is seccompc's own failure, `126`/`127` are exec
  failure, anything else is the command's.
- `-c` / `-d` round trip, with a validator that refuses what the kernel would
  refuse.
- A decimal syscall number works anywhere a name does.

## The validator, and the authority it did not have

`seccompc -d FILE` disassembles a filter and refuses one the kernel
would not accept. That refusal was the only claim in this program
with nothing behind it: every other behaviour is checked by being
run, and the validator only ever saw filters this program had just
emitted. A filter it accepted and the kernel refused turned up
indirectly as a failed install. A filter it **refused** that the
kernel would have accepted was invisible.

`seccompc --probe FILE` asks the kernel. The suite sweeps 11 filters
through both, 6 the kernel accepts and 5 it refuses, and requires
them to agree on every one. Both counts are asserted: a corpus where
everything was valid would agree perfectly while saying nothing about
the refusal half, which is the half that was missing.

### The channel cannot be a syscall the filter might forbid

The plan item said a fork was needed because a successful install may
deny the write that reports it. That was right, and worse than it
sounded.

The first version carried the answer out in the child's exit status.
Two of the five filters this program emits killed it: a default of
`kill` denies `exit_group`, so a child that installed the filter
**successfully** died of `SIGSYS` at the moment it tried to say so.
Both were reported as skips, and the sweep still said "agrees on
all", with a quietly smaller number inside it.

The answer travels on a pipe written **before** the filter exists,
which is the only moment every syscall is certainly available. Data
on the pipe means refused; silence means accepted. So a `SIGSYS`
death after the `seccomp` call is evidence of success, which reads
backwards until you notice that a filter has to exist before it can
kill anything.

The sweep asserts that no filter went unanswered, so a skip cannot
hide inside a pass. That assertion is what catches the mutation
removing the `SIGSYS` case; without it, two filters silently stop
being compared and everything stays green.

`SECCOMPC_PROBE_LIE=1` makes the validator accept everything, so the
comparison can be shown to notice a validator that is wrong. Three
mutations, all caught.

## What does not work

Honestly, and this list is longer than the one above. Twenty-one entries,
every one either measured here or named as untested.

- `execve` cannot be denied to CMD. The filter must be installed before the
  exec that starts CMD, because a process cannot install a filter on a process
  it is not. So the policy has to permit `execve`, and since the filter is one
  domain shared by the whole tree, CMD and all its children can exec too.
  seccompc refuses a policy that denies `execve` instead of adding it
  silently, as systemd's `SystemCallFilter` does. The honest fix is
  a trampoline, permit exec only from a specific `instruction_pointer`, or
  `SECCOMP_RET_TRACE` with a supervisor allowing exactly one, and both are
  larger than this program.
- The errno you choose changes whether the denial works. `ENOSYS` is the
  errno libc fallback paths look for: glibc probes a newer syscall and retries
  an older one on `ENOSYS`. Measured, not guessed:

  ```
  -a 'default=allow; errno=EPERM:statx'  -- stat -c %s F   # fails, EPERM
  -a 'default=allow; errno=ENOSYS:statx' -- stat -c %s F   # SUCCEEDS
  ```

  The second is glibc falling back to `newfstatat`, which strace shows
  directly. That applies equally to `clone3` -> `clone` and `faccessat2` ->
  `faccessat`. Naming every door closes it. There is no way for seccompc to
  know what the doors are.
- Collateral damage is normal and lands far from the syscall named.
  `errno=ENOSYS:newfstatat` makes `sh -c 'stat ...'` report
  `stat: Function not implemented` from the *shell*, because dash resolves a
  PATH lookup with `newfstatat` and so cannot find `stat(1)` at all. That is
  not a bug here. It is what filtering a syscall used by everything looks like.
- No argument filtering, and this is permanent. Classic BPF can compare the
  six `args[]` words, so `open` with a particular flag is expressible, but a
  pointer argument is only the pointer. The filter cannot read the memory it
  names, and userspace can change that memory after the check and before the
  kernel reads it. Offering `arg0==N` would invite exactly that race, so the
  answer is no.
- A policy names syscalls. What libc calls a function is a different vocabulary, and the two diverge.
  `chmod(1)` does not use the `chmod(2)` syscall; glibc routes it through
  `fchmodat(2)`, so `errno=EPERM:chmod` changes nothing. The suite asserts
  that, with the reason, because it is the most likely way for a real policy to
  be full of holes. `strace` is the only reliable way to find out what a
  program actually calls.
- x86-64 only. `AUDIT_ARCH_X86_64` is one constant in `emit()` and
  everything else arrives at a kill. A legitimately 32-bit child process dies
  of `SIGSYS` under any policy, including `default=allow`. That is the safe
  direction and still a surprise.
- Out-of-range syscall numbers are killed outright.
  `syscall(-1)` normally returns `ENOSYS`. Under any seccompc filter it is a
  kill. The transparency claim is scoped to syscalls the policy can name.
- `-a` cannot install a filter from a file. `-c` output is for inspection,
  diffing and feeding to some other program; `-a` recompiles from the policy.
  So `-c` plus `-d` is a loop that never reaches the kernel. That is exactly
  why the round trip ranks last as an oracle.
- The `-d` validator has no external authority. It is ours, and it is not
  checked against the kernel's `bpf_check_classic()`. A filter we accept and
  the kernel refuses shows up only indirectly, as an install failure on a
  filter we emitted ourselves. A filter we *refuse* and the kernel would accept
  is invisible. The fix is a probe mode that loads a filter file in a forked
  child and reports the kernel's errno, and it is item 1 in `PLAN.md`.
- `-d` is a seccomp disassembler, not a BPF one. It refuses an absolute
  load outside the 64 bytes of `seccomp_data`, because the kernel does, so it
  is useless for socket filters.
- x32 is driven by reconstruction, with no x32 binary involved. The 64-bit probe
  sets bit 30 in `rax`, and seccomp sees that either way, so the assertion
  is sound, but it is not the x32 entry path itself. That needs
  `CONFIG_X86_X32_ABI` and an x32 toolchain.
- `kill_process` and `kill_thread` are not distinguished. They differ only
  in how much of a multi-threaded process they take down, the probe has one
  thread, and the suite reports that as a skip instead of inventing an
  assertion.
- `log=` is asserted to allow the call, not to log it. The other half needs
  `/proc/sys/kernel/seccomp/actions_logged` and a readable audit sink, neither
  guaranteed. The filter is also installed with flags 0, so there is no
  `SECCOMP_FILTER_FLAG_LOG`.
- The missing-action refusal is tested by clamping our own answer.
  `SECCOMPC_NO_ACTION=NAME` proves the refusal logic, on the real kernel,
  through real syscalls. It does not prove the behaviour of a 4.13 kernel,
  which nothing short of a 4.13 kernel can. Same honesty gap as jail's
  `JAIL_ABI_MAX`, and named the same way.
- The syscall and errno name tables are curated, 177 and 30 entries.
  A decimal number works anywhere a name does, so nothing is inexpressible,
  but `unknown syscall name: foo` for a real syscall is a bad error message.
  Generating the list from `<asm/unistd_64.h>` costs one generated file.
- An errno of 0 is refused, so "pretend the call succeeded and did nothing"
  is not expressible. It is a real technique. It is also a way to make a policy
  lie to the program it is confining by accident.
- The PATH preflight is `access(X_OK)`, so a command unlinked between the
  check and the exec still lands in the case the preflight exists to avoid. The
  exec fails, seccompc tries to say so, the `write` is denied, and the caller
  sees 159 with no message. `execveat()` on an `O_PATH` descriptor would close
  it.
- No `SECCOMP_RET_USER_NOTIF` and no `SECCOMP_RET_TRACE`. Both need a
  supervisor process, a different program.
- No `SECCOMP_FILTER_FLAG_TSYNC`. Irrelevant to `-a`, which installs before
  any thread exists. Essential the moment this is used as a library.
- A killed process dumps core by default. seccompc does not change
  `RLIMIT_CORE`. The test harness sets `ulimit -c 0` for its own runs. A policy
  with `default=kill` applied to something that misbehaves in a loop will fill
  whatever your `core_pattern` points at.
- This is not a sandbox on its own. seccomp gates syscalls, not paths: a
  process permitted `openat` can open anything the filesystem permissions
  allow. The sibling repo `jail` is the filesystem half, and the two compose, and neither substitutes for the other.

## Design

One source file plus the probe. `seccompc.c` is 1031 lines, a quarter of them
comments explaining why the kernel insists on something.

```
parse policy  ->  check each action against the kernel  ->  require execve
              ->  resolve CMD through PATH
              ->  emit: arch check, nr range check, one pair per rule, default
              ->  prctl(PR_SET_NO_NEW_PRIVS)  ->  seccomp(SET_MODE_FILTER)
              ->  execvp
```

Five decisions worth naming.

The arch check first. Covered above. It is the reason the program exists.

`no_new_privs` before the filter. Not an ordering preference:
`SECCOMP_SET_MODE_FILTER` returns `EACCES` without it unless you hold
`CAP_SYS_ADMIN`, the very thing being avoided. The reason the kernel insists:
a filtered process that could exec a setuid-root binary would be handed
privileges while a filter it did not choose was still in force, and that
privileged program would meet `EPERM` on a syscall it has always been able to
make. Seccomp's claim is that an unprivileged process may safely restrict
itself, and that only holds if it cannot gain privileges afterwards.

Two instructions per rule, every jump offset 0 or 1. The denser form: one
comparison per rule jumping forward to a shared return, needs a check that
the 8-bit jump offsets still reach. This layout cannot overflow a jump by
construction, and `2N+7 <= BPF_MAXINSNS` allows 2044 rules against the ~360
syscalls that exist, so the denser encoding could never repay the arithmetic.

Actions are checked against the kernel and refused if missing. The kernel
does not reject a filter returning an action it does not know; it treats the
value as the lowest action it recognises, `KILL_THREAD`. So a policy saying
`kill_process` on a 4.13 kernel installs fine and does something else. This is
Landlock's problem inverted: Landlock refuses an unknown access bit so you
cannot be fooled, seccomp accepts an unknown return so you can.

`exec`, not `fork` + `wait`. The command replaces seccompc in the same
process, so there is no status to forward, no signal to re-raise and no pipe to
pump. Transparency is a property of the design. No code here
implements it. It is also safe for the caller's shell: seccompc is already a child, the
filter goes on seccompc's own task, and nothing is ever installed on a process
that did not ask for it.

The file format is the in-memory form, a bare array of `struct sock_filter`
in native byte order with no header and no magic, so there is no transformation
between what `-c` writes and what `-a` installs that could differ.

## Related

`jail`, in the sibling directory, is the filesystem half of the same idea:
Landlock instead of seccomp, paths instead of syscalls, and the same standard
of evidence. The two compose; neither replaces the other.

## License

GPL-3.0. See `LICENSE`.
