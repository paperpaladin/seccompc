# PLAN

## Contract

```
seccompc -a POLICY -- CMD [ARGS...]   install the filter, then exec CMD
seccompc -c POLICY -o FILE            compile POLICY to a filter file
seccompc -d FILE                      disassemble a filter file
seccompc --probe FILE                 ask the kernel to load FILE, report its verdict
seccompc --actions                    the seccomp actions this kernel has
```

POLICY is `;`-separated clauses, one of which must be `default=ACTION`:

```
default=ACTION   allow=LIST   kill=LIST   kill_thread=LIST
trap=LIST        log=LIST     errno=ERRNO:LIST
```

ACTION is `allow`, `kill` (= `kill_process`), `kill_thread`, `trap`, `log` or
`errno:ERRNO`. LIST is comma-separated syscall names or decimal numbers. ERRNO
is a name such as `ENOSYS` or a decimal number in 1..4095.

`-a` builds the same filter `-c` would, sets `PR_SET_NO_NEW_PRIVS`, installs it
with `seccomp(SECCOMP_SET_MODE_FILTER)`, and `exec`s CMD. Every syscall CMD and
all its descendants make is then decided by that filter, forever: a syscall
named in a clause gets that clause's action, everything else gets `default`,
and anything arriving through a syscall entry point other than x86-64's is
killed regardless of the policy.

`seccompc` is otherwise transparent. It `exec`s, so CMD's exit status, death by
signal, and all three standard streams are CMD's own. Exit `125` means seccompc
itself failed and CMD never ran; `126`/`127` mean CMD could not be executed;
anything else came from CMD.

The policy must allow `execve`, and seccompc refuses to run if it does not.
This is structural: the filter has to be installed before the
exec that starts CMD, because a process cannot install a filter on a process it
is not.

`-c` and `-d` write and read a bare array of `struct sock_filter` in native
byte order (no header, no magic) so there is no transformation between what
`-c` writes and what `-a` installs.

On a kernel that does not implement an action the policy asks for, seccompc
refuses instead of installing. It must: the kernel does not reject an unknown
return value, it treats it as the lowest action it knows, `KILL_THREAD`.

## Hard invariant

**A syscall that the policy did not permit never executes, including through a
syscall entry point the policy never contemplated, and the filtered process
cannot remove or widen its own filter.**

Three parts, all of them the kernel's to keep, not ours, and all three
observed through real syscalls:

1. The emitted filter compares `seccomp_data.arch` against `AUDIT_ARCH_X86_64`,
   and refuses anything else, before it looks at `seccomp_data.nr`. Without
   that, `nr` is an index into whichever syscall table the caller's entry point
   uses, and those tables disagree: x86-64 102 is `getuid`, i386 102 is
   `socketcall`. A filter permitting `getuid` would permit any 32-bit caller to
   open a socket. The same applies to x32, which reports `AUDIT_ARCH_X86_64`
   and sets bit 30 of `nr`, so arch alone is necessary and not sufficient.
2. Nothing available to the filtered process removes or widens the filter.
   Not clearing `no_new_privs`, not `PR_SET_SECCOMP` with
   `SECCOMP_MODE_DISABLED`, and not installing a permissive filter of its own,
   which succeeds and changes nothing, because filters accumulate and the most
   restrictive answer wins.
3. The action observed is the action named. `errno=ENOSYS` is exactly `ENOSYS`,
   `kill` is death by `SIGSYS`, `trap` is a catchable `SIGSYS`, `allow` is the
   syscall's own ordinary result.

Corollary held to as well: the `125` / `126-127` / other split on exit status is
never ambiguous, so a filter that was not installed can never be mistaken for a
command that ran.

## Oracle

The kernel is the authority. Ranked by how little we control it, and that is also
the order of what each would cost us to get wrong.

1. The 32-bit entry point, driven for real. `t/try32` is built from the same
   source with `-m32` and does `int $0x80` with `eax=102`. Unfiltered it gets a
   socket; under a policy that permits `getuid`: the same number on x86-64,
   it dies of `SIGSYS`. Four assertions, two of them controls, because without
   them the test would pass for a `-m32` binary that could not run at all or
   for a policy that denied 102 outright. A mutant with the arch comparison's
   `jf` changed from 0 to 1 exits 0 with a socket in hand.
2. The filtered process cannot get out. Four attempts, each reported
   numerically, and then the denied syscall again. The policy deliberately
   permits `prctl` and `seccomp` so the attempts are really made; the
   transcript is asserted to show the permissive self-install *succeeding*,
   because otherwise this group would pass for the wrong reason.
3. A denied syscall returns exactly the errno named. `socket(AF_INET,
   SOCK_STREAM)` cannot fail on this machine, so any errno observed is the
   filter's. Five named errnos, one decimal, and three different returns inside
   one filter.
4. `kill`, `trap` and `log` are the mechanisms claimed. `kill` is wait
   status 159 and is *not* caught by a handler that does catch `trap`. The pair
   is the assertion. Either line alone says nothing. The scope of a kill is
   the same shape: a sibling thread makes the denied call, and `kill_thread`
   leaves the other thread to exit 97 where `kill_process` takes the group to
   159. Dropping `clone` from that policy, or having the main thread make the
   call instead of the sibling, turns the control and the 97 red, so the group
   cannot pass with no second thread in it.
5. `strace` as an independent witness. It sees `socket(...) = -1 EPERM`, and
   `-1 ENOSYS` when only the policy changed; it sees `PR_SET_NO_NEW_PRIVS`
   precede `SECCOMP_SET_MODE_FILTER`, and it reports the program length the
   kernel was handed, which agrees with the instruction count `-d` prints.
   Where strace and this program disagree, this program is wrong.
6. Allowed syscalls still work, and syscalls were really executed. Six
   allowed calls, asserted individually, plus a strace-counted total that must
   exceed ten. A filter that denied everything would satisfy every denial above
   for free, and that is the failure mode this project has been bitten by most.
7. Inheritance. A forked child, an exec'd program, and a grandchild via
   exec-then-fork are all still filtered, and all still get what the policy
   allows.
8. Transparency, through a real dynamically linked program. Exit 0, exit
   42, death by `SIGTERM` (143), exact stdout, stderr not merged, stdin piped
   through. Then one syscall the policy does name, reported by `chmod(1)` in
   its own words.
9. Malformed filter files are refused, never crashed on. Twelve refusals,
   each with a message, each also run under `-fsanitize=address,undefined` with
   `exitcode=86`: a value the suite cannot otherwise produce, because a
   sanitizer abort at the default exit 1 is indistinguishable from an ordinary
   refusal.
10. `--actions` against `/proc/sys/kernel/seccomp/actions_avail`. Different
    kernel code produces each, and nothing here reads the file.
11. The missing-action refusal, driven with `SECCOMPC_NO_ACTION`. Six
    control/refusal pairs. This clamps our own answer downward, so it proves
    the refusal logic, not the behaviour of an old kernel: the same
    honesty gap `JAIL_ABI_MAX` has, and named as such.
12. The sanitizer, over a buffer sized to what arrived. `make overread`
    plants a read one instruction past a filter file and fails unless ASan
    reports a heap overflow. It is a prerequisite of `make test` because it
    is the only witness to its own property: with the shrink in
    `read_filter` reverted, the suite still prints 0 failed.
13. Disassembly round trip. The weakest oracle here, and labelled so in
    `t/run.sh` itself. Both the emitter and the disassembler are ours, so a
    shared misunderstanding passes. It exists to catch a regression in
    instruction order and establishes nothing about correctness; item 1 is what
    does that.

If seccomp filtering is unavailable the harness prints the kernel version and
the two likely reasons and counts every assertion as skipped. If there is no
`-m32` toolchain the four i386 assertions skip loudly and say why. A skip is
never dressed up as a pass.

## Non-goals

- A policy language. No argument matching, no boolean expressions, no includes,
  no profiles, no config file. Six clause kinds and a default.
- Argument filtering. Classic BPF can compare the six `args[]` words, but a
  pointer argument is only the pointer: the memory it names is not readable by
  the filter and can be changed after the check. Offering `arg0==N` would
  invite exactly that race, so the answer is no.
- `SECCOMP_RET_USER_NOTIF` and `SECCOMP_RET_TRACE`. Both need a supervisor
  process, a different program.
- libseccomp, or any dependency. Emitting the BPF is the project.
- Any architecture other than x86-64. The arch check is a single constant on
  purpose. A multi-arch filter is a different and much larger shape.
- Filesystem, network or namespace isolation. That is what the sibling repo
  `jail` is for; seccomp gates syscalls, not paths.
- Running as root, or needing it.

## Commit sequence

Granularity is for `git bisect` and `git revert`, so every commit builds.

- [x] Makefile, LICENSE, .gitignore, and `seccompc.c` reduced to `--actions`.
      why: `SECCOMP_GET_ACTION_AVAIL` is the only feature detection seccomp
      offers, and every promise the tool can make is conditioned on the answer.
      It is also the one piece that cannot be added later without the rest
      having been written against an assumption.
- [x] The policy parser, the name tables and `emit()`, behind `-c`.
      why: the arch check is the whole security of the program and belongs in
      the first commit that produces a filter at all instead of bolted on after. The
      availability refusal lands here too, because a policy and the actions it
      names are one decision.
- [x] `-d`: the disassembler and the file validator.
      why: separable from emitting, and worth isolating because it is the only
      part that reads bytes someone else wrote. Landing it before the harness
      keeps "what we can observe" apart from "what we assert".
- [x] `-a`: `PR_SET_NO_NEW_PRIVS`, install, exec, and the PATH preflight.
      why: the ordering is a kernel requirement, not a preference, and
      this is the first commit where being wrong has consequences. The
      preflight is here because without it the 126/127
      contract is false, not merely untested.
- [x] `t/try.c`, the freestanding probe, built twice.
      why: the oracle needs a program that reports errno numerically and
      depends on nothing, and it needs an i386 twin, because the arch check is
      otherwise a claim, not a measurement.
- [x] `t/run.sh`, 107 assertions, since grown to 137.
      why: one commit, not one per group, because the groups share the
      fixtures and the skip path and splitting them would mean a dozen commits
      each adding three lines to the same file. The two harness bugs found
      while driving it are recorded in the message.
- [x] Free the policy buffer, found by LeakSanitizer.
      why: kept adjacent to the harness commit, since it is what the harness
      found the moment it was run under sanitizers.
- [x] Close the three gaps the mutation sweep found; add `SECCOMPC_NO_ACTION`.
      why: twenty-two mutations, four survivors, three of them real holes in
      fixtures that were being refused for the wrong reason. The fourth is
      untestable on a kernel where every action exists, so it got a
      clamp, not a test.
- [x] The `ENOSYS`-is-routed-around assertions, three of them.
      why: found while declining to write a README sentence without driving it.
      `errno=ENOSYS:statx` leaves `stat(1)` working through `newfstatat` while
      `errno=EPERM:statx` stops it, so the errno a policy chooses decides
      whether the denial holds. That is the strongest argument in the repo
      against treating the errno as cosmetic, and it belonged in the suite
      before it belonged in the prose.
- [x] `README.md`, then this file.
      why: the transcript and the "what does not work" list are a different
      artifact from the contract and the forward plan, and someone reverting
      one rarely wants to revert the other. (This file in fact landed early,
      swept into the commit above by the gate committing the whole tree, which
      is worth recording, not rewriting history over.)

### Milestone 1: the gaps the current suite cannot close

- [x] A probe mode that loads a filter file in a forked child and reports the
      kernel's errno, so `-d`'s validator can be asserted to agree with
      `bpf_check_classic()`.
      why: the validator is the one part of this repo with no external
      authority at all. Today a filter we accept and the kernel refuses shows
      up only indirectly, as an install failure on a filter we emitted
      ourselves, and a filter we *refuse* and the kernel would accept is
      invisible. The fork is needed because a successful install may then deny
      the write that would report it.
- [x] BLOCKED, re-probed 2 November 2026: drive x32 through a real x32 binary
      rather than by setting bit 30 in `rax` from a 64-bit process. What was
      done instead: `t/tryx32` is the probe built with `-mx32`, and a
      `_Static_assert` in `t/try.c` compares `__NR_getuid` against
      `X32_BIT | 102`, so the constant the 64-bit reconstruction uses now has
      an authority outside this repository.
      why it is blocked, measured rather than inferred: the entry path cannot
      be driven here because `execve` of that binary fails with `ENOEXEC`, so
      `CONFIG_X86_X32_ABI` is off on 7.2.13-200.fc44.x86_64. The suite runs
      the unfiltered binary, reads 126 back from the shell, and skips with
      that reason. On a kernel with x32 enabled the assertion runs.
      What this item used to say was the blocker was two things, an x32
      toolchain and the kernel option. The toolchain half was wrong: no
      distribution ships an x32 libc, but a freestanding build needs none and
      the ordinary gcc here produces the binary.
- [x] Observe `kill_process` differing from `kill_thread` by giving the probe a
      second thread.
      why: this was the only skip in the suite. `try thread` clones a sibling
      with `CLONE_THREAD|CLONE_CHILD_CLEARTID` and the sibling makes the
      denied call, so `do_exit(SIGSYS)` and `do_group_exit(SIGSYS)` become 97
      and 159 seen from outside. Three assertions, one of them the control
      that has the sibling's call succeed and report in its own words, because
      97 on its own would also appear for a filter that did nothing to the
      sibling. `try threadx32` is the same sibling calling through the x32
      bit, which makes the scope of the foreign-arch kill observable too.
- [ ] BLOCKED, measured 2 November 2026: assert that `log` actually logs.
      why it is blocked: the kernel emits nothing to log. `seccomp_log()`
      calls `audit_seccomp()`, which returns without writing while
      `audit_enabled` is 0, and this kernel booted without `audit=1`. Both a
      `log=socket` call and a `kill_process` death were run and neither left a
      record. Turning audit on needs `CAP_AUDIT_CONTROL` and `CapEff` here is
      empty.
      The reason this item used to give was "neither
      `/proc/sys/kernel/seccomp/actions_logged` nor a readable audit sink is
      guaranteed", and both halves of that are wrong on this machine.
      `actions_logged` is readable and lists `log`, which the suite now
      asserts. And a sink is readable: `dmesg` is refused
      (`dmesg_restrict` is 1, no `CAP_SYSLOG`) and `/var/log/audit` is
      refused, but `journalctl -k` works and holds the kernel ring buffer.
      It is empty of seccomp records, which is a different fact from having
      no way to look. The suite probes all three sinks at run time and names
      the one it reached, so this starts measuring the moment audit is on.

- [x] Shrink the filter-file buffer to what arrived, and a `make overread`
      gate over it.
      why: `read_filter` allocated `(BPF_MAXINSNS + 1) * 8` = 32776 bytes for
      a file that is typically 72, which is the shape recorded in
      `projects/METHOD.md` as having turned the sanitizer off in twenty-one
      buffers across fifteen repositories. This is the one buffer here holding
      bytes someone else wrote, so a read one instruction past the program
      landed 32 KB inside a live object. Measured rather than reasoned: with
      the shrink reverted the planted read exits 0 and ASan says nothing,
      while `make test` prints 0 failed either way, which is why the gate is a
      prerequisite of the suite and not a chore beside it.
      Nothing else in the program has the shape. `emit()` allocates
      `2 * nrule + 7` and writes exactly that many, the policy copy is
      `strlen(policy) + 1`, and `preflight`'s `char buf[PATH_MAX]` is written
      only by `snprintf` and read only to its NUL, so there is no read to
      plant in it.

### Milestone 2: things the filter cannot currently express

- [ ] Deny `execve` to CMD while still allowing the one exec that starts it.
      why: the largest hole in the contract, and it is structural. The honest
      fix is a trampoline: install a filter that permits exec only from a
      specific `instruction_pointer`, or use `SECCOMP_RET_TRACE` with a
      supervisor that allows exactly one. Both are much larger than this
      program, so the current behaviour is a documented
      refusal, not a silent implicit allow.
- [ ] Group rules by action: one `jeq` per rule jumping to a shared return.
      why: halves the program, and the only reason not to is that it needs a
      check that the 8-bit jump offsets still reach. Worth doing only if a
      policy ever gets large enough for `BPF_MAXINSNS` to matter, which at
      2044 rules against ~360 syscalls it cannot.
- [ ] Generate the syscall name table from `<asm/unistd_64.h>` at build time.
      why: the table is curated and a decimal number is the escape hatch, so
      nothing is inexpressible, but "unknown syscall name: foo" for a real
      syscall is a bad error message. Costs one generated file.
- [ ] `SECCOMP_FILTER_FLAG_TSYNC`, so a filter installed by one thread applies
      to all of them.
      why: irrelevant to `-a`, which installs before any thread exists, and
      essential the moment this becomes usable as a library. Named here so the
      boundary stays explicit.
