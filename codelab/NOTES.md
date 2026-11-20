# Codelab raw notes (Best Codelab bonus)

Working title: *Kernel-enforced least privilege on QNX 8.0: a secpol-typed resource manager in 45 minutes*.
These notes are the gotchas found while building Kervix. Each one becomes a callout in the codelab.

## Environment (S0)
- SDP 8.0 has no macOS or ARM host tools. Run the **Linux** Software Center CLI headless in an x86_64 container (`qnxsoftwarecenter_clt -installBaseline com.qnx.qnx800`).
- Install the SDP into a Docker **named volume**, not a macOS bind mount. macOS file systems are case-insensitive, and the volume is much faster.
- `mkqnximage --type=qemu` assumes a Linux bridge for networking. On macOS, boot the generated `ifs.bin` + `disk-qemu.vmdk` yourself with `-netdev user,hostfwd=...`.
- GNU make ignores pattern rules for targets listed in `.PHONY`.

## secpol (S1/S2)
- The baseline SDP already has `secpolcompile`, `secpolgenerate`, `secpol`, `secpolpush`, `on` and `libsecpol`.
- A channel's type comes from a **trailing type on `allow_attach`**: `allow_attach srv_t /dev/x x_ch_t;`. There is no separate "channel" statement.
- Use **one `dispatch_t` per path** when the paths need different channel types.
- `mkqnximage --secpol=open` runs `secpolgenerate`, which is permissive by default. Types are only held to your base policy if the config contains `type <t> restricted`, and that includes the **server** type. Otherwise its attach-time channel typing is not applied (observed: clients connected to `srv_t`, not `x_ch_t`).
- A denied connect fails with **`EPERM`**, not `EACCES`. That holds even for **uid 0**: types, not users.
- Attaching without a rule fails with `EACCES`, and `slog2info` shows `failed to attach to path ...: no rule`.
- `slog2info | grep secpolgenerate` is the debugger. It names the exact missing ability, e.g. `failed to use ability channel_connect:kxs1_priv_ch_t`.
- `secpol_transition_type(NULL, NULL, 0)` needs `derive_type a_t run b_t;` **and** `allow a_t self:ability { settypeid:b_t };`.
- The sender's type is in **`ctp->info.type_id`** on every message. `ConnectClientInfoExtraArgs(..., &type_id)` returned `0xFFFFFFFF` in our tests.
- QNX 8 resmgr I/O handlers take `void *ocb` unless you define `IOFUNC_OCB_T`. Casting avoids `-Werror=incompatible-pointer-types`.
- Server→client notifications: the client must `MsgRegisterEvent(&ev, fd)` before sending the event. This works across typed channels.
- **Least privilege at boot (M2):** start daemons with `on -T <type>` in `post_start.custom`, then `waitfor <path>` before starting the next one. A daemon denied `random_t` or `slogger_t` fails closed at startup, so harvest those rules from `slog2info` first.
- Channel typing stops channels and paths even for root, but not shared memory, `/proc/<pid>/as` or signals. Give the confined process its own uid (`on -T agentgw_t -u 400:400`) and build the image with `--secure-procfs=yes`.
- **Gotcha:** `channel_connect` is checked when a connection is made. A file connection inherited across spawn (e.g. a boot script's `> /tmp/x.log`) is reused without a new check, so a daemon can appear to need no `devb_t` rule. Write the rule anyway and don't leak fds into confined processes.
- After editing `/data/var/secpol/config` (`type <t> restricted`), reboot; `secpolgenerate` reads it at start.
- **Going secure (M2):** harvest with a base policy + your types `restricted`. Then `/dev/secpolgenerate/policy` holds only the *missing* rules, which are the system half. Gotchas:
  - Drop the `default` type block: it only holds the open image's `libsecpol-gen` symlink, and `secpolcompile` rejects it on secure images (`undefined type 'default'`).
  - secpolgenerate repeats your `allow X ch_t:channel connect` grants in `self:ability { channel_connect:ch_t }` form. Filter your own types out of the harvest instead of keeping both.
  - Secure images don't ship `secpolgenerate`. To keep a refusal log, install it from a snippet with an explicit source (`bin/secpolgenerate=bin/secpolgenerate`; a bare name was silently skipped) and run it in monitor mode under its own type (rules from the docs).
  - `secpolcompile` enforces **no privilege gain** across `settypeid`: `sshd_t` -> `user_root_t` means the root shell can't get a right `sshd_t` lacks. Give such rights to a dedicated type (`on -T operator_t ...`).
  - Anything the harvest never saw is refused. Here the root shell's `pidin` was refused `xprocess_query:40` on the monitor's uid. Run everything the secure image will do, harness included, before harvesting.

## qcrypto (S3)
- The baseline image ships `/proc/boot/qcrypto.conf` (`openssl-3 tags=*`), the plugin and `libcrypto.so.3`. Just link `-lqcrypto`.
- Ed25519 uses **two names**: `qcrypto_keygen_request("ed25519")` for keys, but `qcrypto_signature_request("eddsa-pure")` for signing. `"ed25519"` as a signature name returns `-400 algorithm not found`.
- Import a raw seed as PKCS#8 DER: `302e020100300506032b657004220420 || seed` with `QCRYPTO_KEY_FMT_DER`.
- Export the raw public key: `qcrypto_pubkey_to_mem(..., QCRYPTO_KEY_FMT_DER)` gives 44 bytes of SPKI; the raw key is the last 32.
- A context is **single-use after a one-shot op**: a second call returns `-412` (invalid state). Do not mistake that for "signature invalid" in negative tests.
- Call `qcrypto_keypair_init(ctx, &zeroed_args)` before `qcrypto_keypair_generate()`.
- `verify_oneshot` reports the result in `*status`: 1 = valid, 0 = invalid. Its return code only signals API errors.
- Ed25519 is deterministic, so a published vector (RFC 8032 key + COSE Sig_structure) is a byte-exact test of the whole pipeline.

## Boot-time services (S4)
- mkqnximage reads `local/snippets/*.custom` from its working directory:
  - `system_files.custom` uses lines like `[perms=0755] bin/kervix/s4_gw=/abs/host/path` and installs to `/system/bin/kervix/s4_gw`.
  - `post_start.custom` holds commands run at the end of boot.
- Snippets are preprocessed, so `#if defined(OPT_SECPOL_no)` works for writing policy-aware start lines.
- Start each service with `on -T <type> -p <prio> <cmd> &`. Types and priorities are applied before `main()`, and the process can confirm both with `secpol_type_id()` and `pthread_getschedparam()`.
- QEMU user networking (`-netdev user,hostfwd=tcp:127.0.0.1:7301-:7301`) is enough for host ⇄ target TCP. No bridge or tap is needed, so it works on macOS.

## Periodic publisher + subscribers (vsimd)
- A periodic job is a timer that delivers a **pulse** to a private channel: `timer_create(CLOCK_MONOTONIC, &pulse_ev)`, then `MsgReceivePulse()` on a SCHED_FIFO thread. There are no signals and no sleeping loops.
- Server-to-client doorbell: the client does `MsgRegisterEvent(&ev, fd)` and sends the event in a devctl. The server keeps the `rcvid` and later calls `MsgDeliverEvent(rcvid, &ev)`. Delivery failure means the client is gone, so drop it. Also drop it in `close_ocb`.
- Bulk data goes through `shm_open` + a seqlock, not messages. Map it `PROT_READ` in readers, so a compromised reader cannot forge state. Copy with `__atomic` relaxed word loads so ThreadSanitizer stays quiet.
- Resource-manager text nodes: `io_write` reads the payload with `resmgr_msgget(ctp, buf, n, sizeof msg->i)`; `io_read` replies with `MsgReply` and returns `_RESMGR_NOREPLY`. A one-line-per-open reply (EOF when `offset > 0`) keeps `cat` and `echo` usable from the shell.
- gcc 12 `-Werror=maybe-uninitialized` fires on structs filled through a pointer by inline helpers. Zero-initialize them.

## Authority/actuator plumbing (kervixd, sdv_actuatord)
- A devctl can return a small status without a payload: the server sets `msg->o.ret_val = code`, and the client reads it through `devctl(fd, dcmd, buf, n, &ret)`. Kervix uses this for reason codes on REDEEM and EXECUTE.
- `__DIOTF(class, cmd, type)` sends **and** receives `sizeof(type)` bytes. Use the larger of request and reply, here a union of intent and decision, so a single buffer serves both directions.
- Identify callers from `ctp->info.pid` and `ctp->info.type_id`, never from the payload. That is what makes a stolen grant useless to a different process (GRANT_BINDING).
- A client that keeps a server fd open (actuatord → kervixd) gets `EBADF`/`ESRCH` after the server restarts. Close, reopen once, and otherwise **fail closed**.
- qcrypto inits lazily: the first DRBG request costs milliseconds. Warm it at start-up if first-request latency matters.

## Deferred replies (kervixd AWAIT)
- To keep a client waiting without a thread per waiter: store `ctp->rcvid`, return `_RESMGR_NOREPLY`, and later `MsgReply(rcvid, EOK, &reply, n)`. For a devctl, the reply is `struct _io_devctl_reply` (set `.nbytes`) followed by the data.
- **Handle unblock.** Resource-manager channels use `_NTO_CHF_UNBLOCK`, so a REPLY-blocked client can't be interrupted until the server replies. Set `io_funcs.unblock`. The blocked client's rcvid is in the **pulse value** (`msg->value.sival_int`), not in `ctp->rcvid`. Then `MsgError(rcvid, EINTR)`.
  - Without this, Ctrl-C or SIGTERM on a waiting client hangs until the reply arrives.
  - We first compared against `ctp->rcvid` and it never matched.
- A REPLY-blocked process also keeps QNX `sshd` from closing the session, even with `nohup` and all stdio redirected. Test waiter and resolver in the **same** session.
- Shell trap: `cd dir && cmd & p=$!` backgrounds the whole `&&` list, so `$!` is a subshell and `kill $p` misses `cmd`. Write `cd dir; cmd & p=$!`.
- Non-interactive shells start background jobs with SIGINT ignored. Use SIGTERM to test interruption.

## Signed ledger (kervixd)
- QNX `struct iovec` uses unions, so build iovecs with `SETIOV(&iov[i], ptr, len)`, not positional initializers.
- qcrypto key persistence: `qcrypto_privkey_to_mem(..., QCRYPTO_KEY_FMT_DER)` gives 48-byte PKCS#8, and `qcrypto_privkey_from_mem()` reloads it. Write it with `O_EXCL` and mode 0400, then `fsync`.
- Keep signing off the hot path. A bounded queue plus a low-priority writer thread keeps decisions in microseconds while Ed25519 and `fsync` take milliseconds.
- "No audit, no action" needs **reservations**, not just a free-space check. Otherwise a flood can starve the record of an action that was already authorized.
- Recovery must never silently drop bytes: quarantine the torn tail and record how many bytes were moved in the next capsule.

## Supervision (kx-supervisor)
- Start the child in a type with `secpol_posix_spawnattr_settypeid(NULL, &attr, "kervix_t", SECPOL_TYPE_NAME)`. Without a policy it does nothing, so the same binary works on plain images. The policy needs `allow supervisor_t self:ability { spawn settypeid:kervix_t };`.
- Give the child a **pipe** for stdout/stderr (`posix_spawn_file_actions_adddup2`) instead of a log file. The child inherits no file connection, and EOF on the pipe is the earliest sign the child is gone, before `waitpid`.
- **Gotchas found by the tests:**
  - QNX `slay` exits with the **number of processes signalled**, so under `set -e` a successful `slay` aborts the script. Append `; true`.
  - `pidin -F "%N"` pads names with spaces, so `^name$` never matches. Strip with `tr -d ' '`.
  - **`mkqnximage` remembers options between builds.** A "plain" build after `--secpol=secure` is still secure. Always pass `--secpol=no --policy=none --secure-procfs=no` and override them when needed.
  - `SIGSTOP` the supervisor to hold the system "authority down" long enough to prove fail-closed behaviour deterministically, then `SIGCONT`.

## Same C, everywhere (replay via WebAssembly)
- A portable C core (no OS headers, no malloc, no clocks) compiles unmodified to `--target=wasm32 -ffreestanding -nostdlib` with a ~40-line libc shim (memcpy/memset/strcmp/...). The result is 27 KB.
- Export a setter API (`__attribute__((export_name(...)))`) rather than sharing struct layouts with JavaScript. 64-bit values cross as BigInt.
- Apple clang ships without the wasm backend. A native-arch `ubuntu:24.04` container with `clang lld` builds it in seconds, and the Linux CI runner just needs `apt install lld`.


## Network gateways (kxgw)
- **A typed, non-root process that opens a socket needs `network/jailroot`.** io-sock asks for it on every socket of a non-root caller. The refusal surfaces as `EPERM` from `bind`/`listen`, not from `socket()`. The log names it: `failed to use ability network/jailroot as non-root`. Grant it explicitly: `allow agentgw_t self:ability { nonroot network/jailroot };`, plus `allow agentgw_t io_sock_t:channel connect;`.
- An `ability` may be declared only once across the files you concatenate into one policy. When a hand-written policy takes over a declaration that `secpolgenerate` harvested (`ability network/jailroot allow { root nonroot };`, `type io_sock_t;`), delete it from the harvested half.
- **Read-only access is a channel type, not a flag.** `/dev/kervix/stats` used to share the agent channel, so anything that could read stats could also propose. Moving it onto its own dispatch channel (`kx_obs_ch_t`) means the observer's type can read and the kernel refuses it the authority's propose channel (`EPERM`).
- Uid separation for a node you write: give the gateway its own uid and set the node's group (`attr.gid`) instead of running the gateway as root. Running as root would let it signal or `/proc`-read the daemons, because those are uid matters, not secpol.
- Escalation push with no polling: each HMI connection gets a thread that `MsgReceivePulse()`s a private channel registered with the authority (`MsgRegisterEvent` + subscribe devctl). A `TimerTimeout` every 2 s checks that the subscription is still alive and resubscribes after an authority restart.
- Keep the gateway dumb: it forwards a replayed grant instead of filtering it. The authority refuses it **and records the attempt**. A smart gateway would hide attacks from the ledger.

## On-target selftest (kx-selftest)
- A selftest that runs each role *as that role* (`on -T agentgw_t -u 400:400 …`) tests the deployment, not just the code. It caught a harness bug in which the agent's type tried to move the simulator. secpol refused it and logged the refusal, which is exactly right.
- `popen()` + a background child: the child can inherit popen's pipe and keep it open, so `pclose()`/`fread()` block until the child exits. Start background jobs with `system("… < /dev/null > file 2>&1 &")` and poll a marker in the file.
- Report SKIP, not PASS, for kernel-enforcement checks on an image without a policy (`on -T` fails there), so a table can never claim protection that was not active.
