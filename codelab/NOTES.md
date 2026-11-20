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

