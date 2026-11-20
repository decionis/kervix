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
