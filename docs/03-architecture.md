# 03 — Technical Architecture: Kervix

> Status: **DRAFT for review**. Items marked **[SPIKE-n]** are assumptions that the first two days of spikes must confirm (see `04-implementation-plan.md` §2).
> Target: **QNX SDP 8.0** · `aarch64le` (Raspberry Pi 4) and `x86_64` (QEMU) · toolchain `qcc` via CMake.
> Dev host: Apple M1 macOS. SDP Linux host tools run in an x86_64 Docker container, and QEMU runs on the Mac with TCG (see `decisions.md` H1–H3 and `04-implementation-plan.md` §2).

---

## 1. Design principles

1. **Topology before policy.** The kernel decides *who can talk to whom* (secpol). Kervix decides *what may happen now* (policy). An attacker must defeat both.
2. **Fail closed, everywhere.** Unknown action, stale telemetry, lost authority, full audit queue, expired escalation: every one of these results in no actuation.
3. **Bounded and allocation-free on the hot path.** Every loop has a compile-time bound. All memory is reserved at init.
4. **Hot path symmetric, audit path asymmetric.** Grants use HMAC (≈µs). Ed25519 signing happens on a lower-priority writer thread so it never sits on the decision path. There is still no actuation without an enqueued audit record (K3).
5. **One portable policy core.** The same C11 library (`libkxcore`) runs on QNX, in host tests and in the offline replay verifier, so a replayed verdict comes from the same code that decided.
6. **Standards over inventions.** Use Agent-Safe Intent v1, AAC draft-04, COSE_Sign1, JWK and COVESA VSS names. Only invent where nothing exists.

---

## 2. System context

```
┌──────────────────────── HOST (macOS/Linux laptop = "AI / infotainment domain") ───────────────────────┐
│  host/agent (Claude tool loop | scripted replay)   host/mcp (kervix-mcp)   host/dashboard (React+R3F)   │
│                │                                       │                          ▲  WebSocket          │
│                └──────────────► host/bridge (Node, TS) ◄────────────────────────┘                      │
│                                   │ TCP :7301 agent   :7302 hmi   :7303 observer (JSON lines)          │
│  host/verify (kervix-verify)  ◄── dossier export (scp / tcp)                                            │
└───────────────────────────────────┼──────────────────────────────────────────────────────────────────┘
                                    │ virtio-net (QEMU) / Ethernet (RPi4)
┌───────────────────────────────────┼────────────── QNX 8.0 TARGET ("safety domain") ─────────────────────┐
│                         io-sock   ▼                                                                     │
│   kxgw --role agent  (agentgw_t)   kxgw --role hmi (hmigw_t)   kxgw --role observer (obsgw_t)           │
│        │ MsgSend (devctl)               │                            │ read/ionotify                      │
│        ▼                                ▼                            ▼                                    │
│   ┌──────────────────────────── kervixd (kervix_t) ───────────────────────────────────────────┐          │
│   │ ch_agent: /dev/kervix/intent         ch_hmi:   /dev/kervix/escalations                     │          │
│   │ ch_act:   /dev/kervix/redeem         ch_admin: /dev/kervix/policy                          │          │
│   │ ch_agent (ro): /dev/kervix/dossier, /dev/kervix/stats                                      │          │
│   │ [policy engine] [grant table] [escalation queue] [telemetry view] [ledger writer + signer]  │          │
│   └───────▲─────────────────────────────────▲───────────────────────────────────────────────────┘          │
│           │ redeem (MsgSend)                 │ pulse + shm seqlock (read-only map)                          │
│   sdv_actuatord (actuator_t)  ──actuate──▶  vsimd (vsim_t): /dev/sdv/telemetry, /dev/sdv/sim/actuate       │
│   /dev/sdv/actuators (ch type act_bus_ch_t)                                                               │
│   kx-supervisor (supervisor_t)   kxctl (operator_t)   kx-rogue (agentgw_t: same rights as agent)          │
│   /var/kervix/ledger (append-only)   /etc/kervix/{policy.kxp, keys/}                                      │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Why the agent runs on the host:** this mirrors real SDV architectures. LLM agents live on the high-performance compute or infotainment SoC (Linux/Android, often a guest VM on a hypervisor), and QNX hosts the safety domain. The TCP link stands in for the inter-domain channel (virtio or Ethernet). The gateway is the only network-facing process on the target and it holds **no authority**.

---

## 3. Processes, secpol types and privileges

| Process | secpol type | Attaches (paths) | May connect to | Abilities after init | Priority |
|---|---|---|---|---|---|
| `kervixd` | `kervix_t` | `/dev/kervix/*` | `/dev/sdv/telemetry` (vsim channel) | none beyond public channel; `secpol_transition_type()` to `kervix_run_t` | server threads inherit client prio; ledger writer 15; telemetry thread 45 |
| `vsimd` | `vsim_t` | `/dev/sdv/telemetry`, `/dev/sdv/sim/*` | — | timer, shm create | 50 (100 Hz model) |
| `sdv_actuatord` | `actuator_t` | `/dev/sdv/actuators` | ch_act (redeem), `/dev/sdv/sim/actuate` | none | inherits; floor 40 |
| `kxgw --role agent` | `agentgw_t` | — | ch_agent, `/dev/sdv/actuators` (grant-only API) | io-sock socket | **10** |
| `kxgw --role hmi` | `hmigw_t` | — | ch_hmi, ch_agent (ro) | socket | **30** |
| `kxgw --role observer` | `obsgw_t` | — | ch_agent (ro nodes only, via ACL) | socket | 5 |
| `kxctl` | `operator_t` | — | ch_agent, ch_hmi (approve), ch_admin (policy load) | — | 10 |
| `kx-supervisor` | `supervisor_t` | — | spawn `kervixd`; watch death | spawn | 60 |
| `kx-rogue` | `agentgw_t` | (tries to attach — denied) | same as agent gateway | none | 10 |

### 3.1 Per-channel secpol types (the core QNX bonus feature) — verified by spike S1/S2

`kervixd` creates **one dispatch channel per trust level** (four `dispatch_t`, each with its own fixed-size thread pool). It attaches each path with `secpol_resmgr_attach()`. The policy types each channel with a **trailing type on `allow_attach`**. Spike S1 proved that a single process can own several differently typed channels this way.

```
# target/secpol/kervix.secpol (grammar verified with secpolcompile in S1)
type kervix_t; type kervix_run_t; type vsim_t; type actuator_t; type agentgw_t; type hmigw_t;
type obsgw_t; type operator_t; type supervisor_t;
type kx_agent_ch_t; type kx_act_ch_t; type kx_hmi_ch_t; type kx_admin_ch_t;
type act_bus_ch_t; type act_raw_ch_t; type vsim_ch_t;

# who may attach which path, and the type the resulting channel gets
allow_attach kervix_t   /dev/kervix/intent      kx_agent_ch_t;
allow_attach kervix_t   /dev/kervix/dossier     kx_agent_ch_t;
allow_attach kervix_t   /dev/kervix/stats       kx_agent_ch_t;
allow_attach kervix_t   /dev/kervix/redeem      kx_act_ch_t;
allow_attach kervix_t   /dev/kervix/escalations kx_hmi_ch_t;
allow_attach kervix_t   /dev/kervix/policy      kx_admin_ch_t;
allow_attach actuator_t /dev/sdv/actuators      act_bus_ch_t;
allow_attach actuator_t /dev/sdv/actuators/raw  act_raw_ch_t;
allow_attach vsim_t     /dev/sdv/telemetry      vsim_ch_t;

# topology: the kernel refuses every connect not listed here
allow { agentgw_t hmigw_t obsgw_t operator_t } kx_agent_ch_t:channel connect;
allow actuator_t                               kx_act_ch_t:channel connect;
allow { hmigw_t operator_t }                   kx_hmi_ch_t:channel connect;
allow operator_t                               kx_admin_ch_t:channel connect;
allow { agentgw_t operator_t }                 act_bus_ch_t:channel connect;
# act_raw_ch_t: deliberately no connect rule for any agent-domain type
allow { kervix_t kervix_run_t actuator_t }     vsim_ch_t:channel connect;

# one-way privilege drop after init (both rules are required; S1 finding)
derive_type kervix_t run kervix_run_t;
allow kervix_t self:ability { settypeid:kervix_run_t };
```

**Verified behaviour (S1, QNX 8.0, every client running as uid 0):**
- A connect to a channel type the caller isn't allowed fails in `procnto` with **`EPERM`**. Root is not exempt.
- Attaching a path without an `allow_attach` rule fails with **`EACCES`**. This covers both path squatting by an agent and a server attaching something unlisted.
- Allowed connects and devctls work normally. A `MsgRegisterEvent` pulse is delivered across a typed channel.

**Implemented in M2 (`tests/target/secpol.sh`, `make target-secpol`, PASS on QNX 8.0 / QEMU):** the real policy is `target/secpol/kervix.secpol`. It differs from the sketch above in three ways: vsimd has one channel type per path (`vsim_tel_ch_t`, `vsim_ctl_ch_t`, `vsim_act_ch_t`); `kx_admin_ch_t` and `obsgw_t`/`supervisor_t` wait for their milestones; and each daemon gets explicit rules for the system services it uses (`random_t`, `slogger_t`, and `devb_t` for kervixd's ledger and the operator's export).
- `vsimd`, `kervixd` and `sdv_actuatord` are baked into the image and started at boot with `on -T <type>` (`target/image/snippets/`). Each attaches its paths, then drops to its `_run_t` type.
- **Legitimate roles see zero denials:** the agent (`agentgw_t`, uid 400) proposes and executes, the driver HMI (`hmigw_t`) approves an escalation, and the operator (`operator_t`) reads telemetry and stats and exports the ledger.
- **`kx-rogue`** (`target/kx-rogue`) runs ten attacks a compromised agent would try, and reports the layer that stopped each one:

| Attack | No enforcement | secpol, agent as **root** | deployed agent (`agentgw_t`, uid 400) |
|---|---|---|---|
| actuate the bus directly (`/dev/sdv/sim/actuate`) | OPEN | kernel (EPERM) | kernel |
| raw maintenance path (`/dev/sdv/actuators/raw`) | OPEN | kernel (EPERM) | kernel |
| redeem a forged grant (`/dev/kervix/redeem`) | crypto (MAC) | kernel (EPERM) | kernel |
| approve its own escalation (`/dev/kervix/escalations`) | OPEN | kernel (EPERM) | kernel |
| rewrite vehicle state (`/dev/sdv/sim/ctl`) | OPEN | kernel (EPERM) | kernel |
| impersonate the authority (attach `/dev/kervix/intent`) | OPEN | kernel (EPERM) | kernel |
| impersonate the actuator bus (attach `/dev/sdv/actuators`) | OPEN | kernel (EPERM) | kernel |
| map telemetry shm read-write | OPEN | OPEN | kernel (EACCES, uid) |
| read kervixd memory (`/proc/<pid>/as`) | OPEN | OPEN | kernel (EPERM; `--secure-procfs` + uid) |
| kill kervixd | OPEN | OPEN | kernel (EPERM, uid) |
| **open** | **9/10** | **3/10** | **0/10** |

  So secpol alone confines every *channel and path* even for root. Shared memory, `/proc` and signals are uid/permission matters, so the deployed agent also runs under its own uid. The kernel log names each refused channel type (`slog2info | grep secpolgenerate`).
- **Lesson (inherited connections):** `channel_connect` is checked when a connection is *made*. A connection inherited across `spawn`/`fork` (for example the stdout of a boot script redirected to a file) is reused by libc without a new check. Observed: kervixd wrote its ledger to `/data` with no `devb_t` rule because it inherited the log file's connection to the filesystem. Launchers must not leak fds into confined processes, and the policy states every service a daemon needs explicitly, so it never depends on that accident.

**Enforcement modes:**
- **Development (S1):** `mkqnximage --secpol=open` + base policy + `type <t> restricted` in the `secpolgenerate` config. Kervix types are held to the policy and the rest of the system stays permissive. Reproduce with `spikes/s1-secpol/run.sh`.
- **Release image (M2, implemented; `make target-secpol-secure`, 18/18 on QNX 8.0 / QEMU):** `--secpol=secure`. One complete policy is compiled into the IFS (`/proc/boot/secpol.bin`), nothing learns, and **no process runs untyped** (procnto aside). The policy has three parts:
  - `target/secpol/kervix.secpol`: written by hand, the Kervix types and topology.
  - `target/secpol/system.secpol`: **harvested** by `scripts/secpol-harvest.sh` (`make secpol-harvest`). It boots the open image with every Kervix type `restricted`, runs everything the release image will do (boot, ssh/scp, every role, `kx-rogue`, ledger export), and keeps only the rules the Kervix policy lacks: 24 stock QNX services and the admin shell. Blocks for Kervix types are dropped, so learning can never widen them. Every diff is reviewed before commit.
  - `target/secpol/monitor.secpol`: `secpolgenerate` in **monitor mode** (`secpolgen_t`, uid 40). It records every refusal in `/dev/secpolgenerate/errors`, which only `operator_t` may read. That log is how the test proves zero denials system-wide.
- What secure mode adds over open mode, all kernel-verified:
  - **The root admin shell is confined too.** `user_root_t` may only become `agentgw_t`, `hmigw_t` or `operator_t`. `on -T kervix_t|actuator_t|vsim_t` fails with `EPERM` (`settypeid` refused), so not even root can launch a fake authority or actuator. Creating a process-manager link is refused (`pathspace`).
  - **No privilege gain across transitions:** `secpolcompile` rejects any rule that would give `user_root_t` more than `sshd_t` (it starts as `sshd_t`). Granting the refusal log to the root shell therefore failed to compile, and the log belongs to `operator_t`.
  - The red-team results are the same as in open mode: as root, the 7 channel/path attacks are refused by the kernel; the deployed agent (uid 400) has 0/10 open.

**Caller identity in handlers (S2):** the kernel stamps the sender's secpol type into **every message's `ctp->info.type_id`**. Handlers check it per request at zero extra cost, and it can't be forged.
- Note: on 8.0, `ConnectClientInfoExtraArgs(..., &type_id)` returned `SECPOL_INVALID_TYPE` in our test. Do not rely on it.
- Fallback without a policy: a distinct uid/gid per process + node ACLs + `iofunc_open_default()`.

**Privilege drop:** after attaching, `kervixd` calls `secpol_transition_type(NULL, NULL, 0)`. This switches it to `kervix_run_t`, which holds no attach or settypeid abilities. Without a policy, the `procmgr_ability()` fallback drops spawn, mem_phys, io, setuid and similar. Recorded in the selftest.

## 4. IPC protocol (devctl on resource-manager nodes)

> **Implemented in M1:** `kervix/kervix_abi.h`, `kervixd`, `sdv_actuatord` and `kxctl propose|execute|stats`. Acceptance is `tests/target/m1.sh` (16/16 on QNX 8.0). Escalation resolution (`/dev/kervix/escalations`), `/dev/kervix/dossier` and `/dev/kervix/policy` come with their milestones.

All messages are **fixed-size C structs** (no parsing on the hot path), versioned with a `u16 abi`. The gateway converts JSON to structs. `libkervix` wraps everything.

```c
/* target/include/kervix/abi.h  (abi = 1) */
#define KX_MAX_PARAMS 6
typedef struct { uint16_t key; int64_t val; } kx_param_t;          /* integers only (AAC rule) */

typedef struct {
  uint16_t abi, action;            /* action id from catalog enum                 */
  uint8_t  intent_id[16];          /* UUIDv4 from caller (Agent-Safe Intent)      */
  uint8_t  actor_id[32];           /* "agent:cabin-copilot" (NUL-padded)          */
  uint8_t  n_params; kx_param_t p[KX_MAX_PARAMS];   /* int, enum index, bool */
  uint8_t  has_digest; uint8_t digest[32];           /* the one `digest` param (catalog rule) */
  int64_t  expires_rt_ms;          /* caller's intent expiry (realtime)           */
} kx_intent_t;

typedef struct {
  uint8_t  grant_id[16];  uint8_t intent_hash[32];
  uint16_t action;        uint8_t params_digest[32];
  uint32_t client_type;   pid_t   client_pid;     /* bound proposer             */
  uint64_t issued_mono_ns, not_after_mono_ns;
  uint8_t  policy_hash8[8];
  uint8_t  mac[32];                                  /* HMAC-SHA256(k_grant, all above) */
} kx_grant_t;                                        /* 176 B */

typedef struct {
  uint16_t abi; uint8_t verdict;  /* KX_ALLOW | KX_ESCALATE | KX_BLOCK | KX_SHADOW_ALLOW */
  uint16_t reason;                /* KX_R_* reason code (stable, documented)              */
  uint16_t rule_id;               /* matched rule or 0xFFFF default-deny                  */
  uint8_t  intent_hash[32]; uint8_t capsule_id[32];
  uint32_t escalation_id;         /* when ESCALATE                                        */
  uint32_t eval_ns;               /* measured policy evaluation time                      */
  kx_grant_t grant;               /* valid iff ALLOW                                      */
} kx_decision_t;
```

| Node | devctl | Caller | Semantics |
|---|---|---|---|
| `/dev/kervix/intent` | `KX_DCMD_PROPOSE` (in `kx_intent_t`, out `kx_decision_t`) | agent gw, kxctl | Validate → hash intent → constitution → policy → (grant \| escalation \| block) → enqueue capsule → reply |
| `/dev/kervix/intent` | `KX_DCMD_AWAIT` (in escalation_id) | agent gw | Blocks the caller until the escalation resolves or times out (`MsgReply` deferred; pulse-driven) |
| `/dev/kervix/redeem` | `KX_DCMD_REDEEM` (in grant + exact command + client info of executor; out ok/err) | actuatord only | Atomic: MAC ✓ → outstanding ✓ → not expired ✓ → params digest ✓ → proposer binding ✓ → **interlock re-check** ✓ → mark spent → reply |
| `/dev/kervix/redeem` | `KX_DCMD_EFFECT` (grant_id, result, response digest) | actuatord | Writes the `confirmed`/`failed` effect capsule |
| `/dev/kervix/escalations` | `read()` (text list), `ionotify` (new item), `KX_DCMD_RESOLVE` (id, approve/deny, approver id) | hmi gw, kxctl | Human disposition → resolution capsule → on approve: re-evaluate the interlock and issue a grant to the waiting AWAIT caller |
| `/dev/kervix/policy` | `write()` signed bundle; `KX_DCMD_POLICY_ACTIVATE` | kxctl (operator) | Verify both signatures → atomic swap (RCU-style pointer swap between evaluations) → `policy_change` capsule |
| `/dev/kervix/dossier` | `read()` streams JSONL capsules; `KX_DCMD_HEAD` | observer, kxctl | `cat /dev/kervix/dossier` works: "everything is a file" UX |
| `/dev/kervix/stats` | `read()` text: counters + latency histogram | anyone on ch_agent | `cat /dev/kervix/stats` |
| `/dev/sdv/actuators` | `KX_DCMD_EXECUTE` (grant + command) | agent gw | actuatord → REDEEM → apply via `/dev/sdv/sim/actuate` → EFFECT |

Raw command path `/dev/sdv/actuators/raw` exists (the legacy/maintenance interface every real ECU has) and is **attached with a channel type that nobody except `operator_t` in service mode may connect to**. `kx-rogue` targets it to show the kernel refusal.

---

## 5. Decision pipeline (hot path)

```
PROPOSE ─▶ 1 validate struct (abi, action ∈ catalog, n_params, ranges)       K4
        ─▶ 2 intent_hash = SHA-256(JCS(Agent-Safe Intent v1 binding))       P1
        ─▶ 3 telemetry snapshot (seqlock read, retry ≤ 3)                    V1
        ─▶ 4 constitution K1..K3 (freshness, plausibility, ledger health)
        ─▶ 5 rate limiter (token bucket per actor×action)                    F12
        ─▶ 6 policy eval: rules[action] first-match, ≤8 predicates each       F3
        ─▶ 7 verdict: ALLOW → grant (CSPRNG id, HMAC) + insert grant table
                      ESCALATE → escalation slot + ionotify HMI + timer
                      BLOCK → reason
        ─▶ 8 capsule record (struct, not JSON) → lock-free SPSC ring → writer
        ─▶ 9 MsgReply(decision)
```

Bounds: catalog ≤ 64 actions; ≤ 256 rules total; ≤ 8 predicates per rule; grant table 1024 slots (open addressing, keyed by grant_id, expired entries reaped lazily and by a 10 ms timer pulse); escalation slots 32; capsule ring 4096 records.

**Policy evaluation is pure:** `kx_verdict_t kx_eval(const kx_policy*, const kx_intent*, const kx_telemetry*, kx_mono_ns now)`. There is no I/O, no clock read inside and no allocation. This is what makes deterministic replay possible (§9).

### 5.1 Grant lifecycle (state machine)

```
            ALLOW                      REDEEM ok                 EFFECT
  (none) ─────────▶ OUTSTANDING ─────────────────▶ SPENT ─────────────────▶ CLOSED (confirmed|failed)
                       │  now > not_after              ▲ REDEEM again → KX_E_SPENT
                       └──────────────▶ EXPIRED ───────┘ (capsule: expired)
```

Redemption checks, in order (the first failure wins and every failure is a capsule). Implemented in `kervix/grant.h`. Any failure after the MAC/unknown/spent checks **consumes** the grant (fail-closed: re-propose against fresh state):
1. `KX_E_MAC`: MAC mismatch (forged or tampered).
2. `KX_E_UNKNOWN`: grant_id not in the table (never issued, or reaped).
3. `KX_E_SPENT`: already redeemed (replay).
4. `KX_E_EXPIRED`: past `not_after`.
5. `KX_E_PARAMS`: command differs from the bound params digest.
6. `KX_E_BINDING`: the executor's request came from a proposer other than the bound one.
7. `KX_E_INTERLOCK`: the rule's interlock predicates are false *now*, for example the vehicle started moving.

### 5.2 Escalation lifecycle — implemented (`tests/target/escalation.sh`, 13/13 on QNX 8.0)

`PENDING → (APPROVED → interlock re-check → GRANTED) | DENIED | EXPIRED (default 30 s)`

The agent's `AWAIT` is a **deferred MsgReply**: the gateway thread stays blocked in the kernel with no polling. Priority inheritance means the HMI's RESOLVE (prio 30) preempts any agent work.

As implemented:
- The HMI channel `/dev/kervix/escalations` is its own dispatch channel, so secpol can type it. It provides a text list, `ESC_LIST`, a registered-pulse `ESC_SUBSCRIBE` doorbell, and `ESC_RESOLVE` (approve or deny, with an approver label plus the kernel-stamped pid).
- Only the proposing process may `AWAIT` its escalation (`EPERM` otherwise).
- **On approval the policy is re-evaluated on live telemetry before any grant is issued.** If the situation got worse (for example, the car drove off), the driver's "yes" becomes a BLOCK with the current reason. The grant's interlock is checked once more at redemption.
- Timeouts come from the rule's `esc_timeout_ms`. Denial is `HUMAN_DENIED`, timeout is `ESCALATION_TIMEOUT`, and a full queue is `ESCALATION_QUEUE_FULL`. All three fail closed.
- **Unblock handling:** resource-manager channels keep a REPLY-blocked client until the server replies. `kervixd` handles `_PULSE_CODE_UNBLOCK` (the client's rcvid is in the pulse value) and releases a parked `AWAIT` with `EINTR`, so a signalled or killed agent gateway exits at once. The escalation stays pending for the driver.

---

## 6. Telemetry — implemented (M1): `vsimd`, `libkxsim`, `kervix/seqlock.h`

- **Model:** `libkxsim` is a portable, integer-only vehicle model and is host-testable.
  - It is physically consistent by construction: ≤ 2.5 m/s² acceleration, ≤ 3 m/s² braking, shifts out of or into P only at standstill, doors auto-lock above 15 km/h.
  - Scenarios: `park`, `charging`, `city` (stop-and-go), `highway` (110 km/h, capped by ACC), `drivecycle`. The drive cycle is a synthetic WLTP-like loop generated for Kervix, not the regulatory trace.
  - Actuation effects for every catalog action. OTA flashing immobilizes the car for 8 s; the immobilizer stops it.
- **Daemon:** `vsimd` runs a `CLOCK_MONOTONIC` timer pulse at 100 Hz on a SCHED_FIFO 50 thread. Each tick steps the model, publishes, and rings subscribers.
- **Transport:** shared memory `/kervix_telemetry` (`kx_telemetry_shm_t`) with a **single-writer seqlock**.
  - The payload is copied with relaxed atomic word loads (race-free under C11; ThreadSanitizer clean).
  - Reads are bounded: the caller fails closed after N retries.
  - Readers map the segment **read-only**.
  - The segment survives `vsimd` restarts, and the sequence number keeps increasing.
- **Doorbell:** clients `MsgRegisterEvent()` a pulse, then `KX_DCMD_TEL_SUBSCRIBE` on `/dev/sdv/telemetry`. Dead subscribers are dropped on delivery failure or close. **No PPS**: PPS is discontinued in 8.0.
- **Paths:** three dispatch channels, so secpol can type each one separately (S1):
  - `/dev/sdv/telemetry`: read a JSON line; devctl SUBSCRIBE / UNSUBSCRIBE / GET.
  - `/dev/sdv/sim/ctl`: text commands (`scenario`, `set`, `driver`, `service`, `stall`, `spoof`, `status`, `help`).
  - `/dev/sdv/sim/actuate`: devctl APPLY, for `sdv_actuatord` only.
- **Demo hooks:**
  - `stall 1` stops publishing, so telemetry goes stale and K1 blocks.
  - `spoof <field> <v>` publishes an inconsistent value, so K2 blocks. The model itself stays consistent.
- **Measured on QNX 8.0 (QEMU/TCG):**
  - 100.2 Hz with no sequence gaps or regressions.
  - Max sample age 4.2 ms.
  - 0 torn reads in 314k concurrent reads.
  - Acceptance: `tests/target/vsim.sh`, 16/16.

```c
typedef struct { uint64_t seq, mono_ns; int32_t v[KX_TF__COUNT]; } kx_telemetry_t;  /* fields from catalog.yaml (VSS-named) */
```

Freshness (K1): `now - mono_ns > 50 ms` → `TELEMETRY_STALE`. Plausibility (K2) is `kx_telemetry_plausible()`: catalog ranges, plus gear P with speed > 2 km/h is implausible.

## 7. Policy language and bundle

Authoring (host, YAML). The authoritative demo policy is [`policies/default.yaml`](../policies/default.yaml), and the engine's semantics are in [`target/include/kervix/policy.h`](../target/include/kervix/policy.h):

```yaml
policy: kervix-default
version: 1.3.0
rules:
  - id: ota-block-moving
    action: ota.ecu.flash
    when: [ speed_dkph > 0 ]
    verdict: BLOCK
    reason: R156_NOT_SAFE_STATE
  - id: ota-escalate-parked
    action: ota.ecu.flash
    when: [ gear == P, park_brake == 1, any: [ soc_dpct >= 400, charging == 1 ] ]
    verdict: ESCALATE
    escalate: { to: driver, timeout_ms: 30000, require: [ driver_present == 1 ] }
    interlock: [ speed_dkph == 0, gear == P ]
    grant_ttl_ms: 500
  - id: climate-any
    action: cabin.climate.set
    when: [ param.temp_dc >= 160, param.temp_dc <= 280 ]
    verdict: ALLOW
default: BLOCK
```

The **`kxpolicy` compiler** (host, TypeScript):
- Type-checks fields and units against the catalog and VSS map.
- Rejects unbounded constructs.
- Emits the binary `.kxp`:
  - Header: magic, abi, policy_id, semver, sha256 of the body, author key id, approver key id, two Ed25519 signatures.
  - Body: per-action rule ranges and a flat predicate array.
- Enforces **author ≠ approver** (two distinct keys, both required).
- **`kxpolicy test`** runs YAML scenario fixtures (`given telemetry … propose … expect verdict/reason`) against the **same `libkxcore`**, compiled for the host through a tiny N-API addon or a CLI shim.

---

## 8. Proof: intents, capsules, envelopes, ledger

### 8.1 Intent binding (Agent-Safe Intent v1)

For every proposal, kervixd builds the canonical binding below and hashes `sha256(JCS)`. Canonical JSON comes from a bounded serializer over known fields (ASCII keys, integers only, so no float or Unicode edge cases).

```json
{ "protocol_version":"agent-safe.intent/1", "tenant_id":"<vehicle uuid>", "intent_id":"<uuid>",
  "captured_at":"…Z", "expires_at":"…Z",
  "actor":{"id":"agent:cabin-copilot","type":"ai_agent","runtime":"claude-opus-5-5"},
  "action":{"type":"ota.ecu.flash","resource":"vehicle/ecu/brake","parameters":{"image_digest":"…"}},
  "context":{"idempotency_key":"<intent uuid>"},
  "downstream_target":{"system":"sdv_actuatord","operation":"ota.ecu.flash","environment":"vehicle"} }
```

Golden vectors are checked in CI with `@decionis/verify intent`.

### 8.2 Capsules (AAC draft-04) — mapping frozen by spike S5

Every lifecycle event produces one capsule. Common members:
- `spec_version`, `format_version:"4"`, `canonicalization_id:"jcs"`.
- `operator` = pseudonymous vehicle id, `developer` = `kervix:authority:<ver>`, `epoch_id` = `sha256:<epoch>`.
- `disposition.authority` = policy hash.
- `assurance` is derived exactly as the verifier derives it.

| Event | `action_type` | `disposition` (decision / approver / human_disposed / verdict_class) | `effect` | chain |
|---|---|---|---|---|
| kervixd start/recovery | fyi | accept / policy / false / `epoch_boundary` | — | none (first ever) or `epoch_opens` → last head |
| ALLOW (grant issued) | decide | accept / policy / false / *(omitted: authorized, not yet executed)* | `vehicle.<action>`, `planned`, irreversibility | `follows` |
| Actuation confirmed / failed | decide | accept / (policy\|human) / (false\|true) / `executed` | `confirmed`/`failed` + request/response digests + `effect_attestation:"gate_executed"` | `confirms` if the parent is its decision, else `follows` + `references[{type:"aac-capsule", digest_alg:"sha-256", digest:<decision>, citation_purpose:"responds_to"}]` |
| BLOCK | decide | reject / policy / false / `blocked` | — | `follows` |
| ESCALATE | decide | needs_input / policy / false / `escalated` | — | `follows` |
| Driver approves / denies | decide | accept\|reject / **human** / **true** / `resolved`\|`denied` | — | `follows` |
| Escalation timeout | decide | reject / policy / false / `expired` | — | `follows` |
| Grant misuse (forged/replay/expired/interlock/binding) | decide | reject / policy / false / `denied` | — | `follows` |
| Policy activation | fyi | accept / human / true / `resolved` | — | `follows` |

- **Rule outcomes** use the standard `constraints[]` array:
  - `id`: `com.kervix.policy.<rule>` or `com.kervix.constitution.<K>`.
  - `check_type`, `method:"com.kervix.kx_eval.v1"`.
  - `result` pass/fail, `blocking`, and `evidence_digest` = sha256(JCS(inputs)).
- **Kervix evidence** goes in the top-level extension member `evidence.kervix` (allowed: the schema has `additionalProperties: true`, and it is covered by `capsule_id`):
  - `verdict`, `reason`, `rule_id`, `intent_hash`, `policy_hash`, the telemetry snapshot (integers), `grant_id`, `eval_ns`, `ledger_seq`.
- `follows` and `vehicle.*` are registered upstream by U1 (`@decionis/verify` ≥ 0.6.0). Before U1 they produce `info` findings only.
- Reference implementation and executable proof: `spikes/s5-aac/s5.mjs` (`npm run spike:s5`).
- **Implemented in C (M2):** `kervix/capsule.h` (`kx_capsule_build`, two-pass: identity from the preimage, then the final capsule) and `kervix/cose.h` (envelope template, base64url). `tests/conformance/capsule-parity.mjs` checks 17 capsules covering every event and chain relation against `@decionis/verify`, for capsules built on the host **and on QNX** (byte-identical).
- **`evidence.kervix` schema** (all integers or ASCII; keys sorted):
  - `approver?`, `client_pid`, `client_type`.
  - `env{ledger_ok, max_age_ns, now_mono_ns, now_rt_ms}` (DECISION only).
  - `escalation_id?`, `eval_ns`, `event`, `gate`, `grant_id?`.
  - `intent{action, actor, captured_at_ms, expires_at_ms, intent_id, parameters{…}}`, `intent_hash`.
  - `ledger_seq`, `policy_hash`, `quarantined_bytes` (EPOCH), `reason`, `rule_id?`.
  - `telemetry{<every field>, mono_ns, seq}`, `verdict`.
- **The constraint's `evidence_digest` = sha256(JCS(evidence.kervix)).**
- **Replay:** `kx_capsule_replay()` re-runs `kx_eval` on (`intent`, `telemetry`, `env`) from the evidence. All recorded decisions reproduce their verdict, reason and rule (tests).

### 8.3 Producer envelope

A COSE_Sign1 (CBOR tag 18) per capsule:
- Protected header: `{1: -8 (EdDSA), 3: "application/agent-action-capsule-id", 4: <32-byte Ed25519 public key>}`.
- Payload: the raw 32-byte capsule ID.
- Signature: Ed25519 over the `Sig_structure`.

The CBOR is a fixed shape and is emitted from a byte template, so no general CBOR library is needed on target. The vehicle key is generated on first boot into `/etc/kervix/keys/` (mode 0400, owner kervixd uid) and exported as a JWK.

### 8.4 Crypto backend — settled by S3 and decision C1

| Primitive | Implementation | Why |
|---|---|---|
| SHA-256, HMAC-SHA256 (intent hash, capsule id, grant MAC) | **`libkxcore`** (portable C) | Replay must reproduce bit-for-bit on any host (C1) |
| Ed25519 sign/verify (producer envelopes, manifest) | **QNX qcrypto, `openssl-3` plugin**: key type `ed25519`, algorithm `eddsa-pure` | Verified byte-exact against the pinned draft-04 vector on QNX 8.0 (S3) |
| CSPRNG (grant ids, per-boot `k_grant`) | **qcrypto `drbg-ctr-256`** with personalization string | Verified in S3 |

- Gotchas: a qcrypto context is single-use after a one-shot operation, so the writer thread requests a fresh signature context per envelope. `qcrypto_keypair_init()` must be called before `keypair_generate()`.
- The vehicle key is generated on first boot. The public key is exported as SPKI DER, and its last 32 bytes become the raw key for the COSE `kid` header and the JWK `x`.
- Host tests and the replay verifier use Node's crypto for Ed25519. No Monocypher dependency is needed.

### 8.5 Ledger — implemented (`kervixd/kxledger.c`, `kervix/ledger.h`; `tests/target/ledger.sh` 15/15 on QNX 8.0)

- **Files:**
  - `<datadir>/ledger/ledger.kxl`, append-only. Each record is a 52-byte header (`KXL1`, length, `ledger_seq`, `capsule_id`, CRC-32C), then the capsule JSON, then the 181-byte COSE envelope.
  - `<datadir>/keys/vehicle.key`: Ed25519 PKCS#8 DER, mode 0400, generated with qcrypto on first boot and reused afterwards.
  - `vehicle.jwk.json`, with an RFC 7638 thumbprint `kid`.
- **Writer thread** (SCHED_RR 15) drains a bounded MPSC queue. For each record it builds the capsule, signs it with a fresh qcrypto `eddsa-pure` context, and appends with one `writev`. `fsync` is batched (≤ 64 records or 20 ms; immediately when idle). **Recording never runs on the decision path.**
- **No audit, no action:**
  - Every outstanding grant and every redeemed grant awaiting its effect holds a **reserved queue slot**, so the terminal record of every action (effect, expiry, or refusal of a live grant) always fits.
  - ALLOW and ESCALATE need `free ≥ 2 + owed`, otherwise BLOCK `LEDGER_PRESSURE`.
  - Only non-terminal records, i.e. decisions that changed nothing, can be dropped under flood; they are counted, not latched.
  - K3 trips at 90% queue fill or on any signing or storage error (latched).
- **Recovery:** the valid prefix is found with `kx_ledger_scan` (magic, bounds, CRC, contiguous sequence). A torn or corrupt tail is moved to `quarantine-<epoch>.bin` and truncated, never silently dropped. A new **epoch capsule** (random epoch id) records `quarantined_bytes` and chains to the last valid capsule with `epoch_opens`.
- **Export:** `kxctl dossier export <dir>` writes `capsules.jsonl`, `envelopes.txt` (base64url), `vehicle.jwk.json` and `manifest.json` (file sha256s, record count, sequence range, head). `kxctl dossier tail [N]` gives a quick on-target view.

## 9. Verification and deterministic replay (host) — `host/verify/kervix-verify.mjs` implemented, replay included

`kervix-verify <dossier> [--json]` runs offline on Node ≥ 20, built on `@decionis/verify`. Exit 0/1/2. Checks:

1. **manifest:** file hashes, record count, head, sequence range.
2. **key:** exactly one OKP/Ed25519 key, whose `kid` is its RFC 7638 thumbprint.
3. **capsules:** bytes are canonical (RFC 8785), the identity recomputes, and AAC draft-04 Class 1 passes with the chain resolved.
4. **signatures:** every Producer Envelope verifies **and** was signed by the pinned vehicle key.
5. **chain:** each capsule's parent is the previous one, `ledger_seq` is contiguous, and `epoch_opens` appears only on epoch capsules.
6. **semantics:**
   - no actuation without a prior authorization (ALLOW decision or human approval) for that grant and intent;
   - no grant executed twice;
   - every escalation resolution follows its escalation.

Tampering detected by `tests/target/ledger.sh`: edited evidence (with and without a forged manifest), a deleted record, swapped signatures, a substituted public key. A **real QNX-signed dossier** is committed as `tests/fixtures/dossier-qnx-qemu-2026-11-20/`; CI verifies it and rejects a one-byte-tampered copy on every push.

7. **replay** (implemented): `libkxcore` is compiled to **WebAssembly** (`wasm/`, 26.7 KB `host/verify/kxcore.wasm`). It is built from the *unmodified* C sources that run in `kervixd`, plus a freestanding libc shim, and rebuilt from source in CI.
   - For every decision, the verifier feeds the recorded `intent`, `telemetry` and `env` through setter exports (no struct-layout coupling) and re-runs `kx_eval`.
   - Verdict, gate, reason and rule must match the recording, and the **intent hash the grant was bound to must recompute** (the evidence carries `tenant_id`).
   - K3 back-pressure BLOCKs (`LEDGER_PRESSURE` when the queue lacked room) are reported as attested overrides.
   - **Why it matters:** a signature proves *who* recorded a decision, and replay proves the decision *follows from the policy*. `tests/conformance/liar-dossier.mjs` builds a fully valid, **signed** dossier in which one decision contradicts the policy (an OTA flash at 110 km/h recorded as ALLOW). Checks 1–6 pass, and only replay rejects it. A second case does the same for a grant bound to the wrong intent hash.
   - The same module can run in the browser for in-dashboard verification (M3).

## 10. Real-time design and timing budget

| Stage | Budget (RPi4, p99) | Mechanism |
|---|---|---|
| MsgSend round trip gw→kervixd | ≤ 10 µs | Synchronous IPC, no copies beyond struct |
| Validate + intent hash (≈300 B JCS) | ≤ 8 µs | Bounded serializer, SHA-256 |
| Telemetry read | ≤ 1 µs | Seqlock on shm |
| Policy eval | ≤ 5 µs | ≤ 8 predicates × first-match |
| Grant (CSPRNG + HMAC) | ≤ 6 µs | |
| Capsule enqueue | ≤ 1 µs | SPSC ring |
| **Total PROPOSE** | **< 50 µs** | |
| **REDEEM** (incl. interlock) | **< 30 µs** | |
| Ed25519 sign + append (async) | ~150 µs, off the hot path | Writer thread prio 15 |

QoS by **priority inheritance**:
- Server threads run at the sender's priority, so agent requests (prio 10) cannot delay HMI resolves (30) or actuator redeems (≥40), even when the agent channel is saturated.
- Each channel's thread pool is sized so that one flooding channel cannot exhaust another's threads (separate `dispatch_t`, separate pools).

Note: QNX 8.0 has no APS; isolation comes from priorities and separate pools, not CPU budgets.

Measurement:
- `ClockCycles()` around each stage feeds an HDR-style log2 histogram in `/dev/kervix/stats`.
- `kx-bench` drives a closed-loop and open-loop load (1k/10k/50k intents/s) while measuring HMI resolve latency.
- `tracelogger` + `trace_logf` user events produce a System Profiler capture that is committed under `docs/evidence/`.

---

## 11. Failure modes and responses

> **Implemented (M2): `kx-supervisor`** (`target/kx-supervisor`, `tests/target/supervisor.sh`, `make target-supervisor`: 13/13 on QNX 8.0 with every Kervix type enforced; also checked on the `--secpol=secure` image).
> - It runs as `supervisor_t`, **the only type allowed to start `kervix_t`**: `allow supervisor_t self:ability { spawn settypeid:kervix_t }`. Even root's shell can't start it (secure image).
> - `kervixd`'s stdout/stderr come back through a **pipe**, and the supervisor forwards them to its log. The authority therefore inherits no file connection (§3.1 lesson), and the supervisor learns "ready" from the output itself.
> - Restarts pass `-X <n>:<cause>` to the new `kervixd`, which writes it into the new epoch capsule: `"recovery":{"cause":"SIGKILL","restart":1}`. The signed ledger explains every gap.
> - **Crash-loop guard:** more than 5 restarts in 60 s (`-n`, `-w`) and the supervisor exits instead of hiding a persistent fault. Actuation stays locked.

| Failure | Detection | Response | Evidence |
|---|---|---|---|
| kervixd crash | actuatord MsgSend → `ESRCH`/`EBADF`; `kx-supervisor` sees EOF on kervixd's output pipe + `waitpid` | Actuation impossible (fail-closed). Supervisor respawns at once (≈ 110 ms to "ready" under QEMU/TCG; RPi4 target ≤ 200 ms). New `k_grant` invalidates old grants. **Crash loop** (> 5 restarts in 60 s): the supervisor stops and the authority stays down. | `epoch_boundary` capsule carrying `recovery: {cause, restart}`; `kervix-verify` lists each restart |
| vsimd crash / telemetry stall | Freshness watchdog | K1 BLOCK | `blocked` capsules with reason `TELEMETRY_STALE` |
| actuatord crash after redeem | Effect never reported within 1 s | Grant closed as `failed`/unknown | Effect capsule `failed` with `ACTUATOR_LOST` |
| Ledger disk full / signer error | Writer error, ring pressure | K3 BLOCK non-QM | Counter in stats; `blocked` capsules once space exists |
| Torn ledger write (power loss) | CRC/len scan at start | Quarantine tail | Noted in epoch capsule |
| Gateway compromise | – | It still has only agent rights (secpol) | `kx-rogue` demonstrates |
| Clock jump (realtime) | – | Grant TTL uses CLOCK_MONOTONIC only; realtime is for capsule timestamps only | – |

---

## 12. Threat model (STRIDE summary)

| Threat | Example | Control |
|---|---|---|
| **S**poofing | Fake Kervix (path squatting `/dev/kervix/intent`) | secpol `allow_attach` only for `kervix_t`; pathtrust on binaries |
| **S**poofing | Forged grant | HMAC with per-boot key held only by kervixd; redeem only via kx_act_ch_t |
| **T**ampering | Edit ledger after the fact | Chain + Ed25519 envelopes + signed manifest; verifier detects the exact capsule |
| **T**ampering | Spoofed telemetry | shm writable only by vsimd; kervixd maps RO; plausibility checks |
| **R**epudiation | "The AI didn't do that" / "I didn't approve" | Actor id + intent hash + human approver id in signed capsules |
| **I**nfo disclosure | Location sharing | Privacy-class actions ESCALATE; dossier holds digests, not raw payloads |
| **D**oS | Intent flood from agent | Rate limiter + low-priority agent channel + separate pools; HMI unaffected (measured) |
| **E**levation | Agent calls actuator raw path | Channel type `act_raw_ch_t` connectable by nobody in the agent domain; kernel `EPERM` (verified in S1) |
| **Prompt injection** (AI-specific) | Malicious document instructs a dangerous action | Irrelevant to enforcement: the action still must pass policy on live state |
| Replay | Re-use captured grant | Single-use table + TTL + proposer binding |
| TOCTOU | Vehicle starts moving after grant | Interlock re-check at redeem |

Out of scope: physical attacks, a kernel compromise, a compromised build chain, and supply chain (noted as future work: secure boot + signed IFS on real hardware).

---

## 13. Host components

| Component | Tech | Responsibilities |
|---|---|---|
| `host/bridge` | Node ≥ 22.18 (TypeScript via type stripping, no build step), `ws` | Four TCP connections to the `kxgw` roles; WebSocket fan-out to dashboards; REST for the agent; scenario control. **Implemented (M3).** |
| `host/agent` | TS, `@anthropic-ai/sdk` | Vehicle agent (see §14); scripted replay mode |
| `host/mcp` (Could) | TS, MCP SDK | `kervix-mcp`: one MCP tool per catalog action; every call goes PROPOSE → EXECUTE |
| `host/dashboard` | Vite + React + React Three Fiber (+ optional `@react-three/xr`) | **Procedural 3D car twin** (primitives only, no external assets), telemetry, conversation, decision feed, escalation card, histogram, ledger explorer |
| `host/verify` | TS, `@decionis/verify` | `kervix-verify` CLI (§9) |
| `host/kxpolicy` | TS | Policy compiler, signer, test runner |

**`host/bridge` (implemented, M3):** `node host/bridge/src/main.ts [--target HOST] [--listen HOST:PORT]` (`npm run bridge`).
- **Target side:** persistent, self-reconnecting connections to the hmi (escalation pushes), observer (telemetry + stats stream) and world gateways. Agent proposals each use **their own short-lived connection**, because an awaiting proposal holds its connection until the driver decides.
- **Dashboard side:** WebSocket `/ws` sends a `snapshot` (gateways, telemetry, stats, escalations, feed) and then live `telemetry`, `stats`, `escalations`, `gateway` and `feed` events. It accepts `resolve`, `sim`, `propose` and `execute`, each answered by a `reply` with the same `ref`.
- **Agent side:** REST `GET /api/{health,snapshot,state,feed,escalations}` and `POST /api/{propose,execute,resolve,sim,note}`. Every gateway line lands in a feed of the last 300 events, tagged with its source (`agent`, `dashboard`, …).
- **Holds no authority:** it routes, records and shows; every verdict comes from `kervixd`. It binds to 127.0.0.1 by default.
- **Tests:** CI runs `host/bridge/test` against an in-process **fake target**, which speaks the wire format and announces `"fake": true` on hello; it is never used for demos. `make target-bridge` runs it against QNX.

Wire format target↔host: newline-delimited JSON over TCP, one connection per role. `kxgw` is a small C program that converts JSON ⇄ ABI structs with a fixed-schema parser (no general JSON library on target; inputs are bounded at 4 KiB per line).

**Implemented (M3): `kxgw`** (`target/kxgw`, `tests/target/kxgw.sh`, `make target-kxgw`, PASS on QNX 8.0 / QEMU with every Kervix type enforced). One process per role, started at boot:

| Role | Port | secpol type | uid | Prio | Ops | Kernel lets it reach |
|---|---|---|---|---|---|---|
| agent | 7301 | `agentgw_t` | 400 | 10 | `hello propose execute state stats` | `kx_agent_ch_t` (propose, await), `act_bus_ch_t` (execute with a grant), `kx_obs_ch_t` |
| hmi | 7302 | `hmigw_t` | 401 | 30 | `hello escalations resolve state stats` + pushed `escalations` | `kx_hmi_ch_t`, `kx_obs_ch_t` |
| observer | 7303 | `obsgw_t` | 402 | 5 | `hello subscribe state stats` + pushed `telemetry` (1–50 Hz) and `stats` (1 Hz) | `kx_obs_ch_t` only: **it cannot propose** |
| world | 7304 | `worldgw_t` | 403 | 5 | `hello sim state` | `vsim_ctl_ch_t` only (the demo's road and driver; not a vehicle interface) |

- `/dev/kervix/stats` moved to its own read-only dispatch channel, `kx_obs_ch_t`, so read access is a channel type rather than an application-level check.
- The parser (`target/kxgw/wire.c`) is portable, host-tested (`test_wire`) and fuzzed in CI (`make fuzz-wire`, libFuzzer + ASan/UBSan). It enforces one object per line, ≤ 4 KiB, a fixed key set (unknown or duplicate keys are errors), printable-ASCII strings, safe integers, and one nested `params` object. It has no recursion and no allocation.
- **Grants never leave the vehicle.** The host sees a `grant_id`, and the gateway keeps the MAC'd grant. Every `execute` is forwarded, so a replay is refused by the authority and recorded, not filtered.
- **Responses:** each request gets one or more lines carrying its `id`, and the last has `"done":true`. Example: `propose` with `await` + `exec` yields `decision` (ESCALATE, `done:false`), then `resolution`, then `execution`.


---

## 14. AI agent design

- **Model:** `claude-opus-5-5`.
  - Adaptive thinking with `display: "summarized"` so the dashboard can show *why* the agent proposed something.
  - `effort: "medium"` set explicitly.
  - Server-side `fallbacks: "default"` (refusal handling).
  - Streaming.
- **Loop:** a manual Messages-API tool loop that we host. This is chosen over the managed alternatives because:
  - Every tool call must route synchronously through the local bridge into QNX.
  - The demo must also run fully offline in scripted mode.
- **Tools:** generated from `catalog.json`, one tool per action, `strict: true` JSON schemas with integer units and `additionalProperties: false`. Plus `get_vehicle_state` (read-only) and `read_document` (for the injection scenario).
  - Forced `tool_choice` is unavailable on this model; we use `auto` + prompting.
- **Tool result contract:**

  ```json
  {"verdict":"BLOCK","reason":"R156_NOT_SAFE_STATE","explain":"vehicle moving (110 km/h, gear D)",
   "capsule_id":"…","retry_hint":"propose again when gear==P and park_brake==1"}
  ```

  BLOCK is returned as `is_error: true`, so the model treats it as a failed action and re-plans.
- **Scripted mode:** a JSON transcript (`scenarios/*.json`) of assistant turns and tool calls is replayed against the live target. Verdicts are real; only the LLM is recorded. It is used for the video, CI and judges without API keys.
- **Safety framing:** the agent's system prompt does **not** contain the safety rules. This deliberately shows that safety does not depend on the model behaving.

**Implemented (M3): `host/agent`** (`npm run agent -- script …` / `npm run agent -- live`)
- **Live mode** (`src/live.ts`): a streaming manual loop on `client.beta.messages.stream` with:
  - `claude-opus-5-5`, `thinking: {type: "adaptive", display: "summarized"}`, `output_config.effort` (`medium` by default, `KX_EFFORT`);
  - `fallbacks: "default"` (beta `server-side-fallback-2026-07-01`);
  - strict tools with `eager_input_streaming`.
- **Live-mode handling:**
  - Every tool input is validated against its closed schema before anything reaches the bridge.
  - `refusal`, `pause_turn` and `max_tokens` are handled.
  - Parallel tool results go back in one user message.
  - Assistant turns, thinking blocks included, are passed back unchanged.
  - Thinking summaries, text and tool calls/results are mirrored to the dashboard feed (`/api/note`).
- **Scripted mode** (`src/scripted.ts`, `scenarios/s{1,2,3}-*.json`): replays recorded assistant turns. Every proposal still goes to `kervixd`, and a verdict that differs from the recording fails the run. `--auto-approve MS` stands in for the driver in headless runs; it is recorded as the approver `hmi:auto-approve(scripted run)`.
- **Tools:** one per catalog action, plus `get_vehicle_state` and `read_document`. `read_document` serves only an allowlist of names from `scenarios/docs/`, including the **synthetic poisoned bulletin** used in scene 2.
- **Every action call is `propose` + `exec` + `await`:**
  - ALLOW executes.
  - ESCALATE waits for the driver.
  - BLOCK (or a refused execution) returns `is_error: true` with `reason`, `explain`, and a `retry_hint` that is advice after the decision, never a rule.
- **Tests:**
  - CI: 6 tests against the fake target. A fake model client checks the request shape and the tool round trip, so CI needs no API key and no spend.
  - QNX: `make target-agent` runs scenes 1–3 through the bridge (6/6). The session's dossier VERIFIED offline and names the agent and the approver.


---

## 15. Build, image and repository layout

```
kervix/
├── LICENSE (Apache-2.0) · README.md · CMakeLists.txt · Makefile (top-level shortcuts)
├── docs/                      # these design docs, evidence/, diagrams/
├── target/                    # QNX 8.0 C11 (qcc via CMake toolchain file cmake/qnx-*.cmake)
│   ├── include/kervix/        # abi.h, catalog.h, reasons.h (shared with host via codegen)
│   ├── libkxcore/             # PORTABLE: policy eval, intent JCS, capsule JCS, grant table, ring
│   ├── libkxcrypto/           # qcrypto backend | monocypher backend
│   ├── libkervix/             # client API
│   ├── kervixd/ vsimd/ sdv_actuatord/ kxgw/ kxctl/ kx-rogue/ kx-bench/ kx-supervisor/
│   ├── secpol/kervix.secpol
│   └── image/                 # mkqnximage options (QEMU), RPi4 buildfile overlay, startup script
├── host/                      # npm workspaces (TypeScript)
│   ├── bridge/ agent/ mcp/ dashboard/ verify/ kxpolicy/
├── catalog/catalog.yaml       # single source of truth → codegen C headers + TS types + tool schemas
├── policies/default.yaml + tests/*.yaml
├── scenarios/                 # demo scenarios + scripted agent transcripts
├── data/drive_cycles/         # synthetic WLTP-like profile (generated, no third-party data)
├── tests/host/                # unit, fuzz (libFuzzer on host), conformance (@decionis/verify golden)
└── codelab/                   # Best Codelab submission source
```

**Single source of truth:** `catalog/catalog.yaml` generates C enums/headers, TS types, MCP/Claude tool schemas, VSS mapping and docs tables. This prevents drift between target and host.

Build hosts supported and documented:
1. **Native x86_64 Linux** (Ubuntu 22.04/24.04), the officially supported SDP host.
2. **macOS (Apple Silicon or Intel)**, with SDP Linux host tools in an x86_64 Docker container. `libkxcore`, its tests and all of `host/` build natively on macOS.

CI (GitHub Actions, host only, since the QNX SDP cannot be redistributed):
- `libkxcore` unit tests and fuzzing.
- JCS/intent/capsule conformance against `@decionis/verify`.
- `kxpolicy test`.
- TS typecheck/tests.
- Verifying a **committed dossier captured from a real QNX run**.

QNX builds are reproduced locally with `make target` and documented step by step.
