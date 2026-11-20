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

### 3.1 Per-channel secpol types (the core QNX bonus feature)

`kervixd` creates **four dispatch channels** (four `dispatch_t`, each with its own fixed-size thread pool). Each path is attached with `secpol_resmgr_attach()`, and the policy assigns a **channel type per path**:

```
# target/secpol/kervix.secpol (sketch — exact grammar validated in [SPIKE-1])
type kervix_t; type vsim_t; type actuator_t; type agentgw_t; type hmigw_t;
type obsgw_t; type operator_t; type supervisor_t;
type kx_agent_ch_t; type kx_act_ch_t; type kx_hmi_ch_t; type kx_admin_ch_t; type act_bus_ch_t;

allow_attach kervix_t   { /dev/kervix/intent /dev/kervix/dossier /dev/kervix/stats
                          /dev/kervix/redeem /dev/kervix/escalations /dev/kervix/policy };
allow_attach vsim_t     { /dev/sdv/telemetry /dev/sdv/sim/actuate };
allow_attach actuator_t { /dev/sdv/actuators };

# channel typing: path -> channel type
channel kervix_t /dev/kervix/intent      kx_agent_ch_t;
channel kervix_t /dev/kervix/redeem      kx_act_ch_t;
channel kervix_t /dev/kervix/escalations kx_hmi_ch_t;
channel kervix_t /dev/kervix/policy      kx_admin_ch_t;
channel actuator_t /dev/sdv/actuators    act_bus_ch_t;

allow { agentgw_t hmigw_t obsgw_t operator_t } kx_agent_ch_t:channel connect;
allow actuator_t                               kx_act_ch_t:channel connect;
allow { hmigw_t operator_t }                   kx_hmi_ch_t:channel connect;
allow operator_t                               kx_admin_ch_t:channel connect;
allow { agentgw_t operator_t }                 act_bus_ch_t:channel connect;
allow actuator_t  vsim_t:channel connect;       # /dev/sdv/sim/actuate — ONLY actuator moves the car
allow kervix_t    vsim_t:channel connect;       # telemetry
```

Result: an agent-type process that tries to `open("/dev/kervix/redeem")`, `open("/dev/sdv/sim/actuate")` or attach `/dev/kervix/intent` is refused **by procnto**. That is the "kernel boundary" claim, made true.

**Defence in depth inside handlers:** each handler also checks the client's secpol type id, obtained with `ConnectClientInfoExt(..., _NTO_CLIENTINFO_GETTYPEID)` **[SPIKE-2]**. Fallback if it is unavailable: a distinct uid/gid per process + node ACLs + `iofunc_open_default()` permission checks.

**Privilege drop:** after attaching, `kervixd` calls `secpol_transition_type()` and `procmgr_ability()` to drop spawn, mem_phys, io, setuid and similar. Recorded in the selftest.

---

## 4. IPC protocol (devctl on resource-manager nodes)

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

Redemption checks, in order (the first failure wins and every failure is a capsule):
1. `KX_E_MAC`: MAC mismatch (forged or tampered).
2. `KX_E_UNKNOWN`: grant_id not in the table (never issued, or reaped).
3. `KX_E_SPENT`: already redeemed (replay).
4. `KX_E_EXPIRED`: past `not_after`.
5. `KX_E_PARAMS`: command differs from the bound params digest.
6. `KX_E_BINDING`: the executor's request came from a proposer other than the bound one.
7. `KX_E_INTERLOCK`: the rule's interlock predicates are false *now*, for example the vehicle started moving.

### 5.2 Escalation lifecycle

`PENDING → (APPROVED → interlock re-check → GRANTED) | DENIED | EXPIRED (default 30 s)`

The agent's `AWAIT` is a **deferred MsgReply**: the gateway thread stays blocked in the kernel with no polling. Priority inheritance means the HMI's RESOLVE (prio 30) preempts any agent work.

---

## 6. Telemetry

- `vsimd` runs a 100 Hz `timer_create` with pulse delivery. Each tick integrates the vehicle model (drive-cycle replay or scenario-directed) and publishes a `kx_telemetry_t` snapshot.
- **Transport:** `shm_open("/kervix_telemetry")` holding a **seqlock** (even/odd sequence). vsimd maps it RW. kervixd maps it **read-only** (`PROT_READ`). After each publish, vsimd sends a pulse to subscribers registered via `/dev/sdv/telemetry` devctl `SUBSCRIBE` (sigevent registered with `MsgRegisterEvent` **[SPIKE-1]**).
- **No PPS:** PPS is discontinued in QNX 8.0.

```c
typedef struct {
  uint64_t seq, mono_ns;
  int32_t  speed_dkph;        /* Vehicle.Speed ×10 */
  uint8_t  gear;              /* Vehicle.Powertrain.Transmission.SelectedGear: P R N D */
  uint8_t  park_brake;        /* Vehicle.Chassis.ParkingBrake.IsEngaged */
  int16_t  soc_dpct;          /* Vehicle.Powertrain.TractionBattery.StateOfCharge.Current ×10 */
  uint8_t  charging, driver_present, service_mode, doors_locked_mask;
  int16_t  cabin_temp_dc; uint8_t window_pos_pct[4]; int16_t acc_target_kph;
} kx_telemetry_t;
```

Freshness: `now - mono_ns > 50 ms` → `TELEMETRY_STALE` (K1). Plausibility (K2): gear∈{P} ∧ speed>2 kph; |Δspeed| > physical max per tick; seq not monotonic; SoC outside range.

---

## 7. Policy language and bundle

Authoring (host, YAML):

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

### 8.3 Producer envelope

A COSE_Sign1 (CBOR tag 18) per capsule:
- Protected header: `{1: -8 (EdDSA), 3: "application/agent-action-capsule-id", 4: <32-byte Ed25519 public key>}`.
- Payload: the raw 32-byte capsule ID.
- Signature: Ed25519 over the `Sig_structure`.

The CBOR is a fixed shape and is emitted from a byte template, so no general CBOR library is needed on target. The vehicle key is generated on first boot into `/etc/kervix/keys/` (mode 0400, owner kervixd uid) and exported as a JWK.

### 8.4 Crypto backend

`kx_crypto.h` abstracts SHA-256, HMAC-SHA256, Ed25519 sign and CSPRNG:
- **Target:** QNX **qcrypto** (`openssl-3` provider) **[SPIKE-3]**. Fallback: vendored **Monocypher** (CC0/BSD-2, allocation-free).
- **Host tests:** OpenSSL or Monocypher.

The grant key `k_grant` comes from 32 bytes of CSPRNG output at each start, which invalidates every outstanding grant on restart (fail-closed).

### 8.5 Ledger

- **Ledger file:** `/var/kervix/ledger/<epoch>.kxl`, append-only. Each record is `[u32 len][u32 crc32c][capsule JSON][u16 env_len][COSE bytes]`, written with `fsync` batching (≤ 20 ms or 64 records).
- **Restart:** scan the tail. A torn record is truncated into `quarantine/` and its offset is noted in the `epoch_boundary` capsule. The last valid capsule_id becomes the chain parent.
- **Writer thread** (prio 15): drains the SPSC ring, serializes JCS, computes capsule_id, signs and appends. Ring > 90% full sets the `LEDGER_PRESSURE` flag, which trips K3, and new non-QM actions get BLOCK. This is "no audit, no action".
- **Export:** `kxctl export` writes `dossier/` containing:
  - `capsules.jsonl`
  - `envelopes.b64` (one per line)
  - `vehicle.jwk.json`
  - `policy/*.kxp` + their YAML source
  - `telemetry/` (snapshots referenced by capsules)
  - `manifest.json` (file sha256s, head capsule id, Ed25519-signed)

---

## 9. Verification and deterministic replay (host)

`kervix-verify dossier/` (TypeScript, Node ≥ 18, offline) runs these checks:

1. **Capsule identity and Class 1:** `verifyAgentActionCapsuleV04Class1(capsule, {known_capsules})` for every capsule.
2. **Signatures:** `verifyAgentActionCapsuleProducerEnvelope(cose, capsule_id)`; the public key must equal the pinned `vehicle.jwk.json`.
3. **Chain:** one linear stream, no gaps, `epoch_opens` only after a gap, and `ledger_seq` strictly increasing.
4. **Semantic invariants:**
   - Every `confirmed` effect has an earlier accepting decision with the same `intent_hash` and `grant_id`.
   - No `grant_id` is executed twice.
   - No effect follows a `blocked` decision for the same intent.
   - Every human resolution precedes its grant.
5. **Replay:** for each decision capsule, load the policy bundle with that `policy_hash` and call `libkxcore` `kx_eval()` with the recorded intent and telemetry. The verdict, reason and rule must be byte-identical.
   - Delivery: a native helper first; a WASM build of `libkxcore` (freestanding C → `wasm32`) is the stretch, so the dashboard can do the same in-browser.
6. **Report:** a human table plus `--json`. Exit code 0/1/2, matching `@decionis/verify` conventions.

---

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

| Failure | Detection | Response | Evidence |
|---|---|---|---|
| kervixd crash | actuatord MsgSend → `ESRCH`/`EBADF`; supervisor `waitpid` | Actuation impossible (fail-closed). Supervisor respawns ≤ 200 ms. New `k_grant` invalidates old grants. | `epoch_boundary` capsule with gap info |
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
| **E**levation | Agent calls actuator raw path | Channel type `act_raw_ch_t` connectable by nobody in the agent domain; kernel `EACCES` |
| **Prompt injection** (AI-specific) | Malicious document instructs a dangerous action | Irrelevant to enforcement: the action still must pass policy on live state |
| Replay | Re-use captured grant | Single-use table + TTL + proposer binding |
| TOCTOU | Vehicle starts moving after grant | Interlock re-check at redeem |

Out of scope: physical attacks, a kernel compromise, a compromised build chain, and supply chain (noted as future work: secure boot + signed IFS on real hardware).

---

## 13. Host components

| Component | Tech | Responsibilities |
|---|---|---|
| `host/bridge` | Node 20, TS, `ws` | Three TCP connections to `kxgw` roles; WebSocket fan-out to dashboard; REST for agent/MCP; scenario control |
| `host/agent` | TS, `@anthropic-ai/sdk` | Vehicle agent (see §14); scripted replay mode |
| `host/mcp` (Could) | TS, MCP SDK | `kervix-mcp`: one MCP tool per catalog action; every call goes PROPOSE → EXECUTE |
| `host/dashboard` | Vite + React + React Three Fiber (+ optional `@react-three/xr`) | **Procedural 3D car twin** (primitives only, no external assets), telemetry, conversation, decision feed, escalation card, histogram, ledger explorer |
| `host/verify` | TS, `@decionis/verify` | `kervix-verify` CLI (§9) |
| `host/kxpolicy` | TS | Policy compiler, signer, test runner |

Wire format target↔host: newline-delimited JSON over TCP, one connection per role. `kxgw` is a small C program that converts JSON ⇄ ABI structs with a fixed-schema parser (no general JSON library on target; inputs are bounded at 4 KiB per line).

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
