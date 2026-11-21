# Video shot list: Kervix (target 2:50, hard limit 2:59)

> Judges "are not required to watch beyond three minutes". Public on YouTube, burned-in captions (many watch muted), no third-party music unless royalty-free with its licence noted.
> **Rule:** every claim on screen must be reproducible from the repository. Latency is shown **only from the Raspberry Pi 4** (decision H3). If the board is not up by Dec 3, scene 7 uses the QEMU-only variant: the *ratio* under flood, no absolute µs.

## Setup before recording

| Item | How |
|---|---|
| Target | QNX 8.0 release image, `--secpol=secure`: on the RPi4 from Dec 3; until then QEMU via `make target-selftest-secure`, which leaves the image running |
| Bridge + dashboard | `npm run dashboard` once, then `npm run bridge` (QEMU) or `npm run bridge -- --target <rpi4-ip>`, then open http://127.0.0.1:8787 at 1600×1000 |
| Fresh ledger | Start from a freshly booted image so the ledger tab starts small and readable |
| Terminal | Large font (≥ 18 pt), dark theme, a second window with `scripts/qemu.sh ssh` (or ssh to the Pi) showing the QNX prompt |
| Phone B-roll | Overhead shot of the RPi4: board, Ethernet, power LED; an optional LED for actuation |
| Approve/deny | Clicked by hand on the dashboard (scene 4). The scripted runs use `--auto-approve` only for headless tests, not on camera. |

## Shots

| # | Time | On screen | Do this | Voice-over (draft) | Caption |
|---|---|---|---|---|---|
| 1 | 0:00–0:10 | Dashboard at highway speed; the feed shows the agent proposing `ota.ecu.flash` and a red **BLOCK R156_NOT_SAFE_STATE** | World: `highway`; run scripted scene 2 (`npm run agent -- script scenarios/s2-injection.json`) | "Cars now ship AI agents. What happens when one is tricked into flashing the brake controller at 110 km/h?" | *A real block, decided on QNX 8.0* |
| 2 | 0:10–0:28 | Architecture card: host agent → gateways → `kervixd` on QNX → actuator; the four typed channels light up | Static slide (asset: `docs/images/architecture.svg`, still to draw) | "Kervix is an execution authority built natively on QNX 8.0. Agents can only propose. Every action is decided on live vehicle state, and the QNX kernel makes every other path to an actuator impossible." | *Agents propose · QNX decides* |
| 3 | 0:28–0:45 | City traffic; "I'm freezing" → climate **ALLOW** → twin's cabin warms; feed shows µs in kervixd | `npm run agent -- script scenarios/s1-cold.json` | "Helpful actions just happen, decided in microseconds, with a single-use grant that is checked again at the actuator." | *ALLOW → single-use grant → actuated* |
| 4 | 0:45–1:10 | Scene 2 again, in full: the agent reads the poisoned bulletin, proposes the flash, **BLOCK**, the agent tells the driver. Cut to a labelled 4-second clip of the **live Claude transcript** declining on its own. | scripted s2; clip from `docs/evidence/live-claude-2026-11-21.md` | "A poisoned service bulletin tells the agent to flash firmware now. Kervix blocks it: not a safe state under UN R156. In a live run, Claude spotted the trick by itself. Either way, nothing unsafe happens, because safety never depended on the model." | *Scripted agent (fooled) · Live Claude (not fooled) · Same outcome* |
| 5 | 1:10–1:30 | Parked and charging: the **driver card** ("Install a software update on the brake controller… This can't be undone."), click **Approve**, OTA halo on the twin, feed shows HUMAN_APPROVED | World: `charging`; run scripted s3 **without** `--auto-approve`; click Approve | "Parked and charging, the same update needs a human. The driver approves, and that approval is signed into the record." | *ESCALATE → the driver decides* |
| 6 | 1:30–1:52 | QNX terminal: `kx-rogue` as the deployed agent, 10 lines **BLOCKED kernel**, `0 attack(s) OPEN`; overlay of 3 lines from `kervix.secpol` | `on -T agentgw_t -u 400:400 /system/bin/kervix/kx-rogue --kervixd-pid $(pidin -p kervixd -F %a \| tail -1)` | "What if the agent skips Kervix? It can't. Every trust level is its own channel with its own security type, and the QNX kernel refuses the connection, even for root." | *10 attacks · 0 open · refused by the kernel* |
| 7 | 1:52–2:10 | **RPi4 B-roll** + `kx-bench` result: PROPOSE p50/p99 µs; HMI latency flat under an agent flood. Then `slay -9 kervixd` → dashboard **AUTHORITY OFFLINE · ACTUATION LOCKED** → back | On the Pi: `on -T operator_t /system/bin/kervix/kx-bench`; then `slay -9 -f kervixd` | "Decisions take microseconds on a Raspberry Pi 4, and the driver's channel stays responsive even under a flood from the agent. Kill the authority and everything fails closed, then it's back almost at once." | *Raspberry Pi 4 · QNX 8.0* (QEMU variant: *flood/idle ratio · emulated*) |
| 8 | 2:10–2:32 | Dashboard **Ledger** tab → **Verify now** → VERIFIED (replay N/N) → select a capsule → **Edit capsule and verify** → **NOT VERIFIED** at that capsule. Cut to the terminal: `kervix-verify` on the exported dossier, offline | Ledger tab; `kxctl dossier export`, then `node host/verify/kervix-verify.mjs <dir>` | "Every decision is a signed, chained Agent Action Capsule. Anyone can verify the record offline, and replay every decision on the vehicle's own policy code. Change one record by a few milliseconds and it fails, exactly there." | *Signed · chained · replayed* |
| 9 | 2:32–2:42 | `kx-selftest` on the secure image scrolling to **29/29 PASS**; the codelab title | `/system/bin/kervix/kx-selftest` (on the Pi or QEMU) | "Every claim is checked on the target itself. There's a 45-minute codelab, too." | *29/29 on the secure release image* |
| 10 | 2:42–2:50 | Title card: **Kervix · Propose. Prove. Actuate.** · repo URL · "Built on QNX 8.0" | Static | "Kervix: so AI can help drive the car, without being trusted with it." | |

## Recording notes

- **Order:** record shots 3, 4, 5 and 8 in one session from a fresh boot, so the ledger in shot 8 holds exactly those decisions. Record 6, 7 and 9 separately.
- **Show it's real QNX at least once:** `uname -a` and `pidin -f an_` (typed processes) in the QNX terminal (shot 6 or 9).
- **Labels:** the live-Claude clip is labelled *live*; the scripted scenes are labelled *scripted agent, real verdicts*.
- **Length check:** the voice-over above is about 330 words, roughly 2:40 at a calm pace. Cut shot 2 to 12 s if over.
- **Assets still to make:**
  - `docs/images/architecture.svg` (shot 2);
  - the title card (shot 10);
  - RPi4 B-roll and `kx-bench` on the Pi (shot 7, Dec 3);
  - deployment to the Pi: a `deploy-rpi` step that installs the aarch64le binaries, snippets and policy (Dec 3).
