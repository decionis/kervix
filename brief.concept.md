Kervix

Project : Kervix: Kernel-Native Execution Governance for Software-Defined Vehicles
* Target Category: Automotive & Mobility (with direct alignment for the Best use of QNX-specific Technologies bonus prize)
* The Problem: Modern Software-Defined Vehicles (SDVs) increasingly rely on autonomous AI agents for diagnostics, cabin automation, and over-the-air (OTA) management. However, if an AI agent hallucinates or is compromised, a single unverified command—such as triggering an ECU firmware flash while driving or altering brake-by-wire calibration at highway speeds—can cause catastrophic safety failures. Standard middleware lacks deterministic, kernel-enforced authorization and tamper-proof auditability at the actuator boundary.
* The Solution: We built /dev/decionis, a native QNX 8.0 C/C++ Resource Manager that acts as an execution-authority firewall between untrusted AI vehicle agents and safety-critical vehicle actuators (/dev/sdv_actuators). Using QNX’s synchronous message-passing IPC (MsgSend/devctl), every proposed vehicle action is evaluated in microseconds against real-time vehicle telemetry (speed, gear, battery SoC, driver presence). Safe actions receive a time-bound, single-use cryptographic Execution Grant (ALLOW), risky actions require human sign-off (ESCALATE), and unsafe commands are dropped at the kernel boundary (BLOCK). Every decision is recorded into a SHA-256 hash-chained Decision Dossier that can be exported and cryptographically verified offline using Decionis (@decionis/verify).
* Why QNX + Decionis Wins:
    * True QNX Microkernel Architecture: Rather than bolting on heavy containers or Node.js runtimes, /dev/decionis runs as an isolated, zero-allocation QNX resource manager leveraging native resmgr_attach(), POSIX file descriptors, and deterministic IPC.
    * Cryptographic Accountability Meets Real-Time Safety: Pairing QNX 8.0’s microsecond determinism with Decionis’s single-use execution grants and hash-chained Decision Dossiers eliminates replay attacks, prevents unauthorized actuation, and provides OEMs with an offline-verifiable black-box audit trail for regulatory compliance.


By building the native /dev/decionis Resource Manager first and using a simulated Software-Defined Vehicle (SDV) control loop as your client workload, you avoid heavy hypervisor/Node.js dependencies inside QEMU while proving real-world automotive safety value.

Unified Architecture for QEMU

￼



Why This Hybrid Wins on QEMU
* Zero Heavy Runtimes on Target: Everything on QNX 8.0 compiles into tiny, fast C/C++ binaries using the QNX Momentics/SDP toolchain, booting in seconds inside QEMU.
* True QNX-Native Architecture: Implementing /dev/decionis using resmgr_attach(), iofunc_func_init(), and synchronous MsgSend/MsgReceive IPC showcases QNX's microkernel design far better than standard POSIX sockets.
* Compelling Live Demo: You can run a simple CLI or web dashboard on your host machine (bridged to QEMU via virtio-net) acting as an AI diagnostic agent sending vehicle commands—showing real-time ALLOW (e.g., adjusting cabin climate at 60 mph), BLOCK (e.g., triggering OTA firmware flash while in DRIVE), and ESCALATE (requiring driver confirmation), followed by offline verification of the exported Decision Dossier.

Build Roadmap
1. Build /dev/decionis : Set up a standard QNX C/C++ resource manager handling io_write (to receive JSON/struct action intents) and io_devctl (to verify grants and fetch audit logs).
2. Implement Grant & Dossier Logic: Add deterministic policy evaluation (checking mock vehicle telemetry like gear == PARK and speed == 0), single-use nonce tracking (preventing replay attacks), and SHA-256 hash chaining for the Decision Dossier.
3. Create the SDV Simulator & Host Bridge: Build a second lightweight QNX process representing the vehicle actuator bus that refuses commands unless accompanied by a valid grant token issued by /dev/decionis, plus a small Python/Node script on your host to drive demo scenarios and run @decionis/verify on the exported logs.
4. VR dashboard modeling vehicle responding to AI agent commands received

