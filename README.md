# Kervix

**Kernel-enforced execution authority for software-defined vehicles, on QNX 8.0.**

AI agents *propose* vehicle actions. Kervix decides in microseconds, on live vehicle state, whether each action is **ALLOWED** (single-use grant), **ESCALATED** to the driver, or **BLOCKED**. QNX security policies make every other path to an actuator impossible at the kernel's IPC layer. Every decision becomes an Ed25519-signed, chained [Agent Action Capsule](docs/03-architecture.md#82-capsules-aac-draft-04--mapping-frozen-by-spike-s5) that anyone can verify, and replay, offline.

**Propose. Prove. Actuate.**

> 🚧 Under active development for the QNX Global Hackathon (Nov 20 – Dec 15, 2026). See [`docs/`](docs/README.md) for the design and [`docs/progress.md`](docs/progress.md) for status.

## Quick start (host-only parts)

```bash
npm ci
make test      # portable C core + unit tests, codegen check, AAC/COSE conformance vs @decionis/verify
```

QNX 8.0 target build and run: see [docs/setup-macos.md](docs/setup-macos.md) (macOS) or the Linux notes there. Full build/run instructions (QNX version, QEMU x86_64 and Raspberry Pi 4 targets, toolchain) will land here before submission.

## License

Apache-2.0. See [LICENSE](LICENSE).
