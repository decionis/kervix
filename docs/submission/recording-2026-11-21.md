# Kervix demo recording — 21 November 2026

The **2:50 QEMU edition** follows the ten time ranges in [video-shot-list.md](video-shot-list.md). It uses the real dashboard and QNX target, male synthetic narration at conversational pace, burned-in captions, and no music. [Watch the public video on YouTube](https://youtu.be/QaLS1neHT2s), published on the Decionis channel on 21 November with an English (United Kingdom) subtitle track and the title-card thumbnail. Raspberry Pi footage and physical-headset testing remain pending.

## Delivery

The local delivery directory is `out/submission-2026-11-21/` (ignored by Git):

- `Kervix-Demo.mp4` — 1920×1080, 30 fps, H.264, Rec.709, AAC stereo at 48 kHz, fast-start MP4, under 100 MB.
- `Kervix-Demo.srt` — the same text as the burned-in captions.
- `Transcript.md` — exact narration, with scene timestamps.
- `ContactSheet.jpg` and `GalleryContactSheet.jpg` — inspection frames and gallery overview.
- `Manifest.json`, `VideoVerification.json`, `Provenance.md` — source timeline, output hash, delivery checks and edit notes.

The transcript, subtitles and compact recording receipt are also retained beside this document for review. The source captures and assembly script are retained locally under the `KervixSubmission20261121` operations directory.

## Edit and source map

| Time | Scene | Source and observation |
|---|---|---|
| 0:00–0:10 | Hook | Actual highway BLOCK; excerpt of the same recorded scenario shown in scene 4 |
| 0:10–0:28 | Architecture | [architecture.svg](../images/architecture.svg), with the four gateway roles highlighted in turn |
| 0:28–0:45 | Helpful action | Scripted cold-driver scenario, actual ALLOW and executed 22.5°C setpoint |
| 0:45–1:10 | Injection | Actual scripted BLOCK; four-second, explicitly labelled excerpt from the separately recorded live Claude transcript |
| 1:10–1:30 | Driver approval | Actual 30-second approval card, dashboard Approve clicked while pending, HUMAN_APPROVED and OTA halo |
| 1:30–1:52 | Kernel boundary | Actual `uname`, selected `pidin` rows and ten `kx-rogue` refusals, reformatted for readability; three actual secpol rules |
| 1:52–2:10 | Flood and recovery | Recorded QEMU flood/idle ratio; real authority-offline and supervised-recovery capture |
| 2:10–2:32 | Evidence | Verify original seven-capsule ledger, edit only verification copy #4 and reject it, then actual offline verifier output |
| 2:32–2:42 | Self-test / codelab | Actual 31/31 target self-test result and [codelab](../../codelab/README.md) title |
| 2:42–2:50 | Close | [title-card.svg](../images/title-card.svg), repository URL, QNX and QEMU disclosure |

Browser capture frames are sampled using their capture timestamps, then presented at 30 fps. The 1600×1000 dashboard is scaled to 1728×1080 with 96-pixel side padding; critical verdicts and the approval card remain visible. Two-line captions are balanced and placed over the bottom demo-control area, away from approvals and vehicle-state values.

The authority-offline frame is held for **1.6 seconds** so its message can be read; the video explicitly labels that hold. The displayed recovery interval is therefore not a timing measurement. Terminal output is faithfully reformatted; the full logs retain all rows and timings. Committed text logs trim trailing whitespace; untouched originals are retained with the source captures. Selected process rows and omitted timing columns are labelled.

The narration is **macOS Daniel**, a synthetic male voice. No cloned voice, third-party music, stock vehicle footage or generated product screen is used. The opening sentence is slowed without shifting pitch; the other narration runs at its generated conversational pace.

## Gallery

The refreshed PNGs are direct captures of the live local dashboard, except for the close crop of the driver card and the captured WebXR emulator canvas. Higher-contrast flat surfaces, brighter car lighting, antialiasing and sharper contact shadows are implemented in the dashboard itself. There is no artificial gradient laid over the capture. The grayscale/dimming effect when authority is offline is retained because it communicates the real locked state.

The UI clearly labels **QNX 8.0 · QEMU emulation** and omits absolute emulated policy latency from the histogram and event feed. The WebXR image is from a Meta Quest 3 emulator, not a physical headset.

The WebXR recapture also exposed an offscreen contact-shadow pass rendering through the XR camera. Contact shadows now run only in the regular dashboard view; directional shadows remain in XR. The corrected emulator capture uses a closer, unsaved headset pose with the emulated controllers disconnected so they do not obscure the car. The 1340×860 PNG is a direct crop of that canvas, and the full dashboard capture is retained as `XrCorrectedContext.png` in the operations directory.

See the [signed record and target results](../evidence/demo-2026-11-21/README.md) for the three decisions, publication of `@decionis/verify@0.6.1`, ten kernel refusals, flood result and 31-check self-test.
