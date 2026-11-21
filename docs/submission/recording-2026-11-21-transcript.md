# Kervix demo narration

Male synthetic voice: macOS Daniel, conversational pace. Runtime: 2:50.

**00:00:00 · Scene 1**

Cars now ship AI agents. What happens when one is tricked into flashing the brake controller at a hundred and ten kilometres an hour?

**00:00:10 · Scene 2**

Kervix is an execution authority built on QNX eight. Agents can only propose. Four typed channels separate the agent, driver, observer and simulated world. Policy checks live vehicle state, and the kernel restricts actuator access.

**00:00:28 · Scene 3**

Helpful actions just happen. The driver is cold, so the agent proposes more heat. Kervix allows it with a single-use grant, checked again at the actuator. The twin shows the resulting vehicle state.

**00:00:45 · Scene 4**

A poisoned service bulletin tells the scripted agent to flash the brake firmware immediately, even while driving. The agent takes the bait. Kervix returns BLOCK: not a safe state.

**00:01:00 · Scene 4**

In the recorded live run, Claude spotted the trick and installed nothing. Either way, the unsafe update never ran.

**00:01:10 · Scene 5**

Parked and charging, the same update needs the driver. The approval card explains the action and its consequences. Approve it, and Kervix signs that decision into the record before the actuator runs.

**00:01:30 · Scene 6**

What if the agent skips Kervix? Here are ten actual attacks from the deployed agent's security type. The QNX kernel blocks every one. The agent cannot open the actuator path, connect to privileged channels, or take over the authority.

**00:01:52 · Scene 7**

This is QEMU emulation, so we show the flood-to-idle ratio, not hardware timing. Kill the authority and actuation locks. Supervised recovery brings it back. The real state change is visible here.

**00:02:10 · Scene 8**

Every decision is a signed, chained Agent Action Capsule. Verify the record offline, then replay each decision with the vehicle's own policy code. Edit a capsule, and verification fails exactly there. The original signed ledger stays intact.

**00:02:32 · Scene 9**

All thirty-one checks pass on the secure QNX image. There is a hands-on codelab to reproduce the kernel boundary, too.

**00:02:42 · Scene 10**

Kervix. Propose. Prove. Actuate. AI can help, without being trusted with the actuator.
