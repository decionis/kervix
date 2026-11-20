import assert from "node:assert/strict";
import { test } from "node:test";

import catalog from "../../shared/catalog.gen.json" with { type: "json" };
import { driverText, shortRef } from "../src/driverText.ts";

test("the OTA request reads as a driver would want it", () => {
  const t = driverText(
    { action: "ota.ecu.flash", actor: "agent:cabin-copilot", params: { ecu: "brake", image_digest: "sha256:9f2c4e1ab07d3c58e6f1a2b4c8d0e7f3a5b6c9d1e2f4a7b8c0d3e5f6a1b2c4d7" } },
    "DRIVER_CONSENT", "Requires the driver's explicit consent.");
  assert.equal(t.action, "Install a software update on the brake controller");
  assert.equal(t.why, "Requires your consent.");
  assert.equal(t.requester, "your in-car assistant");
  assert.equal(t.reference, "9F2C-4E1A");
  assert.match(String(t.consequence), /stays parked.*can't be undone/);
});

test("second person everywhere, no system vocabulary", () => {
  const params: Record<string, Record<string, unknown>> = {
    "cabin.climate.set": { temp_dc: 215 }, "cabin.window.set": { window: "rear_left", pos_pct: 100 }, "body.door.unlock": { door: "front_left" },
    "light.hazard.set": { on: true }, "adas.acc.set_speed": { target_kph: 125 }, "battery.charge_limit.set": { pct: 90 },
    "telematics.location.share": { recipient: "fleet_operator", duration_s: 3600 }, "diag.dtc.clear": { ecu: "powertrain" },
    "vehicle.immobilizer.engage": {}, "chassis.brake.calibration.write": { ecu: "brake", blob_digest: "sha256:" + "ab".repeat(32) },
    "ota.ecu.flash": { ecu: "bms", image_digest: "sha256:" + "01".repeat(32) },
  };
  for (const a of catalog.actions) {
    for (const reason of ["DRIVER_CONSENT", "WINDOW_HIGH_SPEED", "SPEED_DELTA_LARGE"]) {
      const t = driverText({ action: a.name, actor: "agent:x", params: params[a.name] ?? {} }, reason);
      const all = [t.action, t.why, t.consequence ?? ""].join(" ");
      assert.doesNotMatch(all, /sha256|_|\bdriver's\b|\bthe driver\b|[a-z]+\.[a-z]+\.[a-z]+/i, `${a.name}: ${all}`);
    }
  }
  assert.equal(driverText({ action: "telematics.location.share", actor: "agent:x", params: { recipient: "fleet_operator", duration_s: 3600 } }, "DRIVER_CONSENT").action,
    "Share your car's location with your fleet operator for 1 hour");
  assert.equal(driverText({ action: "cabin.window.set", actor: "agent:x", params: { window: "rear_left", pos_pct: 100 } }, "WINDOW_HIGH_SPEED").why,
    "You're driving fast; a wide-open window needs your OK.");
  assert.equal(shortRef("nonsense"), null);
});
