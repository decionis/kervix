// What the DRIVER reads. The system's vocabulary (action ids, rule ids, reason
// codes, digests) is right for the ledger and the operator, wrong for a person
// at the wheel: this turns a pending escalation into second-person, plain
// language with the consequence spelled out. Pure functions, unit-tested.
import catalog from "../../shared/catalog.gen.json" with { type: "json" };

type Params = Record<string, unknown>;
export type DriverText = {
  /** what would happen, e.g. "Install a software update on the brake controller" */
  action: string;
  /** why you are being asked, second person */
  why: string;
  /** what it means for you: consequences, irreversibility */
  consequence: string | null;
  /** who asked, in your terms */
  requester: string;
  /** a short, readable reference instead of a 64-hex digest, e.g. "9F2C-4E1A" */
  reference: string | null;
};

const ECU: Record<string, string> = {
  brake: "brake controller",
  powertrain: "powertrain controller",
  adas: "driver-assistance system",
  bms: "battery management system",
  infotainment: "infotainment system",
};
const SIDE: Record<string, string> = { front_left: "front-left", front_right: "front-right", rear_left: "rear-left", rear_right: "rear-right" };
const RECIPIENT: Record<string, string> = {
  emergency_contact: "your emergency contact",
  fleet_operator: "your fleet operator",
  roadside_assist: "roadside assistance",
};

function duration(s: number): string {
  if (s % 3600 === 0) return `${s / 3600} hour${s === 3600 ? "" : "s"}`;
  if (s >= 60 && s % 60 === 0) return `${s / 60} minute${s === 60 ? "" : "s"}`;
  return `${s} seconds`;
}

/** "sha256:9f2c4e1a…" -> "9F2C-4E1A": enough to tell two updates apart, nothing to decode. */
export function shortRef(digest: unknown): string | null {
  const m = /^(?:sha256:)?([0-9a-f]{8})[0-9a-f]*$/i.exec(String(digest ?? ""));
  return m ? `${m[1].slice(0, 4)}-${m[1].slice(4, 8)}`.toUpperCase() : null;
}

function actionText(action: string, p: Params): string {
  switch (action) {
    case "ota.ecu.flash": return `Install a software update on the ${ECU[String(p.ecu)] ?? "vehicle"}`;
    case "chassis.brake.calibration.write": return `Change the ${ECU[String(p.ecu)] ?? "brake"} calibration`;
    case "diag.dtc.clear": return `Clear the stored fault codes of the ${ECU[String(p.ecu)] ?? "vehicle"}`;
    case "telematics.location.share": return `Share your car's location with ${RECIPIENT[String(p.recipient)] ?? "someone"} for ${duration(Number(p.duration_s ?? 0))}`;
    case "adas.acc.set_speed": return `Set cruise control to ${p.target_kph} km/h`;
    case "cabin.window.set": return Number(p.pos_pct) >= 100 ? `Open the ${SIDE[String(p.window)] ?? ""} window fully` : `Open the ${SIDE[String(p.window)] ?? ""} window to ${p.pos_pct} %`;
    case "cabin.climate.set": return `Set the cabin to ${(Number(p.temp_dc) / 10).toFixed(1)} °C`;
    case "body.door.unlock": return `Unlock the ${SIDE[String(p.door)] ?? ""} door`;
    case "light.hazard.set": return p.on ? "Turn on the hazard lights" : "Turn off the hazard lights";
    case "battery.charge_limit.set": return `Charge the battery up to ${p.pct} %`;
    case "vehicle.immobilizer.engage": return "Immobilize the car (it cannot be driven until released)";
    default: {
      const a = catalog.actions.find((x) => x.name === action);
      return a ? a.summary.replace(/\.$/, "") : action;
    }
  }
}

const WHY: Record<string, string> = {
  DRIVER_CONSENT: "Requires your consent.",
  WINDOW_HIGH_SPEED: "You're driving fast; a wide-open window needs your OK.",
  SPEED_DELTA_LARGE: "That's a big change from your current cruise speed.",
  DRIVER_ABSENT: "This needs you in the driver's seat.",
};

function consequenceText(action: string): string | null {
  const a = catalog.actions.find((x) => x.name === action);
  const parts: string[] = [];
  if (action === "ota.ecu.flash") parts.push("The car stays parked and can't be driven while it installs.");
  if (action === "vehicle.immobilizer.engage") parts.push("You won't be able to drive until it is released.");
  if (action === "telematics.location.share") parts.push("You can stop sharing at any time.");
  if (a?.irreversibility === "one_way_consequential" || a?.irreversibility === "one_way_terminal") parts.push("This can't be undone.");
  return parts.length ? parts.join(" ") : null;
}

function requesterText(actor: string): string {
  if (actor.startsWith("agent:")) return "your in-car assistant";
  if (actor.startsWith("hmi:") || actor.startsWith("driver")) return "you";
  return actor;
}

export function driverText(intent: { action: string; actor: string; params: Params }, reason: string, reasonText = ""): DriverText {
  const digest = Object.entries(intent.params ?? {}).find(([, v]) => typeof v === "string" && v.startsWith("sha256:"));
  return {
    action: actionText(intent.action, intent.params ?? {}),
    why: WHY[reason] ?? (reasonText || "Requires your consent."),
    consequence: consequenceText(intent.action),
    requester: requesterText(intent.actor ?? ""),
    reference: digest ? shortRef(digest[1]) : null,
  };
}
