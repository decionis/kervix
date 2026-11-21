// Procedural 3D twin of the simulated vehicle: primitives only (no external
// assets, no brand). It renders telemetry, i.e. what the vehicle reports, never
// what the agent asked for: an action shows up here only after Kervix allowed
// it, the actuator applied it, and vsimd published the new state.
//   x = forward, y = up, z = left (right-handed)
// WebXR (optional, X6): "Enter VR" / "View in AR" appear only on a device with
// WebXR. The twin is built in metres, so in a headset it stands life-size on the
// floor, 4 m in front of you, with a beacon above it for the latest decision.
// XR is view-only: driver approvals stay on the HMI card, where they are explained.
import { ContactShadows, OrbitControls, RoundedBox } from "@react-three/drei";
import { Canvas, useFrame } from "@react-three/fiber";
import { IfInSessionMode, XR, XROrigin, createXRStore } from "@react-three/xr";
import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";

import type { Tel } from "./model.ts";

// ?xr=emulate (localhost only): a Meta Quest 3 emulator (IWER), for development without a headset.
// Installed here with forceInstall: desktop Chrome exposes a navigator.xr without any device, and
// IWER >= 2.8 will not replace it otherwise (so the library's own `emulate` option never starts).
const EMULATE = typeof location !== "undefined" && location.hostname === "localhost" && new URLSearchParams(location.search).get("xr") === "emulate";
const xrStore = createXRStore({ offerSession: false, emulate: false });
if (EMULATE) {
  void import("iwer").then(({ XRDevice, metaQuest3 }) => {
    new XRDevice(metaQuest3).installRuntime({ forceInstall: true });
    window.dispatchEvent(new Event("kx-xr-emulator"));
  });
}

/** Which immersive modes this browser offers; re-checked when a device (or the emulator) appears. */
function useXRSupport(): { vr: boolean; ar: boolean } {
  const [s, set] = useState({ vr: false, ar: false });
  useEffect(() => {
    let live = true;
    const check = () => {
      const xr = typeof navigator !== "undefined" ? navigator.xr : undefined;
      if (!xr) return;
      void Promise.all([xr.isSessionSupported("immersive-vr").catch(() => false), xr.isSessionSupported("immersive-ar").catch(() => false)])
        .then(([vr, ar]) => { if (live) set({ vr, ar }); });
    };
    check();
    window.addEventListener("kx-xr-emulator", check);
    navigator.xr?.addEventListener("devicechange", check);
    return () => { live = false; window.removeEventListener("kx-xr-emulator", check); navigator.xr?.removeEventListener("devicechange", check); };
  }, []);
  return s;
}

const BODY = "#5a6f8f";
const GLASS = "#16283a";
const STATUS_GOOD = "#0ca30c";
const STATUS_CRITICAL = "#d03b3b";
const AMBER = "#fab219";
const BLUE = "#3987e5";

type Verdict = "ALLOW" | "ESCALATE" | "BLOCK";
type Props = { tel: Tel | null; offline: boolean; verdict?: Verdict | null; pending?: number };

function hvacColor(dc: number): THREE.Color {
  // 16.0 °C cool blue -> 28.0 °C warm orange
  const t = Math.min(1, Math.max(0, (dc - 160) / 120));
  return new THREE.Color("#3987e5").lerp(new THREE.Color("#ec835a"), t);
}

function Wheel({ x, z, spin }: { x: number; z: number; spin: React.RefObject<number> }) {
  const ref = useRef<THREE.Group>(null);
  useFrame(() => {
    if (ref.current) ref.current.rotation.z = -spin.current;
  });
  return (
    <group position={[x, 0.38, z]}>
      <group ref={ref}>
        <mesh rotation={[Math.PI / 2, 0, 0]} castShadow>
          <cylinderGeometry args={[0.38, 0.38, 0.28, 32]} />
          <meshStandardMaterial color="#111" roughness={0.9} />
        </mesh>
        {/* hub with spokes so rotation is visible */}
        <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, z > 0 ? 0.15 : -0.15]}>
          <cylinderGeometry args={[0.22, 0.22, 0.02, 5]} />
          <meshStandardMaterial color="#9aa3ad" metalness={0.6} roughness={0.3} />
        </mesh>
      </group>
    </group>
  );
}

function Door({ x, z, locked, windowPct }: { x: number; z: number; locked: boolean; windowPct: number }) {
  const side = z > 0 ? 1 : -1;
  // the pane retracts into the door: its visible part shrinks from the top
  const open = Math.min(100, Math.max(0, windowPct)) / 100;
  const paneH = Math.max(0.001, 0.42 * (1 - open));
  return (
    <group position={[x, 0, z]}>
      <mesh position={[0, 0.68, 0]} castShadow>
        <boxGeometry args={[1.08, 0.58, 0.04]} />
        <meshStandardMaterial color={BODY} metalness={0.4} roughness={0.45} />
      </mesh>
      {/* side window: lowers with the reported position */}
      <mesh position={[0, 0.99 + paneH / 2, -side * 0.08]} visible={open < 0.99}>
        <boxGeometry args={[0.92, paneH, 0.02]} />
        <meshStandardMaterial color={GLASS} transparent opacity={0.78} metalness={0.2} roughness={0.05} />
      </mesh>
      {/* lock light on the handle */}
      <mesh position={[0.3, 0.82, side * 0.03]}>
        <sphereGeometry args={[0.045, 16, 16]} />
        <meshStandardMaterial color={locked ? STATUS_CRITICAL : STATUS_GOOD} emissive={locked ? STATUS_CRITICAL : STATUS_GOOD} emissiveIntensity={1.4} />
      </mesh>
    </group>
  );
}

function Vehicle({ tel }: { tel: Tel | null }) {
  const t = tel ?? {};
  const speed = (t.speed_dkph ?? 0) / 36; // m/s
  const spin = useRef(0);
  const road = useRef<THREE.Group>(null);
  const body = useRef<THREE.MeshStandardMaterial>(null);
  const halo = useRef<THREE.Mesh>(null);
  const hazards = useRef<THREE.MeshStandardMaterial[]>([]);
  const charge = useRef<THREE.MeshStandardMaterial>(null);
  const beacon = useRef<THREE.Mesh>(null);
  const cabin = useRef<THREE.PointLight>(null);
  const flashing = t.ota_state === 1;

  useFrame((_, dt) => {
    const now = performance.now() / 1000;
    spin.current += (speed / 0.38) * dt;
    if (road.current) road.current.position.x = -((now * speed) % 4);
    const blink = Math.sin(now * 2 * Math.PI * 1.5) > 0;
    for (const m of hazards.current) if (m) m.emissiveIntensity = t.hazard_on ? (blink ? 3.2 : 1.2) : 0.4;
    if (body.current) body.current.emissiveIntensity = flashing ? 0.35 + 0.35 * Math.sin(now * 6) : 0;
    if (halo.current) {
      halo.current.visible = flashing;
      halo.current.rotation.z = now * 1.5; // in-plane spin (x is already -PI/2: lying flat)
    }
    if (charge.current) charge.current.emissiveIntensity = t.charging ? 1.2 + Math.sin(now * 3) : 0;
    if (beacon.current) {
      beacon.current.visible = t.location_shared === 1;
      const s = 1 + ((now * 0.8) % 1) * 3;
      beacon.current.scale.set(s, 1, s);
    }
    if (cabin.current) cabin.current.color = hvacColor(t.hvac_setpoint_dc ?? 210);
  });

  const lanes = useMemo(() => Array.from({ length: 14 }, (_, i) => -26 + i * 4), []);
  const mask = t.doors_locked_mask ?? 15;
  const win = [t.window_fl_pct ?? 0, t.window_fr_pct ?? 0, t.window_rl_pct ?? 0, t.window_rr_pct ?? 0];

  return (
    <group>
      {/* road: lane marks scroll with the reported speed */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
        <planeGeometry args={[60, 14]} />
        <meshStandardMaterial color="#242422" roughness={1} />
      </mesh>
      <group ref={road}>
        {lanes.map((x) => (
          <group key={x}>
            {[-2.6, 2.6].map((z) => (
              <mesh key={z} position={[x, 0.005, z]} rotation={[-Math.PI / 2, 0, 0]}>
                <planeGeometry args={[2, 0.12]} />
                <meshStandardMaterial color="#8a8984" />
              </mesh>
            ))}
          </group>
        ))}
      </group>

      {/* body + cabin */}
      <RoundedBox args={[4.4, 0.62, 1.86]} radius={0.18} position={[0, 0.66, 0]} castShadow>
        <meshStandardMaterial ref={body} color={BODY} emissive={BLUE} emissiveIntensity={0} metalness={0.5} roughness={0.4} />
      </RoundedBox>
      <RoundedBox args={[2.3, 0.56, 1.66]} radius={0.22} position={[-0.25, 1.22, 0]} castShadow>
        <meshStandardMaterial color={GLASS} transparent opacity={0.55} metalness={0.3} roughness={0.1} />
      </RoundedBox>
      <pointLight ref={cabin} position={[-0.2, 1.15, 0]} intensity={2.2} distance={2.2} />

      {/* doors: FL, FR, RL, RR (bit i of doors_locked_mask) with their windows */}
      <Door x={0.45} z={0.95} locked={(mask & 1) !== 0} windowPct={win[0]} />
      <Door x={0.45} z={-0.95} locked={(mask & 2) !== 0} windowPct={win[1]} />
      <Door x={-0.7} z={0.95} locked={(mask & 4) !== 0} windowPct={win[2]} />
      <Door x={-0.7} z={-0.95} locked={(mask & 8) !== 0} windowPct={win[3]} />

      {/* lights: front white / rear red; both blink amber with the hazards */}
      {[1, -1].map((s, i) => (
        <mesh key={s} position={[s * 2.21, 0.78, 0]}>
          <boxGeometry args={[0.04, 0.1, 1.5]} />
          <meshStandardMaterial ref={(m) => { if (m) hazards.current[i] = m; }} color={t.hazard_on ? AMBER : s > 0 ? "#e8e6df" : "#7a1d1d"} emissive={t.hazard_on ? AMBER : s > 0 ? "#e8e6df" : STATUS_CRITICAL} emissiveIntensity={0.4} />
        </mesh>
      ))}

      {/* charge port (left rear) */}
      <mesh position={[-1.75, 0.8, 0.94]}>
        <cylinderGeometry args={[0.08, 0.08, 0.03, 24]} />
        <meshStandardMaterial ref={charge} color="#1c3a1c" emissive={STATUS_GOOD} emissiveIntensity={0} />
      </mesh>

      {/* OTA flashing halo */}
      <mesh ref={halo} position={[0, 0.05, 0]} rotation={[-Math.PI / 2, 0, 0]} visible={flashing}>
        <ringGeometry args={[2.6, 2.75, 64, 1, 0, Math.PI * 1.6]} />
        <meshBasicMaterial color={BLUE} transparent opacity={0.85} />
      </mesh>
      {/* immobilizer ring */}
      {t.immobilizer_on === 1 && (
        <mesh position={[0, 0.03, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[2.9, 3.0, 64]} />
          <meshBasicMaterial color={STATUS_CRITICAL} />
        </mesh>
      )}
      {/* location sharing beacon */}
      <mesh ref={beacon} position={[-0.3, 1.52, 0]} visible={t.location_shared === 1}>
        <torusGeometry args={[0.12, 0.012, 8, 32]} />
        <meshBasicMaterial color={BLUE} transparent opacity={0.8} />
      </mesh>

      <Wheel x={1.38} z={0.86} spin={spin} />
      <Wheel x={1.38} z={-0.86} spin={spin} />
      <Wheel x={-1.38} z={0.86} spin={spin} />
      <Wheel x={-1.38} z={-0.86} spin={spin} />
    </group>
  );
}

/* XR only: what Kervix decided last, by shape AND colour (never colour alone):
 * ALLOW = ring, ESCALATE = slowly turning diamond (waiting for the driver), BLOCK = cross.
 * Authority offline: a cross over a red floor ring (actuation locked). */
function DecisionBeacon({ verdict, pending, offline }: { verdict: Verdict | null; pending: number; offline: boolean }) {
  const spin = useRef<THREE.Group>(null);
  const shown: Verdict | null = offline ? "BLOCK" : pending > 0 ? "ESCALATE" : verdict;
  useFrame((_, dt) => { if (spin.current) spin.current.rotation.y = shown === "ESCALATE" ? spin.current.rotation.y + dt * 0.8 : 0; });
  if (!shown) return null;
  const color = shown === "ALLOW" ? STATUS_GOOD : shown === "ESCALATE" ? AMBER : STATUS_CRITICAL;
  return (
    <group position={[0, 2.35, 0]}>
      <group ref={spin}>
        {shown === "ALLOW" && (
          <mesh>
            <torusGeometry args={[0.22, 0.05, 12, 48]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.6} />
          </mesh>
        )}
        {shown === "ESCALATE" && (
          <mesh>
            <octahedronGeometry args={[0.24]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.6} />
          </mesh>
        )}
        {shown === "BLOCK" && [Math.PI / 4, -Math.PI / 4].map((r) => (
          <mesh key={r} rotation={[0, 0, r]}>
            <boxGeometry args={[0.56, 0.1, 0.1]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.6} />
          </mesh>
        ))}
      </group>
      {offline && (
        <mesh position={[0, -2.32, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[3.2, 3.35, 64]} />
          <meshBasicMaterial color={STATUS_CRITICAL} />
        </mesh>
      )}
    </group>
  );
}

export function CarTwin({ tel, offline, verdict = null, pending = 0 }: Props) {
  const { vr, ar } = useXRSupport();
  return (
    <>
      <Canvas shadows camera={{ position: [5.2, 3.0, 5.6], fov: 38 }} style={{ filter: offline ? "grayscale(0.85) brightness(0.6)" : undefined }}>
        <XR store={xrStore}>
          <IfInSessionMode deny="immersive-ar">
            <color attach="background" args={["#1a1a19"]} />
          </IfInSessionMode>
          <hemisphereLight args={["#dfe7f2", "#1a1a19", 1.1]} />
          <directionalLight position={[6, 9, 4]} intensity={2.4} castShadow shadow-mapSize={[1024, 1024]} />
          <directionalLight position={[-6, 4, -5]} intensity={0.8} />
          <Vehicle tel={tel} />
          <ContactShadows position={[0, 0.01, 0]} opacity={0.5} scale={12} blur={2.4} far={3} />
          <IfInSessionMode deny={["immersive-vr", "immersive-ar"]}>
            <OrbitControls enablePan={false} minDistance={5} maxDistance={14} maxPolarAngle={Math.PI / 2.1} target={[0, 0.7, 0]} />
          </IfInSessionMode>
          <IfInSessionMode>
            {/* you stand 4.2 m to the car's left, facing it */}
            <XROrigin position={[0, 0, 4.2]} />
            <DecisionBeacon verdict={verdict} pending={pending} offline={offline} />
          </IfInSessionMode>
          <IfInSessionMode allow="immersive-vr">
            <gridHelper args={[20, 20, "#3a3a38", "#2a2a28"]} position={[0, 0.002, 0]} />
          </IfInSessionMode>
        </XR>
      </Canvas>
      {(vr || ar) && (
        <div className="xrbar">
          {vr && <button onClick={() => void xrStore.enterVR()} title="See the twin life-size in a headset (view only)">Enter VR</button>}
          {ar && <button onClick={() => void xrStore.enterAR()} title="Place the twin life-size in your room (view only)">View in AR</button>}
        </div>
      )}
    </>
  );
}
