// Procedural 3D twin of the simulated vehicle: primitives only (no external
// assets, no brand). It renders telemetry, i.e. what the vehicle reports, never
// what the agent asked for: an action shows up here only after Kervix allowed
// it, the actuator applied it, and vsimd published the new state.
//   x = forward, y = up, z = left (right-handed)
import { ContactShadows, OrbitControls, RoundedBox } from "@react-three/drei";
import { Canvas, useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

import type { Tel } from "./model.ts";

const BODY = "#5a6f8f";
const GLASS = "#16283a";
const STATUS_GOOD = "#0ca30c";
const STATUS_CRITICAL = "#d03b3b";
const AMBER = "#fab219";
const BLUE = "#3987e5";

type Props = { tel: Tel | null; offline: boolean };

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
  const drop = (Math.min(100, Math.max(0, windowPct)) / 100) * 0.42;
  return (
    <group position={[x, 0, z]}>
      <mesh position={[0, 0.68, 0]} castShadow>
        <boxGeometry args={[1.08, 0.58, 0.04]} />
        <meshStandardMaterial color={BODY} metalness={0.4} roughness={0.45} />
      </mesh>
      {/* side window: lowers with the reported position */}
      <mesh position={[0, 1.26 - drop, -side * 0.08]}>
        <boxGeometry args={[0.92, 0.42, 0.02]} />
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
    for (const m of hazards.current) if (m) m.emissiveIntensity = t.hazard_on ? (blink ? 3 : 0.1) : 0.4;
    if (body.current) body.current.emissiveIntensity = flashing ? 0.35 + 0.35 * Math.sin(now * 6) : 0;
    if (halo.current) {
      halo.current.visible = flashing;
      halo.current.rotation.y = now * 1.5;
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
          <meshStandardMaterial ref={(m) => { if (m) hazards.current[i] = m; }} color={s > 0 ? "#e8e6df" : "#7a1d1d"} emissive={t.hazard_on ? AMBER : s > 0 ? "#e8e6df" : STATUS_CRITICAL} emissiveIntensity={0.4} />
        </mesh>
      ))}

      {/* charge port (left rear) */}
      <mesh position={[-1.75, 0.8, 0.94]}>
        <cylinderGeometry args={[0.08, 0.08, 0.03, 24]} />
        <meshStandardMaterial ref={charge} color="#1c3a1c" emissive={STATUS_GOOD} emissiveIntensity={0} />
      </mesh>

      {/* OTA flashing halo */}
      <mesh ref={halo} position={[0, 0.05, 0]} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
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
      <mesh ref={beacon} position={[-0.3, 1.52, 0]} visible={false}>
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

export function CarTwin({ tel, offline }: Props) {
  return (
    <Canvas shadows camera={{ position: [5.2, 3.0, 5.6], fov: 38 }} style={{ filter: offline ? "grayscale(0.85) brightness(0.6)" : undefined }}>
      <color attach="background" args={["#1a1a19"]} />
      <hemisphereLight args={["#dfe7f2", "#1a1a19", 1.1]} />
      <directionalLight position={[6, 9, 4]} intensity={2.4} castShadow shadow-mapSize={[1024, 1024]} />
      <directionalLight position={[-6, 4, -5]} intensity={0.8} />
      <Vehicle tel={tel} />
      <ContactShadows position={[0, 0.01, 0]} opacity={0.5} scale={12} blur={2.4} far={3} />
      <OrbitControls enablePan={false} minDistance={5} maxDistance={14} maxPolarAngle={Math.PI / 2.1} target={[0, 0.7, 0]} />
    </Canvas>
  );
}
