// Signed policy bundles (.kxp): the compiled body plus two Ed25519 signatures,
// one by an AUTHOR key and one by a DIFFERENT APPROVER key (separation of duties).
//   "KXP1" | u32 body_len | body | u8 n_sigs | n_sigs x { u8 role (1 author, 2 approver) | pubkey[32] | sig[64] }
// Each signature covers  "kervix.policy-signature/1" 0x00 role sha256(body).
// The vehicle trusts keys listed in its trust file:  "<role> ed25519:<64 hex> <label>"  per line.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";

export const ROLE = { author: 1, approver: 2 } as const;
export type Role = keyof typeof ROLE;
export type Signature = { role: Role; pub: Buffer; sig: Buffer };
export type Bundle = { body: Buffer; sigs: Signature[] };

const MAGIC = Buffer.from("KXP1");
const DOMAIN = Buffer.from("kervix.policy-signature/1\0");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // Ed25519 SubjectPublicKeyInfo

export const bodyDigest = (body: Uint8Array) => createHash("sha256").update(body).digest();
const message = (role: Role, body: Uint8Array) => Buffer.concat([DOMAIN, Buffer.from([ROLE[role]]), bodyDigest(body)]);

export function rawPublicKey(key: KeyObject): Buffer {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}
export function keyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}
export function generateKey(): { privatePem: string; pub: Buffer } {
  const { privateKey } = generateKeyPairSync("ed25519");
  return { privatePem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(), pub: rawPublicKey(privateKey) };
}
export const loadPrivateKey = (pem: string) => createPrivateKey(pem);

export function addSignature(b: Bundle, role: Role, key: KeyObject): Bundle {
  const pub = rawPublicKey(key);
  if (b.sigs.some((s) => s.role === role)) throw new Error(`the bundle already has an ${role} signature`);
  if (b.sigs.some((s) => s.pub.equals(pub))) throw new Error("author and approver must be different keys");
  return { body: b.body, sigs: [...b.sigs, { role, pub, sig: sign(null, message(role, b.body), key) }] };
}

export function encode(b: Bundle): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(b.body.length);
  const sigs = b.sigs.map((s) => Buffer.concat([Buffer.from([ROLE[s.role]]), s.pub, s.sig]));
  return Buffer.concat([MAGIC, len, b.body, Buffer.from([b.sigs.length]), ...sigs]);
}

export function decode(buf: Buffer): Bundle {
  if (buf.length < 9 || !buf.subarray(0, 4).equals(MAGIC)) throw new Error("not a .kxp bundle");
  const n = buf.readUInt32LE(4);
  if (n > buf.length - 9) throw new Error("truncated bundle");
  const body = buf.subarray(8, 8 + n);
  const count = buf[8 + n];
  if (count > 2 || buf.length !== 9 + n + count * 97) throw new Error("malformed signature block");
  const sigs: Signature[] = [];
  for (let i = 0; i < count; i++) {
    const o = 9 + n + i * 97;
    const role = buf[o] === 1 ? "author" : buf[o] === 2 ? "approver" : null;
    if (!role) throw new Error("unknown signature role");
    sigs.push({ role, pub: buf.subarray(o + 1, o + 33), sig: buf.subarray(o + 33, o + 97) });
  }
  return { body, sigs };
}

export type TrustEntry = { role: Role; pub: Buffer; label: string };
export function parseTrust(text: string): TrustEntry[] {
  return text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => {
    const m = /^(author|approver)\s+ed25519:([0-9a-f]{64})\s*(.*)$/.exec(l);
    if (!m) throw new Error(`trust file: cannot parse "${l}"`);
    return { role: m[1] as Role, pub: Buffer.from(m[2], "hex"), label: m[3] };
  });
}
export const trustLine = (role: Role, pub: Buffer, label: string) => `${role} ed25519:${pub.toString("hex")} ${label}`;

/** The vehicle's acceptance rule, mirrored for the host: both roles, different keys, each trusted for its role, both valid. */
export function check(b: Bundle, trust: TrustEntry[]): { ok: boolean; problems: string[]; signers: string[] } {
  const problems: string[] = [];
  const signers: string[] = [];
  for (const role of ["author", "approver"] as const) {
    const s = b.sigs.find((x) => x.role === role);
    if (!s) { problems.push(`missing ${role} signature`); continue; }
    const t = trust.find((x) => x.role === role && x.pub.equals(s.pub));
    if (!t) problems.push(`${role} key ${s.pub.toString("hex").slice(0, 16)}… is not trusted as ${role}`);
    else signers.push(`${role}: ${t.label}`);
    if (!verify(null, message(role, b.body), keyFromRaw(Buffer.from(s.pub)), s.sig)) problems.push(`${role} signature does not verify`);
  }
  const [a, p] = [b.sigs.find((x) => x.role === "author"), b.sigs.find((x) => x.role === "approver")];
  if (a && p && a.pub.equals(p.pub)) problems.push("author and approver are the same key");
  return { ok: problems.length === 0, problems, signers };
}
