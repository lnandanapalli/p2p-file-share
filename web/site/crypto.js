// Crypto for the browser client: short codes, SPAKE2 and AES-GCM.
//
// Everything here is built on the browser's own WebCrypto (SHA-256, HMAC,
// AES-GCM) and BigInt (SPAKE2 group math). No libraries.
//
// SPAKE2 (RFC 9382) runs in the RFC 3526 group 14 prime-order subgroup, as in
// p2p.py, but with its own labels: web codes and CLI codes never mix.

import { WORDS } from "./words.js";

const enc = new TextEncoder();
const subtle = crypto.subtle;

// ---- bytes ------------------------------------------------------------------

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function hex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function fromHex(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function u32be(n) {
  return new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function u64be(n) {      // n < 2^53
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

const toBig = (b) => (b.length ? BigInt("0x" + hex(b)) : 0n);
const fromBig = (n, len) => fromHex(n.toString(16).padStart(len * 2, "0"));

export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export async function hmac(key, data, hash = "SHA-256") {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

export const kdf = (h, label) => hmac(h, enc.encode(label));

// ---- codes ------------------------------------------------------------------
//
// "4821-apple-river-ocean": the number picks a relay mailbox (not secret),
// the words are the SPAKE2 password (30 bits).

export const CODE_WORDS = 3;
const WORD_INDEX = new Map(WORDS.map((w, i) => [w, i]));

function randInt(n) {     // uniform in [0, n), n < 2^32
  const lim = Math.floor(0x100000000 / n) * n;
  const b = new Uint32Array(1);
  do crypto.getRandomValues(b); while (b[0] >= lim);
  return b[0] % n;
}

export function makeCode() {
  const parts = [String(1000 + randInt(9000))];
  for (let i = 0; i < CODE_WORDS; i++) parts.push(WORDS[randInt(WORDS.length)]);
  return parts.join("-");
}

// Accepts dashes or spaces, any case, or a whole share link. Returns
// { code, nameplate, password } or throws an Error with a readable message.
export function parseCode(input) {
  let s = String(input).trim();
  const hashAt = s.indexOf("#");
  if (hashAt >= 0) s = s.slice(hashAt + 1);
  const parts = s.toLowerCase().replace(/[-_.,]/g, " ").split(/\s+/).filter(Boolean);
  if (parts.length !== 1 + CODE_WORDS || !/^[0-9]{1,6}$/.test(parts[0]))
    throw new Error(`A code is a number and ${CODE_WORDS} words, like 4821-apple-river-ocean.`);
  for (const w of parts.slice(1))
    if (!WORD_INDEX.has(w)) throw new Error(`"${w}" isn't one of the code words. Check the spelling.`);
  parts[0] = String(parseInt(parts[0], 10));
  const code = parts.join("-");
  return { code, nameplate: parts[0], password: enc.encode(code) };
}

// Mailbox id from the number only: the relay must never see anything derived
// from the words, or it could test guesses offline.
export async function mailboxToken(nameplate) {
  return hex(await sha256(enc.encode("p2p-web-nameplate-v1:" + nameplate))).slice(0, 32);
}

// ---- SPAKE2 -----------------------------------------------------------------

const P = BigInt("0x" +
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
const Q = (P - 1n) / 2n;      // 2 generates the subgroup of this prime order
const ELEM_BYTES = 256;

function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return r;
}

function randBelow(n) {       // 128 extra bits: negligible bias
  return toBig(crypto.getRandomValues(new Uint8Array(ELEM_BYTES + 16))) % n;
}

// Hash into the subgroup (hash, then square), so nobody knows the discrete log.
async function hashToGroup(label) {
  let out = new Uint8Array(0);
  for (let ctr = 0; out.length < ELEM_BYTES + 32; ctr++)
    out = concat(out, await sha256(concat(enc.encode(label), u32be(ctr))));
  return modPow(toBig(out) % P, 2n, P);
}

let groupMN = null;
const getMN = () => (groupMN ??= Promise.all([
  hashToGroup("p2p-web-spake2-M-v1"), hashToGroup("p2p-web-spake2-N-v1")]));

export class MismatchError extends Error {
  constructor() { super("The codes didn't match."); }
}

// One side of SPAKE2. The sender plays A (uses M), the receiver B (uses N).
export class Spake2 {
  static async create(password, isSender) {
    const [M, N] = await getMN();
    const s = new Spake2();
    s.isSender = isSender;
    s.w = toBig(await hmac(enc.encode("p2p-web-spake2-pw-v1"), password, "SHA-512")) % (Q - 1n) + 1n;
    s.x = randBelow(Q - 1n) + 1n;
    const mine = isSender ? M : N;
    s.theirs = isSender ? N : M;
    s.msg = fromBig((modPow(2n, s.x, P) * modPow(mine, s.w, P)) % P, ELEM_BYTES);
    return s;
  }

  // Returns the 32-byte transcript hash. Throws on an invalid element.
  async finish(peerMsg) {
    if (peerMsg.length !== ELEM_BYTES) throw new Error("bad SPAKE2 element");
    const y = toBig(peerMsg);
    if (y <= 1n || y >= P - 1n || modPow(y, Q, P) !== 1n) throw new Error("SPAKE2 element not in the group");
    const unmasked = (y * modPow(this.theirs, Q - this.w, P)) % P;   // strip theirs^w
    const k = modPow(unmasked, this.x, P);
    const parts = [
      enc.encode("p2p-web-sender"), enc.encode("p2p-web-receiver"),
      this.isSender ? this.msg : peerMsg, this.isSender ? peerMsg : this.msg,
      fromBig(k, ELEM_BYTES), fromBig(this.w, ELEM_BYTES),
    ];
    return sha256(concat(...parts.flatMap((p) => [u64be(p.length), p])));
  }
}

// ---- AES-GCM ----------------------------------------------------------------

export const aesKey = (raw) => subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

export function nonce96(counter) {    // 4 zero bytes || 64-bit counter
  return concat(new Uint8Array(4), u64be(counter));
}

export async function seal(key, nonce, data) {
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data));
}

// Returns the plaintext, or null if it doesn't authenticate.
export async function open(key, nonce, data) {
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, data));
  } catch {
    return null;
  }
}
