// One send or receive session: code -> SPAKE2 -> WebRTC (or relay) -> file.
//
// 1. Both sides meet in a relay mailbox picked by the code's number and run
//    SPAKE2 with the words as the password, with key confirmation. A wrong
//    code aborts both sides.
// 2. Unless either side asked for "relay only", they swap WebRTC offer/answer
//    sealed under the SPAKE2 key. That authenticates the DTLS fingerprints in
//    the SDP, so the relay can't sit in the middle of the WebRTC connection.
// 3. The SENDER decides the transport (WebRTC if its data channel opened in
//    time, else the relay) and tells the receiver, so both always agree.
// 4. The file goes over a SecureStream (AES-GCM, ordered, acknowledged) on
//    that transport: META -> ACCEPT/DECLINE -> DATA... -> END -> DONE.

import * as C from "./crypto.js";
import { RelayPipe, RtcPipe, Mailbox, SecureStream, relayReachable } from "./transport.js";
import { RELAY_URL, ICE_SERVERS } from "./config.js";
import { sleep, setTimer, clearTimer } from "./timers.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

// Rendezvous message kinds
const MAGIC = enc.encode("SPW1");
const K_ELEM = 0x45, K_CONF = 0x43, K_OFFER = 0x4f, K_ANSWER = 0x41, K_TRANSPORT = 0x54;
const VERSION = 1;
const F_RELAY = 1;          // this side asked for relay only

// Stream message types
const T_META = 1, T_ACCEPT = 2, T_DECLINE = 3, T_DATA = 4, T_END = 5, T_CANCEL = 6, T_DONE = 7;

export const CHUNK = 60 * 1024;   // + ~30 bytes framing must fit the relay batch format's 16-bit lengths
const READ_BLOCK = 1024 * 1024;
const WAIT_FOREVER = 3600 * 1000;
const RESEND = 5000, REPLY_GAP = 1000;
const ICE_GATHER_MAX = 3000, ICE_AFTER_SRFLX = 500, ANSWER_TIMEOUT = 30000, RTC_OPEN_TIMEOUT = 10000;

export class CancelledError extends Error {
  constructor() { super("Cancelled."); }
}

// ---- rendezvous ---------------------------------------------------------------

class Rendezvous {
  constructor(token, isSender) {
    this.isSender = isSender;
    this.pipe = new RelayPipe(RELAY_URL, token, isSender ? "s2r" : "r2s", isSender ? "r2s" : "s2r");
    this.mb = new Mailbox(this.pipe);
    this.keys = null;
    this.conf = null;
    this.cancelled = false;
  }

  sendRaw(kind, body) { this.pipe.send(C.concat(MAGIC, new Uint8Array([kind]), body)); }
  sendPkts(pkts) { for (const p of pkts) if (p) this.pipe.send(p); }

  async next(ms) {
    for (;;) {
      if (this.cancelled) throw new CancelledError();
      const p = await this.mb.next(ms);
      if (!p) return null;
      if (p.length >= 5 && C.equalBytes(p.subarray(0, 4), MAGIC)) return { kind: p[4], body: p.subarray(5) };
    }
  }

  // Each (direction key, kind) seals exactly one message, so the kind can
  // serve as the GCM nonce; resends repeat the identical packet.
  async seal(kind, payload) {
    const k = this.isSender ? this.keys.rdvS2R : this.keys.rdvR2S;
    return C.concat(MAGIC, new Uint8Array([kind]), await C.seal(k, C.nonce96(kind), payload));
  }

  async open(kind, body) {
    const k = this.isSender ? this.keys.rdvR2S : this.keys.rdvS2R;
    return C.open(k, C.nonce96(kind), body);
  }

  // SPAKE2 + key confirmation. Returns the peer's flags, null on timeout;
  // throws MismatchError if the codes differ.
  async handshake(spake, myFlags, timeoutMs, onWait) {
    const start = Date.now();
    let lastSend = start, lastReply = start;
    this.sendRaw(K_ELEM, spake.msg);
    while (Date.now() - start < timeoutMs) {
      const now = Date.now();
      if (now - lastSend >= RESEND) { this.sendRaw(K_ELEM, spake.msg); this.sendPkts([this.conf]); lastSend = now; }
      onWait(now - start);
      const m = await this.next(250);
      if (!m) continue;
      if (m.kind === K_ELEM) {
        if (!this.keys) {
          let h;
          try { h = await spake.finish(m.body); } catch { continue; }
          this.keys = await deriveKeys(h);
          this.conf = await this.seal(K_CONF, new Uint8Array([VERSION, myFlags]));
          this.sendRaw(K_ELEM, spake.msg);
          this.sendPkts([this.conf]);
          lastSend = lastReply = Date.now();
        } else if (now - lastReply >= REPLY_GAP) {
          // The peer is still repeating itself: maybe it missed ours.
          this.sendRaw(K_ELEM, spake.msg);
          this.sendPkts([this.conf]);
          lastReply = now;
        }
      } else if (m.kind === K_CONF && this.keys) {
        const info = await this.open(K_CONF, m.body);
        if (!info || info.length < 2 || info[0] !== VERSION) throw new C.MismatchError();
        return info[1];
      }
    }
    return null;
  }

  // Wait for a sealed message of one of `kinds`, re-sending `resend` every
  // few seconds. Returns { kind, payload } or null on timeout.
  async waitFor(kinds, timeoutMs, resend) {
    const start = Date.now();
    let lastSend = 0;
    while (Date.now() - start < timeoutMs) {
      if (Date.now() - lastSend >= RESEND) { this.sendPkts(resend()); lastSend = Date.now(); }
      const m = await this.next(250);
      if (!m || !kinds.includes(m.kind)) continue;
      const payload = await this.open(m.kind, m.body);
      if (payload) return { kind: m.kind, payload };
    }
    return null;
  }

  close() { return this.pipe.close(); }
}

async function deriveKeys(h) {
  const k = (label) => C.kdf(h, label);
  return {
    rdvS2R: await C.aesKey(await k("p2p-web-rdv-s2r")),
    rdvR2S: await C.aesKey(await k("p2p-web-rdv-r2s")),
    dataS2R: await C.aesKey(await k("p2p-web-data-s2r")),
    dataR2S: await C.aesKey(await k("p2p-web-data-r2s")),
    relayToken: C.hex(await k("p2p-web-relay-token")).slice(0, 32),
  };
}

// ---- WebRTC helpers -----------------------------------------------------------

// Non-trickle ICE: send one SDP once gathering completes, or shortly after
// the first public (STUN) candidate shows up, or after ICE_GATHER_MAX.
// Gathering can hang for many seconds on an unreachable STUN server or IPv6.
function iceGathered(pc) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    let done = false, soon = null;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimer(cap);
      if (soon) clearTimer(soon);
      resolve();
    };
    const cap = setTimer(finish, ICE_GATHER_MAX);
    pc.addEventListener("icegatheringstatechange", () => pc.iceGatheringState === "complete" && finish());
    pc.addEventListener("icecandidate", (e) => {
      if (!e.candidate) return finish();
      if (e.candidate.type === "srflx" && !soon) soon = setTimer(finish, ICE_AFTER_SRFLX);
    });
  });
}

const sdpPayload = (pc) => enc.encode(JSON.stringify({ sdp: pc.localDescription.sdp }));
const sdpFrom = (payload) => JSON.parse(dec.decode(payload)).sdp;

// Sender: offer, wait for the answer, wait for the channel. RtcPipe or null.
async function senderWebRtc(rdv) {
  let pc;
  try {
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    const dc = pc.createDataChannel("file", { ordered: true });
    const opened = new Promise((r) => { dc.onopen = () => r(true); });
    await pc.setLocalDescription(await pc.createOffer());
    await iceGathered(pc);
    const offer = await rdv.seal(K_OFFER, sdpPayload(pc));
    const ans = await rdv.waitFor([K_ANSWER], ANSWER_TIMEOUT, () => [offer, rdv.conf]);
    if (!ans) throw new Error("no answer");
    await pc.setRemoteDescription({ type: "answer", sdp: sdpFrom(ans.payload) });
    if (!(await Promise.race([opened, sleep(RTC_OPEN_TIMEOUT).then(() => false)]))) throw new Error("no channel");
    return new RtcPipe(pc, dc);
  } catch (e) {
    if (e instanceof CancelledError) throw e;
    try { pc && pc.close(); } catch {}
    return null;
  }
}

// ---- helpers --------------------------------------------------------------------

// Messages other than DATA, as an awaitable queue.
class Inbox {
  constructor() { this.items = []; this.waiter = null; this.error = null; }
  push(m) { if (this.waiter) { const w = this.waiter; this.waiter = null; w.resolve(m); } else this.items.push(m); }
  fail(e) { this.error = e; if (this.waiter) { const w = this.waiter; this.waiter = null; w.reject(e); } }
  next() {
    if (this.items.length) return Promise.resolve(this.items.shift());
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => (this.waiter = { resolve, reject }));
  }
}

const json = (o) => enc.encode(JSON.stringify(o));
const unjson = (b) => JSON.parse(dec.decode(b));

function speedometer() {
  const samples = [];
  return (bytes) => {
    const now = performance.now();
    samples.push([now, bytes]);
    while (samples.length > 2 && now - samples[0][0] > 3000) samples.shift();
    const [t0, b0] = samples[0];
    return now - t0 > 200 ? ((bytes - b0) * 1000) / (now - t0) : 0;
  };
}

// Keep re-sending the transport decision until the receiver shows up on the
// chosen transport, then leave the mailbox.
async function announceTransport(rdv, stream, decision) {
  const pkt = await rdv.seal(K_TRANSPORT, enc.encode(decision));
  const start = Date.now();
  while (!stream.gotAny && !stream.failed && !stream.closed && Date.now() - start < 120000) {
    rdv.sendPkts([pkt]);
    await sleep(2000);
  }
  await rdv.close();
}

// ---- send ---------------------------------------------------------------------------

// ui: { code(code), status(text), hint(text), connected(kind), waitingAccept(),
//       progress(done, total, bytesPerSec), done(text) }
export function startSend(file, opts, ui) {
  const ctl = { cancelled: false, stream: null, rdv: null };
  ctl.cancel = () => cancel(ctl);
  ctl.result = (async () => {
    if (!(await relayReachable(RELAY_URL))) throw new Error("Can't reach the relay. Check your internet connection.");
    const code = C.makeCode();
    const { nameplate, password } = C.parseCode(code);
    const spake = await C.Spake2.create(password, true);
    const rdv = (ctl.rdv = new Rendezvous(await C.mailboxToken(nameplate), true));
    if (ctl.cancelled) throw new CancelledError();
    ui.code(code);
    try {
      const myFlags = opts.relayOnly ? F_RELAY : 0;
      const peerFlags = await rdv.handshake(spake, myFlags, WAIT_FOREVER,
        (ms) => ui.status(`Waiting for the receiver to enter the code… ${fmtTime(ms)}`));
      if (peerFlags === null) throw new Error("Nobody entered the code within an hour.");
      ui.status("Code verified. Connecting…");

      let pipe = (myFlags | peerFlags) & F_RELAY ? null : await senderWebRtc(rdv);
      const decision = pipe ? "webrtc" : "relay";
      if (!pipe) pipe = new RelayPipe(RELAY_URL, rdv.keys.relayToken, "s2r", "r2s");
      const stream = (ctl.stream = new SecureStream(pipe, rdv.keys.dataS2R, rdv.keys.dataR2S));
      const inbox = new Inbox();
      stream.onmessage = async (type, payload) => inbox.push({ type, payload });
      stream.onerror = (e) => inbox.fail(e);
      announceTransport(rdv, stream, decision);
      ui.connected(decision);

      await stream.send(T_META, json({ name: file.name, size: file.size, type: file.type || "" }));
      ui.waitingAccept();
      const reply = await inbox.next();
      if (reply.type === T_DECLINE) { await stream.close(); return ui.done("The receiver declined the file."); }
      if (reply.type === T_CANCEL) { await stream.close(); throw new Error("The receiver cancelled."); }
      if (reply.type !== T_ACCEPT) throw new Error("Unexpected reply from the receiver.");

      const speed = speedometer();
      let sent = 0;
      ui.progress(0, file.size, 0);
      for (let off = 0; off < file.size; off += READ_BLOCK) {
        const block = new Uint8Array(await file.slice(off, off + READ_BLOCK).arrayBuffer());
        for (let i = 0; i < block.length; i += CHUNK) {
          if (ctl.cancelled) throw new CancelledError();
          if (inbox.items.some((m) => m.type === T_CANCEL)) throw new Error("The receiver cancelled.");
          const chunk = block.subarray(i, i + CHUNK);
          await stream.send(T_DATA, chunk);
          sent += chunk.length;
          ui.progress(sent, file.size, speed(sent));
        }
      }
      await stream.send(T_END, json({ size: file.size }));
      ui.status("Waiting for the receiver to finish saving…");
      for (;;) {
        const m = await inbox.next();
        if (m.type === T_DONE) break;
        if (m.type === T_CANCEL) throw new Error("The receiver cancelled.");
      }
      await sleep(300);           // let our final ack reach the receiver
      await stream.close();
      ui.done(`Sent ${file.name}. The receiver has it.`);
    } catch (e) {
      await teardown(ctl);
      throw e;
    }
  })();
  return ctl;
}

// ---- receive -------------------------------------------------------------------------

// ui: { status(text), hint(text), connected(kind), offer(meta) -> Promise<sink|null>,
//       progress(done, total, bytesPerSec), done(text) }
// A sink is { write(Uint8Array), close(), abort() } created by the UI (it needs
// the user's click to open a save dialog).
export function startReceive(codeText, opts, ui) {
  const ctl = { cancelled: false, stream: null, rdv: null };
  ctl.cancel = () => cancel(ctl);
  ctl.result = (async () => {
    const { nameplate, password } = C.parseCode(codeText);
    if (!(await relayReachable(RELAY_URL))) throw new Error("Can't reach the relay. Check your internet connection.");
    const spake = await C.Spake2.create(password, false);
    const rdv = (ctl.rdv = new Rendezvous(await C.mailboxToken(nameplate), false));
    let sink = null, pc = null;
    try {
      const myFlags = opts.relayOnly ? F_RELAY : 0;
      let hinted = false;
      const peerFlags = await rdv.handshake(spake, myFlags, WAIT_FOREVER, (ms) => {
        ui.status(`Finding the sender… ${fmtTime(ms)}`);
        if (ms > 30000 && !hinted) {
          hinted = true;
          ui.hint("Taking a while. Check that the sender's page is still open and that the number is right.");
        }
      });
      if (peerFlags === null) throw new Error("Couldn't find the sender.");
      ui.hint("");
      ui.status("Code verified. Connecting…");

      // Answer a WebRTC offer if one comes; the sender's transport decision ends this.
      let answer = null, rtcPipe = null, decision = null;
      while (!decision) {
        const m = await rdv.waitFor([K_OFFER, K_TRANSPORT], 120000, () => [rdv.conf, answer]);
        if (!m) throw new Error("Lost contact with the sender.");
        if (m.kind === K_TRANSPORT) { decision = dec.decode(m.payload); break; }
        if (pc) continue;
        try {
          pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
          const gotChannel = new Promise((resolve) => {
            pc.ondatachannel = (e) => {
              const dc = e.channel;
              const pipe = new RtcPipe(pc, dc);      // buffers anything that arrives early
              if (dc.readyState === "open") resolve(pipe);
              else dc.addEventListener("open", () => resolve(pipe));
            };
          });
          rtcPipe = gotChannel;
          await pc.setRemoteDescription({ type: "offer", sdp: sdpFrom(m.payload) });
          await pc.setLocalDescription(await pc.createAnswer());
          await iceGathered(pc);
          answer = await rdv.seal(K_ANSWER, sdpPayload(pc));
          rdv.sendPkts([answer]);
        } catch {
          try { pc.close(); } catch {}
          pc = null; rtcPipe = null;     // the sender times out and picks the relay
          answer = null;
        }
      }

      let pipe;
      if (decision === "webrtc") {
        pipe = rtcPipe && (await Promise.race([rtcPipe, sleep(15000).then(() => null)]));
        if (!pipe) throw new Error("The direct connection failed. Try again with “Relay only”.");
      } else {
        try { pc && pc.close(); } catch {}
        pipe = new RelayPipe(RELAY_URL, rdv.keys.relayToken, "r2s", "s2r");
      }
      rdv.close();
      const stream = (ctl.stream = new SecureStream(pipe, rdv.keys.dataR2S, rdv.keys.dataS2R));
      ui.connected(decision);
      ui.status("Connected. Waiting for the file details…");

      const inbox = new Inbox();
      let meta = null, received = 0;
      const speed = speedometer();
      stream.onmessage = async (type, payload) => {
        if (type !== T_DATA) return inbox.push({ type, payload });
        if (!sink) throw new Error("Data arrived before the file was accepted.");
        if (received + payload.length > meta.size) throw new Error("The sender sent more data than announced.");
        await sink.write(payload);     // a view into this message's own buffer
        received += payload.length;
        ui.progress(received, meta.size, speed(received));
      };
      stream.onerror = (e) => inbox.fail(e);

      const first = await inbox.next();
      if (first.type === T_CANCEL) throw new Error("The sender cancelled.");
      if (first.type !== T_META) throw new Error("Unexpected message from the sender.");
      meta = unjson(first.payload);
      if (typeof meta.name !== "string" || !Number.isSafeInteger(meta.size) || meta.size < 0)
        throw new Error("The sender sent invalid file details.");
      meta.name = safeName(meta.name);

      sink = await ui.offer(meta);
      if (ctl.cancelled) throw new CancelledError();
      if (!sink) {
        await stream.send(T_DECLINE);
        await stream.flush(5000).catch(() => {});
        await stream.close();
        return ui.done("You declined the file.");
      }
      await stream.send(T_ACCEPT);
      ui.progress(0, meta.size, 0);

      for (;;) {
        const m = await inbox.next();
        if (m.type === T_CANCEL) throw new Error("The sender cancelled.");
        if (m.type === T_END) break;
      }
      if (received !== meta.size) throw new Error("The transfer ended early.");
      ui.status("Saving…");
      await sink.close();
      sink = null;
      await stream.send(T_DONE);
      await stream.flush(5000).catch(() => {});
      await stream.close();
      ui.done(`Received ${meta.name}.`);
    } catch (e) {
      if (sink) { try { await sink.abort(); } catch {} }
      await teardown(ctl);             // flushes the stream (e.g. a CANCEL) first
      try { pc && pc.close(); } catch {}
      throw e;
    }
  })();
  return ctl;
}

// ---- shared ----------------------------------------------------------------------

async function cancel(ctl) {
  if (ctl.cancelled) return;
  ctl.cancelled = true;
  if (ctl.rdv) ctl.rdv.cancelled = true;
  const s = ctl.stream;
  if (s && !s.failed && !s.closed) {
    // Best effort: tell the peer, without waiting long.
    await Promise.race([s.send(T_CANCEL, enc.encode("cancelled")).catch(() => {}), sleep(1000)]);
    await sleep(300);
  }
  await teardown(ctl);
}

async function teardown(ctl) {
  try { if (ctl.stream) await ctl.stream.close(500); } catch {}
  try { if (ctl.rdv) await ctl.rdv.close(); } catch {}
}

function safeName(name) {
  let n = name.split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_").trim();
  if (!n || n === "." || n === "..") n = "download";
  return n.slice(0, 200);
}

export function fmtTime(ms) {
  const s = Math.floor(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}
