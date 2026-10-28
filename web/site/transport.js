// Transports for the browser client.
//
//   RelayPipe    -- datagrams through the relay mailbox (HTTPS POST + long-poll
//                   GET), same mailbox API and batch format the CLI uses.
//   RtcPipe      -- datagrams over a WebRTC data channel.
//   Mailbox      -- awaitable receive queue on top of a pipe.
//   SecureStream -- encrypted, numbered, acknowledged messages over either
//                   pipe (AES-GCM + go-back-N), so the rest of the app never
//                   cares which transport is underneath.

import { concat, nonce96, seal, open } from "./crypto.js";
import { sleep, setTimer, clearTimer, every, anySignal, timeoutSignal } from "./timers.js";

// ---- relay ------------------------------------------------------------------

const POST_GAP = 80;          // ms between POSTs  } stays well under the relay's
const GET_GAP = 50;           // ms between GETs   } 50 requests/s per IP
const POLL_TIMEOUT = 25000;   // ms; must exceed the relay's 20 s long-poll
const POST_TIMEOUT = 15000;
const RETRY = 250;
const BATCH_BYTES = 2 * 1024 * 1024;   // relay rejects bodies over 4 MiB
const BATCH_PACKETS = 256;

function encodeBatch(pkts) {
  let size = 2;
  for (const p of pkts) size += 2 + p.length;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, pkts.length);
  let o = 2;
  for (const p of pkts) { dv.setUint16(o, p.length); out.set(p, o + 2); o += 2 + p.length; }
  return out;
}

function decodeBatch(body) {
  const out = [];
  if (body.length < 2) return out;
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const count = dv.getUint16(0);
  let o = 2;
  for (let i = 0; i < count && o + 2 <= body.length; i++) {
    const len = dv.getUint16(o);
    if (o + 2 + len > body.length) break;
    out.push(body.slice(o + 2, o + 2 + len));
    o += 2 + len;
  }
  return out;
}

function backoff(resp) {
  const ra = parseFloat(resp.headers.get("Retry-After"));
  return Math.max(RETRY, Math.min(Number.isFinite(ra) ? ra * 1000 : 1000, 10000));
}

export async function relayReachable(base) {
  try {
    const r = await fetch(base + "/healthz", { signal: timeoutSignal(8000), cache: "no-store" });
    return r.ok;
  } catch {
    return false;
  }
}

export class RelayPipe {
  constructor(base, token, sendDir, recvDir) {
    this.sendUrl = `${base}/relay/${token}/${sendDir}/send`;
    this.recvUrl = `${base}/relay/${token}/${recvDir}/recv`;
    this.queue = [];
    this.onpacket = null;
    this.closed = false;
    this.ctl = new AbortController();
    this.wake = null;
    this.posting = false;
    this.kind = "relay";
    this.sendLoop();
    this.recvLoop();
  }

  send(pkt) {
    if (this.closed) return;
    this.queue.push(pkt);
    if (this.wake) { this.wake(); this.wake = null; }
  }

  // Waits (up to flushMs) for queued packets to go out, then stops.
  async close(flushMs = 2000) {
    const end = Date.now() + flushMs;
    while ((this.queue.length || this.posting) && Date.now() < end) await sleep(20);
    this.closed = true;
    this.ctl.abort();
    if (this.wake) this.wake();
  }

  async sendLoop() {
    let last = 0;
    while (!this.closed) {
      if (!this.queue.length) {
        await new Promise((r) => (this.wake = r));
        continue;
      }
      const gap = POST_GAP - (Date.now() - last);
      if (gap > 0) await sleep(gap);       // packets queued meanwhile join this batch
      const batch = [];
      let bytes = 0;
      while (this.queue.length && batch.length < BATCH_PACKETS && bytes < BATCH_BYTES) {
        const p = this.queue.shift();
        batch.push(p);
        bytes += p.length;
      }
      const body = encodeBatch(batch);
      this.posting = true;
      // Retry THIS batch on throttling / network errors instead of dropping it.
      while (!this.closed) {
        last = Date.now();
        let resp;
        try {
          resp = await fetch(this.sendUrl, {
            method: "POST", body, cache: "no-store",
            signal: anySignal([this.ctl.signal, timeoutSignal(POST_TIMEOUT)]),
          });
        } catch {
          await sleep(RETRY);
          continue;
        }
        if (resp.ok) break;
        if (resp.status === 429 || resp.status === 503) { await sleep(backoff(resp)); continue; }
        break;      // 4xx: retrying won't help; the stream layer resends
      }
      this.posting = false;
    }
  }

  async recvLoop() {
    let last = 0;
    while (!this.closed) {
      const gap = GET_GAP - (Date.now() - last);
      if (gap > 0) await sleep(gap);
      last = Date.now();
      let resp, body;
      try {
        resp = await fetch(this.recvUrl, {
          cache: "no-store",
          signal: anySignal([this.ctl.signal, timeoutSignal(POLL_TIMEOUT)]),
        });
        body = new Uint8Array(await resp.arrayBuffer());
      } catch {
        if (!this.closed) await sleep(RETRY);
        continue;
      }
      if (!resp.ok) {
        await sleep(resp.status === 429 || resp.status === 503 ? backoff(resp) : RETRY);
        continue;
      }
      for (const p of decodeBatch(body)) if (!this.closed && this.onpacket) this.onpacket(p);
    }
  }
}

// ---- WebRTC -----------------------------------------------------------------

export class RtcPipe {
  constructor(pc, dc) {
    this.pc = pc;
    this.dc = dc;
    this.kind = "webrtc";
    this.handler = null;
    this.early = [];        // packets that arrive before anyone listens
    this.onclose = null;
    dc.binaryType = "arraybuffer";
    dc.onmessage = (e) => {
      const p = new Uint8Array(e.data);
      if (this.handler) this.handler(p);
      else this.early.push(p);
    };
    dc.onclose = () => this.onclose && this.onclose();
  }

  get onpacket() { return this.handler; }
  set onpacket(fn) {
    this.handler = fn;
    while (fn && this.early.length) fn(this.early.shift());
  }

  send(pkt) {
    if (this.dc.readyState === "open") this.dc.send(pkt);
  }

  async close(flushMs = 2000) {
    const end = Date.now() + flushMs;
    while (this.dc.readyState === "open" && this.dc.bufferedAmount > 0 && Date.now() < end) await sleep(20);
    this.dc.onclose = null;
    try { this.dc.close(); } catch {}
    try { this.pc.close(); } catch {}
  }
}

// ---- Mailbox: await the next packet -----------------------------------------

export class Mailbox {
  constructor(pipe) {
    this.pipe = pipe;
    this.items = [];
    this.waiter = null;
    pipe.onpacket = (p) => {
      if (this.waiter) { const w = this.waiter; this.waiter = null; w(p); }
      else this.items.push(p);
    };
  }

  // Next packet, or null after `ms`.
  next(ms) {
    if (this.items.length) return Promise.resolve(this.items.shift());
    return new Promise((resolve) => {
      const t = setTimer(() => { this.waiter = null; resolve(null); }, ms);
      this.waiter = (p) => { clearTimer(t); resolve(p); };
    });
  }
}

// ---- SecureStream -----------------------------------------------------------
//
// Packet on the wire: counter(8) || AES-GCM(key_dir, nonce = 0^4 || counter,
// frame). Frame: kind(1) || n(4, big-endian) || body.
//   kind 0 = MSG, n = sequence number, body = type(1) || payload
//   kind 1 = ACK, n = next sequence number expected (cumulative)
// Each direction has its own key, and the counter never repeats (resends are
// re-encrypted under a fresh counter). Messages are delivered exactly once
// and in order; a replayed or duplicated packet is just an old sequence
// number. Acks only go out once a message has been handled, which gives
// end-to-end backpressure (e.g. a slow disk on the receiver).

const MSG = 0, ACK = 1;

export class StreamError extends Error {}

export class SecureStream {
  constructor(pipe, sendKey, recvKey, opts = {}) {
    this.pipe = pipe;
    this.sendKey = sendKey;
    this.recvKey = recvKey;
    this.window = opts.window ?? 128;
    this.rto = opts.rto ?? 10000;          // ms without ack progress before resending
    this.idleTimeout = opts.idleTimeout ?? 120000;
    this.onmessage = null;                 // async (type, payload) => {}
    this.onerror = null;                   // (StreamError) => {}
    this.onfirstpacket = null;             // first authentic packet from the peer

    this.counter = 0;
    this.nextSeq = 0;                      // next sequence number to assign
    this.base = 0;                         // oldest unacked
    this.frames = new Map();               // seq -> frame, until acked
    this.spaceWaiters = [];
    this.progressAt = Date.now();
    this.lastTx = Date.now();
    this.lastRx = Date.now();
    this.gotAny = false;

    this.expected = 0;                     // next sequence number to deliver
    this.unacked = 0;
    this.ackTimer = null;

    this.txChain = Promise.resolve();      // keeps packets in order through async encryption
    this.rxChain = Promise.resolve();
    this.failed = null;
    this.closed = false;

    pipe.onpacket = (p) => { this.rxChain = this.rxChain.then(() => this.receive(p)); };
    // Handle a closed channel only after packets already received (e.g. a
    // CANCEL) have been processed, so the peer's last message isn't lost.
    if ("onclose" in pipe) pipe.onclose = () => { this.rxChain = this.rxChain.then(() => this.fail("The connection closed.")); };
    this.stopTicks = every(() => this.tick(), 250);
  }

  // ---- sending

  // Queue a message. Resolves once it is in flight (waits while the window is full).
  async send(type, payload = new Uint8Array(0)) {
    while (this.nextSeq - this.base >= this.window) {
      if (this.failed) throw this.failed;
      await new Promise((r) => this.spaceWaiters.push(r));
    }
    if (this.failed) throw this.failed;
    const seq = this.nextSeq++;
    const frame = concat(new Uint8Array([MSG]), u32(seq), new Uint8Array([type]), payload);
    this.frames.set(seq, frame);
    this.transmit(frame);
  }

  // Resolves when everything sent so far is acknowledged.
  async flush(timeoutMs = 30000) {
    const end = Date.now() + timeoutMs;
    while (this.base < this.nextSeq) {
      if (this.failed) throw this.failed;
      if (Date.now() > end) throw new StreamError("Timed out waiting for the other side.");
      await sleep(50);
    }
  }

  transmit(frame) {
    const ctr = this.counter++;
    this.lastTx = Date.now();
    this.txChain = this.txChain.then(async () => {
      if (this.closed) return;
      const ct = await seal(this.sendKey, nonce96(ctr), frame);
      this.pipe.send(concat(u64(ctr), ct));
    });
  }

  sendAck() {
    this.unacked = 0;
    if (this.ackTimer) { clearTimer(this.ackTimer); this.ackTimer = null; }
    this.transmit(concat(new Uint8Array([ACK]), u32(this.expected)));
  }

  // ---- receiving

  async receive(pkt) {
    if (this.closed || pkt.length < 8 + 16 + 5) return;
    const ctr = Number(new DataView(pkt.buffer, pkt.byteOffset, 8).getBigUint64(0));
    const frame = await open(this.recvKey, nonce96(ctr), pkt.subarray(8));
    if (!frame) return;                              // forged or corrupted: ignore
    this.lastRx = Date.now();
    if (!this.gotAny) { this.gotAny = true; this.onfirstpacket && this.onfirstpacket(); }
    const n = new DataView(frame.buffer, frame.byteOffset + 1, 4).getUint32(0);
    if (frame[0] === ACK) {
      if (n > this.base && n <= this.nextSeq) {
        for (let s = this.base; s < n; s++) this.frames.delete(s);
        this.base = n;
        this.progressAt = Date.now();
        for (const w of this.spaceWaiters.splice(0)) w();
      }
      return;
    }
    if (frame[0] !== MSG || frame.length < 6) return;
    if (n !== this.expected) {       // duplicate or gap: re-ack so the sender catches up
      this.sendAck();
      return;
    }
    try {
      if (this.onmessage) await this.onmessage(frame[5], frame.subarray(6));
    } catch (e) {
      this.fail(e.message || String(e));
      return;
    }
    this.expected++;
    if (++this.unacked >= 8) this.sendAck();
    else if (!this.ackTimer) this.ackTimer = setTimer(() => this.sendAck(), 40);
  }

  // ---- timers

  tick() {
    if (this.closed) return;
    const now = Date.now();
    if (this.base < this.nextSeq && now - this.progressAt > this.rto) {
      // Go-back-N: resend everything unacked.
      this.progressAt = now;
      for (let s = this.base; s < this.nextSeq; s++) this.transmit(this.frames.get(s));
    }
    if (now - this.lastTx > 10000) this.sendAck();          // keepalive
    if (now - this.lastRx > this.idleTimeout) this.fail("Lost contact with the other side.");
  }

  fail(reason) {
    if (this.failed || this.closed) return;
    this.failed = new StreamError(reason);
    for (const w of this.spaceWaiters.splice(0)) w();
    if (this.onerror) this.onerror(this.failed);
  }

  async close(flushMs = 2000) {
    if (this.closed) return;
    try { await this.txChain; } catch {}
    this.fail("The connection closed.");      // wakes anything still waiting
    this.closed = true;
    this.stopTicks();
    if (this.ackTimer) clearTimer(this.ackTimer);
    await this.pipe.close(flushMs);
  }
}

function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

function u64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}
