// Timers that keep running at full speed in background tabs.
//
// Browsers slow down page timers in hidden tabs (Chrome: at most once a
// second, and much less after a few minutes), which would stall a relay
// transfer the moment the user switches tabs. Timers inside a dedicated
// Worker aren't throttled that way, so the page asks a tiny worker to keep
// time for it. Falls back to plain timers if a worker can't be created.

let worker = null;
let nextId = 1;
const callbacks = new Map();

try {
  const src = "const t=new Map();onmessage=(e)=>{const[id,ms]=e.data;" +
    "if(ms<0){clearTimeout(t.get(id));t.delete(id);}" +
    "else t.set(id,setTimeout(()=>{t.delete(id);postMessage(id);},ms));};";
  worker = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
  worker.onmessage = (e) => {
    const fn = callbacks.get(e.data);
    callbacks.delete(e.data);
    if (fn) fn();
  };
} catch {
  worker = null;
}

export function setTimer(fn, ms) {
  if (!worker) return setTimeout(fn, ms);
  const id = nextId++;
  callbacks.set(id, fn);
  worker.postMessage([id, ms]);
  return id;
}

export function clearTimer(id) {
  if (!worker) return clearTimeout(id);
  if (callbacks.delete(id)) worker.postMessage([id, -1]);
}

export const sleep = (ms) => new Promise((r) => setTimer(r, ms));

// Calls fn every `ms` until the returned function is called.
export function every(fn, ms) {
  let id, stopped = false;
  const loop = () => { if (stopped) return; fn(); id = setTimer(loop, ms); };
  id = setTimer(loop, ms);
  return () => { stopped = true; clearTimer(id); };
}

// AbortSignal.any / AbortSignal.timeout, with fallbacks for older browsers.
export function anySignal(signals) {
  if (AbortSignal.any) return AbortSignal.any(signals);
  const c = new AbortController();
  for (const s of signals) {
    if (s.aborted) { c.abort(); break; }
    s.addEventListener("abort", () => c.abort(), { once: true });
  }
  return c.signal;
}

export function timeoutSignal(ms) {
  const c = new AbortController();
  setTimer(() => c.abort(), ms);
  return c.signal;
}
