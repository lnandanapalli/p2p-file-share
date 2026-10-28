// Page logic: wires the UI to session.js.

import { startSend, startReceive, CancelledError } from "./session.js";
import { MismatchError, parseCode } from "./crypto.js";

const $ = (id) => document.getElementById(id);
let active = null;         // the running session, if any
let offerResolve = null;   // pending Accept/Decline answer

// ---- formatting

function fmtBytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n} B` : `${n.toFixed(1)} ${units[i]}`;
}

function fmtEta(sec) {
  if (!isFinite(sec) || sec <= 0) return "";
  sec = Math.round(sec);
  if (sec < 60) return `${sec}s left`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s left`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m left`;
}

// ---- tabs

function showTab(name) {
  const send = name === "send";
  $("tab-send").setAttribute("aria-selected", String(send));
  $("tab-recv").setAttribute("aria-selected", String(!send));
  $("send-pane").hidden = !send;
  $("recv-pane").hidden = send;
}
$("tab-send").onclick = () => !active && showTab("send");
$("tab-recv").onclick = () => !active && showTab("recv");

function lockTabs(locked) {
  $("tab-send").disabled = locked;
  $("tab-recv").disabled = locked;
}

// ---- status area

function status(text, kind = "") {
  $("status-box").hidden = false;
  $("status").textContent = text;
  $("status").className = kind;
}

function hint(text) {
  $("hint").hidden = !text;
  $("hint").textContent = text;
}

// Redraw at most ~10 times a second: a redraw per 32 KB chunk costs real throughput.
let lastDraw = 0;
function progress(done, total, bps) {
  const now = performance.now();
  if (done < total && done > 0 && now - lastDraw < 100) return;
  lastDraw = now;
  $("progress").hidden = false;
  const pct = total ? Math.floor((done / total) * 100) : 100;
  $("bar").style.width = `${pct}%`;
  let d = `${fmtBytes(done)} of ${fmtBytes(total)} · ${pct}%`;
  if (bps > 0 && done < total) d += ` · ${fmtBytes(bps)}/s · ${fmtEta((total - done) / bps)}`;
  $("detail").textContent = d;
  status(done < total ? (sendingMode ? "Sending…" : "Receiving…") : "Finishing…");
}

function connected(kind) {
  $("transport").hidden = false;
  $("transport").textContent = kind === "webrtc" ? "Direct connection" : "Through the relay";
  $("transport").title = kind === "webrtc"
    ? "The file goes straight between the two browsers (WebRTC)."
    : "The file goes through the relay. It is end-to-end encrypted, so the relay can't read it.";
}

let sendingMode = true;

function begin(isSend) {
  sendingMode = isSend;
  lockTabs(true);
  $("cancel").hidden = false;
  $("again").hidden = true;
  hint("");
  window.addEventListener("beforeunload", warnLeave);
}

function finish(text, kind) {
  status(text, kind);
  hint("");
  $("cancel").hidden = true;
  $("again").hidden = false;
  $("again").textContent = sendingMode ? "Send another file" : "Receive another file";
  $("offer").hidden = true;
  active = null;
  window.removeEventListener("beforeunload", warnLeave);
}

function warnLeave(e) { e.preventDefault(); e.returnValue = ""; }

function explain(err) {
  if (err instanceof CancelledError) return "Cancelled.";
  if (err instanceof MismatchError)
    return "The codes didn't match. Check the code for typos; the sender needs to start again for a new code.";
  return err && err.message ? err.message : String(err);
}

async function run(ctl) {
  active = ctl;
  try {
    await ctl.result;
  } catch (e) {
    finish(ctl.cancelled ? "Cancelled." : explain(e), ctl.cancelled ? "" : "bad");
  }
}

$("cancel").onclick = async () => {
  if (!active) return;
  $("cancel").disabled = true;
  if (offerResolve) { offerResolve(null); offerResolve = null; }
  await active.cancel();
  $("cancel").disabled = false;
};
$("again").onclick = () => { location.href = location.pathname; };

// ---- send

function pickFile(file) {
  if (!file || active) return;
  $("send-pick").hidden = true;
  $("send-info").hidden = false;
  $("send-file").textContent = `${file.name} (${fmtBytes(file.size)})`;
  begin(true);
  status("Preparing…");
  const ctl = startSend(file, { relayOnly: $("send-relay").checked }, {
    code(code) {
      $("code").textContent = code;
      $("code-box").hidden = false;
      $("copy-code").onclick = () => copy(code, $("copy-code"), "Copy code");
      $("copy-link").onclick = () => copy(`${location.origin}${location.pathname}#${code}`, $("copy-link"), "Copy link");
    },
    status: (t) => status(t),
    hint,
    connected(kind) { $("code-box").hidden = true; connected(kind); },
    waitingAccept: () => status("Waiting for the receiver to accept…"),
    progress,
    done: (t) => finish(t, "ok"),
  });
  run(ctl);
}

async function copy(text, btn, label) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied";
  } catch {
    btn.textContent = "Copy failed";
  }
  setTimeout(() => (btn.textContent = label), 1500);
}

$("file").onchange = (e) => pickFile(e.target.files[0]);
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files.length) pickFile(e.dataTransfer.files[0]);
});

// ---- receive

$("recv-form").onsubmit = (e) => {
  e.preventDefault();
  if (active) return;
  const text = $("code-input").value;
  try {
    parseCode(text);
  } catch (err) {
    status(err.message, "bad");
    return;
  }
  $("code-input").disabled = true;
  $("recv-btn").disabled = true;
  $("recv-relay").disabled = true;
  begin(false);
  status("Connecting…");
  const ctl = startReceive(text, { relayOnly: $("recv-relay").checked }, {
    status: (t) => status(t),
    hint,
    connected,
    offer: (meta) => offer(meta),
    progress,
    done: (t) => finish(t, "ok"),
  });
  run(ctl);
};

const canSaveToDisk = typeof window.showSaveFilePicker === "function";

function offer(meta) {
  $("offer").hidden = false;
  $("offer-name").textContent = meta.name;
  $("offer-size").textContent = fmtBytes(meta.size);
  const note = $("offer-note");
  note.hidden = canSaveToDisk || meta.size < 1024 ** 3;
  note.textContent = "This browser keeps the whole file in memory until it finishes, so a file this big may fail. " +
    "Chrome or Edge save straight to disk instead.";
  status("The sender wants to send you this file.");
  return new Promise((resolve) => {
    offerResolve = resolve;
    $("decline").onclick = () => { offerResolve = null; $("offer").hidden = true; resolve(null); };
    $("accept").onclick = async () => {
      // The save dialog must open straight from the click.
      let sink;
      try {
        sink = canSaveToDisk ? await diskSink(meta) : memorySink(meta);
      } catch (e) {
        if (e && e.name === "AbortError") return;      // closed the dialog: ask again
        sink = memorySink(meta);
      }
      offerResolve = null;
      $("offer").hidden = true;
      resolve(sink);
    };
  });
}

async function diskSink(meta) {
  const handle = await window.showSaveFilePicker({ suggestedName: meta.name });
  const w = await handle.createWritable();
  return {
    write: (chunk) => w.write(chunk),
    close: () => w.close(),
    abort: () => w.abort(),
  };
}

// Without a save dialog the file is collected in the page. Chunks are merged
// into Blobs every few MB: the browser can keep Blob data outside the
// JavaScript heap, and thousands of small arrays make garbage collection crawl.
function memorySink(meta) {
  const blobs = [];
  let parts = [], partBytes = 0;
  const merge = () => {
    if (parts.length) blobs.push(new Blob(parts));
    parts = [];
    partBytes = 0;
  };
  return {
    write(chunk) {
      parts.push(chunk);
      if ((partBytes += chunk.length) >= 8 * 1024 * 1024) merge();
    },
    close() {
      merge();
      const blob = new Blob(blobs, { type: meta.type || "application/octet-stream" });
      blobs.length = 0;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = meta.name;
      a.hidden = true;
      document.body.appendChild(a);
      a.click();
      // Keep a link (and the blob) in case the browser blocked the download.
      const again = Object.assign(document.createElement("a"), { href: url, download: meta.name, textContent: "save it here" });
      $("save-again").replaceChildren("If the download didn't start, ", again, ".");
      $("save-again").hidden = false;
    },
    abort() { parts = []; blobs.length = 0; },
  };
}

// ---- start-up

if (!window.isSecureContext || !crypto.subtle) {
  status("This page must be opened over HTTPS.", "bad");
  $("drop").style.pointerEvents = "none";
  $("recv-btn").disabled = true;
} else if (location.hash.length > 1) {
  // Opened from a share link: fill in the code, then drop it from the address bar.
  $("code-input").value = decodeURIComponent(location.hash.slice(1));
  history.replaceState(null, "", location.pathname + location.search);
  showTab("recv");
  $("recv-btn").focus();
}
