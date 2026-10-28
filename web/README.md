# Browser client (share.nlpdf.site)

Send a file from one browser to another with a short code, nothing to install. This is a separate app from `p2p.py` / `p2p.ps1` (they don't talk to each other); it only shares the relay in `../relay`.

1. The sender opens the page, picks a file, and gets a code like `4821-apple-river-ocean` (plus a **Copy link** button: the link opens the receive page with the code filled in).
2. The receiver opens the page, enters the code (or opens the link), and accepts the file.
3. The file goes **directly between the two browsers** (WebRTC) when possible, otherwise **through the relay**. Either way it is end-to-end encrypted.

Plain HTML and JavaScript: no frameworks, no npm, no third-party code. The container is a small Go server with no dependencies either.

## How it works

| Step | What happens |
|---|---|
| Meet | Both browsers poll the relay mailbox picked by the code's **number** (not secret). |
| Verify the code | **SPAKE2** (RFC 9382, RFC 3526 2048-bit group) with the code's **words** as the password, plus key confirmation. A wrong code stops both sides. The relay only ever sees data derived from the number, so it can't test guesses offline; an attacker gets one live guess (about 1 in a billion). |
| Connect | The WebRTC offer/answer is sent **encrypted under the SPAKE2 key**. That ties WebRTC's own encryption (DTLS) to the code, so the relay can't sit in the middle. The **sender** decides: WebRTC if its data channel opens within 10 s, otherwise the relay. It tells the receiver, so both always agree. |
| Transfer | Every message is encrypted with **AES-GCM** (separate key per direction), numbered and acknowledged, over whichever transport was chosen. The receiver accepts or declines first, and confirms when the file is saved. |

**Relay only** (a checkbox on either side) skips WebRTC: the other side then never learns your IP address. WebRTC normally reveals each side's IP address to the other, as any direct connection does.

There is no TURN server: when two networks can't connect directly, the relay plays that role, with the same end-to-end encryption.

## Deploying

Runs as a container on the same App Service plan as the relay (one Linux plan can host any number of apps).

### 1. Relay

The relay must allow this site's origin. It reads `RELAY_ALLOWED_ORIGINS` (comma-separated), which defaults to `https://share.nlpdf.site`. If that's your domain, nothing to set; otherwise add it as an App Service app setting on the relay, e.g. `RELAY_ALLOWED_ORIGINS=https://share.nlpdf.site`.

### 2. This site

`Dockerfile` builds a tiny image (a static Go binary on `scratch`, like the relay). The binary contains the files in `site/` and serves them with security headers, including a Content-Security-Policy that only lets the page talk to itself and the relay.

    docker build --platform linux/amd64 -t p2pweb .
    docker run -p 8080:8080 p2pweb

On App Service: create a second Web App (container, Linux) on the existing plan from this image, then

- set `WEBSITES_PORT=8080`,
- add `share.nlpdf.site` as a custom domain with a managed certificate (the page must be served over HTTPS),
- optionally set the health check path to `/healthz`.

Settings (App Service app settings / environment variables):

| Variable | Default | Purpose |
|---|---|---|
| `RELAY_URL` | `https://relay.nlpdf.site` | The relay. Written into `config.js` and the page's Content-Security-Policy, so changing it needs no rebuild. |
| `WEB_ADDR` | `:8080` | Listen address |

Files are revalidated on every load (cheap `304`s), so a new deployment takes effect immediately.

## Browser support

Written for current Chrome, Edge, Firefox and Safari (it uses only standard WebCrypto, WebRTC and BigInt). The automated tests ran in Chromium; try a transfer in Firefox and Safari before relying on them.

- **Chrome and Edge** save straight to disk (a save dialog opens when you accept), so file size isn't limited by memory.
- **Firefox and Safari** collect the file in the page and download it at the end. Very large files (several GB) may fail there; the page warns above 1 GB.
- Keep both pages open until the transfer finishes. Its timers run in a Web Worker so a background tab isn't slowed down, but phones may pause a browser that isn't on screen, so keep it in front there. A dropped transfer can't be resumed; send it again.

## Files

| File | Purpose |
|---|---|
| `site/index.html` | The page and its styles |
| `site/app.js` | Page logic |
| `site/session.js` | One send/receive: rendezvous, SPAKE2, WebRTC or relay, file protocol |
| `site/transport.js` | Relay mailbox pipe, WebRTC pipe, and the encrypted acknowledged stream |
| `site/crypto.js` | Codes, SPAKE2, AES-GCM (WebCrypto + BigInt) |
| `site/timers.js` | Worker-based timers, so background tabs aren't slowed down |
| `site/words.js` | The 1024-word code list |
| `site/config.js` | Relay URL (replaced from `RELAY_URL` by the server) and STUN servers |
| `main.go`, `go.mod`, `Dockerfile` | The container: a small static file server with security headers |
