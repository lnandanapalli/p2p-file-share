# Browser client (share.nlpdf.site)

Send a file from one browser to another with a short code, nothing to install. This is a separate app from `p2p.py` / `p2p.ps1` (they don't talk to each other); it only shares the relay in `../relay`.

1. The sender opens the page, picks a file, and gets a code like `4821-apple-river-ocean` (plus a **Copy link** button: the link opens the receive page with the code filled in).
2. The receiver opens the page, enters the code (or opens the link), and accepts the file.
3. The file goes **directly between the two browsers** (WebRTC) when possible, otherwise **through the relay**. Either way it is end-to-end encrypted.

Plain HTML and JavaScript: no build step, no frameworks, no third-party code.

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

### 1. Relay

The relay must allow this site's origin. It reads `RELAY_ALLOWED_ORIGINS` (comma-separated), which defaults to `https://share.nlpdf.site`. If that's your domain, just redeploy the relay; otherwise set the variable in the App Service's **Environment variables** (App settings), e.g.:

```
RELAY_ALLOWED_ORIGINS=https://share.nlpdf.site
```

### 2. The site

Serve the files in this folder as static files over **HTTPS** (browsers only allow the crypto it uses on secure pages). Any static host works. With **Azure Static Web Apps** (free tier, custom domain + certificate included):

- App location: `web`, no build step (no API, no output location).
- `staticwebapp.config.json` adds security headers, including a Content-Security-Policy that only lets the page talk to itself and the relay.
- Add `share.nlpdf.site` as a custom domain.

### 3. Settings

`config.js` holds the relay URL and STUN servers. If you change the relay URL, also change it in the `connect-src` part of `staticwebapp.config.json` (or the page can't reach it).

## Browser support

Written for current Chrome, Edge, Firefox and Safari (it uses only standard WebCrypto, WebRTC and BigInt). The automated tests ran in Chromium; try a transfer in Firefox and Safari before relying on them.

- **Chrome and Edge** save straight to disk (a save dialog opens when you accept), so file size isn't limited by memory.
- **Firefox and Safari** collect the file in the page and download it at the end. Very large files (several GB) may fail there; the page warns above 1 GB.
- Keep both pages open until the transfer finishes. Its timers run in a Web Worker so a background tab isn't slowed down, but phones may pause a browser that isn't on screen, so keep it in front there. A dropped transfer can't be resumed; send it again.

## Files

| File | Purpose |
|---|---|
| `index.html` | The page and its styles |
| `app.js` | Page logic |
| `session.js` | One send/receive: rendezvous, SPAKE2, WebRTC or relay, file protocol |
| `transport.js` | Relay mailbox pipe, WebRTC pipe, and the encrypted acknowledged stream |
| `crypto.js` | Codes, SPAKE2, AES-GCM (WebCrypto + BigInt) |
| `timers.js` | Worker-based timers, so background tabs aren't slowed down |
| `words.js` | The 1024-word code list |
| `config.js` | Relay URL and STUN servers |
| `staticwebapp.config.json` | Security headers for Azure Static Web Apps |
