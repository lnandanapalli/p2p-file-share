# p2p relay

HTTPS relay for `p2p.py`. With the default short codes (`4821-apple-river-ocean`)
it is the meeting point: both sides find each other in a mailbox picked by the
number, run SPAKE2 and swap their addresses there, then (in direct mode) leave.
With `--relay` on either side the whole transfer goes through it. With
`send --long-code` and no `--relay` the client never contacts it. It is a dumb
in-memory pipe; everything is already encrypted by the client, and the relay
never sees anything derived from the code's words.

## Build and run

    docker build --platform linux/amd64 -t p2prelay .
    docker run -p 8080:8080 p2prelay

The server speaks plain HTTP on `RELAY_ADDR` (default `:8080`). `p2p.py`
connects over HTTPS, so put TLS in front of it (Azure App Service does this).

## Deployment notes

- **Run exactly one instance.** Sessions and rate-limit state live in memory;
  with several instances the two peers could land on different ones.
- **Client IP** is read only from the `X-Client-IP` header (set by Azure App
  Service). `X-Forwarded-For` is ignored on purpose. Requests without a valid
  value share one "unknown" bucket with 4x the limits. If you put another proxy
  in front (Front Door, Cloudflare), update `clientIP()` in `main.go`.
  The relay logs a warning if most requests have no valid `X-Client-IP`.
- **Limits** (constants at the top of `main.go`): 2000 sessions, 512 MiB queued
  in total, 50 req/s per IP, 1 new session per 5 s per IP, 8 concurrent
  long-polls per IP.
- **Browser client** (`web/`): it calls the relay from the page's own origin,
  so the relay sends CORS headers for the origins in `RELAY_ALLOWED_ORIGINS`
  (comma-separated, default `https://share.nlpdf.site`). The CLI clients send
  no `Origin` header and are unaffected. Set it as an App Service app setting
  if the site lives elsewhere.
- Health check: `GET /healthz`.
