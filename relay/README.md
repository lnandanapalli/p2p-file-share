# p2p relay

HTTPS relay for `p2p.py`, used only when **both** sides run with `--relay`.
Without that flag the client never contacts it. It is a dumb in-memory pipe;
packets are already encrypted by the client.

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
- Health check: `GET /healthz`.
