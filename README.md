# p2p.py

Encrypted peer-to-peer file transfer over UDP hole punching. Single file, zero dependencies, nothing beyond the Python 3 standard library.

Think Magic Wormhole, but you don't install anything.

## Quick start

**Send a file:**

```
python p2p.py send photo.jpg
```

You'll get a send code (36 words). Give it to the receiver over any channel -- text, email, Discord, whatever.

**Receive a file:**

```
python p2p.py recv
```

Paste the sender's code when prompted. You'll get a recv code (23 words) -- give that back to the sender. Once both codes are exchanged, the transfer starts automatically.

**Optional timeout control:**

By default, both sides wait up to 1 hour during the code-exchange and hole-punch phases. If your users are slow to exchange codes, you can increase it:

```
python p2p.py send photo.jpg --connect-timeout 7200
python p2p.py recv --connect-timeout 7200
```

The `--connect-timeout` parameter (in seconds) controls how long both sides wait during the hole-punch and initial handshake. The file transfer itself has no time limit (only packet-loss retries apply).

The file saves to the current directory.

## How it works

1. Both sides discover their public IP/port via STUN (Google's public STUN servers).
2. Addresses and a shared secret are packed into human-readable word codes (BIP39 subset, 1024 words).
3. Both sides simultaneously send UDP packets to each other's public and local addresses until one gets through (hole punching).
4. An ephemeral Diffie-Hellman key exchange happens during the punch for forward secrecy.
5. The file is sent over a reliable transport layer (selective-repeat ARQ with windowed retransmission) on top of UDP.
6. Everything on the wire is encrypted and authenticated per-packet.

## NAT compatibility

Works behind most consumer NATs:

- **Full-cone** -- works
- **Address-restricted** -- works
- **Port-restricted** -- works
- **Symmetric** -- will likely fail (both sides behind symmetric NAT is the hard case; no relay server exists to fall back on)

If both peers are on the same LAN, it will connect via local addresses.

## Crypto

> **Warning:** The encryption uses a non-standard construction built from `hashlib` and `hmac` for zero-dependency portability. It has not been independently audited. Do not use this for high-stakes or life-safety transfers. For those, use other tools of your choice. This only helps when you have a low-stakes scenario but cannot install anything on the machine. You should also have Python on the machine. You could also manually encrypt using some other tool before sending which adds an additional layer of security.

What it does:

- **Key derivation:** PBKDF2-HMAC-SHA256, 100k rounds, random 128-bit salt
- **Key exchange:** Ephemeral Diffie-Hellman (RFC 3526 Group 14, 2048-bit MODP) for forward secrecy
- **Encryption:** SHA-256 in counter mode as a stream cipher (generates keystream blocks via `SHA-256(key || nonce || counter)`, XORed with plaintext)
- **Authentication:** HMAC-SHA256 truncated to 128 bits, per packet
- **Integrity:** SHA-256 hash of the entire file, verified on receive
- **Replay protection:** Sliding-window nonce tracking
- **Direction separation:** Independent key pairs for each direction (sender-to-receiver, receiver-to-sender)

The shared secret (128 bits, from `secrets.token_bytes`) travels inside the send code. Anyone who intercepts that code can derive keys, so share it over a reasonably private channel. The DH exchange provides forward secrecy -- even if the code leaks later, previously captured traffic can't be decrypted.

## Limits

| Parameter | Default |
|---|---|
| Max file size | 4 GB |
| Chunk size | 1400 bytes (fits typical MTU) |
| Send window | 32 packets |
| Connection timeout | 3600 seconds (1 hour)* |
| Per-packet retries | 200 |

*Covers hole-punch, code exchange, and handshake phases. Override with `--connect-timeout`.

These are constants near the top of the file. Adjust them if needed.

## Requirements

- Python 3.6+
- Network access to at least one of Google's STUN servers (outbound UDP to port 19302)
- A NAT that isn't symmetric on both ends

No `pip install`. No virtualenv. Just the one file.

## Limitations

- **No relay fallback.** If hole punching fails (symmetric NAT on both sides, aggressive firewall), there's no TURN server to fall through to. The connection just fails.
- **Single file only.** To send a directory, tar/zip it first.
- **IPv4 only.** No IPv6 support in the STUN client or address encoding.
- **No resume.** If the transfer drops, you start over.
- **Non-standard crypto.** The stream cipher is homebrew. It's built from solid primitives (SHA-256, HMAC, PBKDF2, DH) but the composition hasn't been formally analyzed. See the warning above.

## License

MIT License. See [LICENSE](LICENSE).
