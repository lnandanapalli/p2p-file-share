# p2p.py

Encrypted peer-to-peer file transfer over UDP hole punching. Single file, zero dependencies, nothing beyond the Python 3 standard library.

Like Magic Wormhole, but you don't install anything.

## Quick start

**Send a file:**

```
python p2p.py send photo.jpg
```

You'll get a send code (36 words). Give it to the receiver over any channel -- text, email, Discord, whatever.

By default, the app hides technical connection details like IP addresses and STUN/handshake status. Add `--verbose` if you want to see those details:

```
python p2p.py send photo.jpg --verbose
python p2p.py recv --verbose
```

**Receive a file:**

```
python p2p.py recv
```

Paste the sender's code when prompted. You'll get a recv code (23 words) -- give that back to the sender. Once both codes are exchanged, you'll see the filename and file size. Accept or decline the transfer. If accepted, the encrypted transfer begins automatically.

**Resume a dropped transfer:**

```
python p2p.py recv --resume "tmpabcd1234"
```

If a receive is interrupted, the script preserves the partial file and prints the exact resume command, for example:

```
Partial file saved: ./tmpabcd1234
To resume:          python p2p.py recv --resume "./tmpabcd1234"
```

Use the partial/temp file path from that message, not the final filename. The script verifies that the partial file belongs to the same transfer and resumes from the verified byte position.

**Optional timeout control and resume:**

By default, both sides wait up to 1 hour during the code-exchange and hole-punch phases. If your users are slow to exchange codes, you can increase it:

```
python p2p.py send photo.jpg --connect-timeout 7200
python p2p.py recv --connect-timeout 7200
```

To resume a dropped transfer with a custom timeout, use the `--resume` flag with the preserved partial file:

```
python p2p.py recv --resume "./tmpabcd1234" --connect-timeout 7200
```

The `--connect-timeout` parameter (in seconds) controls how long both sides wait during the hole-punch and initial handshake. The file transfer itself has no time limit (only packet-loss retries apply).

The file saves to the current directory.

## How it works

1. Both sides discover their public IP/port via STUN (Google's public STUN servers).
2. Addresses and a shared secret are packed into human-readable word codes (BIP39 subset, 1024 words).
3. Both sides simultaneously send UDP packets to each other's public and local addresses until one gets through (hole punching).
4. An ephemeral Diffie-Hellman key exchange happens during the punch for forward secrecy.
5. The sender's metadata (filename, file size, hash) is sent to the receiver.
6. The receiver sees the filename and file size, then accepts or declines the transfer.
7. If accepted, the file is sent over a reliable transport layer (selective-repeat ARQ with windowed retransmission) on top of UDP.
8. Everything on the wire is encrypted and authenticated per-packet.

If the receiver declines the transfer, both sides are notified and the connection closes gracefully. The sender can then cancel and start a new transfer to a different receiver.


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
- **Resume capability:** SHA-256 verification of the preserved partial file before resuming from the verified position

The shared secret (128 bits, from `secrets.token_bytes`) travels inside the send code. Anyone who intercepts that code can derive keys, so share it over a reasonably private channel. The DH exchange provides forward secrecy -- even if the code leaks later, previously captured traffic can't be decrypted.

## Limits

| Parameter | Default |
|---|---|
| Max file size | 1 TB |
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
- **Manual resume only.** If the transfer drops, restart `recv` with the `--resume` command printed by the previous attempt. Resume depends on keeping the preserved partial/temp file.
- **Non-standard crypto.** The stream cipher is homebrew. It's built from solid primitives (SHA-256, HMAC, PBKDF2, DH) but the composition hasn't been formally analyzed. See the warning above.

## License

MIT License. See [LICENSE](LICENSE).
