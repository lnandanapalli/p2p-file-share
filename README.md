# p2p.py

Encrypted peer-to-peer file transfer over UDP hole punching. Single file, zero dependencies, nothing beyond the Python 3 standard library.

Like Magic Wormhole, but you don't install anything.

## No Python? Use `p2p.ps1` (Windows)

`p2p.ps1` is a drop-in PowerShell client that speaks exactly the same protocol, codes and relay format as `p2p.py`. Either side can be Python or PowerShell, in any combination, in direct or `--relay` mode, including `--resume`.

It needs nothing installed: it runs on the Windows PowerShell 5.1 that ships with Windows 10/11, and on PowerShell 7+ (`pwsh`) on any OS. Same commands and flags, just a different launcher:

```
.\p2p.ps1 send photo.jpg --relay
.\p2p.ps1 recv --relay
```

If Windows says *"running scripts is disabled on this system"*, start it like this instead (this affects only this one run and changes no settings):

```
powershell -ExecutionPolicy Bypass -File .\p2p.ps1 recv --relay
```

Under the hood the transfer engine is C# embedded in the script, compiled in memory by PowerShell's built-in `Add-Type` on first run (a second or two). Plain PowerShell loops would be far too slow for per-packet crypto. Machines locked down by AppLocker / Device Guard (PowerShell "Constrained Language" mode) block `Add-Type`; the script detects that and says so.

**Both machines need matching versions**: relay mode now uses 32 KB chunks, and a mismatched peer is refused up front with a clear message instead of producing a corrupted file. Short codes (`4821-apple-river-ocean`) also need the current version on both sides; an older peer can still be reached with `send --long-code`.

To rebuild `p2p.ps1` after editing the engine: `python build/build.py` (it embeds `build/engine.cs` and the word list from `p2p.py`).

## Quick start

**Send a file:**

```
python p2p.py send photo.jpg
```

You'll get a short code like `4821-apple-river-ocean`. Give it to the receiver over any channel -- text, a phone call, Discord, whatever. It's short enough to read out loud.

By default, the app hides technical connection details like IP addresses and STUN/handshake status. Add `--verbose` if you want to see those details:

```
python p2p.py send photo.jpg --verbose
python p2p.py recv --verbose
```

**Receive a file:**

```
python p2p.py recv
```

Type the sender's code when prompted (dashes or spaces, any case). There is nothing to send back. Both sides verify the code, connect, and you'll see the filename and file size. Accept or decline the transfer. If accepted, the encrypted transfer begins automatically.

A code works **once**: if it is mistyped, both sides stop with "the codes didn't match", and the sender runs `send` again for a new code.

**How short codes work:** the number picks a mailbox on the relay so both sides can find each other; it isn't secret. The words are a password, and the two sides prove to each other that they know it with SPAKE2, a PAKE (password-authenticated key exchange). This turns the short password into a strong encryption key, and nobody watching the network or running the relay can brute-force it offline. An attacker who knows the number gets one live guess, about 1 in a billion. In direct mode, both sides then swap their addresses (encrypted) through the mailbox and leave the relay, and **the file itself goes directly peer-to-peer**.

**Old long codes (`--long-code`):** if you don't want the relay involved at all, the sender can use `send --long-code`. That brings back the original flow: a long send code (36 words for IPv4, 55 for IPv6) that carries the sender's address, and a recv code (23 / 42 words) that the receiver pastes back to the sender. Nothing ever contacts the relay in that mode. The receiver needs no flag; `recv` detects which kind of code was pasted.

**Use IPv6 (recommended when both sides have it):**

```
python p2p.py send photo.jpg -6
python p2p.py recv -6
```

Both sides must use `-6` together, or neither should. With IPv6, there is no NAT, so hole punching is not needed and symmetric NAT is not a problem. If a transfer drops mid-way and you resume, the printed resume command will automatically include `-6` -- you don't have to remember to add it.

**Resume a dropped transfer:**

```
python p2p.py recv --resume "tmpabcd1234"
```

If a receive is interrupted, the script preserves the partial file and prints the exact resume command, for example:

```
Partial file saved: ./tmpabcd1234
To resume:          python p2p.py recv --resume "./tmpabcd1234"
```

If you were using IPv6, the printed command will include `-6` automatically:

```
To resume:          python p2p.py recv -6 --resume "./tmpabcd1234"
```

Use the partial/temp file path from that message, not the final filename. The script verifies that the partial file belongs to the same transfer and resumes from the verified byte position.

**Optional timeout control:**

By default, both sides wait up to 1 hour during the code-exchange and hole-punch phases. If your users are slow to exchange codes, you can increase it:

```
python p2p.py send photo.jpg --connect-timeout 7200
python p2p.py recv --connect-timeout 7200
```

To resume a dropped transfer with a custom timeout:

```
python p2p.py recv --resume "./tmpabcd1234" --connect-timeout 7200
```

The `--connect-timeout` parameter (in seconds) controls how long both sides wait during the hole-punch and initial handshake. The file transfer itself has no time limit (only packet-loss retries apply).

**Relay mode (`--relay`):**

If direct hole punching can't work on your network (CG-NAT, symmetric NAT on both sides, nested VMs, strict firewalls), add `--relay`:

```
python p2p.py send photo.jpg --relay
python p2p.py recv
```

With `--relay` the tool skips STUN and hole punching entirely and sends the same encrypted packets through an HTTPS relay (see `relay/`). The relay only moves encrypted bytes; it can't read your file. With short codes, **one side using `--relay` is enough**: the two sides agree on the mode while verifying the code. If a direct connection is still failing after 30 seconds, the tool prints a reminder about this option. Use `--relay-host HOST` to point at your own relay instead of the default.

With `send --long-code --relay`, the old relay flow is used: one 13-word code, and both sides must pass `--relay`.

The file saves to the current directory.

## How it works

1. The sender makes a short code: a mailbox number plus 3 words (BIP39 subset, 1024 words).
2. Both sides meet at that relay mailbox and run SPAKE2 with the words as the password. Each side checks the other's key confirmation, so a wrong code is caught right away. They also agree on the mode (relay if either side asked for it).
3. Direct mode: both sides discover their public IP/port via STUN (Google's public STUN servers) and swap addresses through the mailbox, encrypted under the SPAKE2 key. With IPv6, the local address is the public address, so STUN is used only for confirmation. (With `--long-code` the addresses travel inside the long codes instead, and steps 1-2 don't happen.)
4. Both sides simultaneously send UDP packets to each other's public and local addresses until one gets through (hole punching), and an ephemeral Diffie-Hellman key exchange happens during the punch. With IPv6, there is no NAT, so this step completes more reliably.
5. The sender's metadata (filename, file size, hash) is sent to the receiver.
6. The receiver sees the filename and file size, then accepts or declines the transfer.
7. If accepted, the file is sent over a reliable transport layer (selective-repeat ARQ with windowed retransmission) on top of UDP.
8. Everything on the wire is encrypted and authenticated per-packet.

If the receiver declines the transfer, both sides are notified and the connection closes gracefully. The sender can then cancel and start a new transfer to a different receiver.


## NAT compatibility

Works behind most consumer NATs (IPv4):

- **Full-cone** -- works
- **Address-restricted** -- works
- **Port-restricted** -- works
- **Symmetric** -- will likely fail (both sides behind symmetric NAT is the hard case). Use `-6` if both sides have IPv6 -- it bypasses NAT entirely -- or run both sides with `--relay`.

**CG-NAT detection:** At startup, the script checks whether STUN reports a private or CG-NAT address (RFC 1918 ranges and RFC 6598 `100.64.0.0/10`). If detected, a warning is printed before attempting the connection. CG-NAT means your ISP is sharing one public IP across many customers; direct UDP hole-punching cannot reach your machine in that configuration; run both sides with `--relay` instead. This check only applies to IPv4; IPv6 has no CG-NAT equivalent.

With **IPv6** (`-6`): NAT does not exist, so all of the above cases are irrelevant. The only requirement is that both peers have a globally routable IPv6 address and that their firewall allows inbound UDP.

If both peers are on the same LAN, it will connect via local addresses regardless of which mode is used.

## Crypto

> **Warning:** The encryption uses a non-standard construction built from `hashlib` and `hmac` for zero-dependency portability. It has not been independently audited. Do not use this for high-stakes or life-safety transfers. For those, use other tools of your choice. This only helps when you have a low-stakes scenario but cannot install anything on the machine. You should also have Python on the machine. You could also manually encrypt using some other tool before sending which adds an additional layer of security.

What it does:

- **Short codes:** SPAKE2 ([RFC 9382](https://www.rfc-editor.org/rfc/rfc9382)) in the RFC 3526 Group 14 prime-order subgroup, with explicit key confirmation. M and N are hashed into the group, so nobody knows their discrete logs. The relay mailbox ID is derived from the number only, never from the words.
- **Key derivation:** PBKDF2-HMAC-SHA256, 100k rounds, salt derived from the SPAKE2 key (random with `--long-code`)
- **Key exchange:** Ephemeral Diffie-Hellman (RFC 3526 Group 14, 2048-bit MODP) for forward secrecy
- **Encryption:** SHA-256 in counter mode as a stream cipher (generates keystream blocks via `SHA-256(key || nonce || counter)`, XORed with plaintext)
- **Authentication:** HMAC-SHA256 truncated to 128 bits, per packet
- **Integrity:** SHA-256 hash of the entire file, verified on receive
- **Replay protection:** Sliding-window nonce tracking
- **Direction separation:** Independent key pairs for each direction (sender-to-receiver, receiver-to-sender)
- **Resume capability:** SHA-256 verification of the preserved partial file before resuming from the verified position

With short codes, the code is only useful while the sender is waiting, and only once. Someone who sees the code *before* the receiver uses it could race the receiver and get the file instead; the real receiver would then just wait at an empty mailbox. Share it over a reasonably private channel, and if the receiver never connects but the sender says the transfer happened, assume the code leaked. A code that leaks after the transfer is worthless: the SPAKE2 and DH keys are ephemeral.

With `--long-code`, the shared secret (128 bits, from `secrets.token_bytes`) travels inside the send code. Anyone who intercepts that code can derive keys, so share it over a reasonably private channel. The DH exchange provides forward secrecy -- even if the code leaks later, previously captured traffic can't be decrypted.

## Limits

| Parameter | Default |
|---|---|
| Max file size | 1 TB |
| Chunk size | 1400 bytes (fits typical MTU) |
| Send window | 32 packets |
| ACK timeout | 2.5 seconds |
| Connection timeout | 3600 seconds (1 hour)* |
| Done handshake timeout | 120 seconds |
| Stall timeout | 300 seconds |
| Per-packet retries | 200 |

*Covers hole-punch, code exchange, and handshake phases. Override with `--connect-timeout`.

These are constants near the top of the file. Adjust them if needed.

## Requirements

- Python 3.6+
- HTTPS access to the relay for short codes (it is only a meeting point in direct mode); not needed with `send --long-code` in direct mode
- Network access to at least one of Google's STUN servers (outbound UDP to port 19302)
- IPv4: a NAT that isn't symmetric on both ends
- IPv6 (`-6`): a globally routable IPv6 address on both sides and a firewall that allows inbound UDP

No `pip install`. No virtualenv. Just the one file.

## Limitations

- **Relaying the file is opt-in, not automatic.** If hole punching fails (symmetric NAT on both sides, CG-NAT, aggressive firewall), the connection fails; it does not switch to the relay on its own. Re-run with `--relay`, or use `-6` if both sides have IPv6 -- it sidesteps NAT entirely.
- **Short codes need the relay as a meeting point.** If it is down, use `send --long-code`.
- **Single file only.** To send a directory, tar/zip it first.
- **Manual resume only.** If the transfer drops, restart `recv` with the `--resume` command printed by the previous attempt. Resume depends on keeping the preserved partial/temp file.
- **Non-standard crypto.** The stream cipher is homebrew. It's built from solid primitives (SHA-256, HMAC, PBKDF2, DH) but the composition hasn't been formally analyzed. See the warning above.

## License

MIT License. See [LICENSE](LICENSE).