#!/usr/bin/env python3
"""
p2p.py  --  Zero-dependency encrypted file transfer over UDP hole punching.

Like Magic Wormhole, but needs nothing beyond the Python standard library.
Works behind most NATs (full-cone, address-restricted, port-restricted).
Symmetric NATs may fail direct hole punching -- that's a hard networking limit.
For those networks, run both sides with --relay to go through an HTTPS relay.

Usage:
    python p2p.py send <file> [-6] [--relay] [--long-code] [--connect-timeout SECONDS] [--verbose]
    python p2p.py recv        [-6] [--relay] [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]

  --connect-timeout controls how long (in seconds) both sides will wait
  during the hole-punch and initial handshake phases.  Default is 3600s
  (1 hour) so users have plenty of time to exchange codes out-of-band.
  The transfer itself has no time limit -- only packet-loss retries apply.
  --verbose shows technical connection details such as IP addresses and
  handshake/STUN status.

Flow (default, short codes):
    1. Sender runs 'send', gets a short code like 4821-apple-river-ocean.
    2. Sender shares the code out-of-band (chat, phone call, etc.).
    3. Receiver runs 'recv' and types the code.
    4. Both sides meet at the relay mailbox picked by the number, prove they
       know the same words with SPAKE2 (a PAKE), and swap their addresses
       encrypted under the resulting key.
    5. Both sides punch through NAT; the file goes directly peer-to-peer.
       (With --relay on either side, the file goes through the relay instead.)
    6. Receiver sees file name and size, then accepts or declines.
    7. If accepted, the encrypted transfer begins.

  With 'send --long-code' the old flow is used instead: a long send code
  that carries the addresses, and a long recv code pasted back. In direct
  mode that never contacts the relay. With --long-code --relay (both sides)
  there is one 13-word code and no recv code.

Crypto:
    - Short codes: SPAKE2 (RFC 9382) over RFC 3526 Group 14 turns the
      30-bit code words into a strong key; one online guess per code
    - Long codes: 128-bit random secret (embedded in the send code)
    - PBKDF2-HMAC-SHA256 key derivation (random salt) -> separate keys per direction
    - Ephemeral Diffie-Hellman (RFC 3526 Group 14) for forward secrecy
    - AES-256-CTR (OpenSSL via ctypes) when both sides can, else
      SHA-256 in CTR mode as a stream cipher (XOR keystream)
    - HMAC-SHA256 truncated to 128 bits for per-packet authentication
    - SHA-256 file hash for end-to-end integrity verification

Security:
    - Forward secrecy via ephemeral DH (compromise of send code
      does not expose previously captured traffic)
    - Replay protection via nonce tracking
    - Path-traversal-safe filename handling
    - Streamed receive (no full-file RAM buffering)
    - File size limit enforced on receiver side
"""

import socket
import struct
import os
import sys
import hashlib
import hmac as _hmac
import base64
import time
import select
import secrets
import json
import math
import tempfile
import shutil
import traceback
import zlib
import http.client
import threading
import queue
import collections

# ===============================================================================
# Configuration
# ===============================================================================

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
]

CHUNK_SIZE = 1400   # bytes per DATA packet payload (fits typical MTU)
WINDOW_SIZE = 32    # max unACKed in-flight packets
ACK_TIMEOUT = 2.5   # seconds before retransmitting; must exceed 2× max round-trip time

# Relay mode travels over HTTPS/TCP, not raw UDP, so the MTU-sized chunk and
# tiny window above only add overhead there: 32 x 1400 B = ~44 KB in flight
# per relay round trip, which caps throughput at ~0.1 MB/s. In relay mode
# main() swaps in these values instead (both sides must run this version).
RELAY_CHUNK_SIZE  = 32 * 1024   # must stay < 65 KB (2-byte length in batch format)
RELAY_WINDOW_SIZE = 96          # ~3 MB in flight per round trip
RELAY_ACK_TIMEOUT = 15.0        # big batches on a slow uplink take seconds; TCP doesn't drop
RELAY_BATCH_BYTES = 2 * 1024 * 1024   # cap per POST (relay rejects > 4 MiB)
# Request pacing: the relay allows ~50 requests/s per IP. 1/0.06 + 1/0.04
# = ~42/s worst case per peer, so we stay under it instead of eating 429s.
RELAY_MIN_POST_GAP = 0.06
RELAY_MIN_GET_GAP  = 0.04
RELAY_CLOSE_FLUSH  = 2.0     # seconds close() waits for queued packets to go out
MAX_RETRIES = 200   # per-packet retransmit limit
CONNECT_TIMEOUT = 3600   # seconds for all connection-phase waits
PUNCH_INTERVAL = 0.25    # seconds between HELLO salvos
DONE_TIMEOUT = 120       # seconds to wait for DONE/DONEACK handshake
STALL_TIMEOUT = 300      # seconds of no progress before declaring the transfer dead
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024 * 1024   # 1 TB receive limit
RESUME_CHUNKS_PER_BIN = 18000   # ~25 MB per binary-search bin (resume negotiation)

# ---- Relay mode (opt-in: only used when BOTH sides pass --relay) -------------
# Some networks (nested virtualization, libslirp-style outbound-only NAT,
# CG-NAT, aggressive firewalls) cannot receive unsolicited inbound UDP at
# all, so no amount of STUN/hole-punching helps. For those, both sides run
# with --relay: no STUN and no hole punching at all, the same encrypted
# packets travel through a small HTTPS relay you control instead. Without
# --relay the relay is never contacted. The relay is a dumb, in-memory
# pipe -- it never sees plaintext, and all encryption/authentication/ARQ
# logic below is completely unaware the transport changed.
RELAY_HOST         = "relay.nlpdf.site"   # point this at your deployed relay
RELAY_HTTP_TIMEOUT = 25      # seconds; must exceed the relay's long-poll window
RELAY_FLUSH_WAIT   = 0.02    # seconds; max delay before an outgoing batch flushes
RELAY_RETRY_SLEEP  = 0.25    # seconds; pause after a failed relay HTTP call
DIRECT_HINT_AFTER  = 30      # seconds of direct connecting before suggesting --relay
_DIRECT_HINT = ("\n  Taking a while. If this keeps failing (strict NAT, CG-NAT, VM networking),\n"
                "  run BOTH sides again with --relay to connect through the relay instead.")
RELAY_SEND_TIMEOUT = 8       # seconds; sends are short, so a dead path is noticed fast
RELAY_BACKOFF_MAX  = 10      # seconds; cap on how long a 429/503 Retry-After is honored
# Connection reuse (keep-alive). Safe by design: any error discards the
# connection, idle/old connections are never trusted, and a stale one is
# retried once on a fresh connection. Set RELAY_REUSE_CONN = False to go
# back to a brand-new HTTPS connection for every request.
RELAY_REUSE_CONN    = True
RELAY_CONN_MAX_AGE  = 60     # seconds; recycle a connection after this long
RELAY_CONN_MAX_REQS = 200    # ...or after this many requests
RELAY_CONN_MAX_IDLE = 15     # seconds; never reuse a connection idle longer than this

# Packet types
T_HELLO   = 1
T_META    = 2
T_DATA    = 3
T_ACK     = 4
T_DONE    = 5
T_DONEACK = 6
T_ABORT   = 7   # receiver declined or cancelled
T_HASHQ   = 8   # receiver asks sender for SHA-256 hash of partial file
T_HASHR   = 9   # sender replies with SHA-256 hash

# Receive buffer (UDP max)
RECV_BUF = 65536

VERBOSE  = False
USE_IPV6 = False
USE_RELAY      = False   # --relay: skip hole punching, use the HTTPS relay only
USE_AES        = False   # set when both sides can do AES-256


def _vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)


# ===============================================================================
# Error handling helpers
# ===============================================================================

def _die(msg, sock=None, code=1):
    """Print a clean error message and exit.  Never shows a traceback."""
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
    print(f"\n  Error: {msg}")
    sys.exit(code)


def _send_abort_signal(sock, cipher, peer, reason="ABORT", tries=6, delay=0.05):
    """Best-effort authenticated abort notification."""
    if not peer:
        return
    try:
        pkt = cipher.encrypt(T_ABORT, reason.encode("utf-8", "replace"))
    except Exception:
        return
    for _ in range(tries):
        try:
            sock.sendto(pkt, peer)
        except OSError:
            pass
        time.sleep(delay)


def _drain_socket(sock):
    """
    Discard every datagram already sitting in the OS receive buffer.

    Why this matters
    ----------------
    The receiver starts hole-punching (and therefore fires HELLO packets
    at the sender's port) the moment it displays its RECV CODE -- before
    the user has even copied that code to the sender.  If the receiver
    then cancels and restarts on a new port, those early HELLOs are still
    sitting in the sender's socket buffer.  Without this drain, punch_hole()
    would read one of those stale HELLOs, "connect" to the now-dead first
    port, derive the wrong DH shared secret, and send META to a closed
    port -- causing ConnectionResetError (WinError 10054) on Windows and a
    silent stall on the receiver side.

    Draining right before punch_hole() ensures only packets that arrive
    *after* the user has actually exchanged both codes are considered.
    The addr-filter inside punch_hole() provides a second layer of defence.
    """
    sock.setblocking(False)
    try:
        while True:
            sock.recvfrom(RECV_BUF)
    except OSError:
        pass
    finally:
        sock.setblocking(True)


def _sock_recv_typed(sock, cipher, peer, want, timeout):
    """
    Block until a packet of type `want` from `peer` arrives, discarding all
    other packet types that come in while waiting.  Returns the decrypted
    payload, or None if `timeout` seconds elapse without a matching packet.

    The key difference from a bare recvfrom loop: on each wakeup the OS
    buffer is drained completely in a non-blocking burst before going back
    to select().  This means a pile of stale wrong-type packets in the
    buffer (e.g. META retransmits during resume negotiation, or duplicate
    HASHQs that built up while the sender was computing a hash) never each
    consume a full 1-second timeout slot -- they're all cleared in
    microseconds and the wait budget is measured in actual wall-clock
    silence, not packets-of-the-wrong-type.
    """
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        try:
            rdy = select.select([sock], [], [], remaining)
        except OSError:
            return None
        if not rdy[0]:
            return None
        # drain the entire OS buffer in one non-blocking burst
        sock.setblocking(False)
        found = None
        try:
            while True:
                try:
                    raw, addr = sock.recvfrom(RECV_BUF)
                except BlockingIOError:
                    break   # buffer empty
                except OSError:
                    break
                if addr != peer:
                    continue
                try:
                    ptype, pl = cipher.decrypt(raw)
                except Exception:
                    continue
                if ptype == want:
                    found = pl
                    break
                # wrong type -- discard and keep draining
        finally:
            sock.setblocking(True)
        if found is not None:
            return found
        # burst found nothing matching; go back to select with remaining time


# ===============================================================================
# STUN Client  (RFC 5389 -- minimal Binding Request)
# ===============================================================================

_STUN_MAGIC = 0x2112A442


def _stun_transact(sock, server):
    """Send a STUN Binding Request and parse the response.

    *server* is a *(hostname, port)* 2-tuple.  The hostname is resolved to
    the address family currently in use (IPv4 or IPv6) via getaddrinfo so
    that AF_INET6 sockets get a proper 4-tuple for sendto.

    Parses both IPv4 and IPv6 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS attributes.
    """
    host, port = server
    family = socket.AF_INET6 if USE_IPV6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)
        if not infos:
            return None
        server_addr = infos[0][4]   # full address tuple for sendto
    except OSError:
        return None

    txn_id = secrets.token_bytes(12)
    req = struct.pack("!HHI", 0x0001, 0, _STUN_MAGIC) + txn_id
    try:
        sock.sendto(req, server_addr)
    except OSError:
        return None

    try:
        ready = select.select([sock], [], [], 2.0)
    except OSError:
        return None
    if not ready[0]:
        return None

    try:
        data, _ = sock.recvfrom(1024)
    except OSError:
        return None

    if len(data) < 20:
        return None
    msg_type, msg_len = struct.unpack("!HH", data[:4])
    if msg_type != 0x0101:
        return None
    if data[8:20] != txn_id:
        return None

    pos = 20
    while pos + 4 <= 20 + msg_len and pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos : pos + 4])
        aval = data[pos + 4 : pos + 4 + alen]
        if len(aval) < alen:
            break

        if atype == 0x0020:                         # XOR-MAPPED-ADDRESS
            if alen >= 8 and aval[1] == 0x01:       # IPv4
                xport = struct.unpack("!H", aval[2:4])[0] ^ (_STUN_MAGIC >> 16)
                xip   = struct.unpack("!I", aval[4:8])[0] ^ _STUN_MAGIC
                return socket.inet_ntoa(struct.pack("!I", xip)), xport
            elif alen >= 20 and aval[1] == 0x02:    # IPv6
                xport   = struct.unpack("!H", aval[2:4])[0] ^ (_STUN_MAGIC >> 16)
                # XOR key: 4-byte magic cookie + 12-byte transaction ID
                xor_key = struct.pack("!I", _STUN_MAGIC) + txn_id
                ip_bytes = bytes(aval[4 + i] ^ xor_key[i] for i in range(16))
                return socket.inet_ntop(socket.AF_INET6, ip_bytes), xport

        elif atype == 0x0001:                       # MAPPED-ADDRESS (fallback)
            if alen >= 8 and aval[1] == 0x01:       # IPv4
                port = struct.unpack("!H", aval[2:4])[0]
                ip   = socket.inet_ntoa(aval[4:8])
                return ip, port
            elif alen >= 20 and aval[1] == 0x02:    # IPv6
                port = struct.unpack("!H", aval[2:4])[0]
                ip   = socket.inet_ntop(socket.AF_INET6, aval[4:20])
                return ip, port

        pos += 4 + alen + ((4 - alen % 4) % 4)
    return None


def stun_discover(sock):
    """Try multiple STUN servers, return first successful (ip, port) or None."""
    for server in STUN_SERVERS:
        result = _stun_transact(sock, server)
        if result:
            return result
    return None


def get_local_ip():
    """Best-effort local IP (not 127.0.0.1 / ::1).

    For IPv6, connecting to Google's public IPv6 DNS lets the OS pick the
    right source address without sending any real traffic -- same trick as
    the IPv4 version, just using a different family and remote address.
    With IPv6 there is no NAT, so this local address IS the public address.
    """
    try:
        if USE_IPV6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("2001:4860:4860::8888", 80, 0, 0))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "::1" if USE_IPV6 else "127.0.0.1"


# ---------------------------------------------------------------------------
# CG-NAT detection  (IPv4 only)
# ---------------------------------------------------------------------------

def _is_cgnat(ip: str) -> bool:
    """Return True if the STUN-reported public IP is in a private or CG-NAT
    range -- meaning hole-punching will almost certainly fail.

    Only meaningful for IPv4; IPv6 has no CG-NAT equivalent, so this
    always returns False when USE_IPV6 is set.

    Ranges:
      10.0.0.0/8       RFC 1918
      172.16.0.0/12    RFC 1918
      192.168.0.0/16   RFC 1918
      100.64.0.0/10    RFC 6598  IANA CG-NAT shared address space
    """
    if USE_IPV6:
        return False
    try:
        a, b, c, d = map(int, ip.split("."))
        if a == 10:                          return True
        if a == 172 and 16 <= b <= 31:       return True
        if a == 192 and b == 168:            return True
        if a == 100 and 64 <= b <= 127:      return True   # RFC 6598
    except Exception:
        pass
    return False


_CGNAT_WARNING = """\
  *** CG-NAT detected ***
  Your STUN-reported public IP ({ip}) is a private/CG-NAT address.
  Your ISP is sharing one real public IP across many customers, so
  direct UDP hole-punching cannot reach your machine and will time out.
  A relay-capable transfer tool is required in this configuration.
  Continuing anyway -- direct connection may succeed on some networks.
"""


# ---------------------------------------------------------------------------
# Address helpers  (IPv4/IPv6 transparent)
# ---------------------------------------------------------------------------

def _ip_pack(addr: str) -> bytes:
    """Encode an IP string to 4 bytes (IPv4) or 16 bytes (IPv6)."""
    if USE_IPV6:
        return socket.inet_pton(socket.AF_INET6, addr)
    return socket.inet_aton(addr)


def _ip_unpack(data: bytes, off: int):
    """Decode an IP from *data* starting at *off*.
    Returns *(ip_string, new_offset)*."""
    if USE_IPV6:
        return socket.inet_ntop(socket.AF_INET6, data[off:off + 16]), off + 16
    return socket.inet_ntoa(data[off:off + 4]), off + 4


def _addr_tuple(ip: str, port: int) -> tuple:
    """Full address tuple for sock.sendto / sock.connect.
    IPv4 → (ip, port); IPv6 → (ip, port, 0, 0)."""
    if USE_IPV6:
        return (ip, port, 0, 0)
    return (ip, port)


def _norm_addr(addr) -> tuple:
    """Collapse any address tuple to a plain *(ip, port)* 2-tuple.
    Needed because IPv6 recvfrom returns a 4-tuple."""
    return (addr[0], addr[1])


def _fmt_addr(ip: str, port: int) -> str:
    """Human-readable address.  IPv6 addresses are bracketed: [::1]:12345."""
    if USE_IPV6:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


# ===============================================================================
# Encryption -- SHA-256 CTR stream cipher + HMAC-SHA-256 per packet
# ===============================================================================


# ---- AES-256-CTR via the OpenSSL library Python itself already uses -----------
#
# The standard library has no AES, but every normal Python build ships
# OpenSSL for its ssl module, and ctypes (also stdlib) can call it. Used only
# when BOTH sides can (agreed during the short-code handshake); otherwise the
# SHA-256 keystream below is used. Nothing is installed either way.
#
# Where OpenSSL is found:
#   - Windows: libcrypto-*.dll next to _ssl.pyd (python.org / Store builds).
#   - Elsewhere: _ssl's own shared object first; dlsym on it also searches
#     the libcrypto it links against. Then the libcrypto already mapped into
#     this process (Linux), Homebrew's OpenSSL (macOS), or the system one
#     (Linux/BSD). macOS's /usr/lib/libcrypto.dylib is never touched: loading
#     it unversioned aborts the whole process.
# Whatever is found must pass a NIST known-answer test before it is trusted.

_AES_LIB = None        # loaded lazily by _aes_available()
_AES_CHECKED = False

# NIST SP 800-38A, F.5.5 (CTR-AES256.Encrypt), first two blocks.
_AES_KAT_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
_AES_KAT_IV  = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
_AES_KAT_PT  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
_AES_KAT_CT  = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5")


def _libcrypto_candidates():
    try:
        import _ssl
        ssl_file = getattr(_ssl, "__file__", None)
    except ImportError:
        return []
    cands = []
    if sys.platform == "win32":
        if ssl_file:
            d = os.path.dirname(ssl_file)
            try:
                names = sorted((n for n in os.listdir(d)
                                if n.lower().startswith("libcrypto") and n.lower().endswith(".dll")),
                               reverse=True)
            except OSError:
                names = []
            cands += [os.path.join(d, n) for n in names]
        return cands
    if ssl_file:
        cands.append(ssl_file)
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/maps") as f:
                for line in f:
                    path = line.split()[-1] if line.strip() else ""
                    if "libcrypto" in os.path.basename(path) and path not in cands:
                        cands.append(path)
        except OSError:
            pass
    if sys.platform == "darwin":
        cands += ["/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
                  "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"]
    else:
        try:
            import ctypes.util
            name = ctypes.util.find_library("crypto")
            if name:
                cands.append(name)
        except Exception:
            pass
    return cands


def _aes_available() -> bool:
    """True if AES-256-CTR from OpenSSL is usable here (cached)."""
    global _AES_LIB, _AES_CHECKED
    if _AES_CHECKED:
        return _AES_LIB is not None
    _AES_CHECKED = True
    try:
        import ctypes
    except ImportError:
        return False
    for path in _libcrypto_candidates():
        if sys.platform == "darwin" and path.startswith("/usr/lib/"):
            continue
        try:
            lib = ctypes.CDLL(path)
            vp, ci = ctypes.c_void_p, ctypes.c_int
            lib.EVP_CIPHER_CTX_new.restype  = vp
            lib.EVP_CIPHER_CTX_new.argtypes = []
            lib.EVP_CIPHER_CTX_free.restype  = None
            lib.EVP_CIPHER_CTX_free.argtypes = [vp]
            lib.EVP_aes_256_ctr.restype  = vp
            lib.EVP_aes_256_ctr.argtypes = []
            lib.EVP_EncryptInit_ex.restype  = ci
            lib.EVP_EncryptInit_ex.argtypes = [vp, vp, vp, ctypes.c_char_p, ctypes.c_char_p]
            lib.EVP_EncryptUpdate.restype  = ci
            lib.EVP_EncryptUpdate.argtypes = [vp, ctypes.c_char_p, ctypes.POINTER(ci),
                                              ctypes.c_char_p, ci]
            _AES_LIB = lib
            ok = _AesCtr(_AES_KAT_KEY).xor_iv(_AES_KAT_IV, _AES_KAT_PT) == _AES_KAT_CT
        except Exception:
            ok = False
        if ok:
            _vprint(f"  AES-256 available (OpenSSL via {os.path.basename(path)}).")
            return True
        _AES_LIB = None
    _vprint("  AES-256 not available here (OpenSSL not found); using the SHA-256 cipher.")
    return False


_CAP_AES = 1   # HELLO capability bit: this side can do AES-256-CTR


def _my_caps() -> int:
    return _CAP_AES if _aes_available() else 0


def _choose_cipher(mine: bool, theirs: bool, other: str):
    """AES-256-CTR if both sides can, else the SHA-256 cipher. Prints which."""
    global USE_AES
    USE_AES = mine and theirs
    if USE_AES:
        print("  Encryption: AES-256-CTR + HMAC-SHA256.")
    else:
        where = "this machine" if not mine else f"the {other}'s machine"
        print(f"  Encryption: SHA-256-CTR + HMAC-SHA256 (AES isn't available on {where}).")


class _AesCtr:
    """AES-256-CTR keystream for one key. Counter block = 8-byte packet
    nonce || 8-byte big-endian block index (same as p2p.ps1)."""

    def __init__(self, key: bytes):
        import ctypes
        self._ctypes = ctypes
        self._lib = lib = _AES_LIB
        self._ctx = lib.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise MemoryError("EVP_CIPHER_CTX_new failed")
        if lib.EVP_EncryptInit_ex(self._ctx, lib.EVP_aes_256_ctr(), None, key, None) != 1:
            raise ValueError("EVP_EncryptInit_ex failed")

    def __del__(self):
        ctx, self._ctx = getattr(self, "_ctx", None), None
        if ctx:
            try:
                self._lib.EVP_CIPHER_CTX_free(ctx)
            except Exception:
                pass

    def xor_iv(self, iv: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        ct = self._ctypes
        if self._lib.EVP_EncryptInit_ex(self._ctx, None, None, None, iv) != 1:
            raise ValueError("EVP_EncryptInit_ex failed")
        out  = ct.create_string_buffer(len(data))
        outl = ct.c_int(0)
        if (self._lib.EVP_EncryptUpdate(self._ctx, out, ct.byref(outl), data, len(data)) != 1
                or outl.value != len(data)):
            raise ValueError("EVP_EncryptUpdate failed")
        return out.raw

    def xor(self, nonce: bytes, data: bytes) -> bytes:
        return self.xor_iv(nonce + b"\0" * 8, data)


class Cipher:
    """
    Symmetric authenticated encryption using only hashlib + hmac.

    Key derivation : PBKDF2-HMAC-SHA256 (100 000 rounds) -> 128 bytes
                     split into sender->receiver and receiver->sender key pairs.
    Encryption     : AES-256-CTR when both sides can (aes=True), else
                     SHA-256 in counter mode (XOR keystream).
    Authentication : HMAC-SHA-256 truncated to 128 bits per packet
                     (encrypt-then-MAC, same packet format either way).

    Each direction gets its own (enc_key, mac_key) so both sides can use
    an independent monotonic counter as nonce without collision.
    """

    def __init__(self, secret: bytes, salt: bytes, is_sender: bool, aes: bool = False):
        km = hashlib.pbkdf2_hmac("sha256", secret, salt, 100_000, dklen=128)
        s2r_enc, s2r_mac = km[:32],   km[32:64]
        r2s_enc, r2s_mac = km[64:96], km[96:128]

        if is_sender:
            self._ek, self._mk  = s2r_enc, s2r_mac
            self._dk, self._dmk = r2s_enc, r2s_mac
        else:
            self._ek, self._mk  = r2s_enc, r2s_mac
            self._dk, self._dmk = s2r_enc, s2r_mac

        self._aes_e = _AesCtr(self._ek) if aes else None
        self._aes_d = _AesCtr(self._dk) if aes else None

        self._ctr = 0
        self._max_nonce = -1
        self._nonce_window = set()
        self._NONCE_WINDOW = 65536

    @staticmethod
    def _keystream(key, nonce, length):
        # Same output as sha256(key + nonce + be64(blk)) per 32-byte block,
        # but hashes the shared prefix once and copies the state.
        base = hashlib.sha256(key + nonce)
        nblocks = (length + 31) // 32
        parts = []
        for blk in range(nblocks):
            h = base.copy()
            h.update(blk.to_bytes(8, "big"))
            parts.append(h.digest())
        return b"".join(parts)[:length]

    @staticmethod
    def _xor(a, b):
        # Whole-buffer XOR via big ints: ~100x faster than a per-byte generator.
        n = len(a)
        return (int.from_bytes(a, "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")

    def encrypt(self, ptype: int, plaintext: bytes) -> bytes:
        nonce = struct.pack(">Q", self._ctr)
        self._ctr += 1
        if self._aes_e:
            ct = self._aes_e.xor(nonce, plaintext)
        else:
            ct = self._xor(plaintext, self._keystream(self._ek, nonce, len(plaintext)))
        header = struct.pack("B", ptype) + nonce
        mac    = _hmac.new(self._mk, header + ct, hashlib.sha256).digest()[:16]
        return header + ct + mac

    def decrypt(self, raw: bytes):
        if len(raw) < 9 + 16:
            return None, None
        ptype  = raw[0]
        nonce  = raw[1:9]
        ct     = raw[9:-16]
        mac    = raw[-16:]
        header = raw[:9]
        expected = _hmac.new(self._dmk, header + ct, hashlib.sha256).digest()[:16]
        if not _hmac.compare_digest(mac, expected):
            return None, None
        nonce_val    = struct.unpack(">Q", nonce)[0]
        window_floor = max(self._max_nonce - self._NONCE_WINDOW + 1, 0)
        if nonce_val < window_floor:
            return None, None
        if nonce_val in self._nonce_window:
            return None, None
        self._nonce_window.add(nonce_val)
        if nonce_val > self._max_nonce:
            self._max_nonce = nonce_val
            # Prune only occasionally. Rebuilding the whole set on every
            # packet cost ~1 ms each. Anything below the floor is already
            # rejected by the check above, so stale entries are harmless.
            if len(self._nonce_window) > 2 * self._NONCE_WINDOW:
                new_floor = max(self._max_nonce - self._NONCE_WINDOW + 1, 0)
                self._nonce_window = {n for n in self._nonce_window if n >= new_floor}
        if self._aes_d:
            return ptype, self._aes_d.xor(nonce, ct)
        pt = self._xor(ct, self._keystream(self._dk, nonce, len(ct)))
        return ptype, pt


# ===============================================================================
# Diffie-Hellman Forward Secrecy  (RFC 3526 Group 14, 2048-bit MODP)
# ===============================================================================

_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2
_DH_KEY_BYTES = 256  # 2048 bits


def _dh_keypair():
    private = int.from_bytes(secrets.token_bytes(32), "big")
    public  = pow(_DH_G, private, _DH_P)
    return private, public.to_bytes(_DH_KEY_BYTES, "big")


def _dh_shared_secret(private_int, peer_pub_bytes):
    peer_pub = int.from_bytes(peer_pub_bytes, "big")
    if peer_pub < 2 or peer_pub >= _DH_P - 1:
        raise ValueError("Invalid DH public key")
    raw_shared = pow(peer_pub, private_int, _DH_P)
    return hashlib.sha256(raw_shared.to_bytes(_DH_KEY_BYTES, "big")).digest()


# ===============================================================================
# Code Encoding  (out-of-band strings the users copy-paste)
# ===============================================================================

# fmt: off
_WORDLIST = [
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "adapt","add","addict","address","adjust","admit","adult","advance",
    "advice","aerobic","afford","afraid","again","age","agent","agree",
    "ahead","aim","air","airport","aisle","alarm","album","alcohol",
    "alert","alien","all","alley","allow","almost","alone","alpha",
    "already","also","alter","always","amateur","amazing","among","amount",
    "amused","analyst","anchor","ancient","anger","angle","angry","animal",
    "ankle","announce","annual","another","answer","antenna","antique","anxiety",
    "any","apart","apology","appear","apple","approve","april","arch",
    "arctic","area","arena","argue","arm","armor","army","around",
    "arrange","arrest","arrive","arrow","art","artefact","artist","artwork",
    "ask","aspect","assault","asset","assist","assume","asthma","athlete",
    "atom","attack","attend","attitude","attract","auction","audit","august",
    "aunt","author","auto","autumn","average","avocado","avoid","awake",
    "aware","away","awesome","awful","awkward","axis","baby","balance",
    "bamboo","banana","banner","barely","bargain","barrel","base","basic",
    "basket","battle","beach","beauty","because","become","beef","before",
    "begin","behave","behind","believe","below","belt","bench","benefit",
    "best","betray","better","between","beyond","bicycle","bid","bike",
    "bind","biology","bird","birth","bitter","black","blade","blame",
    "blanket","blast","bleak","bless","blind","blood","blossom","blouse",
    "blue","blur","blush","board","boat","body","boil","bomb",
    "bone","book","boost","border","boring","borrow","boss","bottom",
    "bounce","box","boy","bracket","brain","brand","brave","breeze",
    "brick","bridge","brief","bright","bring","brisk","broccoli","broken",
    "bronze","broom","brother","brown","brush","bubble","buddy","budget",
    "buffalo","build","bulb","bulk","bullet","bundle","bunker","burden",
    "burger","burst","bus","business","busy","butter","buyer","buzz",
    "cabbage","cabin","cable","cactus","cage","cake","call","calm",
    "camera","camp","can","canal","cancel","candy","cannon","canvas",
    "canyon","capable","capital","captain","car","carbon","card","cargo",
    "carpet","carry","cart","case","cash","casino","castle","casual",
    "cat","catalog","catch","category","cattle","caught","cause","caution",
    "cave","ceiling","celery","cement","census","century","cereal","certain",
    "chair","chalk","champion","change","chaos","chapter","charge","chase",
    "chat","cheap","check","cheese","chef","cherry","chest","chicken",
    "chief","child","chimney","choice","choose","chronic","chuckle","chunk",
    "cigar","cinnamon","circle","citizen","city","civil","claim","clap",
    "clarify","claw","clay","clean","clerk","clever","click","client",
    "cliff","climb","clinic","clip","clock","clog","close","cloth",
    "cloud","clown","club","clump","cluster","clutch","coach","coast",
    "coconut","code","coffee","coil","coin","collect","color","column",
    "combine","come","comfort","comic","common","company","concert","conduct",
    "confirm","congress","connect","consider","control","convince","cook","cool",
    "copper","copy","coral","core","corn","correct","cost","cotton",
    "couch","country","couple","course","cousin","cover","coyote","crack",
    "cradle","craft","cram","crane","crash","crater","crawl","crazy",
    "cream","credit","creek","crew","cricket","crime","crisp","critic",
    "cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch",
    "crush","cry","crystal","cube","culture","cup","cupboard","curious",
    "current","curtain","curve","cushion","custom","cute","cycle","dad",
    "damage","damp","dance","danger","daring","dash","daughter","dawn",
    "day","deal","debate","debris","decade","december","decide","decline",
    "decorate","decrease","deer","defense","define","defy","degree","delay",
    "deliver","demand","demise","denial","dentist","deny","depart","depend",
    "deposit","depth","deputy","derive","describe","desert","design","desk",
    "despair","destroy","detail","detect","develop","device","devote","diagram",
    "dial","diamond","diary","dice","diesel","diet","differ","digital",
    "dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover",
    "disease","dish","dismiss","disorder","display","distance","divert","divide",
    "divorce","dizzy","doctor","document","dog","doll","dolphin","domain",
    "donate","donkey","donor","door","dose","double","dove","draft",
    "dragon","drama","drastic","draw","dream","dress","drift","drill",
    "drink","drip","drive","drop","drum","dry","duck","dumb",
    "dune","during","dust","dutch","duty","dwarf","dynamic","eager",
    "eagle","early","earn","earth","easily","east","easy","echo",
    "ecology","edge","edit","educate","effort","egg","eight","either",
    "elbow","elder","electric","elegant","element","elephant","elevator","elite",
    "else","embark","embody","embrace","emerge","emotion","employ","empower",
    "empty","enable","enact","endless","endorse","enemy","energy","enforce",
    "engage","engine","enhance","enjoy","enlist","enough","enrich","enroll",
    "ensure","enter","entire","entry","envelope","episode","equal","equip",
    "era","erase","erosion","error","erupt","escape","essay","essence",
    "estate","eternal","ethics","evidence","evil","evoke","evolve","exact",
    "example","excess","exchange","excite","exclude","exercise","exhaust","exhibit",
    "exile","exist","exit","exotic","expand","expire","explain","expose",
    "express","extend","extra","eye","fable","face","faculty","faint",
    "faith","fall","false","fame","family","famous","fan","fancy",
    "fantasy","far","fashion","fat","fatal","father","fatigue","fault",
    "favorite","feature","february","federal","fee","feed","feel","feet",
    "fellow","felt","fence","festival","fetch","fever","few","fiber",
    "fiction","field","figure","file","film","filter","final","find",
    "fine","finger","finish","fire","firm","first","fiscal","fish",
    "fit","fitness","fix","flag","flame","flash","flat","flavor",
    "flee","flight","flip","float","flock","floor","flower","fluid",
    "flush","fly","foam","focus","fog","foil","follow","food",
    "foot","force","forest","forget","fork","fortune","forum","forward",
    "fossil","foster","found","fox","fragile","frame","frequent","fresh",
    "friend","fringe","frog","front","frown","frozen","fruit","fuel",
    "fun","funny","furnace","fury","future","gadget","gain","galaxy",
    "gallery","game","gap","garbage","garden","garlic","garment","gasp",
    "gate","gather","gauge","gaze","general","genius","genre","gentle",
    "genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe",
    "girl","give","glad","glance","glare","glass","glide","glimpse",
    "globe","gloom","glory","glove","glow","glue","goat","goddess",
    "gold","good","goose","gorilla","gospel","gossip","govern","gown",
    "grab","grace","grain","grant","grape","grasp","grass","gravity",
    "great","green","grid","grief","grit","grocery","group","grow",
    "grunt","guard","guide","guilt","guitar","gun","gym","habit",
    "hair","half","hammer","hamster","hand","happy","harsh","harvest",
    "hat","have","hawk","hazard","head","health","heart","heavy",
    "hedgehog","height","hello","helmet","help","hen","hero","hidden",
    "high","hill","hint","hip","hire","history","hobby","hockey",
    "hold","hole","hollow","home","honey","hood","hope","horn",
    "hospital","host","hour","hover","hub","huge","human","humble",
    "humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband",
    "hybrid","ice","icon","ignore","ill","illegal","image","imitate",
    "immense","immune","impact","impose","improve","impulse","inbox","income",
    "increase","index","indicate","indoor","industry","infant","inflict","inform",
    "inhale","inject","inner","innocent","input","inquiry","insane","insect",
    "inside","inspire","install","intact","interest","into","invest","invite",
    "involve","iron","island","isolate","issue","item","ivory","jacket",
    "jaguar","jar","jazz","jealous","jeans","jelly","jewel","job",
    "join","joke","journey","joy","judge","juice","jump","jungle",
    "junior","junk","just","kangaroo","keen","keep","ketchup","key",
    "kick","kid","kingdom","kiss","kit","kitchen","kite","kitten",
    "kiwi","knee","knife","knock","know","lab","ladder","lamp",
    "language","laptop","large","later","laugh","laundry","lava","law",
    "lawn","lawsuit","layer","lazy","leader","learn","leave","lecture",
    "left","leg","legal","legend","lemon","lend","length","lens",
    "leopard","lesson","letter","level","liar","liberty","library","license",
    "life","lift","like","limb","lion","liquid","list","little",
    "live","lizard","load","loan","lobster","local","lock","logic",
    "lonely","long","loop","lottery","loud","lounge","love","loyal",
    "lucky","luggage","lumber","lunar","lunch","luxury","mad","magic",
    "magnet","maid","main","mammoth","manage","maple","marble","march",
    "margin","marine","market","marriage","mask","master","match","material",
    "math","matrix","matter","maximum","maze","meadow","mean","medal",
    "media","melody","melt","member","memory","mention","mentor","menu",
    "mercy","mesh","message","metal","method","middle","midnight","milk",
    "million","mimic","mind","minimum","minor","minute","miracle","miss",
    "mitten","mobile","model","modify","mom","monitor","monkey","monster",
    "month","moon","moral","more","morning","mosquito","mother","motion",
    "motor","mountain","mouse","move","movie","much","muffin","mule",
    "multiply","muscle","museum","mushroom","music","must","mutual","myself",
    "mystery","naive","name","napkin","narrow","nasty","nature","near",
    "neck","need","negative","neglect","neither","nephew","nerve","nest",
    "network","news","next","nice","night","noble","noise","nominee",
    "noodle","normal","north","notable","note","nothing","notice","novel",
    "now","nuclear","number","nurse","nut","oak","obey","object",
    "oblige","obscure","obtain","ocean","october","odor","off","offer",
    "office","often","oil","okay","old","olive","olympic","omit",
    "once","onion","open","option","orange","orbit","orchard","order",
    "ordinary","organ","orient","original","orphan","ostrich","other","outdoor",
    "outside","oval","over","own","oyster","ozone","pact","paddle",
    "page","pair","palace","palm","panda","panel","panic","panther",
    "paper","parade","parent","park","parrot","party","pass","patch",
    "path","patrol","pause","pave","payment","peace","peanut","pear",
    "peasant","pelican","pen","penalty","pencil","people","pepper","perfect",
    "permit","person","pet","phone","photo","phrase","physical","piano",
    "picnic","picture","piece","pig","pigeon","pill","pilot","pink",
    "pioneer","pipe","pistol","pitch","pizza","place","planet","plastic",
    "plate","play","please","pledge","pluck","plug","plunge","poem",
    "poet","point","polar","pole","police","pond","pony","pool",
    "popular","portion","position","possible","post","potato","pottery","poverty",
    "powder","power","practice","praise","predict","prefer","prepare","present",
    "pretty","prevent","price","pride","primary","print","priority","prison",
    "private","prize","problem","process","produce","profit","program","project",
    "promote","proof","property","prosper","protect","proud","provide","public",
    "pudding","pull","pulp","pulse","pumpkin","punish","pupil","purchase",
    "purity","purpose","push","put","puzzle","pyramid","quality","quantum",
    "quarter","question","quick","quit","quiz","quote","rabbit","raccoon",
    "race","rack","radar","radio","rage","rail","rain","raise",
    "rally","ramp","ranch","random","range","rapid","rare","rate",
    "rather","raven","reach","ready","real","reason","rebel","rebuild",
    "recall","receive","recipe","record","recycle","reduce","reflect","reform",
    "refuse","region","regret","regular","reject","relax","release","relief",
    "rely","remain","remember","remind","remove","render","renew","rent",
    "reopen","repair","repeat","replace","report","require","rescue","resemble",
    "resist","resource","response","result","retire","retreat","return","reunion",
    "reveal","review","reward","rhythm","ribbon","rice","rich","ride",
    "ridge","rifle","right","rigid","ring","riot","ripple","risk",
    "ritual","rival","river","road","roast","robot","robust","rocket",
    "romance","roof","rookie","rose","rotate","rough","royal","rubber",
    "rude","rug","rule","run","runway","rural","sad","saddle",
    "sadness","safe","sail","salad","salmon","salon","salt","salute",
    "same","sample","sand","satisfy","satoshi","sauce","sausage","save",
    "scale","scan","scatter","scene","scheme","scissors","scorpion","scout",
    "scrap","screen","script","scrub","sea","search","season","seat",
    "second","secret","section","security","seek","segment","select","sell",
    "seminar","senior","sense","series","service","session","settle","setup",
    "seven","shadow","shaft","shallow","share","shed","shell","sheriff",
    "shield","shift","shine","ship","shiver","shock","shoe","shoot",
    "shop","short","shoulder","shove","shrimp","shrug","shuffle","shy",
    "sibling","siege","sight","sign","silent","silk","silly","silver",
    "similar","simple","since","sing","siren","sister","situate","six",
    "size","sketch","skill","skin","skirt","skull","slab","slam",
    "sleep","slender","slice","slide","slight","slim","slogan","slot",
    "slow","slush","small","smart","smile","smoke","smooth","snack",
    "snake","snap","sniff","snow","soap","soccer","social","sock",
    "solar","soldier","solid","solution","solve","someone","song","soon",
    "sorry","soul","sound","soup","source","south","space","spare",
    "spatial","spawn","speak","special","speed","spell","spend","sphere",
    "spice","spider","spike","spin","spirit","split","spoil","sponsor",
    "spoon","spray","spread","spring","spy","square","squeeze","squirrel",
    "stable","stadium","staff","stage","stairs","stamp","stand","start",
    "state","stay","steak","steel","stem","step","stereo","stick",
    "still","sting","stock","stomach","stone","stop","store","storm",
    "story","stove","strategy","street","strike","strong","struggle","student",
    "stuff","stumble","subject","submit","subway","success","such","sudden",
    "suffer","sugar","suggest","suit","summer","sun","sunny","sunset",
    "super","supply","supreme","sure","surface","surge","surprise","sustain",
    "swallow","swamp","swap","swear","sweet","swift","swim","swing",
    "switch","sword","symbol","symptom","syrup","table","tackle","tag",
    "tail","talent","tank","tape","target","task","tattoo","taxi",
    "teach","team","tell","ten","tenant","tennis","tent","term",
    "test","text","thank","that","theme","then","theory","there",
    "they","thing","this","thought","three","thrive","throw","thumb",
    "thunder","ticket","tilt","timber","time","tiny","tip","tired",
    "title","toast","tobacco","today","together","toilet","token","tomato",
    "tomorrow","tone","tongue","tonight","tool","tooth","top","topic",
    "topple","torch","tornado","tortoise","toss","total","tourist","toward",
    "tower","town","toy","track","trade","traffic","tragic","train",
    "transfer","trap","trash","travel","tray","treat","tree","trend",
    "trial","tribe","trick","trigger","trim","trip","trophy","trouble",
    "truck","truly","trumpet","trust","truth","try","tube","tuition",
    "tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty",
    "twice","twin","twist","two","type","typical","ugly","umbrella",
    "unable","uniform","unique","universe","unknown","unlock","until","unusual",
    "unveil","update","upgrade","uphold","upon","upper","upset","urban",
    "usage","use","used","useful","useless","usual","utility","vacant",
    "vacuum","vague","valid","valley","valve","van","vanish","vapor",
    "various","vast","vault","vehicle","velvet","vendor","venture","venue",
    "verify","version","very","veteran","viable","vibrant","vicious","victory",
    "video","view","village","vintage","violin","virtual","virus","visa",
    "visit","visual","vital","vivid","vocal","voice","void","volcano",
    "vote","voyage","wage","wagon","wait","walk","wall","walnut",
    "want","warfare","warm","warrior","waste","water","wave","way",
    "wealth","weapon","wear","weasel","weather","web","wedding","weekend",
    "weird","welcome","well","west","wet","whale","wheat","wheel",
    "when","where","whip","whisper","wide","width","wife","wild",
    "will","win","window","wine","wing","wink","winner","winter",
    "wire","wisdom","wise","wish","witness","wolf","woman","wonder",
    "wood","wool","word","world","worry","worth","wrap","wreck",
    "wrestle","wrist","write","wrong","yard","year","yellow","you",
    "young","youth","zebra","zero","zone","zoo",
]
# fmt: on

_WORDLIST    = _WORDLIST[:1024]
_WORD_INDEX  = {w: i for i, w in enumerate(_WORDLIST)}
_BITS_PER_WORD = 10


def _bytes_to_words(data: bytes) -> str:
    bits    = len(data) * 8
    n_words = math.ceil(bits / _BITS_PER_WORD)
    n       = int.from_bytes(data, "big")
    n     <<= (n_words * _BITS_PER_WORD - bits)
    words   = []
    mask    = (1 << _BITS_PER_WORD) - 1
    for _ in range(n_words):
        words.append(_WORDLIST[n & mask])
        n >>= _BITS_PER_WORD
    return " ".join(reversed(words))


def _words_to_bytes(phrase: str, expected_bytes: int) -> bytes:
    words   = phrase.strip().lower().split()
    n_words = math.ceil(expected_bytes * 8 / _BITS_PER_WORD)
    if len(words) != n_words:
        raise ValueError(f"Expected {n_words} words, got {len(words)}")
    n = 0
    for word in words:
        if word not in _WORD_INDEX:
            raise ValueError(f"Unknown word: {word!r}")
        n = (n << _BITS_PER_WORD) | _WORD_INDEX[word]
    n >>= (n_words * _BITS_PER_WORD - expected_bytes * 8)
    return n.to_bytes(expected_bytes, "big")


def encode_sender_code(secret, salt, pub_ip, pub_port, local_ip, local_port):
    """Pack a sender code.

    IPv4: 16+16+4+2+4+2 = 44 bytes → 36 words
    IPv6: 16+16+16+2+16+2 = 68 bytes → 55 words
    """
    data = (
        secret
        + salt
        + _ip_pack(pub_ip)
        + struct.pack("!H", pub_port)
        + _ip_pack(local_ip)
        + struct.pack("!H", local_port)
    )
    return _bytes_to_words(data)


def decode_sender_code(code):
    """Unpack a sender code.  Auto-detects IPv4/IPv6 from word count.

    Returns *(secret, salt, pub_ip, pub_port, local_ip, local_port, is_ipv6)*.
    Raises *ValueError* on bad input.
    """
    words = code.strip().lower().split()
    nw = len(words)
    if nw == 36:        # IPv4 code: 44 bytes
        total, ipv6 = 44, False
    elif nw == 55:      # IPv6 code: 68 bytes
        total, ipv6 = 68, True
    else:
        raise ValueError(f"Invalid sender code: expected 36 or 55 words, got {nw}")

    data       = _words_to_bytes(code, total)
    secret     = data[:16]
    salt       = data[16:32]
    if ipv6:
        pub_ip     = socket.inet_ntop(socket.AF_INET6, data[32:48])
        pub_port   = struct.unpack("!H", data[48:50])[0]
        local_ip   = socket.inet_ntop(socket.AF_INET6, data[50:66])
        local_port = struct.unpack("!H", data[66:68])[0]
    else:
        pub_ip     = socket.inet_ntoa(data[32:36])
        pub_port   = struct.unpack("!H", data[36:38])[0]
        local_ip   = socket.inet_ntoa(data[38:42])
        local_port = struct.unpack("!H", data[42:44])[0]
    return secret, salt, pub_ip, pub_port, local_ip, local_port, ipv6


def encode_recv_code(pub_ip, pub_port, local_ip, local_port, secret):
    """Pack a receiver code.

    IPv4: 4+2+4+2+16(HMAC) = 28 bytes → 23 words
    IPv6: 16+2+16+2+16(HMAC) = 52 bytes → 42 words
    """
    raw = (
        _ip_pack(pub_ip)
        + struct.pack("!H", pub_port)
        + _ip_pack(local_ip)
        + struct.pack("!H", local_port)
    )
    tag = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
    return _bytes_to_words(raw + tag)


def decode_recv_code(code, secret):
    """Unpack a receiver code.  Auto-detects IPv4/IPv6 from word count.

    Returns *(pub_ip, pub_port, local_ip, local_port)* or *None* on HMAC failure.
    Returns *None* for unknown word counts too.
    """
    words = code.strip().lower().split()
    nw = len(words)
    if nw == 23:        # IPv4: 28 bytes, raw = 12 B, tag = 16 B
        data     = _words_to_bytes(code, 28)
        raw, tag = data[:12], data[12:28]
        expected = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
        if not _hmac.compare_digest(tag, expected):
            return None
        pub_ip     = socket.inet_ntoa(raw[0:4])
        pub_port   = struct.unpack("!H", raw[4:6])[0]
        local_ip   = socket.inet_ntoa(raw[6:10])
        local_port = struct.unpack("!H", raw[10:12])[0]
    elif nw == 42:      # IPv6: 52 bytes, raw = 36 B, tag = 16 B
        data     = _words_to_bytes(code, 52)
        raw, tag = data[:36], data[36:52]
        expected = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
        if not _hmac.compare_digest(tag, expected):
            return None
        pub_ip     = socket.inet_ntop(socket.AF_INET6, raw[0:16])
        pub_port   = struct.unpack("!H", raw[16:18])[0]
        local_ip   = socket.inet_ntop(socket.AF_INET6, raw[18:34])
        local_port = struct.unpack("!H", raw[34:36])[0]
    else:
        return None
    return pub_ip, pub_port, local_ip, local_port


# ===============================================================================
# UDP Hole Punching
# ===============================================================================


def punch_hole(sock, cipher, pub_addr, local_addr, dh_pub_bytes,
               timeout=CONNECT_TIMEOUT, hint=None, caps=0):
    """
    Simultaneously send encrypted HELLOs (carrying our DH public key and our
    capability byte, see _CAP_*) to the peer's public and local endpoints
    until one replies with theirs.
    Returns (peer_addr, peer_dh_pub_bytes, peer_caps) or (None, None, None).

    Robustness measures
    -------------------
    1. _drain_socket() is called first to discard any packets already in
       the OS buffer.  This prevents stale HELLOs from a cancelled earlier
       receiver session from being mistaken for a live peer reply.

    2. Every received packet is checked against the expected peer addresses
       (targets) before being decrypted and processed.  This means a stale
       HELLO that somehow survived the drain (e.g. arrived in the tiny
       window between drain and the first select) is silently discarded
       rather than causing a connection to a dead port.

    3. All socket operations are wrapped in try/except OSError so that
       transient network errors (including Windows ICMP port-unreachable
       feedback, WinError 10054) never propagate as uncaught exceptions.
    """
    # targets: normalized (ip, port) 2-tuples for membership checks
    targets = set()
    targets.add(pub_addr)
    if local_addr and local_addr != pub_addr:
        targets.add(local_addr)
    # Full address tuples for sendto: IPv4 → 2-tuple, IPv6 → 4-tuple
    targets_send = [_addr_tuple(ip, port) for ip, port in targets]

    # Flush stale packets before we start listening.
    _drain_socket(sock)

    hello_payload = b"DH2:" + dh_pub_bytes + bytes([caps])
    hello_pkt     = cipher.encrypt(T_HELLO, hello_payload)
    start         = time.time()

    status = "Punching through NAT..." if VERBOSE else "Connecting..."
    sys.stdout.write(f"  {status}")
    sys.stdout.flush()
    hint_shown = False

    while time.time() - start < timeout:
        # Send a salvo to every target
        for t in targets_send:
            try:
                sock.sendto(hello_pkt, t)
            except OSError:
                pass

        # Listen for a reply
        deadline = time.time() + PUNCH_INTERVAL
        while time.time() < deadline:
            wait = max(deadline - time.time(), 0)
            try:
                ready = select.select([sock], [], [], min(wait, 0.05))
            except OSError:
                continue
            if not ready[0]:
                continue
            try:
                data, addr_raw = sock.recvfrom(RECV_BUF)
            except OSError:
                continue

            # ---- addr filter (the core bug-fix) --------------------------------
            # Only accept HELLOs from the address embedded in the recv/send code.
            # Packets from any other source are silently dropped.  This stops a
            # stale HELLO from a previously cancelled receiver from being
            # accepted as the "connection", which would make the sender target
            # a now-closed port and crash with WinError 10054 on the next recv.
            addr = _norm_addr(addr_raw)   # IPv6 4-tuple → plain (ip, port)
            if addr not in targets:
                continue
            # --------------------------------------------------------------------

            ptype, payload = cipher.decrypt(data)
            if ptype == T_HELLO and payload and payload[:4] == b"DH2:":
                if len(payload) != 4 + _DH_KEY_BYTES + 1:
                    continue   # malformed -- ignore
                peer_dh_pub = payload[4:4 + _DH_KEY_BYTES]
                peer_caps   = payload[-1]
                # Confirm the path with a few extra HELLOs
                addr_full = _addr_tuple(*addr)
                for _ in range(5):
                    try:
                        sock.sendto(hello_pkt, addr_full)
                    except OSError:
                        pass
                    time.sleep(0.05)
                if VERBOSE:
                    print(f"\n  Connected to {_fmt_addr(*addr)}")
                else:
                    print("\n  Connected.")
                return addr_full, peer_dh_pub, peer_caps
            # Any other packet type here (e.g. T_META from a racing sender)
            # is silently ignored; punch_hole only cares about HELLOs.

        elapsed = int(time.time() - start)
        if hint and not hint_shown and elapsed >= DIRECT_HINT_AFTER:
            hint_shown = True
            sys.stdout.write("\n" + hint + "\n")
        if elapsed >= 60:
            sys.stdout.write(f"\r  {status} {elapsed // 60}m {elapsed % 60}s  ")
        else:
            sys.stdout.write(f"\r  {status} {elapsed}s  ")
        sys.stdout.flush()

    if VERBOSE:
        print("\n  Hole punch timed out.")
    else:
        print("\n  Connection timed out.")
    return None, None, None


# ===============================================================================
# Relay transport  (used only when both sides pass --relay)
# ===============================================================================
#
# Design: RelaySocket is a drop-in stand-in for a UDP socket. It implements
# exactly the subset of the socket API that punch_hole(), send_file_reliable(),
# and recv_file_reliable() use -- sendto, recvfrom, fileno, settimeout,
# setblocking, close -- so none of that code needs to know or care that
# packets are travelling over HTTPS instead of raw UDP. In particular,
# punch_hole() itself is reused completely unmodified: pass it a RelaySocket
# and a single placeholder "peer address" instead of a real UDP socket and
# real STUN-discovered addresses, and the exact same HELLO/DH exchange runs
# over the relay.
#
# Internally: outgoing datagrams are queued and flushed to the relay in
# small batches by a background thread (bounded by size or a short timer).
# Incoming batches are long-polled from the relay by another background
# thread and injected into a local loopback UDP socket -- which is what
# recvfrom()/select() actually operate on, so RelaySocket stays select()-able
# without reimplementing socket semantics from scratch.
#
# No retry/ordering logic lives here. The ARQ layer above already assumes
# an unreliable channel (it was written for raw UDP) and will retransmit
# on its own if a batch never arrives -- this stays a dumb pipe.


# Relay mode uses a single short code: just the 128-bit secret (13 words).
# No addresses are needed (nobody punches anything), and the PBKDF2 salt is
# derived from the secret instead of being sent. Direct-mode sender codes are
# 36 or 55 words, so the two code types can never be confused.
RELAY_CODE_WORDS = 13


def _relay_salt(secret: bytes) -> bytes:
    return _hmac.new(secret, b"p2p-relay-salt-v1", hashlib.sha256).digest()[:16]


def encode_relay_code(secret: bytes) -> str:
    """128-bit secret -> 13 words."""
    return _bytes_to_words(secret)


def decode_relay_code(code: str) -> bytes:
    """13 words -> 128-bit secret. Raises ValueError on bad input."""
    return _words_to_bytes(code, 16)


def _relay_session_token(secret: bytes) -> str:
    """
    Both peers derive the same opaque session id from the shared secret
    already embedded in the send/recv codes -- no extra exchange needed,
    and the relay never sees the secret itself, only this derived token.
    """
    return _hmac.new(secret, b"p2p-relay-session-v1", hashlib.sha256).hexdigest()[:32]


def _encode_relay_batch(packets) -> bytes:
    out = struct.pack(">H", len(packets))
    for p in packets:
        out += struct.pack(">H", len(p)) + p
    return out


def _decode_relay_batch(body: bytes):
    if len(body) < 2:
        return []
    (count,) = struct.unpack(">H", body[:2])
    off = 2
    packets = []
    for _ in range(count):
        if off + 2 > len(body):
            break
        (plen,) = struct.unpack(">H", body[off:off + 2])
        off += 2
        if off + plen > len(body):
            break
        packets.append(body[off:off + plen])
        off += plen
    return packets


def _relay_backoff(retry_after):
    """Seconds to wait after a 429/503. Honors the relay's Retry-After,
    clamped to a sane range; defaults to 1s if the header is absent."""
    if retry_after is None:
        retry_after = 1.0
    return max(RELAY_RETRY_SLEEP, min(retry_after, RELAY_BACKOFF_MAX))


class _RelayConn:
    """
    One HTTPS connection to the relay, reused across requests when safe.
    Each background loop owns its own instance (never shared across threads).

    The connection is treated as disposable: on ANY failure it is closed and
    the next request starts on a fresh one. Connections that are old or have
    sat idle are dropped before use, because unstable networks (and NAT
    boxes) silently kill idle TCP connections. If the very first request on
    a reused connection fails, it is retried once on a fresh connection. A
    duplicate request is harmless -- the ARQ layer already tolerates
    duplicated and lost packets.
    """

    def __init__(self, host, timeout):
        self._host = host
        self._timeout = timeout
        self._conn = None
        self._born = 0.0
        self._last_used = 0.0
        self._count = 0

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    @staticmethod
    def _parse_retry_after(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def request(self, method, path, body=None):
        """
        Returns (status, body_bytes, retry_after_seconds_or_None).
        Raises OSError / http.client.HTTPException on failure; the
        connection has already been discarded when that happens.
        """
        now = time.time()
        if not RELAY_REUSE_CONN:
            self.close()
        elif self._conn is not None and (
            now - self._born > RELAY_CONN_MAX_AGE
            or now - self._last_used > RELAY_CONN_MAX_IDLE
            or self._count >= RELAY_CONN_MAX_REQS
        ):
            self.close()

        for attempt in (0, 1):
            reused = self._conn is not None
            if not reused:
                self._conn = http.client.HTTPSConnection(
                    self._host, timeout=self._timeout)
                self._born = time.time()
                self._count = 0
            try:
                self._conn.request(method, path, body=body)
                resp = self._conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException) as e:
                self.close()
                # A reused connection may have been dropped while idle.
                # Retry once on a fresh one -- but never after a timeout,
                # which would just double an already long wait.
                if (reused and attempt == 0
                        and not isinstance(e, (socket.timeout, TimeoutError))):
                    continue
                raise
            self._count += 1
            self._last_used = time.time()
            if resp.will_close or not RELAY_REUSE_CONN:
                self.close()
            return (resp.status, data,
                    self._parse_retry_after(resp.getheader("Retry-After")))


class RelaySocket:
    """See module note above. PEER_ADDR is a fixed placeholder -- nothing
    is ever actually routed to it; it exists only so punch_hole()'s
    addr-equality filtering has a consistent value to compare against."""

    PEER_ADDR = ("127.255.255.1", 1)

    def __init__(self, host, token, send_dir, recv_dir):
        self._host      = host
        self._token     = token
        self._send_dir  = send_dir
        self._recv_dir  = recv_dir

        # Loopback pair purely so recvfrom()/select() keep working exactly
        # like they would on a real UDP socket -- nothing here is a network
        # hop, it's just how incoming relay data gets surfaced through the
        # normal recvfrom()/select() calls the rest of the code already uses.
        #
        # Packets themselves live in an in-memory deque; the socketpair only
        # carries one "doorbell" byte per packet so select()/timeouts/
        # non-blocking reads behave exactly like a UDP socket. (A loopback
        # UDP socket was used before, but its OS buffer -- ~64 KB on Windows
        # -- silently drops packets once the relay delivers big batches.)
        self._in_q = collections.deque()
        self._local, self._bell = socket.socketpair()

        self._out_q = queue.Queue()
        self._stop  = threading.Event()
        self._closing = False
        self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._send_thread.start()
        self._recv_thread.start()

    # ---- socket-like interface used by punch_hole / *_reliable -------------

    def sendto(self, data, _addr):
        self._out_q.put(bytes(data))

    def recvfrom(self, bufsize):
        # Honors blocking / timeout / non-blocking mode of self._local and
        # raises OSError (incl. BlockingIOError, socket.timeout) like UDP.
        if not self._local.recv(1):
            raise OSError("relay socket closed")
        return self._in_q.popleft(), self.PEER_ADDR

    def fileno(self):
        return self._local.fileno()

    def settimeout(self, t):
        self._local.settimeout(t)

    def setblocking(self, flag):
        self._local.setblocking(flag)

    def close(self):
        # Flush what's still queued (e.g. the final DONEACK) before stopping,
        # or the peer waits out its whole DONE timeout.
        self._closing = True
        self._send_thread.join(timeout=RELAY_CLOSE_FLUSH)
        self._stop.set()
        for s in (self._bell, self._local):
            try:
                s.close()
            except OSError:
                pass

    # ---- background transport ------------------------------------------

    def _send_loop(self):
        conn = _RelayConn(self._host, RELAY_SEND_TIMEOUT)
        path = f"/relay/{self._token}/{self._send_dir}/send"
        try:
            last_post = 0.0
            while not self._stop.is_set():
                try:
                    first = self._out_q.get(timeout=RELAY_FLUSH_WAIT)
                except queue.Empty:
                    if self._closing:
                        break       # everything flushed
                    continue
                # Pace POSTs so a peer stays under the relay's per-IP rate
                # limit; packets queued during the pause join this batch.
                gap = RELAY_MIN_POST_GAP - (time.time() - last_post)
                if gap > 0:
                    self._stop.wait(gap)
                batch, nbytes = [first], len(first)
                while len(batch) < WINDOW_SIZE and nbytes < RELAY_BATCH_BYTES:
                    try:
                        pkt = self._out_q.get_nowait()
                    except queue.Empty:
                        break
                    batch.append(pkt)
                    nbytes += len(pkt)
                body = _encode_relay_batch(batch)
                # Retry THIS batch on throttling / network errors instead of
                # dropping it: a drop costs a full ACK timeout in the ARQ layer.
                while not self._stop.is_set():
                    last_post = time.time()
                    try:
                        status, _, retry_after = conn.request("POST", path, body)
                    except (OSError, http.client.HTTPException):
                        _vprint("  [relay] send batch failed, retrying")
                        self._stop.wait(RELAY_RETRY_SLEEP)
                        continue
                    if status == 200:
                        break
                    if status in (429, 503):
                        delay = _relay_backoff(retry_after)
                        _vprint(f"  [relay] send throttled (HTTP {status}), "
                                f"backing off {delay:.1f}s")
                        self._stop.wait(delay)
                        continue
                    # Anything else (400/413...) won't succeed on retry; drop
                    # it and let the ARQ layer resend.
                    _vprint(f"  [relay] send rejected (HTTP {status})")
                    self._stop.wait(RELAY_RETRY_SLEEP)
                    break
        finally:
            conn.close()

    def _recv_loop(self):
        conn = _RelayConn(self._host, RELAY_HTTP_TIMEOUT)
        path = f"/relay/{self._token}/{self._recv_dir}/recv"
        try:
            last_get = 0.0
            while not self._stop.is_set():
                gap = RELAY_MIN_GET_GAP - (time.time() - last_get)
                if gap > 0:
                    self._stop.wait(gap)
                last_get = time.time()
                try:
                    status, body, retry_after = conn.request("GET", path)
                except (OSError, http.client.HTTPException):
                    self._stop.wait(RELAY_RETRY_SLEEP)
                    continue
                if status != 200:
                    # Error bodies are plain text, not batches: never feed
                    # them to the decoder. Back off before polling again so
                    # a throttled client doesn't spin.
                    if status in (429, 503):
                        delay = _relay_backoff(retry_after)
                        _vprint(f"  [relay] recv throttled (HTTP {status}), "
                                f"backing off {delay:.1f}s")
                    else:
                        delay = RELAY_RETRY_SLEEP
                        _vprint(f"  [relay] recv rejected (HTTP {status})")
                    self._stop.wait(delay)
                    continue
                for pkt in _decode_relay_batch(body):
                    self._in_q.append(pkt)          # data first...
                    try:
                        self._bell.sendall(b"\0")   # ...then ring
                    except OSError:
                        self._in_q.pop()
                        return                      # socket closed
        finally:
            conn.close()


# ===============================================================================
# Short codes: SPAKE2 password-authenticated key exchange  (the default)
# ===============================================================================
#
# The sender gets a short code such as "4821-apple-river-ocean":
#   - The number is a "nameplate". It only picks a mailbox on the relay so
#     both sides meet in the same place; it is not secret.
#   - The words are a short password (30 bits). SPAKE2 turns it into a strong
#     shared key. Someone watching (or running) the relay cannot brute-force
#     it offline, and an active attacker gets exactly one guess per code: a
#     wrong guess aborts the transfer on both sides.
#
# Both sides meet at the relay mailbox, run SPAKE2 and agree on the mode
# (relay if EITHER side asked for --relay). In direct mode they then swap
# their STUN addresses, encrypted under the new key, and leave the relay:
# the file itself still goes peer-to-peer over UDP. The key from SPAKE2 then
# takes the place of the long codes' secret; everything after that (DH HELLO,
# per-packet crypto, transfer, resume) is unchanged.
#
# SPAKE2 (RFC 9382) runs in the same RFC 3526 group 14 as the DH above. p is
# a safe prime and 2 generates the subgroup of prime order q = (p-1)/2. M and
# N are hashed into that subgroup (hash, then square), so nobody knows their
# discrete logs.

PAKE_WORDS     = 3      # password words in a short code (10 bits each)
PAKE_RESEND    = 5.0    # seconds between rendezvous resends (the relay rarely drops)
PAKE_REPLY_GAP = 1.0    # seconds; min gap between replies to a peer's repeats
_PAKE_VERSION  = 1
_PAKE_F_RELAY  = 1      # flag: this side asked for --relay
_PAKE_F_IPV6   = 2      # flag: this side uses -6
_PAKE_F_AES    = 4      # flag: this side can do AES-256-CTR
_PAKE_MAGIC    = b"SPK1"

_SPAKE_Q = (_DH_P - 1) // 2


def _spake_hash_to_group(label: bytes) -> int:
    out, ctr = b"", 0
    while len(out) < _DH_KEY_BYTES + 32:          # extra bytes: negligible mod-p bias
        out += hashlib.sha256(label + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return pow(int.from_bytes(out, "big") % _DH_P, 2, _DH_P)


_SPAKE_M = _spake_hash_to_group(b"p2p-spake2-M-v1")
_SPAKE_N = _spake_hash_to_group(b"p2p-spake2-N-v1")


class PakeMismatch(Exception):
    """The peer's confirmation didn't verify: the codes differ."""


def make_pake_code() -> str:
    nameplate = str(secrets.randbelow(9000) + 1000)
    words = [_WORDLIST[secrets.randbelow(len(_WORDLIST))] for _ in range(PAKE_WORDS)]
    return "-".join([nameplate] + words)


def parse_pake_code(code: str):
    """
    "4821-apple-river-ocean" (dashes or spaces, any case) ->
    (nameplate, password_bytes). Returns None if this isn't a short code at
    all (so the caller can try the long formats). Raises ValueError if it
    looks like a short code but is malformed.
    """
    parts = code.strip().lower().replace("-", " ").split()
    if not parts or not all(c in "0123456789" for c in parts[0]):
        return None
    if len(parts[0]) > 6 or len(parts) != 1 + PAKE_WORDS:
        raise ValueError(f"A short code is a number and {PAKE_WORDS} words, "
                         f"like 4821-apple-river-ocean.")
    for w in parts[1:]:
        if w not in _WORD_INDEX:
            raise ValueError(f"Unknown word: {w!r}")
    nameplate = str(int(parts[0]))
    return nameplate, "-".join([nameplate] + parts[1:]).encode()


def _pake_token(nameplate: str) -> str:
    # Derived from the nameplate only: the relay must never see anything
    # derived from the password, or it could test guesses offline.
    return hashlib.sha256(b"p2p-pake-nameplate-v1:" + nameplate.encode()).hexdigest()[:32]


def _pake_salt(secret: bytes) -> bytes:
    return _hmac.new(secret, b"p2p-pake-salt-v1", hashlib.sha256).digest()[:16]


class Spake2:
    """One side of SPAKE2. The sender plays A (uses M), the receiver B (uses N)."""

    def __init__(self, password: bytes, is_sender: bool):
        h = _hmac.new(b"p2p-spake2-pw-v1", password, hashlib.sha512).digest()
        self._w = int.from_bytes(h, "big") % (_SPAKE_Q - 1) + 1
        self._x = secrets.randbelow(_SPAKE_Q - 1) + 1
        self._is_sender = is_sender
        mine, self._theirs = (_SPAKE_M, _SPAKE_N) if is_sender else (_SPAKE_N, _SPAKE_M)
        elem = pow(_DH_G, self._x, _DH_P) * pow(mine, self._w, _DH_P) % _DH_P
        self.msg = elem.to_bytes(_DH_KEY_BYTES, "big")

    def finish(self, peer_msg: bytes) -> bytes:
        """Returns the 32-byte transcript hash. Raises ValueError on a bad element."""
        if len(peer_msg) != _DH_KEY_BYTES:
            raise ValueError("bad SPAKE2 element length")
        y = int.from_bytes(peer_msg, "big")
        if not 1 < y < _DH_P - 1 or pow(y, _SPAKE_Q, _DH_P) != 1:
            raise ValueError("SPAKE2 element not in the group")
        # Strip the peer's password mask (theirs^-w = theirs^(q-w)), then DH.
        unmasked = y * pow(self._theirs, _SPAKE_Q - self._w, _DH_P) % _DH_P
        k = pow(unmasked, self._x, _DH_P)
        t, s = (self.msg, peer_msg) if self._is_sender else (peer_msg, self.msg)
        tt = b""
        for part in (b"p2p-sender", b"p2p-receiver", t, s,
                     k.to_bytes(_DH_KEY_BYTES, "big"),
                     self._w.to_bytes(_DH_KEY_BYTES, "big")):
            tt += struct.pack(">Q", len(part)) + part
        return hashlib.sha256(tt).digest()


def _pake_seal(key, kind: bytes, payload: bytes) -> bytes:
    """Encrypt-then-MAC one rendezvous message. Each (key, kind) pair is used
    for exactly one plaintext, so a fixed nonce per kind is safe."""
    ek, mk = key
    ct = Cipher._xor(payload, Cipher._keystream(ek, kind * 8, len(payload)))
    return _PAKE_MAGIC + kind + ct + _hmac.new(mk, kind + ct, hashlib.sha256).digest()


def _pake_open(key, kind: bytes, body: bytes):
    ek, mk = key
    if len(body) < 32:
        return None
    ct, tag = body[:-32], body[-32:]
    if not _hmac.compare_digest(tag, _hmac.new(mk, kind + ct, hashlib.sha256).digest()):
        return None
    return Cipher._xor(ct, Cipher._keystream(ek, kind * 8, len(ct)))


class PakeSession:
    """SPAKE2 + small authenticated messages over the relay mailbox."""

    def __init__(self, nameplate: str, password: bytes, is_sender: bool):
        self._is_sender = is_sender
        self._spake = Spake2(password, is_sender)
        self._elem_pkt = _PAKE_MAGIC + b"E" + self._spake.msg
        self._conf_pkt = None
        self._mine = self._theirs = None
        self.secret = None
        send_dir, recv_dir = ("s2r", "r2s") if is_sender else ("r2s", "s2r")
        self.sock = RelaySocket(RELAY_HOST, _pake_token(nameplate), send_dir, recv_dir)

    def close(self):
        self.sock.close()

    def _send(self, *pkts):
        for p in pkts:
            if p is not None:
                self.sock.sendto(p, RelaySocket.PEER_ADDR)

    def _recv(self, timeout):
        """One rendezvous packet as (kind, body), or None."""
        try:
            if not select.select([self.sock], [], [], timeout)[0]:
                return None
            pkt, _ = self.sock.recvfrom(RECV_BUF)
        except OSError:
            return None
        if len(pkt) < 5 or pkt[:4] != _PAKE_MAGIC:
            return None
        return pkt[4:5], pkt[5:]

    def handshake(self, my_flags: int, timeout, status, hint=None):
        """
        Run SPAKE2 and key confirmation. Returns the peer's flags, or None
        on timeout. Raises PakeMismatch if the codes differ.
        """
        info  = bytes([_PAKE_VERSION, my_flags])
        start = time.time()
        last_send = last_reply = start
        last_shown = -1
        hint_shown = False
        self._send(self._elem_pkt)
        while time.time() - start < timeout:
            now = time.time()
            if now - last_send >= PAKE_RESEND:
                self._send(self._elem_pkt, self._conf_pkt)
                last_send = now
            elapsed = int(now - start)
            if elapsed != last_shown:
                last_shown = elapsed
                if hint and not hint_shown and elapsed >= DIRECT_HINT_AFTER:
                    hint_shown = True
                    sys.stdout.write("\n" + hint + "\n")
                sys.stdout.write(f"\r  {status} {elapsed // 60}m {elapsed % 60}s  " if elapsed >= 60
                                 else f"\r  {status} {elapsed}s  ")
                sys.stdout.flush()

            got = self._recv(0.25)
            if got is None:
                continue
            kind, body = got
            if kind == b"E":
                if self.secret is None:
                    try:
                        h = self._spake.finish(body)
                    except ValueError:
                        continue
                    kdf = lambda label: _hmac.new(h, label, hashlib.sha256).digest()
                    s2r = (kdf(b"p2p-pake-enc-s2r"), kdf(b"p2p-pake-mac-s2r"))
                    r2s = (kdf(b"p2p-pake-enc-r2s"), kdf(b"p2p-pake-mac-r2s"))
                    self._mine, self._theirs = (s2r, r2s) if self._is_sender else (r2s, s2r)
                    self.secret = kdf(b"p2p-pake-session")
                    self._conf_pkt = _pake_seal(self._mine, b"C", info)
                    self._send(self._elem_pkt, self._conf_pkt)
                    last_send = last_reply = now
                elif now - last_reply >= PAKE_REPLY_GAP:
                    # The peer is still repeating itself: maybe it missed ours.
                    self._send(self._elem_pkt, self._conf_pkt)
                    last_reply = now
            elif kind == b"C" and self.secret is not None:
                peer_info = _pake_open(self._theirs, b"C", body)
                if peer_info is None:
                    raise PakeMismatch()
                if len(peer_info) < 2 or peer_info[0] != _PAKE_VERSION:
                    raise PakeMismatch()
                print()
                return peer_info[1]
        print()
        return None

    def exchange(self, kind: bytes, payload: bytes, timeout):
        """Swap one encrypted message of `kind` with the peer (after handshake)."""
        pkt   = _pake_seal(self._mine, kind, payload)
        start = time.time()
        last_send = 0.0
        while time.time() - start < timeout:
            now = time.time()
            if now - last_send >= PAKE_RESEND:
                # Re-send our confirmation too, in case the peer missed it.
                self._send(self._conf_pkt, pkt)
                last_send = now
            got = self._recv(0.25)
            if got is None or got[0] != kind:
                continue
            peer_payload = _pake_open(self._theirs, kind, got[1])
            if peer_payload is not None:
                return peer_payload
        return None


# ===============================================================================
# Reliable Transfer  (selective-repeat ARQ over UDP)
# ===============================================================================


def _send_data_pkt(sock, peer, cipher, seq, chunk):
    """Send one data chunk.  Silently absorbs transient OS errors;
    the retransmit logic will resend any unACKed packet automatically."""
    payload = struct.pack(">I", seq) + chunk
    try:
        sock.sendto(cipher.encrypt(T_DATA, payload), peer)
    except OSError:
        pass   # retransmit will cover it


def send_file_reliable(sock, peer, cipher, filepath, filesize, filehash,
                       connect_timeout=CONNECT_TIMEOUT):
    """
    Read the file in chunks and deliver it with windowed retransmission.

    Returns True on success, False on any recoverable failure.
    Raises nothing -- all errors are caught and turned into a False return
    with an explanatory message printed to stdout.
    """
    total_chunks = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

    # ---- Send META until the receiver ACKs or declines ----------------------
    meta = json.dumps(
        {"name": os.path.basename(filepath), "size": filesize, "hash": filehash,
         "chunk": CHUNK_SIZE}
    ).encode()
    meta_acked   = False
    meta_declined = False
    meta_start   = time.time()
    meta_deadline = meta_start + connect_timeout
    last_print   = 0.0
    resume_seq   = 0   # chunks already received by peer (0 = fresh start)

    try:
        while time.time() < meta_deadline:
            try:
                sock.sendto(cipher.encrypt(T_META, meta), peer)
            except OSError:
                pass

            try:
                ready = select.select([sock], [], [], 0.5)
            except OSError:
                continue

            if ready[0]:
                try:
                    raw, _ = sock.recvfrom(RECV_BUF)
                except OSError:
                    continue
                try:
                    ptype, pl = cipher.decrypt(raw)
                except Exception:
                    continue
                if ptype == T_ACK:
                    meta_acked = True
                    if pl and len(pl) >= 4:
                        val = struct.unpack(">I", pl[:4])[0]
                        resume_seq = 0 if val == 0xFFFFFFFF else val
                    break
                if ptype == T_ABORT:
                    meta_declined = True
                    break
                if ptype == T_HASHQ and pl and len(pl) >= 8:
                    try:
                        n_chunks = struct.unpack(">Q", pl[:8])[0]
                        hval = _prefix_sha256_chunks(filepath, n_chunks)
                        sock.sendto(cipher.encrypt(T_HASHR,
                            struct.pack(">Q", n_chunks) + hval), peer)
                        # hash computation can take seconds; drain any duplicate
                        # HASHQs that piled up in the buffer during that time
                        # so the META loop doesn't recompute for each one
                        _drain_socket(sock)
                    except OSError:
                        pass

            elapsed = time.time() - meta_start
            if elapsed - last_print >= 30:
                last_print = elapsed
                sys.stdout.write(f"\r  Waiting for receiver... {int(elapsed)}s  ")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n  Cancelled.")
        _send_abort_signal(sock, cipher, peer, "CANCEL")
        return False

    if meta_declined:
        print("\n  Receiver declined the transfer.")
        return False
    if not meta_acked:
        print("\n  Receiver did not respond to file info -- timed out.")
        return False

    if total_chunks == 0:
        # Empty file -- just signal DONE
        for _ in range(10):
            try:
                sock.sendto(cipher.encrypt(T_DONE, b"DONE"), peer)
            except OSError:
                pass
            time.sleep(0.05)
        return True

    print(f"  Sending {total_chunks} chunks ({_fmt(filesize)})")

    # ---- Chunked send with sliding-window ARQ --------------------------------
    try:
        fh = open(filepath, "rb")
    except OSError as e:
        print(f"\n  Cannot open file for reading: {e}")
        return False

    chunk_cache = {}
    acked       = set()
    sent_time   = {}
    retries     = {}
    next_seq    = 0

    if resume_seq > 0:
        acked    = set(range(resume_seq))
        next_seq = resume_seq
        print(f"  Skipping {resume_seq} already-received chunks "
              f"({_fmt(min(resume_seq * CHUNK_SIZE, filesize))} already at receiver).")

    def _get_chunk(seq):
        if seq not in chunk_cache:
            try:
                fh.seek(seq * CHUNK_SIZE)
                chunk_cache[seq] = fh.read(CHUNK_SIZE)
            except OSError as e:
                raise OSError(f"Error reading source file: {e}") from e
        return chunk_cache[seq]

    last_acked_count  = 0
    # None until the first packet is sent; prevents the stall timer from
    # firing before any data has left the socket.
    last_progress_t   = None

    try:
        while len(acked) < total_chunks:
            now = time.time()

            # ---- Stall detection --------------------------------------------
            # If the acked count hasn't moved in STALL_TIMEOUT seconds the
            # receiver has gone away without sending T_ABORT.
            if len(acked) > last_acked_count:
                last_acked_count = len(acked)
                last_progress_t  = now
            elif last_progress_t is not None and now - last_progress_t > STALL_TIMEOUT:
                print(f"\n  Transfer stalled -- no progress for {STALL_TIMEOUT}s. "
                      f"Receiver may have disconnected.")
                return False

            # ---- Fill the send window ---------------------------------------
            while (
                next_seq < total_chunks
                and (next_seq - len(acked)) < WINDOW_SIZE
            ):
                _send_data_pkt(sock, peer, cipher, next_seq, _get_chunk(next_seq))
                sent_time[next_seq] = now
                retries.setdefault(next_seq, 0)
                if last_progress_t is None:
                    last_progress_t = now   # arm stall timer on first send
                next_seq += 1

            # ---- Retransmit timed-out packets --------------------------------
            # Also prunes acked entries so the scan stays O(in-flight),
            # not O(total-chunks-ever-sent) -- critical for large files.
            for seq in list(sent_time):
                if seq in acked:
                    del sent_time[seq]
                    retries.pop(seq, None)
                    continue
                if now - sent_time[seq] > ACK_TIMEOUT:
                    retries[seq] += 1
                    if retries[seq] > MAX_RETRIES:
                        print(f"\n  Chunk {seq} hit the retry limit "
                              f"({MAX_RETRIES} attempts). "
                              f"Network may be too lossy or receiver disconnected.")
                        return False
                    _send_data_pkt(sock, peer, cipher, seq, _get_chunk(seq))
                    sent_time[seq] = now

            # ---- Drain incoming ACKs ----------------------------------------
            while True:
                try:
                    ready = select.select([sock], [], [], 0.01)
                except OSError:
                    break
                if not ready[0]:
                    break
                try:
                    raw, _ = sock.recvfrom(RECV_BUF)
                    ptype, pl = cipher.decrypt(raw)
                    if ptype == T_ACK and pl and len(pl) >= 4:
                        ack_seq = struct.unpack(">I", pl[:4])[0]
                        if ack_seq != 0xFFFFFFFF:
                            acked.add(ack_seq)
                            chunk_cache.pop(ack_seq, None)
                    elif ptype == T_ABORT:
                        print("\n  Receiver cancelled the transfer.")
                        return False
                except OSError:
                    pass

            # ---- Progress display -------------------------------------------
            pct        = len(acked) * 100 // total_chunks
            done_bytes = min(len(acked) * CHUNK_SIZE, filesize)
            sys.stdout.write(
                f"\r  Progress: {pct:3d}%  ({_fmt(done_bytes)} / {_fmt(filesize)})"
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n  Cancelled.")
        _send_abort_signal(sock, cipher, peer, "CANCEL")
        return False
    except OSError as e:
        print(f"\n  I/O error during transfer: {e}")
        return False
    finally:
        fh.close()

    # ---- Signal completion --------------------------------------------------
    done_pkt      = cipher.encrypt(T_DONE, b"DONE")
    done_deadline = time.time() + DONE_TIMEOUT
    got_doneack   = False
    try:
        while time.time() < done_deadline:
            try:
                sock.sendto(done_pkt, peer)
            except OSError:
                pass
            try:
                ready = select.select([sock], [], [], 0.5)
            except OSError:
                continue
            if ready[0]:
                try:
                    raw, _ = sock.recvfrom(RECV_BUF)
                except OSError:
                    continue
                ptype, _ = cipher.decrypt(raw)
                if ptype == T_DONEACK:
                    got_doneack = True
                    break
                if ptype == T_ABORT:
                    print("\n  Receiver cancelled the transfer.")
                    return False
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        _send_abort_signal(sock, cipher, peer, "CANCEL")
        return False

    print(f"\r  Progress: 100%  ({_fmt(filesize)} / {_fmt(filesize)})")
    if not got_doneack:
        print("  Warning: receiver did not acknowledge completion "
              f"(no DONEACK within {DONE_TIMEOUT}s). "
              "The file was fully transferred but the receiver may still be processing.")
    return True


def recv_file_reliable(sock, peer, cipher, connect_timeout=CONNECT_TIMEOUT,
                       max_size=MAX_FILE_SIZE, resume_path=None):
    """
    Receive a file, streaming chunks to a temp file.
    Returns (filename, temp_path, expected_hash) or None on any failure.

    Raises nothing.  Every error path cleans up the temp file and prints
    a user-friendly explanation.
    """

    # ---- Wait for META and let the user approve or decline ------------------
    print("  Waiting for file info (you will approve before transfer starts)...")
    accepted   = None
    t0         = time.time()
    deadline   = t0 + connect_timeout
    last_print = 0.0

    while accepted is None:
        if time.time() > deadline:
            print("\n  Timed out waiting for sender to send file info.")
            return None

        elapsed = time.time() - t0
        if elapsed - last_print >= 30:
            last_print = elapsed
            mins, secs = divmod(int(elapsed), 60)
            label = f"{mins}m {secs}s" if mins else f"{secs}s"
            sys.stdout.write(f"\r  Still waiting for sender... {label}  ")
            sys.stdout.flush()

        try:
            ready = select.select([sock], [], [], 2.0)
        except OSError:
            continue
        if not ready[0]:
            continue

        try:
            raw, addr = sock.recvfrom(RECV_BUF)
        except OSError:
            continue

        ptype, payload = cipher.decrypt(raw)
        if ptype == T_HELLO:
            pass   # late punch reply -- ignore (DH already done)
        elif ptype == T_ABORT:
            reason = payload[:200].decode("utf-8", "replace") if payload else "ABORT"
            print(f"\n  Sender cancelled before transfer started ({reason}).")
            return None
        elif ptype == T_META and payload:
            try:
                meta = json.loads(payload)
            except Exception:
                continue

            if not isinstance(meta, dict):
                continue
            if not isinstance(meta.get("name"), str) or not meta["name"]:
                continue
            if not isinstance(meta.get("size"), int) or meta["size"] < 0:
                continue
            if not isinstance(meta.get("hash"), str) or len(meta["hash"]) != 64:
                continue

            raw_name = meta["name"]
            filename = os.path.basename(raw_name)
            if not filename or filename.startswith("."):
                print(f"\n  Sender provided an invalid filename: {raw_name!r}")
                return None

            filesize = meta["size"]
            filehash = meta["hash"]

            # Old senders don't send "chunk" and always used 1400.
            peer_chunk = meta.get("chunk", 1400)
            if peer_chunk != CHUNK_SIZE:
                print(f"\n  Version mismatch: sender uses {peer_chunk}-byte chunks, "
                      f"this side uses {CHUNK_SIZE}.\n"
                      f"  Update p2p.py on BOTH machines to the same version.")
                _send_abort_signal(sock, cipher, addr, "VERSION")
                return None

            if filesize > max_size:
                print(f"\n  File too large ({_fmt(filesize)}). "
                      f"Limit is {_fmt(max_size)}.")
                _send_abort_signal(sock, cipher, addr, "SIZE")
                return None

            print(f"\n  Incoming file : {filename}  ({_fmt(filesize)})")
            try:
                answer = input("  Accept this file? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                _send_abort_signal(sock, cipher, addr, "CANCEL")
                print("\n  Cancelled.")
                return None

            if answer not in ("y", "yes"):
                _send_abort_signal(sock, cipher, addr, "NO")
                print("  Transfer declined.")
                return None

            # ---- Resume negotiation (before sending META-ACK) ---------------
            confirmed_chunks = 0
            using_resume     = False

            if resume_path is not None:
                if not os.path.isfile(resume_path):
                    print(f"  Resume error: '{resume_path}' not found.")
                    _send_abort_signal(sock, cipher, addr, "ABORT")
                    return None

                partial_size = os.path.getsize(resume_path)

                if partial_size == 0:
                    print("  Partial file is empty -- starting fresh.")
                elif partial_size > filesize:
                    print(f"  Resume error: partial file ({_fmt(partial_size)}) is "
                          f"larger than incoming file ({_fmt(filesize)}). Wrong file?")
                    _send_abort_signal(sock, cipher, addr, "ABORT")
                    return None
                else:
                    partial_chunks   = math.ceil(partial_size / CHUNK_SIZE)
                    confirmed_chunks = _resume_binary_search(
                        sock, addr, cipher, resume_path, partial_chunks,
                        # keep bins ~25 MB regardless of chunk size
                        chunks_per_bin=max(1, (RESUME_CHUNKS_PER_BIN * 1400) // CHUNK_SIZE),
                    )
                    if confirmed_chunks == 0:
                        print("  Partial file does not match this transfer -- "
                              "cannot resume. Run recv without --resume to start over.")
                        _send_abort_signal(sock, cipher, addr, "ABORT")
                        return None
                    using_resume = True

            ack_seq = confirmed_chunks if using_resume else 0xFFFFFFFF
            try:
                sock.sendto(cipher.encrypt(T_ACK, struct.pack(">I", ack_seq)), addr)
            except OSError:
                pass
            peer     = addr
            accepted = (filename, filesize, filehash, confirmed_chunks, using_resume)

    filename, filesize, filehash, confirmed_chunks, using_resume = accepted
    total_chunks = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

    print(f"  Receiving: {filename}  ({_fmt(filesize)})")

    if total_chunks == 0:
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, dir=".")
            os.chmod(tmp.name, 0o600)
            tmp.close()
        except OSError as e:
            print(f"\n  Cannot create temp file: {e}")
            return None
        return filename, tmp.name, filehash

    # ---- Open working file (resume in-place or fresh temp) ------------------
    if using_resume:
        try:
            tmp          = open(resume_path, "r+b")
            working_path = resume_path
            tmp.seek(confirmed_chunks * CHUNK_SIZE)
            tmp.truncate()   # discard anything past the verified boundary
        except OSError as e:
            print(f"\n  Cannot open partial file for resume: {e}")
            return None
    else:
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, dir=".")
            os.chmod(tmp.name, 0o600)
            working_path = tmp.name
        except OSError as e:
            print(f"\n  Cannot create temp file: {e}")
            return None

    received_seqs = set(range(confirmed_chunks)) if using_resume else set()
    done          = False
    last_recv_t   = time.time()

    try:
        while len(received_seqs) < total_chunks or not done:
            # ---- Stall detection --------------------------------------------
            if time.time() - last_recv_t > STALL_TIMEOUT:
                print(f"\n  Transfer stalled -- no data received for "
                      f"{STALL_TIMEOUT}s. Sender may have disconnected.")
                _send_abort_signal(sock, cipher, peer, "STALL")
                tmp.close()
                _partial_saved_msg(working_path)
                return None

            try:
                ready = select.select([sock], [], [], 2.0)
            except OSError:
                continue
            if not ready[0]:
                if len(received_seqs) >= total_chunks:
                    break   # have everything, must have missed DONE
                continue

            try:
                raw, addr = sock.recvfrom(RECV_BUF)
            except OSError:
                continue

            # Reset stall timer on any successful receive from our peer
            if addr == peer:
                last_recv_t = time.time()

            ptype, payload = cipher.decrypt(raw)
            if ptype is None:
                continue
            if addr != peer:
                continue

            if ptype == T_DATA and payload and len(payload) > 4:
                seq = struct.unpack(">I", payload[:4])[0]
                if seq >= total_chunks:
                    continue
                if seq not in received_seqs:
                    chunk = payload[4:]
                    try:
                        tmp.seek(seq * CHUNK_SIZE)
                        tmp.write(chunk)
                    except OSError as e:
                        print(f"\n  Disk write error: {e}")
                        _send_abort_signal(sock, cipher, peer, "ERROR")
                        tmp.close()
                        _partial_saved_msg(working_path)
                        return None
                    received_seqs.add(seq)
                # Always ACK (even duplicates) so sender can advance its window
                try:
                    sock.sendto(cipher.encrypt(T_ACK, struct.pack(">I", seq)), addr)
                except OSError:
                    pass

                pct = len(received_seqs) * 100 // total_chunks
                got = min(len(received_seqs) * CHUNK_SIZE, filesize)
                sys.stdout.write(
                    f"\r  Progress: {pct:3d}%  ({_fmt(got)} / {_fmt(filesize)})"
                )
                sys.stdout.flush()

            elif ptype == T_DONE:
                try:
                    sock.sendto(cipher.encrypt(T_DONEACK, b"OK"), addr)
                except OSError:
                    pass
                done = True
                if len(received_seqs) >= total_chunks:
                    break

            elif ptype == T_META:
                # Re-ACK in case sender missed our first META-ACK
                try:
                    ack_seq = confirmed_chunks if using_resume else 0xFFFFFFFF
                    sock.sendto(
                        cipher.encrypt(T_ACK, struct.pack(">I", ack_seq)), addr
                    )
                except OSError:
                    pass

            elif ptype == T_ABORT:
                reason = payload[:200].decode("utf-8", "replace") if payload else "ABORT"
                print(f"\n  Sender cancelled the transfer ({reason}).")
                tmp.close()
                _partial_saved_msg(working_path)
                return None

        # ---- Finalize the temp file -----------------------------------------
        try:
            tmp.truncate(filesize)
            tmp.close()
        except OSError as e:
            print(f"\n  Disk error finalising file: {e}")
            try:
                tmp.close()
            except OSError:
                pass
            _partial_saved_msg(working_path)
            return None

    except KeyboardInterrupt:
        _send_abort_signal(sock, cipher, peer, "CANCEL")
        tmp.close()
        print("\n  Cancelled by receiver.")
        _partial_saved_msg(working_path)
        return None

    print(f"\r  Progress: 100%  ({_fmt(filesize)} / {_fmt(filesize)})")

    # ---- Verify end-to-end hash ---------------------------------------------
    sha = hashlib.sha256()
    try:
        with open(working_path, "rb") as f:
            while True:
                blk = f.read(1 << 20)
                if not blk:
                    break
                sha.update(blk)
    except OSError as e:
        print(f"\n  Cannot read temp file for verification: {e}")
        _partial_saved_msg(working_path)
        return None

    actual = sha.hexdigest()
    if actual != filehash:
        print("  ERROR: SHA-256 mismatch -- file is corrupted or tampered!")
        print(f"    expected {filehash}")
        print(f"    got      {actual}")
        print("  The partial data is preserved. You can retry with the resume")
        print("  command shown below.")
        _partial_saved_msg(working_path)
        return None
    return filename, working_path, filehash


# ===============================================================================
# Utilities
# ===============================================================================


def _fmt(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


def _partial_saved_msg(working_path):
    """Print a consistent 'partial file kept' message on any mid-transfer failure."""
    flags = (" -6" if USE_IPV6 else "") + (" --relay" if USE_RELAY else "")
    print(f"  Partial file saved: {working_path}")
    print(f"  To resume:          python p2p.py recv{flags} --resume \"{working_path}\"")


# ===============================================================================
# Resume helpers  (prefix hashing + binary search)
# ===============================================================================


def _prefix_crc32_chunks(filepath, num_chunks):
    """CRC32 of the first num_chunks * CHUNK_SIZE bytes of filepath."""
    crc = 0
    remaining = num_chunks * CHUNK_SIZE
    with open(filepath, "rb") as f:
        while remaining > 0:
            blk = f.read(min(65536, remaining))
            if not blk:
                break
            crc = zlib.crc32(blk, crc)
            remaining -= len(blk)
    return struct.pack(">I", crc & 0xFFFFFFFF)

def _prefix_sha256_chunks(filepath, num_chunks):
    """SHA-256 of the first num_chunks * CHUNK_SIZE bytes of filepath."""
    h = hashlib.sha256()
    remaining = num_chunks * CHUNK_SIZE
    with open(filepath, "rb") as f:
        while remaining > 0:
            blk = f.read(min(65536, remaining))
            if not blk:
                break
            h.update(blk)
            remaining -= len(blk)
    return h.digest()


def _precompute_bin_crc32s(filepath, partial_chunks, chunks_per_bin):
    """
    Single sequential pass through filepath.
    Returns a list where result[i] = CRC32(bytes 0 .. (i+1)*chunks_per_bin*CHUNK_SIZE - 1).
    Unwritten regions (partial final chunk) are treated as zero bytes.
    Length = ceil(partial_chunks / chunks_per_bin).
    """
    snapshots = []
    crc = 0
    with open(filepath, "rb") as f:
        for idx in range(partial_chunks):
            blk = f.read(CHUNK_SIZE)
            if not blk:
                blk = b"\x00" * CHUNK_SIZE
            elif len(blk) < CHUNK_SIZE:
                blk = blk + b"\x00" * (CHUNK_SIZE - len(blk))
            crc = zlib.crc32(blk, crc)
            if (idx + 1) % chunks_per_bin == 0:
                snapshots.append(crc & 0xFFFFFFFF)
    if partial_chunks % chunks_per_bin != 0:
        snapshots.append(crc & 0xFFFFFFFF)
    return snapshots


def _resume_binary_search(sock, peer, cipher, partial_path, partial_chunks,
                           chunks_per_bin=RESUME_CHUNKS_PER_BIN):
    """
    Hybrid resume strategy: exact prefix check, then go-back-N fallback
    (up to min(3, available bins) steps), then binary search only when the
    file has >=3 bins and all 3 go-back steps fail.
    Returns the number of verified-good chunks, or 0 if nothing matches.
    """
    if partial_chunks == 0:
        return 0

    print("  Verifying partial file for resume...")

    def _query(num_chunks):
        # Send HASHQ, wait for the matching HASHR.  Retry up to 5 times with
        # an 8-second window each -- _sock_recv_typed drains wrong-type packets
        # instantly so the budget measures genuine silence, not noise.
        req = struct.pack(">Q", num_chunks)
        for _ in range(5):
            try:
                sock.sendto(cipher.encrypt(T_HASHQ, req), peer)
            except OSError:
                pass
            pl = _sock_recv_typed(sock, cipher, peer, T_HASHR, 8.0)
            if pl is None:
                continue
            if len(pl) >= 40 and struct.unpack(">Q", pl[:8])[0] == num_chunks:
                return pl[8:40]
        return None

    def _verify(num_chunks):
        # Returns True (match), False (mismatch), or None (no sender response).
        sender_sha = _query(num_chunks)
        if sender_sha is None:
            return None
        recv_sha = _prefix_sha256_chunks(partial_path, num_chunks)
        return _hmac.compare_digest(sender_sha[:32], recv_sha)

    # ---- Exact prefix check (fast path) -------------------------------------
    result = _verify(partial_chunks)
    if result is None:
        print("  Resume verification failed -- no response from sender.")
        return 0
    if result:
        print(f"  Prefix verified. Resuming from chunk {partial_chunks} "
              f"({_fmt(partial_chunks * CHUNK_SIZE)}).")
        return partial_chunks

    print(f"  Prefix mismatch at chunk {partial_chunks}. Trying go-back-N...")

    # ---- Go-back-N: step back by chunks_per_bin, up to 3 valid steps --------
    goback_candidates = []
    for k in range(1, 4):
        candidate = partial_chunks - k * chunks_per_bin
        if candidate <= 0:
            break
        goback_candidates.append(candidate)

    num_goback  = len(goback_candidates)   # 0-3
    last_failed = partial_chunks           # tightest known-bad bound

    for step_idx, candidate in enumerate(goback_candidates):
        result = _verify(candidate)
        if result is None:
            print(f"  No response from sender at chunk {candidate}. Aborting.")
            return 0
        if result:
            print(f"  Go-back-N matched at chunk {candidate} "
                  f"({_fmt(candidate * CHUNK_SIZE)}) "
                  f"after {step_idx + 1} step(s).")
            return candidate
        last_failed = candidate
        print(f"  Mismatch at chunk {candidate} "
              f"(step {step_idx + 1}/{num_goback}).")

    # ---- Binary search: only for files with >=3 bins when all 3 steps fail --
    if num_goback < 3:
        print(f"  File has {num_goback} bin(s). All go-back steps exhausted. "
              f"Cannot resume.")
        return 0

    print("  All go-back-N steps failed. Running binary search...")

    lo = 0            # highest known-good (empty prefix is vacuously good)
    hi = last_failed  # lowest known-bad

    while hi - lo > 1:
        mid = (lo + hi) // 2
        result = _verify(mid)
        if result is None:
            print(f"  No sender response at chunk {mid}. Aborting binary search.")
            return 0
        if result:
            lo = mid
        else:
            hi = mid

    if lo == 0:
        print("  Binary search found no verified prefix. Cannot resume.")
        return 0

    print(f"  Binary search found verified prefix at chunk {lo} "
          f"({_fmt(lo * CHUNK_SIZE)}).")
    return lo




# ===============================================================================
# CLI Commands
# ===============================================================================

BANNER = r"""
  +-----------------------------------------+
  |   p2p.py -- encrypted hole-punch xfer   |
  |   no dependencies . short PAKE codes    |
  +-----------------------------------------+
"""


def _relay_reachable():
    """Quick check that the relay answers, so --relay fails fast with a clear
    message instead of waiting out the (very long) connect timeout."""
    try:
        c = http.client.HTTPSConnection(RELAY_HOST, timeout=8)
        try:
            c.request("GET", "/healthz")
            r = c.getresponse()
            r.read()
            return r.status == 200
        finally:
            c.close()
    except (OSError, http.client.HTTPException):
        return False


def _use_relay_mode():
    """Switch to relay transport and its bigger chunk/window sizes."""
    global USE_RELAY, CHUNK_SIZE, WINDOW_SIZE, ACK_TIMEOUT
    USE_RELAY   = True
    CHUNK_SIZE  = RELAY_CHUNK_SIZE
    WINDOW_SIZE = RELAY_WINDOW_SIZE
    ACK_TIMEOUT = RELAY_ACK_TIMEOUT


def _bind_udp():
    """Returns (sock, local_ip, local_port). Exits on failure."""
    family    = socket.AF_INET6 if USE_IPV6 else socket.AF_INET
    bind_host = "::" if USE_IPV6 else ""
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if USE_IPV6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except (AttributeError, OSError):
                pass
        sock.bind((bind_host, 0))
    except OSError as e:
        print(f"  Error: cannot create UDP socket: {e}")
        sys.exit(1)
    return sock, get_local_ip(), sock.getsockname()[1]   # index 1 = port for both AF families


def _discover_endpoint(sock, local_ip, local_port):
    """STUN (skipped in relay mode). Returns (pub_ip, pub_port)."""
    if USE_RELAY:
        _vprint("  Relay mode: skipping STUN and hole punching.")
        pub = None
    else:
        _vprint("  Discovering public endpoint via STUN...")
        pub = stun_discover(sock)
    if pub:
        pub_ip, pub_port = pub
        try:
            if USE_IPV6:
                socket.inet_pton(socket.AF_INET6, pub_ip)
            else:
                socket.inet_aton(pub_ip)   # guard: only same-family addresses
            _vprint(f"  Public : {_fmt_addr(pub_ip, pub_port)}")
        except OSError:
            pub_ip, pub_port = local_ip, local_port
            _vprint("  STUN returned wrong-family address -- using local address.")
    else:
        pub_ip, pub_port = local_ip, local_port
        if USE_RELAY:
            pass   # addresses in the codes are unused in relay mode
        elif USE_IPV6:
            _vprint("  STUN failed -- using local IPv6 address (IPv6 has no NAT).")
        else:
            _vprint("  STUN failed -- using local address (LAN-only transfer).")
    _vprint(f"  Local  : {_fmt_addr(local_ip, local_port)}")
    if not USE_RELAY and _is_cgnat(pub_ip):
        print(_CGNAT_WARNING.format(ip=pub_ip))
    return pub_ip, pub_port


def _pake_connect(code, is_sender, sock, local_ip, local_port, connect_timeout):
    """
    Short-code flow: meet the peer at the relay, run SPAKE2, agree on the
    mode and (direct mode only) swap addresses. Returns
    (secret, salt, peer_pub, peer_local); the peer addresses are None in
    relay mode. Exits on failure.
    """
    nameplate, password = parse_pake_code(code)
    my_flags = ((_PAKE_F_RELAY if USE_RELAY else 0) | (_PAKE_F_IPV6 if USE_IPV6 else 0)
                | (_PAKE_F_AES if _aes_available() else 0))
    other = "receiver" if is_sender else "sender"
    sess = PakeSession(nameplate, password, is_sender)
    try:
        status = "Waiting for the receiver to enter the code..." if is_sender else "Finding the sender..."
        hint = None if is_sender else (
            "\n  Taking a while. Check that the sender is still waiting and that the\n"
            "  number at the start of the code is right.")
        try:
            peer_flags = sess.handshake(my_flags, connect_timeout, status, hint)
        except PakeMismatch:
            print("\n  Error: the codes didn't match.")
            print("  Check the code for typos. Each code allows only one attempt, so the")
            print("  sender has to run 'send' again for a new code.")
            sock.close()
            sys.exit(1)
        if peer_flags is None:
            print(f"  Timed out: the {other} never showed up.")
            sock.close()
            sys.exit(1)
        print("  Code verified.")
        # Short codes pick the cipher here, so even the HELLOs below use it.
        _choose_cipher(bool(my_flags & _PAKE_F_AES), bool(peer_flags & _PAKE_F_AES), other)

        if (my_flags | peer_flags) & _PAKE_F_RELAY:
            if not USE_RELAY:
                print(f"  The {other} asked for --relay, so the transfer goes through the relay.")
            _use_relay_mode()
            return sess.secret, _pake_salt(sess.secret), None, None

        if bool(peer_flags & _PAKE_F_IPV6) != USE_IPV6:
            print("  Error: address-family mismatch.")
            print(f"  The {other} is using {'IPv6 (-6)' if peer_flags & _PAKE_F_IPV6 else 'IPv4'}."
                  " Both sides must agree on -6 (or neither), or use --relay.")
            sock.close()
            sys.exit(1)

        # STUN only now, with both sides present, so the NAT mapping is fresh
        # when hole punching starts.
        pub_ip, pub_port = _discover_endpoint(sock, local_ip, local_port)
        mine = (_ip_pack(pub_ip) + struct.pack("!H", pub_port)
                + _ip_pack(local_ip) + struct.pack("!H", local_port))
        theirs = sess.exchange(b"A", mine, connect_timeout)
        if theirs is None or len(theirs) != len(mine):
            print(f"  Error: lost contact with the {other} while exchanging addresses.")
            sock.close()
            sys.exit(1)
        peer_pub_ip, off = _ip_unpack(theirs, 0)
        (peer_pub_port,) = struct.unpack("!H", theirs[off:off + 2])
        peer_local_ip, off = _ip_unpack(theirs, off + 2)
        (peer_local_port,) = struct.unpack("!H", theirs[off:off + 2])
        _vprint(f"  Peer public : {_fmt_addr(peer_pub_ip, peer_pub_port)}")
        _vprint(f"  Peer local  : {_fmt_addr(peer_local_ip, peer_local_port)}")
        return (sess.secret, _pake_salt(sess.secret),
                (peer_pub_ip, peer_pub_port), (peer_local_ip, peer_local_port))
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sock.close()
        sys.exit(0)
    finally:
        sess.close()


def cmd_send(filepath, connect_timeout=CONNECT_TIMEOUT, long_code=False):
    # ---- Pre-flight checks --------------------------------------------------
    if not os.path.isfile(filepath):
        print(f"  Error: '{filepath}' not found or is not a file.")
        sys.exit(1)

    filename = os.path.basename(filepath)
    try:
        filesize = os.path.getsize(filepath)
    except OSError as e:
        print(f"  Error: cannot stat file: {e}")
        sys.exit(1)

    print(f"  File : {filename}")
    print(f"  Size : {_fmt(filesize)}")

    # ---- Hash the file before binding the socket ----------------------------
    print("  Hashing file...")
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                blk = f.read(1 << 20)
                if not blk:
                    break
                sha.update(blk)
    except OSError as e:
        print(f"  Error: cannot read file: {e}")
        sys.exit(1)
    filehash = sha.hexdigest()

    # ---- Bind UDP socket ----------------------------------------------------
    sock, local_ip, local_port = _bind_udp()

    if long_code:
        pub_ip, pub_port = _discover_endpoint(sock, local_ip, local_port)
        secret = secrets.token_bytes(16)
        if USE_RELAY:
            salt = _relay_salt(secret)
            code = encode_relay_code(secret)
        else:
            salt = secrets.token_bytes(16)
            code = encode_sender_code(secret, salt, pub_ip, pub_port, local_ip, local_port)
    else:
        code = make_pake_code()

    print()
    print("  +==========================================================+")
    print("  |  SEND CODE -- give this to the receiver:                 |")
    print("  +==========================================================+")
    print()
    print(f"  {code}")
    print()

    if not long_code:
        # Short code: the receiver types it in and both sides meet at the
        # relay; there is nothing to paste back.
        secret, salt, peer_pub, peer_local = _pake_connect(
            code, True, sock, local_ip, local_port, connect_timeout)
        if not USE_RELAY:
            (peer_pub_ip, peer_pub_port), (peer_local_ip, peer_local_port) = peer_pub, peer_local
    elif USE_RELAY:
        # Relay mode: there is no receiver code. We are already holding the
        # secret, so go straight to the relay and wait for the receiver there.
        print("  Relay mode: nothing to paste back. The receiver needs only the code above.")
    else:
        # ---- Wait for receiver's code -------------------------------------------
        try:
            rcode = input("  Paste receiver's code: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelled.")
            sock.close()
            sys.exit(0)

        if not rcode:
            print("  No code entered.")
            sock.close()
            sys.exit(1)

        # Detect IPv4/IPv6 mismatch before decoding
        _rwords = rcode.strip().lower().split()
        _expected_rwords = 42 if USE_IPV6 else 23
        if len(_rwords) != _expected_rwords:
            print("  Error: invalid receiver code.")
            if not USE_IPV6 and len(_rwords) == 42:
                print("  The receiver is using IPv6 (-6). Re-run: python p2p.py send <file> -6 --long-code")
            elif USE_IPV6 and len(_rwords) == 23:
                print("  The receiver is using IPv4. Both sides must agree on -6 (or neither).")
            else:
                print("  Make sure you copied the entire RECV CODE from the receiver's screen.")
            sock.close()
            sys.exit(1)

        result = decode_recv_code(rcode, secret)
        if result is None:
            print("  Error: invalid receiver code.")
            print("  Make sure you copied the entire RECV CODE from the receiver's screen,")
            print("  and that the receiver used the SEND CODE you gave them (not an old one).")
            sock.close()
            sys.exit(1)

        peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port = result
        _vprint(f"  Peer public : {_fmt_addr(peer_pub_ip, peer_pub_port)}")
        _vprint(f"  Peer local  : {_fmt_addr(peer_local_ip, peer_local_port)}")

    # ---- Handshake ----------------------------------------------------------
    _vprint("  Deriving handshake keys (PBKDF2, 100k rounds)...")
    handshake_cipher = Cipher(secret, salt, is_sender=True, aes=USE_AES)
    dh_priv, dh_pub  = _dh_keypair()

    relay_sock = None
    if USE_RELAY:
        # Relay mode: no hole punching at all -- both sides meet at the relay.
        print("  Relay mode: connecting through the relay" + (" (receiver must also use --relay)." if long_code else "."))
        token = _relay_session_token(secret)
        relay_sock = RelaySocket(RELAY_HOST, token, send_dir="s2r", recv_dir="r2s")
        try:
            peer, peer_dh_pub, peer_caps = punch_hole(
                relay_sock, handshake_cipher,
                RelaySocket.PEER_ADDR, RelaySocket.PEER_ADDR,
                dh_pub, timeout=connect_timeout, caps=_my_caps(),
            )
        except KeyboardInterrupt:
            print("\n  Cancelled during connection.")
            relay_sock.close()
            sock.close()
            sys.exit(0)

        if not peer:
            print("  Could not reach the receiver through the relay.")
            print("  Possible causes:")
            print("    - The receiver is not running 'recv --relay' right now")
            print("    - The receiver pasted a different (old) send code")
            print("    - The relay server became unreachable")
            relay_sock.close()
            sock.close()
            sys.exit(1)
    else:
        try:
            peer, peer_dh_pub, peer_caps = punch_hole(
                sock,
                handshake_cipher,
                (peer_pub_ip, peer_pub_port),
                (peer_local_ip, peer_local_port),
                dh_pub,
                timeout=connect_timeout,
                hint=_DIRECT_HINT,
                caps=_my_caps(),
            )
        except KeyboardInterrupt:
            print("\n  Cancelled during connection.")
            sock.close()
            sys.exit(0)

        if not peer:
            print("  Could not reach the receiver.")
            print("  Possible causes:")
            print("    - The receiver is not running 'recv' right now")
            print("    - The recv code is from a different session (try again from the start)")
            print("    - One or both sides are behind CG-NAT or symmetric NAT")
            print("  If direct connection keeps failing, run both sides with --relay.")
            sock.close()
            sys.exit(1)

    try:
        dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    except ValueError as e:
        print(f"  Handshake error: {e}")
        if relay_sock:
            relay_sock.close()
        sock.close()
        sys.exit(1)

    if long_code:
        # Long codes learn the peer's AES support from its HELLO; only the
        # HELLOs themselves used the SHA-256 cipher.
        _choose_cipher(bool(_my_caps() & _CAP_AES), bool(peer_caps & _CAP_AES), "receiver")
    _vprint("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=True, aes=USE_AES)

    # ---- Transfer -----------------------------------------------------------
    xfer_sock = relay_sock if relay_sock else sock
    ok = send_file_reliable(
        xfer_sock, peer, session_cipher, filepath, filesize, filehash,
        connect_timeout=connect_timeout,
    )
    if relay_sock:
        relay_sock.close()
    sock.close()

    if ok:
        print("  Done -- file sent successfully!")
    else:
        sys.exit(1)


def cmd_recv(connect_timeout=CONNECT_TIMEOUT, max_size=MAX_FILE_SIZE, resume_path=None):
    save_dir = "."

    # ---- Bind ---------------------------------------------------------------
    sock, local_ip, local_port = _bind_udp()

    # ---- Get sender code ----------------------------------------------------
    print()
    try:
        scode = input("  Paste sender's code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sock.close()
        sys.exit(0)

    if not scode:
        print("  No code entered.")
        sock.close()
        sys.exit(1)

    try:
        long_code = parse_pake_code(scode) is None
    except ValueError as e:
        print("  Error: invalid sender code.")
        print(f"  {e}" + (" (check the spelling)" if str(e).startswith("Unknown word") else ""))
        sock.close()
        sys.exit(1)

    if not long_code:
        if not USE_RELAY and not _relay_reachable():   # main() already checked with --relay
            print(f"  Error: cannot reach the relay at {RELAY_HOST} to look up the code.")
            print("  Check your internet connection, or point at another relay with --relay-host.")
            sock.close()
            sys.exit(1)
        secret, salt, peer_pub, peer_local = _pake_connect(
            scode, False, sock, local_ip, local_port, connect_timeout)
        if not USE_RELAY:
            (peer_pub_ip, peer_pub_port), (peer_local_ip, peer_local_port) = peer_pub, peer_local
    else:
        pub_ip, pub_port = _discover_endpoint(sock, local_ip, local_port)

    _nwords = len(scode.split())
    if not long_code:
        pass   # handled above
    elif USE_RELAY:
        if _nwords in (36, 55):
            print("  Error: this is a direct-mode code (the sender did not use --relay).")
            print("  Both sides must use --relay, or neither.")
            sock.close()
            sys.exit(1)
        try:
            secret = decode_relay_code(scode)
        except Exception as e:
            print("  Error: invalid sender code.")
            print(f"  A relay code is {RELAY_CODE_WORDS} words. Make sure you copied the whole SEND CODE.")
            if str(e).startswith("Unknown word"):
                print(f"  {e} (check the spelling)")
            sock.close()
            sys.exit(1)
        salt = _relay_salt(secret)
        print()
        print("  Relay mode: nothing to send back. You only need the sender's code.")
    else:
        if _nwords == RELAY_CODE_WORDS:
            print("  Error: this is a relay code (the sender used --relay).")
            print("  Both sides must use --relay, or neither. Re-run: python p2p.py recv --relay")
            sock.close()
            sys.exit(1)
        try:
            secret, salt, peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port, code_ipv6 = (
                decode_sender_code(scode)
            )
        except Exception as e:
            print("  Error: invalid sender code.")
            print("  Make sure you copied the entire SEND CODE from the sender's screen.")
            if str(e).startswith("Unknown word"):
                print(f"  {e} (check the spelling)")
            sock.close()
            sys.exit(1)

        if code_ipv6 != USE_IPV6:
            print("  Error: address-family mismatch.")
            if code_ipv6:
                print("  The sender is using IPv6 (-6). Re-run: python p2p.py recv -6")
            else:
                print("  The sender is using IPv4. Both sides must agree on -6 (or neither).")
            sock.close()
            sys.exit(1)

        _vprint(f"  Peer public : {_fmt_addr(peer_pub_ip, peer_pub_port)}")
        _vprint(f"  Peer local  : {_fmt_addr(peer_local_ip, peer_local_port)}")

        # ---- Display RECV CODE --------------------------------------------------
        rcode = encode_recv_code(pub_ip, pub_port, local_ip, local_port, secret)
        print()
        print("  +==========================================================+")
        print("  |  RECV CODE -- give this back to the sender:              |")
        print("  +==========================================================+")
        print()
        print(f"  {rcode}")
        print()

    # ---- Handshake ----------------------------------------------------------
    _vprint("  Deriving handshake keys (PBKDF2, 100k rounds)...")
    handshake_cipher = Cipher(secret, salt, is_sender=False, aes=USE_AES)
    dh_priv, dh_pub  = _dh_keypair()

    relay_sock = None
    if USE_RELAY:
        # Relay mode: no hole punching at all -- both sides meet at the relay.
        print("  Relay mode: connecting through the relay" + (" (sender must also use --relay)." if long_code else "."))
        token = _relay_session_token(secret)
        relay_sock = RelaySocket(RELAY_HOST, token, send_dir="r2s", recv_dir="s2r")
        try:
            peer, peer_dh_pub, peer_caps = punch_hole(
                relay_sock, handshake_cipher,
                RelaySocket.PEER_ADDR, RelaySocket.PEER_ADDR,
                dh_pub, timeout=connect_timeout, caps=_my_caps(),
            )
        except KeyboardInterrupt:
            print("\n  Cancelled during connection.")
            relay_sock.close()
            sock.close()
            sys.exit(0)

        if not peer:
            print("  Could not reach the sender through the relay.")
            print("  Possible causes:")
            print("    - The sender is not running 'send --relay' right now")
            print("    - The send code you used is from a different (old) session")
            print("    - The relay server became unreachable")
            relay_sock.close()
            sock.close()
            sys.exit(1)
    else:
        try:
            peer, peer_dh_pub, peer_caps = punch_hole(
                sock,
                handshake_cipher,
                (peer_pub_ip, peer_pub_port),
                (peer_local_ip, peer_local_port),
                dh_pub,
                timeout=connect_timeout,
                hint=_DIRECT_HINT,
                caps=_my_caps(),
            )
        except KeyboardInterrupt:
            print("\n  Cancelled during connection.")
            sock.close()
            sys.exit(0)

        if not peer:
            print("  Could not reach the sender.")
            print("  Possible causes:")
            print("    - The sender has not yet pasted your recv code")
            print("    - The send code you used is from a different session")
            print("    - One or both sides are behind CG-NAT or symmetric NAT")
            print("  If direct connection keeps failing, run both sides with --relay.")
            sock.close()
            sys.exit(1)

    try:
        dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    except ValueError as e:
        print(f"  Handshake error: {e}")
        if relay_sock:
            relay_sock.close()
        sock.close()
        sys.exit(1)

    if long_code:
        # Long codes learn the peer's AES support from its HELLO; only the
        # HELLOs themselves used the SHA-256 cipher.
        _choose_cipher(bool(_my_caps() & _CAP_AES), bool(peer_caps & _CAP_AES), "sender")
    _vprint("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=False, aes=USE_AES)

    # ---- Receive ------------------------------------------------------------
    xfer_sock = relay_sock if relay_sock else sock
    result = recv_file_reliable(
        xfer_sock, peer, session_cipher, connect_timeout=connect_timeout,
        max_size=max_size, resume_path=resume_path
    )
    if relay_sock:
        relay_sock.close()
    sock.close()

    if result is None:
        sys.exit(1)

    filename, temp_path, _ = result

    # ---- Save to disk -------------------------------------------------------
    save_path = os.path.join(save_dir, filename)

    # If we resumed in-place the file is already at its final destination
    if os.path.abspath(temp_path) == os.path.abspath(save_path):
        print(f"  Saved: {save_path}")
        print("  Done -- file received successfully!")
        return

    if os.path.exists(save_path):
        if resume_path is None:
            # Only delete temp if it's not the user's resume file
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        print(f"  Error: '{save_path}' already exists. Will not overwrite.")
        print(f"  The received data is in: {temp_path}")
        sys.exit(1)

    try:
        shutil.move(temp_path, save_path)
    except OSError as e:
        print(f"  Error saving file to '{save_path}': {e}")
        print(f"  The received data is in: {temp_path}")
        sys.exit(1)

    print(f"  Saved: {save_path}")
    print("  Done -- file received successfully!")


# ===============================================================================
# Entry point
# ===============================================================================


def main():
    global RELAY_HOST
    print(BANNER)

    if len(sys.argv) < 2 or "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print("  Usage:")
        print("    python p2p.py send <file> [-6] [--relay] [--long-code] [--connect-timeout SECONDS] [--verbose]")
        print("    python p2p.py recv        [-6] [--relay] [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]")
        print()
        print("  The sender gets a short code like 4821-apple-river-ocean; the receiver")
        print("  types it in. Both sides meet briefly at the relay to verify the code")
        print("  (SPAKE2) and swap addresses, then the file goes directly peer-to-peer.")
        print()
        print("  -6                 Use IPv6 (both sides must agree). Bypasses NAT")
        print("                     entirely -- works wherever IPv6 is available.")
        print("  --connect-timeout  Seconds to wait during hole-punch and")
        print(f"                     handshake phases (default: {CONNECT_TIMEOUT}).")
        print("  --resume FILE      Resume a dropped transfer. Point to the partial")
        print("                     file from a previous recv. The script will verify")
        print("                     how much was received correctly and resume from there.")
        print("  --verbose          Show technical connection details such as IP")
        print("                     addresses, STUN status, and handshake status.")
        print("  --relay            Send the file itself through the HTTPS relay instead")
        print("                     of direct hole punching. With short codes, one side")
        print("                     using it is enough.")
        print("  --long-code        (send) Use the old long word codes instead: no relay")
        print("                     at all in direct mode, but the receiver has to send")
        print("                     a code back. With --relay: one 13-word code, and")
        print("                     both sides must use --relay.")
        print(f"  --relay-host HOST  Override the relay server (default: {RELAY_HOST}).")
        sys.exit(0)

    # Parse optional flags
    args            = sys.argv[1:]
    connect_timeout = CONNECT_TIMEOUT
    resume_path     = None
    verbose         = False
    use_ipv6        = False
    use_relay       = False
    long_code       = False
    old_no_relay    = False
    filtered        = []
    i = 0
    while i < len(args):
        if args[i] == "--connect-timeout" and i + 1 < len(args):
            try:
                connect_timeout = int(args[i + 1])
                if connect_timeout <= 0:
                    raise ValueError
            except ValueError:
                print("  Error: --connect-timeout must be a positive integer.")
                sys.exit(1)
            i += 2
        elif args[i] == "--resume" and i + 1 < len(args):
            resume_path = args[i + 1]
            i += 2
        elif args[i] == "--verbose":
            verbose = True
            i += 1
        elif args[i] in ("-6", "--ipv6"):
            use_ipv6 = True
            i += 1
        elif args[i] == "--relay":
            use_relay = True
            i += 1
        elif args[i] == "--long-code":
            long_code = True
            i += 1
        elif args[i] == "--no-relay":   # old flag: direct-only is now the default
            old_no_relay = True
            i += 1
        elif args[i] == "--relay-host" and i + 1 < len(args):
            RELAY_HOST = args[i + 1]
            i += 2
        else:
            filtered.append(args[i])
            i += 1
    args = filtered
    global VERBOSE, USE_IPV6
    VERBOSE        = verbose
    USE_IPV6       = use_ipv6
    if use_relay:
        _use_relay_mode()
    if old_no_relay:
        print("  Note: --no-relay is no longer needed; the relay is only used with --relay.")
    if use_relay and old_no_relay:
        print("  Error: --relay and --no-relay cannot be used together.")
        sys.exit(1)

    if not args:
        print("  Use 'send' or 'recv'.  Run with -h for help.")
        sys.exit(1)

    cmd = args[0].lower()

    # Short codes always meet at the relay; a receiver only knows which kind
    # of code it has once it is pasted, so cmd_recv checks that case itself.
    if (USE_RELAY and cmd in ("send", "recv", "receive")) or (cmd == "send" and not long_code):
        if not _relay_reachable():
            print(f"  Error: cannot reach the relay at {RELAY_HOST}.")
            print("  Check your internet connection, or point at another relay with --relay-host.")
            if not USE_RELAY:
                print("  Or use --long-code for a direct transfer that never contacts the relay.")
            sys.exit(1)

    try:
        if cmd == "send":
            if len(args) < 2:
                print("  Usage: python p2p.py send <file> [-6]")
                sys.exit(1)
            cmd_send(args[1], connect_timeout=connect_timeout, long_code=long_code)

        elif cmd in ("recv", "receive"):
            cmd_recv(connect_timeout=connect_timeout, resume_path=resume_path)

        else:
            print(f"  Unknown command: {cmd!r}")
            print("  Use 'send' or 'recv'.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n  Interrupted.")
        sys.exit(0)

    except SystemExit:
        raise   # let sys.exit() pass through cleanly

    except Exception as e:
        # Something truly unexpected slipped past all the specific handlers.
        # Write the full traceback to a log file so it can be reported,
        # but show a clean one-liner to the user.
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "p2p_error.log")
        try:
            with open(log_path, "w") as lf:
                traceback.print_exc(file=lf)
            print(f"\n  Unexpected error: {e}")
            print(f"  Full details saved to: {log_path}")
            print("  Please share that file if you report this issue.")
        except Exception:
            # Even writing the log failed -- just show the error inline.
            print(f"\n  Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()