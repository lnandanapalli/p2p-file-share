#!/usr/bin/env python3
"""
p2p.py  --  Zero-dependency encrypted file transfer over UDP hole punching.

Like Magic Wormhole, but needs nothing beyond the Python standard library.
Works behind most NATs (full-cone, address-restricted, port-restricted).
Symmetric NATs may fail without a relay -- that's a hard networking limit.

Usage:
    python p2p.py send <file> [--connect-timeout SECONDS] [--verbose]
    python p2p.py recv        [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]

  --connect-timeout controls how long (in seconds) both sides will wait
  during the hole-punch and initial handshake phases.  Default is 3600s
  (1 hour) so users have plenty of time to exchange codes out-of-band.
  The transfer itself has no time limit -- only packet-loss retries apply.
  --verbose shows technical connection details such as IP addresses and
  handshake/STUN status.

Flow:
    1. Sender runs 'send', gets a SEND CODE.
    2. Sender shares the code out-of-band (chat, email, etc.).
    3. Receiver runs 'recv', pastes the send code, gets a RECV CODE.
    4. Receiver shares the recv code back to the sender.
    5. Sender pastes the recv code.
    6. Both sides punch through NAT.
    7. Receiver sees file name and size, then accepts or declines.
    8. If accepted, the encrypted transfer begins.

Crypto:
    - 128-bit random secret (embedded in the send code)
    - PBKDF2-HMAC-SHA256 key derivation (random salt) -> separate keys per direction
    - Ephemeral Diffie-Hellman (RFC 3526 Group 14) for forward secrecy
    - SHA-256 in CTR mode as a stream cipher (XOR keystream)
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
ACK_TIMEOUT = 0.5   # seconds before retransmitting a packet
MAX_RETRIES = 200   # per-packet retransmit limit
CONNECT_TIMEOUT = 3600   # seconds for all connection-phase waits
PUNCH_INTERVAL = 0.25    # seconds between HELLO salvos
DONE_TIMEOUT = 60        # seconds for DONE/DONEACK at end of transfer
STALL_TIMEOUT = 120      # seconds without progress before declaring transfer dead
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024 * 1024   # 1 TB receive limit
RESUME_CHUNKS_PER_BIN = 18000   # ~25 MB per binary-search bin (resume negotiation)

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

VERBOSE = False


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


# ===============================================================================
# STUN Client  (RFC 5389 -- minimal Binding Request)
# ===============================================================================

_STUN_MAGIC = 0x2112A442


def _stun_transact(sock, server):
    """Send a STUN Binding Request and parse the response."""
    txn_id = secrets.token_bytes(12)
    req = struct.pack("!HHI", 0x0001, 0, _STUN_MAGIC) + txn_id
    try:
        sock.sendto(req, server)
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

        if atype == 0x0020 and alen >= 8:   # XOR-MAPPED-ADDRESS
            if aval[1] == 0x01:             # IPv4
                xport = struct.unpack("!H", aval[2:4])[0] ^ (_STUN_MAGIC >> 16)
                xip   = struct.unpack("!I", aval[4:8])[0] ^ _STUN_MAGIC
                return socket.inet_ntoa(struct.pack("!I", xip)), xport

        elif atype == 0x0001 and alen >= 8:  # MAPPED-ADDRESS (fallback)
            if aval[1] == 0x01:
                port = struct.unpack("!H", aval[2:4])[0]
                ip   = socket.inet_ntoa(aval[4:8])
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
    """Best-effort LAN IP (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ===============================================================================
# Encryption -- SHA-256 CTR stream cipher + HMAC-SHA-256 per packet
# ===============================================================================


class Cipher:
    """
    Symmetric authenticated encryption using only hashlib + hmac.

    Key derivation : PBKDF2-HMAC-SHA256 (100 000 rounds) -> 128 bytes
                     split into sender->receiver and receiver->sender key pairs.
    Encryption     : SHA-256 in counter mode (XOR keystream).
    Authentication : HMAC-SHA-256 truncated to 128 bits per packet.

    Each direction gets its own (enc_key, mac_key) so both sides can use
    an independent monotonic counter as nonce without collision.
    """

    def __init__(self, secret: bytes, salt: bytes, is_sender: bool):
        km = hashlib.pbkdf2_hmac("sha256", secret, salt, 100_000, dklen=128)
        s2r_enc, s2r_mac = km[:32],   km[32:64]
        r2s_enc, r2s_mac = km[64:96], km[96:128]

        if is_sender:
            self._ek, self._mk  = s2r_enc, s2r_mac
            self._dk, self._dmk = r2s_enc, r2s_mac
        else:
            self._ek, self._mk  = r2s_enc, r2s_mac
            self._dk, self._dmk = s2r_enc, s2r_mac

        self._ctr = 0
        self._max_nonce = -1
        self._nonce_window = set()
        self._NONCE_WINDOW = 65536

    @staticmethod
    def _keystream(key, nonce, length):
        out = bytearray()
        blk = 0
        while len(out) < length:
            out += hashlib.sha256(key + nonce + struct.pack(">Q", blk)).digest()
            blk += 1
        return bytes(out[:length])

    @staticmethod
    def _xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, ptype: int, plaintext: bytes) -> bytes:
        nonce = struct.pack(">Q", self._ctr)
        self._ctr += 1
        ct     = self._xor(plaintext, self._keystream(self._ek, nonce, len(plaintext)))
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
            new_floor = max(self._max_nonce - self._NONCE_WINDOW + 1, 0)
            self._nonce_window = {n for n in self._nonce_window if n >= new_floor}
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
    data = (
        secret
        + salt
        + socket.inet_aton(pub_ip)
        + struct.pack("!H", pub_port)
        + socket.inet_aton(local_ip)
        + struct.pack("!H", local_port)
    )
    return _bytes_to_words(data)


def decode_sender_code(code):
    data       = _words_to_bytes(code, 44)
    secret     = data[:16]
    salt       = data[16:32]
    pub_ip     = socket.inet_ntoa(data[32:36])
    pub_port   = struct.unpack("!H", data[36:38])[0]
    local_ip   = socket.inet_ntoa(data[38:42])
    local_port = struct.unpack("!H", data[42:44])[0]
    return secret, salt, pub_ip, pub_port, local_ip, local_port


def encode_recv_code(pub_ip, pub_port, local_ip, local_port, secret):
    raw = (
        socket.inet_aton(pub_ip)
        + struct.pack("!H", pub_port)
        + socket.inet_aton(local_ip)
        + struct.pack("!H", local_port)
    )
    tag = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
    return _bytes_to_words(raw + tag)


def decode_recv_code(code, secret):
    data     = _words_to_bytes(code, 28)
    raw, tag = data[:12], data[12:28]
    expected = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
    if not _hmac.compare_digest(tag, expected):
        return None
    pub_ip     = socket.inet_ntoa(raw[0:4])
    pub_port   = struct.unpack("!H", raw[4:6])[0]
    local_ip   = socket.inet_ntoa(raw[6:10])
    local_port = struct.unpack("!H", raw[10:12])[0]
    return pub_ip, pub_port, local_ip, local_port


# ===============================================================================
# UDP Hole Punching
# ===============================================================================


def punch_hole(sock, cipher, pub_addr, local_addr, dh_pub_bytes,
               timeout=CONNECT_TIMEOUT):
    """
    Simultaneously send encrypted HELLOs (carrying our DH public key) to
    the peer's public and local endpoints until one replies with theirs.
    Returns (peer_addr, peer_dh_pub_bytes) or (None, None).

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
    targets = set()
    targets.add(pub_addr)
    if local_addr and local_addr != pub_addr:
        targets.add(local_addr)

    # Flush stale packets before we start listening.
    _drain_socket(sock)

    hello_payload = b"DH1:" + dh_pub_bytes
    hello_pkt     = cipher.encrypt(T_HELLO, hello_payload)
    start         = time.time()

    status = "Punching through NAT..." if VERBOSE else "Connecting..."
    sys.stdout.write(f"  {status}")
    sys.stdout.flush()

    while time.time() - start < timeout:
        # Send a salvo to every target
        for t in targets:
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
                data, addr = sock.recvfrom(RECV_BUF)
            except OSError:
                continue

            # ---- addr filter (the core bug-fix) --------------------------------
            # Only accept HELLOs from the address embedded in the recv/send code.
            # Packets from any other source are silently dropped.  This stops a
            # stale HELLO from a previously cancelled receiver from being
            # accepted as the "connection", which would make the sender target
            # a now-closed port and crash with WinError 10054 on the next recv.
            if addr not in targets:
                continue
            # --------------------------------------------------------------------

            ptype, payload = cipher.decrypt(data)
            if ptype == T_HELLO and payload and payload[:4] == b"DH1:":
                peer_dh_pub = payload[4:]
                if len(peer_dh_pub) != _DH_KEY_BYTES:
                    continue   # malformed -- ignore
                # Confirm the path with a few extra HELLOs
                for _ in range(5):
                    try:
                        sock.sendto(hello_pkt, addr)
                    except OSError:
                        pass
                    time.sleep(0.05)
                if VERBOSE:
                    print(f"\n  Connected to {addr[0]}:{addr[1]}")
                else:
                    print("\n  Connected.")
                return addr, peer_dh_pub
            # Any other packet type here (e.g. T_META from a racing sender)
            # is silently ignored; punch_hole only cares about HELLOs.

        elapsed = int(time.time() - start)
        if elapsed >= 60:
            sys.stdout.write(f"\r  {status} {elapsed // 60}m {elapsed % 60}s  ")
        else:
            sys.stdout.write(f"\r  {status} {elapsed}s  ")
        sys.stdout.flush()

    if VERBOSE:
        print("\n  Hole punch timed out.")
    else:
        print("\n  Connection timed out.")
    return None, None


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
        {"name": os.path.basename(filepath), "size": filesize, "hash": filehash}
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
                    # Receiver is asking for SHA-256 of the partial file
                    try:
                        n_chunks = struct.unpack(">Q", pl[:8])[0]
                        hval = _prefix_sha256_chunks(filepath, n_chunks)
                        response_data = struct.pack(">Q", n_chunks) + hval
                        response = cipher.encrypt(T_HASHR, response_data)
                        sock.sendto(response, peer)
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
                        sock, addr, cipher, resume_path, partial_chunks
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
    print(f"  Partial file saved: {working_path}")
    print(f"  To resume:          python p2p.py recv --resume \"{working_path}\"")


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
    Verify that the partial file matches the sender's file by comparing SHA-256.
    
    Returns the number of verified-good chunks, or 0 if nothing matches.
    """
    print("  Verifying partial file with SHA-256...")
    
    def _query(num_chunks):
        req = struct.pack(">Q", num_chunks)
        for _ in range(20):
            try:
                sock.sendto(cipher.encrypt(T_HASHQ, req), peer)
            except OSError:
                pass
            try:
                rdy = select.select([sock], [], [], 1.0)
            except OSError:
                continue
            if not rdy[0]:
                continue
            try:
                raw, addr = sock.recvfrom(RECV_BUF)
            except OSError:
                continue
            if addr != peer:
                continue
            try:
                ptype, pl = cipher.decrypt(raw)
            except Exception:
                continue
            if ptype == T_HASHR and pl and len(pl) >= 40:
                resp_n = struct.unpack(">Q", pl[:8])[0]
                if resp_n == num_chunks:
                    return pl[8:]
        return None

    # Verify the partial file by SHA-256
    confirmed_chunks = partial_chunks

    sender_sha = _query(confirmed_chunks)
    if sender_sha is None:
        print("  ✗ SHA-256 verification failed - no response from sender.")
        return 0

    recv_sha = _prefix_sha256_chunks(partial_path, confirmed_chunks)

    if _hmac.compare_digest(sender_sha[:32], recv_sha):
        print(f"  ✓ SHA-256 verified. Resuming from {_fmt(confirmed_chunks * CHUNK_SIZE)}.")
        return confirmed_chunks
    else:
        print("  ✗ SHA-256 mismatch - partial file does not match this transfer.")
        return 0


# ===============================================================================
# CLI Commands
# ===============================================================================

BANNER = r"""
  +-----------------------------------------+
  |   p2p.py -- encrypted hole-punch xfer   |
  |   no dependencies . no relay server     |
  +-----------------------------------------+
"""


def cmd_send(filepath, connect_timeout=CONNECT_TIMEOUT):
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
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 0))
    except OSError as e:
        print(f"  Error: cannot create UDP socket: {e}")
        sys.exit(1)

    local_port = sock.getsockname()[1]
    local_ip   = get_local_ip()

    # ---- STUN ---------------------------------------------------------------
    _vprint("  Discovering public endpoint via STUN...")
    pub = stun_discover(sock)
    if pub:
        pub_ip, pub_port = pub
        try:
            socket.inet_aton(pub_ip)   # guard: only IPv4 is supported in codes
            _vprint(f"  Public : {pub_ip}:{pub_port}")
        except OSError:
            pub_ip, pub_port = local_ip, local_port
            _vprint("  STUN returned a non-IPv4 address -- using local address.")
    else:
        pub_ip, pub_port = local_ip, local_port
        _vprint("  STUN failed -- using local address (LAN-only transfer).")
    _vprint(f"  Local  : {local_ip}:{local_port}")
    secret = secrets.token_bytes(16)
    salt   = secrets.token_bytes(16)
    code   = encode_sender_code(secret, salt, pub_ip, pub_port, local_ip, local_port)

    print()
    print("  +==========================================================+")
    print("  |  SEND CODE -- give this to the receiver:                 |")
    print("  +==========================================================+")
    print()
    print(f"  {code}")
    print()

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

    result = decode_recv_code(rcode, secret)
    if result is None:
        print("  Error: invalid receiver code.")
        print("  Make sure you copied the entire RECV CODE from the receiver's screen,")
        print("  and that the receiver used the SEND CODE you gave them (not an old one).")
        sock.close()
        sys.exit(1)

    peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port = result
    _vprint(f"  Peer public : {peer_pub_ip}:{peer_pub_port}")
    _vprint(f"  Peer local  : {peer_local_ip}:{peer_local_port}")

    # ---- Handshake ----------------------------------------------------------
    _vprint("  Deriving handshake keys (PBKDF2, 100k rounds)...")
    handshake_cipher = Cipher(secret, salt, is_sender=True)
    dh_priv, dh_pub  = _dh_keypair()

    try:
        peer, peer_dh_pub = punch_hole(
            sock,
            handshake_cipher,
            (peer_pub_ip, peer_pub_port),
            (peer_local_ip, peer_local_port),
            dh_pub,
            timeout=connect_timeout,
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
        if VERBOSE:
            print("    - Both sides are behind symmetric NAT (needs a relay server)")
        else:
            print("    - One of the networks is blocking direct peer-to-peer connections")
        sock.close()
        sys.exit(1)

    try:
        dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    except ValueError as e:
        print(f"  Handshake error: {e}")
        sock.close()
        sys.exit(1)

    _vprint("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=True)

    # ---- Transfer -----------------------------------------------------------
    ok = send_file_reliable(
        sock, peer, session_cipher, filepath, filesize, filehash,
        connect_timeout=connect_timeout,
    )
    sock.close()

    if ok:
        print("  Done -- file sent successfully!")
    else:
        sys.exit(1)


def cmd_recv(connect_timeout=CONNECT_TIMEOUT, max_size=MAX_FILE_SIZE, resume_path=None):
    save_dir = "."

    # ---- Bind ---------------------------------------------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 0))
    except OSError as e:
        print(f"  Error: cannot create UDP socket: {e}")
        sys.exit(1)

    local_port = sock.getsockname()[1]
    local_ip   = get_local_ip()

    # ---- STUN ---------------------------------------------------------------
    _vprint("  Discovering public endpoint via STUN...")
    pub = stun_discover(sock)
    if pub:
        pub_ip, pub_port = pub
        try:
            socket.inet_aton(pub_ip)   # guard: only IPv4 is supported in codes
            _vprint(f"  Public : {pub_ip}:{pub_port}")
        except OSError:
            pub_ip, pub_port = local_ip, local_port
            _vprint("  STUN returned a non-IPv4 address -- using local address.")
    else:
        pub_ip, pub_port = local_ip, local_port
        _vprint("  STUN failed -- using local address (LAN-only transfer).")
    _vprint(f"  Local  : {local_ip}:{local_port}")

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
        secret, salt, peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port = (
            decode_sender_code(scode)
        )
    except Exception:
        print("  Error: invalid sender code.")
        print("  Make sure you copied the entire SEND CODE from the sender's screen.")
        sock.close()
        sys.exit(1)

    _vprint(f"  Peer public : {peer_pub_ip}:{peer_pub_port}")
    _vprint(f"  Peer local  : {peer_local_ip}:{peer_local_port}")

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
    handshake_cipher = Cipher(secret, salt, is_sender=False)
    dh_priv, dh_pub  = _dh_keypair()

    try:
        peer, peer_dh_pub = punch_hole(
            sock,
            handshake_cipher,
            (peer_pub_ip, peer_pub_port),
            (peer_local_ip, peer_local_port),
            dh_pub,
            timeout=connect_timeout,
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
        if VERBOSE:
            print("    - Both sides are behind symmetric NAT (needs a relay server)")
        else:
            print("    - One of the networks is blocking direct peer-to-peer connections")
        sock.close()
        sys.exit(1)

    try:
        dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    except ValueError as e:
        print(f"  Handshake error: {e}")
        sock.close()
        sys.exit(1)

    _vprint("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=False)

    # ---- Receive ------------------------------------------------------------
    result = recv_file_reliable(
        sock, peer, session_cipher, connect_timeout=connect_timeout,
        max_size=max_size, resume_path=resume_path
    )
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
    print(BANNER)

    if len(sys.argv) < 2 or "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print("  Usage:")
        print("    python p2p.py send <file> [--connect-timeout SECONDS] [--verbose]")
        print("    python p2p.py recv        [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]")
        print()
        print("  --connect-timeout  Seconds to wait during hole-punch and")
        print(f"                     handshake phases (default: {CONNECT_TIMEOUT}).")
        print("  --resume FILE      Resume a dropped transfer. Point to the partial")
        print("                     file from a previous recv. The script will verify")
        print("                     how much was received correctly and resume from there.")
        print("  --verbose          Show technical connection details such as IP")
        print("                     addresses, STUN status, and handshake status.")
        sys.exit(0)

    # Parse optional flags
    args            = sys.argv[1:]
    connect_timeout = CONNECT_TIMEOUT
    resume_path     = None
    verbose         = False
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
        else:
            filtered.append(args[i])
            i += 1
    args = filtered
    global VERBOSE
    VERBOSE = verbose

    if not args:
        print("  Use 'send' or 'recv'.  Run with -h for help.")
        sys.exit(1)

    cmd = args[0].lower()

    try:
        if cmd == "send":
            if len(args) < 2:
                print("  Usage: python p2p.py send <file>")
                sys.exit(1)
            cmd_send(args[1], connect_timeout=connect_timeout)

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
