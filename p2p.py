#!/usr/bin/env python3
"""
p2p.py  --  Zero-dependency encrypted file transfer over UDP hole punching.

Like Magic Wormhole, but needs nothing beyond the Python standard library.
Works behind most NATs (full-cone, address-restricted, port-restricted).
Symmetric NATs may fail without a relay -- that's a hard networking limit.

Usage:
    python p2p.py send <file> [--connect-timeout SECONDS]
    python p2p.py recv        [--connect-timeout SECONDS]

  --connect-timeout controls how long (in seconds) both sides will wait
  during the hole-punch and initial handshake phases.  Default is 3600s
  (1 hour) so users have plenty of time to exchange codes out-of-band.
  The transfer itself has no time limit -- only packet-loss retries apply.

Flow:
    1. Sender runs 'send', gets a SEND CODE.
    2. Sender shares the code out-of-band (chat, email, etc.).
    3. Receiver runs 'recv', pastes the send code, gets a RECV CODE.
    4. Receiver shares the recv code back to the sender.
    5. Sender pastes the recv code.
    6. Both sides punch through NAT and transfer the file, encrypted.

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

CHUNK_SIZE = 1400  # bytes per DATA packet payload (fits typical MTU)
WINDOW_SIZE = 32  # max unACKed in-flight packets
ACK_TIMEOUT = 0.5  # seconds before retransmitting a packet
MAX_RETRIES = 200  # per-packet retransmit limit
CONNECT_TIMEOUT = 3600  # seconds for all connection-phase waits:
                        #   hole-punch, META send/ACK (both sides)
                        #   overridable via --connect-timeout
PUNCH_INTERVAL = 0.25  # seconds between HELLO salvos
DONE_TIMEOUT = 60       # seconds for DONE/DONEACK at end of transfer
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4 GB receive limit

# Packet types
T_HELLO = 1
T_META = 2
T_DATA = 3
T_ACK = 4
T_DONE = 5
T_DONEACK = 6

# Receive buffer (UDP max)
RECV_BUF = 65536


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

    ready = select.select([sock], [], [], 2.0)
    if not ready[0]:
        return None

    try:
        data, _ = sock.recvfrom(1024)
    except OSError:
        return None

    if len(data) < 20:
        return None
    msg_type, msg_len = struct.unpack("!HH", data[:4])
    if msg_type != 0x0101:  # not Binding Success
        return None
    if data[8:20] != txn_id:  # transaction ID mismatch -- possible spoof
        return None

    pos = 20
    while pos + 4 <= 20 + msg_len and pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos : pos + 4])
        aval = data[pos + 4 : pos + 4 + alen]
        if len(aval) < alen:
            break

        if atype == 0x0020 and alen >= 8:  # XOR-MAPPED-ADDRESS
            if aval[1] == 0x01:  # IPv4
                xport = struct.unpack("!H", aval[2:4])[0] ^ (_STUN_MAGIC >> 16)
                xip = struct.unpack("!I", aval[4:8])[0] ^ _STUN_MAGIC
                return socket.inet_ntoa(struct.pack("!I", xip)), xport

        elif atype == 0x0001 and alen >= 8:  # MAPPED-ADDRESS (fallback)
            if aval[1] == 0x01:
                port = struct.unpack("!H", aval[2:4])[0]
                ip = socket.inet_ntoa(aval[4:8])
                return ip, port

        pos += 4 + alen + ((4 - alen % 4) % 4)  # STUN attr padding
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
        km = hashlib.pbkdf2_hmac(
            "sha256", secret, salt, 100_000, dklen=128
        )
        # First 64 bytes  -> sender-to-receiver keys
        # Second 64 bytes -> receiver-to-sender keys
        s2r_enc, s2r_mac = km[:32], km[32:64]
        r2s_enc, r2s_mac = km[64:96], km[96:128]

        if is_sender:
            self._ek, self._mk = s2r_enc, s2r_mac
            self._dk, self._dmk = r2s_enc, r2s_mac
        else:
            self._ek, self._mk = r2s_enc, r2s_mac
            self._dk, self._dmk = s2r_enc, s2r_mac

        self._ctr = 0  # send counter (nonce)
        # Replay protection: sliding window over received nonce counters.
        # We track the highest nonce seen (_max_nonce) and a set of seen
        # nonces within a window below it.  Anything below the window
        # floor is implicitly "seen" (rejected).
        self._max_nonce = -1
        self._nonce_window = set()  # nonces in [_max_nonce - _NONCE_WINDOW + 1, _max_nonce]
        self._NONCE_WINDOW = 65536  # must be >= WINDOW_SIZE * MAX_RETRIES to tolerate reordering

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _keystream(key, nonce, length):
        """Generate `length` bytes of keystream from SHA-256(key||nonce||ctr)."""
        out = bytearray()
        blk = 0
        while len(out) < length:
            out += hashlib.sha256(
                key + nonce + struct.pack(">Q", blk)
            ).digest()
            blk += 1
        return bytes(out[:length])

    @staticmethod
    def _xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    # -- public API --------------------------------------------------------

    def encrypt(self, ptype: int, plaintext: bytes) -> bytes:
        """Encrypt & authenticate.  Returns wire-ready packet bytes."""
        nonce = struct.pack(">Q", self._ctr)
        self._ctr += 1
        ct = self._xor(plaintext, self._keystream(self._ek, nonce, len(plaintext)))
        header = struct.pack("B", ptype) + nonce  # 9 bytes
        mac = _hmac.new(self._mk, header + ct, hashlib.sha256).digest()[:16]
        return header + ct + mac

    def decrypt(self, raw: bytes):
        """Decrypt & verify.  Returns (ptype, plaintext) or (None, None)."""
        if len(raw) < 9 + 16:  # header + mac minimum
            return None, None
        ptype = raw[0]
        nonce = raw[1:9]
        ct = raw[9:-16]
        mac = raw[-16:]
        header = raw[:9]
        expected = _hmac.new(self._dmk, header + ct, hashlib.sha256).digest()[:16]
        if not _hmac.compare_digest(mac, expected):
            return None, None
        # Replay protection -- sliding window over nonce counter values
        nonce_val = struct.unpack(">Q", nonce)[0]
        window_floor = max(self._max_nonce - self._NONCE_WINDOW + 1, 0)
        if nonce_val < window_floor:
            return None, None  # too old -- implicitly rejected
        if nonce_val in self._nonce_window:
            return None, None  # already seen within window
        # Accept -- update window
        self._nonce_window.add(nonce_val)
        if nonce_val > self._max_nonce:
            self._max_nonce = nonce_val
            # Prune entries that fell below the new window floor
            new_floor = max(self._max_nonce - self._NONCE_WINDOW + 1, 0)
            self._nonce_window = {
                n for n in self._nonce_window if n >= new_floor
            }
        pt = self._xor(ct, self._keystream(self._dk, nonce, len(ct)))
        return ptype, pt


# ===============================================================================
# Diffie-Hellman Forward Secrecy  (RFC 3526 Group 14, 2048-bit MODP)
# ===============================================================================

# RFC 3526 Group 14 -- well-known 2048-bit safe prime
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
    """Generate an ephemeral DH keypair.  Returns (private_int, public_bytes)."""
    private = int.from_bytes(secrets.token_bytes(32), "big")  # 256-bit exponent
    public = pow(_DH_G, private, _DH_P)
    return private, public.to_bytes(_DH_KEY_BYTES, "big")


def _dh_shared_secret(private_int, peer_pub_bytes):
    """Compute DH shared secret -> 32 bytes (SHA-256 of raw shared value)."""
    peer_pub = int.from_bytes(peer_pub_bytes, "big")
    # Reject degenerate public keys (must be in [2, p-2])
    if peer_pub < 2 or peer_pub >= _DH_P - 1:
        raise ValueError("Invalid DH public key")
    raw_shared = pow(peer_pub, private_int, _DH_P)
    return hashlib.sha256(raw_shared.to_bytes(_DH_KEY_BYTES, "big")).digest()


# ===============================================================================
# Code Encoding  (out-of-band strings the users copy-paste)
#
# Human-memorable word codes using a subset of the BIP39 English wordlist
# (1024 words, 10 bits per word).  All data is binary-packed then encoded
# as words.
#
#   SEND code : secret(16) + salt(16) + pub_ip(4) + pub_port(2)
#               + local_ip(4) + local_port(2) = 44 bytes = 352 bits
#               -> ceil(352/10) = 36 words
#
#   RECV code : pub_ip(4) + pub_port(2) + local_ip(4) + local_port(2)
#               + hmac(16) = 28 bytes = 224 bits -> ceil(224/10) = 23 words
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

_WORDLIST = _WORDLIST[:1024]   # 1024 words -> 10 bits per word
_WORD_INDEX = {w: i for i, w in enumerate(_WORDLIST)}

_BITS_PER_WORD = 10  # log2(1024)


def _bytes_to_words(data: bytes) -> str:
    """Encode bytes as a space-separated sequence of common English words."""
    bits = len(data) * 8
    n_words = math.ceil(bits / _BITS_PER_WORD)
    n = int.from_bytes(data, "big")
    n <<= (n_words * _BITS_PER_WORD - bits)
    words = []
    mask = (1 << _BITS_PER_WORD) - 1
    for _ in range(n_words):
        words.append(_WORDLIST[n & mask])
        n >>= _BITS_PER_WORD
    return " ".join(reversed(words))


def _words_to_bytes(phrase: str, expected_bytes: int) -> bytes:
    """Decode a word phrase back to bytes."""
    words = phrase.strip().lower().split()
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
    # 16 + 16 + 4 + 2 + 4 + 2 = 44 bytes -> 36 words
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
    data = _words_to_bytes(code, 44)
    secret = data[:16]
    salt = data[16:32]
    pub_ip = socket.inet_ntoa(data[32:36])
    pub_port = struct.unpack("!H", data[36:38])[0]
    local_ip = socket.inet_ntoa(data[38:42])
    local_port = struct.unpack("!H", data[42:44])[0]
    return secret, salt, pub_ip, pub_port, local_ip, local_port


def encode_recv_code(pub_ip, pub_port, local_ip, local_port, secret):
    # 4 + 2 + 4 + 2 = 12 bytes of address data
    raw = (
        socket.inet_aton(pub_ip)
        + struct.pack("!H", pub_port)
        + socket.inet_aton(local_ip)
        + struct.pack("!H", local_port)
    )
    tag = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
    # 12 + 16 = 28 bytes -> 23 words
    return _bytes_to_words(raw + tag)


def decode_recv_code(code, secret):
    data = _words_to_bytes(code, 28)
    raw, tag = data[:12], data[12:28]
    expected = _hmac.new(secret, raw, hashlib.sha256).digest()[:16]
    if not _hmac.compare_digest(tag, expected):
        return None
    pub_ip = socket.inet_ntoa(raw[0:4])
    pub_port = struct.unpack("!H", raw[4:6])[0]
    local_ip = socket.inet_ntoa(raw[6:10])
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
    """
    targets = set()
    targets.add(pub_addr)
    if local_addr and local_addr != pub_addr:
        targets.add(local_addr)

    hello_payload = b"DH1:" + dh_pub_bytes  # 4 + 256 = 260 bytes
    hello_pkt = cipher.encrypt(T_HELLO, hello_payload)
    start = time.time()

    sys.stdout.write("  Punching through NAT...")
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
            ready = select.select([sock], [], [], min(wait, 0.05))
            if not ready[0]:
                continue
            try:
                data, addr = sock.recvfrom(RECV_BUF)
                ptype, payload = cipher.decrypt(data)
                if ptype == T_HELLO and payload and payload[:4] == b"DH1:":
                    peer_dh_pub = payload[4:]
                    if len(peer_dh_pub) != _DH_KEY_BYTES:
                        continue  # malformed -- ignore
                    # Confirm the path with a few extra HELLOs
                    for _ in range(5):
                        try:
                            sock.sendto(hello_pkt, addr)
                        except OSError:
                            pass
                        time.sleep(0.05)
                    print(f"\n  Connected to {addr[0]}:{addr[1]}")
                    return addr, peer_dh_pub
            except OSError:
                pass

        elapsed = int(time.time() - start)
        if elapsed >= 60:
            sys.stdout.write(f"\r  Punching through NAT... {elapsed // 60}m {elapsed % 60}s  ")
        else:
            sys.stdout.write(f"\r  Punching through NAT... {elapsed}s  ")
        sys.stdout.flush()

    print("\n  Hole punch timed out.")
    return None, None


# ===============================================================================
# Reliable Transfer  (selective-repeat ARQ over UDP)
# ===============================================================================


def _send_data_pkt(sock, peer, cipher, seq, chunk):
    payload = struct.pack(">I", seq) + chunk
    sock.sendto(cipher.encrypt(T_DATA, payload), peer)


def send_file_reliable(sock, peer, cipher, filepath, filesize, filehash,
                       connect_timeout=CONNECT_TIMEOUT):
    """Read file in chunks and send with windowed retransmission."""
    total_chunks = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

    # -- send META until ACKed (time-based deadline, not a loop count) --
    meta = json.dumps(
        {"name": os.path.basename(filepath), "size": filesize, "hash": filehash}
    ).encode()
    meta_acked = False
    meta_start = time.time()
    meta_deadline = meta_start + connect_timeout
    last_print = 0.0
    while time.time() < meta_deadline:
        sock.sendto(cipher.encrypt(T_META, meta), peer)
        ready = select.select([sock], [], [], 0.5)
        if ready[0]:
            raw, _ = sock.recvfrom(RECV_BUF)
            ptype, pl = cipher.decrypt(raw)
            if ptype == T_ACK:
                meta_acked = True
                break
        elapsed = time.time() - meta_start
        if elapsed - last_print >= 30:
            last_print = elapsed
            sys.stdout.write(
                f"\r  Waiting for receiver... {int(elapsed)}s  "
            )
            sys.stdout.flush()
    if not meta_acked:
        print("\n  Failed to deliver file metadata -- receiver never responded.")
        return False

    if total_chunks == 0:
        # empty file -- just send DONE
        for _ in range(10):
            sock.sendto(cipher.encrypt(T_DONE, b"DONE"), peer)
            time.sleep(0.05)
        return True

    print(f"  Sending {total_chunks} chunks ({_fmt(filesize)})")

    # -- chunked send --
    fh = open(filepath, "rb")
    chunk_cache = {}
    acked = set()
    sent_time = {}
    retries = {}
    next_seq = 0

    def _get_chunk(seq):
        if seq not in chunk_cache:
            fh.seek(seq * CHUNK_SIZE)
            chunk_cache[seq] = fh.read(CHUNK_SIZE)
        return chunk_cache[seq]

    try:
        while len(acked) < total_chunks:
            now = time.time()

            # Fill the send window
            while (
                next_seq < total_chunks
                and (next_seq - len(acked)) < WINDOW_SIZE
            ):
                _send_data_pkt(sock, peer, cipher, next_seq, _get_chunk(next_seq))
                sent_time[next_seq] = now
                retries.setdefault(next_seq, 0)
                next_seq += 1

            # Retransmit timed-out packets
            for seq in list(sent_time):
                if seq in acked:
                    continue
                if now - sent_time[seq] > ACK_TIMEOUT:
                    retries[seq] += 1
                    if retries[seq] > MAX_RETRIES:
                        print(f"\n  ERROR: chunk {seq} exceeded {MAX_RETRIES} retries")
                        return False
                    _send_data_pkt(sock, peer, cipher, seq, _get_chunk(seq))
                    sent_time[seq] = now

            # Drain ACKs
            while True:
                ready = select.select([sock], [], [], 0.01)
                if not ready[0]:
                    break
                try:
                    raw, _ = sock.recvfrom(RECV_BUF)
                    ptype, pl = cipher.decrypt(raw)
                    if ptype == T_ACK and pl and len(pl) >= 4:
                        ack_seq = struct.unpack(">I", pl[:4])[0]
                        if ack_seq != 0xFFFFFFFF:
                            acked.add(ack_seq)
                            # Free cache for acked chunks to save memory
                            chunk_cache.pop(ack_seq, None)
                except OSError:
                    pass

            # Progress
            pct = len(acked) * 100 // total_chunks
            done_bytes = min(len(acked) * CHUNK_SIZE, filesize)
            sys.stdout.write(
                f"\r  Progress: {pct:3d}%  ({_fmt(done_bytes)} / {_fmt(filesize)})"
            )
            sys.stdout.flush()

    finally:
        fh.close()

    # -- send DONE (time-based deadline) --
    done_pkt = cipher.encrypt(T_DONE, b"DONE")
    done_deadline = time.time() + DONE_TIMEOUT
    while time.time() < done_deadline:
        sock.sendto(done_pkt, peer)
        ready = select.select([sock], [], [], 0.5)
        if ready[0]:
            raw, _ = sock.recvfrom(RECV_BUF)
            ptype, _ = cipher.decrypt(raw)
            if ptype == T_DONEACK:
                break

    print(f"\r  Progress: 100%  ({_fmt(filesize)} / {_fmt(filesize)})")
    return True


def recv_file_reliable(sock, peer, cipher, connect_timeout=CONNECT_TIMEOUT):
    """Receive a file, streaming chunks to a temp file.
    Returns (filename, temp_path, expected_hash) or None."""

    # -- wait for META (time-based deadline) --
    print("  Waiting for file info (sender may still be setting up)...")
    meta = None
    t0 = time.time()
    deadline = t0 + connect_timeout
    last_print = 0.0
    while meta is None:
        if time.time() > deadline:
            print("\n  Timed out waiting for metadata.")
            return None
        elapsed = time.time() - t0
        if elapsed - last_print >= 30:
            last_print = elapsed
            mins, secs = divmod(int(elapsed), 60)
            label = f"{mins}m {secs}s" if mins else f"{secs}s"
            sys.stdout.write(f"\r  Still waiting for sender... {label}  ")
            sys.stdout.flush()
        ready = select.select([sock], [], [], 2.0)
        if not ready[0]:
            continue
        raw, addr = sock.recvfrom(RECV_BUF)
        ptype, payload = cipher.decrypt(raw)
        if ptype == T_HELLO:
            # Late punch reply -- respond and keep waiting
            # (DH key already exchanged; just echo back)
            pass
        elif ptype == T_META and payload:
            meta = json.loads(payload)
            sock.sendto(
                cipher.encrypt(T_ACK, struct.pack(">I", 0xFFFFFFFF)), addr
            )
            peer = addr

    # -- validate metadata types --
    if not isinstance(meta, dict):
        print("  Error: malformed metadata (not a JSON object).")
        return None
    if not isinstance(meta.get("name"), str) or not meta["name"]:
        print("  Error: missing or invalid 'name' in metadata.")
        return None
    if not isinstance(meta.get("size"), int) or meta["size"] < 0:
        print("  Error: missing or invalid 'size' in metadata.")
        return None
    if not isinstance(meta.get("hash"), str) or len(meta["hash"]) != 64:
        print("  Error: missing or invalid 'hash' in metadata.")
        return None

    # -- sanitise filename (#1 -- path traversal) --
    raw_name = meta["name"]
    filename = os.path.basename(raw_name)
    if not filename or filename.startswith("."):
        print(f"  Error: invalid filename received: {raw_name!r}")
        return None

    filesize = meta["size"]
    filehash = meta["hash"]

    # -- enforce file size limit (#8) --
    if filesize > MAX_FILE_SIZE:
        print(f"  Error: file too large ({_fmt(filesize)}). "
              f"Limit is {_fmt(MAX_FILE_SIZE)}.")
        return None

    total_chunks = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

    print(f"  Receiving: {filename}  ({_fmt(filesize)})")

    if total_chunks == 0:
        # Empty file -- create empty temp file
        tmp = tempfile.NamedTemporaryFile(delete=False, dir=".")
        tmp.close()
        return filename, tmp.name, filehash

    # -- receive DATA -- stream to temp file (#7) --
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=".")
    received_seqs = set()
    done = False

    try:
        while len(received_seqs) < total_chunks or not done:
            ready = select.select([sock], [], [], 3.0)
            if not ready[0]:
                if len(received_seqs) >= total_chunks:
                    break  # probably missed DONE, we have everything
                continue
            try:
                raw, addr = sock.recvfrom(RECV_BUF)
            except OSError:
                continue

            ptype, payload = cipher.decrypt(raw)
            if ptype is None:
                continue

            # Only accept packets from the established peer
            if addr != peer:
                continue

            if ptype == T_DATA and payload and len(payload) > 4:
                seq = struct.unpack(">I", payload[:4])[0]
                if seq >= total_chunks:
                    continue  # out-of-range seq -- ignore
                if seq not in received_seqs:
                    chunk = payload[4:]
                    # Write chunk at correct offset in temp file
                    tmp.seek(seq * CHUNK_SIZE)
                    tmp.write(chunk)
                    received_seqs.add(seq)
                # Always ACK (even duplicates)
                sock.sendto(cipher.encrypt(T_ACK, struct.pack(">I", seq)), addr)

                pct = len(received_seqs) * 100 // total_chunks
                got = min(len(received_seqs) * CHUNK_SIZE, filesize)
                sys.stdout.write(
                    f"\r  Progress: {pct:3d}%  ({_fmt(got)} / {_fmt(filesize)})"
                )
                sys.stdout.flush()

            elif ptype == T_DONE:
                sock.sendto(cipher.encrypt(T_DONEACK, b"OK"), addr)
                done = True
                if len(received_seqs) >= total_chunks:
                    break

            elif ptype == T_META:
                # Re-ACK in case sender didn't get our first ACK
                sock.sendto(
                    cipher.encrypt(T_ACK, struct.pack(">I", 0xFFFFFFFF)), addr
                )

        # Truncate to exact file size (last chunk may be short)
        tmp.truncate(filesize)
        tmp.close()

    except Exception:
        tmp.close()
        os.unlink(tmp.name)
        raise

    print(f"\r  Progress: 100%  ({_fmt(filesize)} / {_fmt(filesize)})")

    # -- verify hash --
    sha = hashlib.sha256()
    with open(tmp.name, "rb") as f:
        while True:
            blk = f.read(1 << 20)
            if not blk:
                break
            sha.update(blk)
    actual = sha.hexdigest()

    if actual != filehash:
        print("  ERROR: SHA-256 mismatch -- file is corrupted or tampered!")
        print(f"    expected {filehash}")
        print(f"    got      {actual}")
        os.unlink(tmp.name)
        return None
    else:
        print("  Integrity verified (SHA-256).")

    return filename, tmp.name, filehash


# ===============================================================================
# Utilities
# ===============================================================================


def _fmt(n):
    """Human-readable byte size."""
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


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
    if not os.path.isfile(filepath):
        print(f"  Error: '{filepath}' not found.")
        sys.exit(1)

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    print(f"  File : {filename}")
    print(f"  Size : {_fmt(filesize)}")

    # Hash the file
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            blk = f.read(1 << 20)
            if not blk:
                break
            sha.update(blk)
    filehash = sha.hexdigest()

    # Bind UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    local_port = sock.getsockname()[1]
    local_ip = get_local_ip()

    # STUN discovery
    print("  Discovering public endpoint via STUN...")
    pub = stun_discover(sock)
    if pub:
        pub_ip, pub_port = pub
        print(f"  Public : {pub_ip}:{pub_port}")
    else:
        pub_ip, pub_port = local_ip, local_port
        print(f"  STUN failed -- falling back to local address.")
    print(f"  Local  : {local_ip}:{local_port}")

    # Generate secret, salt & code
    secret = secrets.token_bytes(16)
    salt = secrets.token_bytes(16)
    code = encode_sender_code(secret, salt, pub_ip, pub_port, local_ip, local_port)

    print()
    print("  +==========================================================+")
    print("  |  SEND CODE -- give this to the receiver:                 |")
    print("  +==========================================================+")
    print()
    print(f"  {code}")
    print()

    # Wait for receiver's code
    try:
        rcode = input("  Paste receiver's code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sock.close()
        sys.exit(0)

    result = decode_recv_code(rcode, secret)
    if result is None:
        print("  Error: invalid receiver code (bad secret or garbled).")
        sock.close()
        sys.exit(1)

    peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port = result
    print(f"  Peer public : {peer_pub_ip}:{peer_pub_port}")
    print(f"  Peer local  : {peer_local_ip}:{peer_local_port}")

    # Handshake cipher (pre-DH, for HELLO encryption only)
    print("  Deriving handshake keys (PBKDF2, 100k rounds)...")
    handshake_cipher = Cipher(secret, salt, is_sender=True)

    # Generate ephemeral DH keypair
    dh_priv, dh_pub = _dh_keypair()

    # Hole punch (exchanges DH public keys)
    peer, peer_dh_pub = punch_hole(
        sock,
        handshake_cipher,
        (peer_pub_ip, peer_pub_port),
        (peer_local_ip, peer_local_port),
        dh_pub,
        timeout=connect_timeout,
    )
    if not peer:
        print("  Could not establish a connection. The NAT(s) may be too strict.")
        sock.close()
        sys.exit(1)

    # Compute DH shared secret and derive session cipher (forward secrecy)
    dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    print("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=True)

    # Transfer
    ok = send_file_reliable(
        sock, peer, session_cipher, filepath, filesize, filehash,
        connect_timeout=connect_timeout,
    )
    sock.close()

    if ok:
        print("  Done -- file sent successfully!")
    else:
        print("  Transfer failed.")
        sys.exit(1)


def cmd_recv(connect_timeout=CONNECT_TIMEOUT):
    save_dir = "."

    # Bind
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    local_port = sock.getsockname()[1]
    local_ip = get_local_ip()

    # STUN
    print("  Discovering public endpoint via STUN...")
    pub = stun_discover(sock)
    if pub:
        pub_ip, pub_port = pub
        print(f"  Public : {pub_ip}:{pub_port}")
    else:
        pub_ip, pub_port = local_ip, local_port
        print(f"  STUN failed -- falling back to local address.")
    print(f"  Local  : {local_ip}:{local_port}")

    # Get sender code
    print()
    try:
        scode = input("  Paste sender's code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sock.close()
        sys.exit(0)

    try:
        secret, salt, peer_pub_ip, peer_pub_port, peer_local_ip, peer_local_port = (
            decode_sender_code(scode)
        )
    except Exception:
        print("  Error: invalid sender code.")
        sock.close()
        sys.exit(1)

    print(f"  Peer public : {peer_pub_ip}:{peer_pub_port}")
    print(f"  Peer local  : {peer_local_ip}:{peer_local_port}")

    # Display receiver code
    rcode = encode_recv_code(pub_ip, pub_port, local_ip, local_port, secret)

    print()
    print("  +==========================================================+")
    print("  |  RECV CODE -- give this back to the sender:              |")
    print("  +==========================================================+")
    print()
    print(f"  {rcode}")
    print()

    # Handshake cipher (pre-DH, for HELLO encryption only)
    print("  Deriving handshake keys (PBKDF2, 100k rounds)...")
    handshake_cipher = Cipher(secret, salt, is_sender=False)

    # Generate ephemeral DH keypair
    dh_priv, dh_pub = _dh_keypair()

    # Synchronisation pause
    try:
        input("  Press ENTER once the sender has pasted your code... ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sock.close()
        sys.exit(0)

    # Hole punch (exchanges DH public keys)
    peer, peer_dh_pub = punch_hole(
        sock,
        handshake_cipher,
        (peer_pub_ip, peer_pub_port),
        (peer_local_ip, peer_local_port),
        dh_pub,
        timeout=connect_timeout,
    )
    if not peer:
        print("  Could not establish a connection. The NAT(s) may be too strict.")
        sock.close()
        sys.exit(1)

    # Compute DH shared secret and derive session cipher (forward secrecy)
    dh_shared = _dh_shared_secret(dh_priv, peer_dh_pub)
    print("  Forward-secret session keys established (DH + PBKDF2).")
    session_cipher = Cipher(secret + dh_shared, salt, is_sender=False)

    # Receive
    result = recv_file_reliable(sock, peer, session_cipher,
                                connect_timeout=connect_timeout)
    sock.close()

    if result is None:
        print("  Transfer failed.")
        sys.exit(1)

    filename, temp_path, _ = result

    # Save to current directory -- never overwrite
    save_path = os.path.join(save_dir, filename)
    if os.path.exists(save_path):
        os.unlink(temp_path)  # clean up temp file
        print(f"  Error: '{save_path}' already exists. Will not overwrite.")
        sys.exit(1)

    shutil.move(temp_path, save_path)

    print(f"  Saved: {save_path}")
    print("  Done -- file received successfully!")


# ===============================================================================
# Entry point
# ===============================================================================


def main():
    print(BANNER)

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("  Usage:")
        print("    python p2p.py send <file> [--connect-timeout SECONDS]")
        print("    python p2p.py recv        [--connect-timeout SECONDS]")
        print()
        print("  --connect-timeout  Seconds to wait during hole-punch and")
        print(f"                     handshake phases (default: {CONNECT_TIMEOUT}).")
        print("                     Increase if users are slow to exchange codes.")
        print()
        sys.exit(0)

    # Parse optional --connect-timeout N (works anywhere after the subcommand)
    args = sys.argv[1:]
    connect_timeout = CONNECT_TIMEOUT
    filtered = []
    i = 0
    while i < len(args):
        if args[i] == "--connect-timeout" and i + 1 < len(args):
            try:
                connect_timeout = int(args[i + 1])
                if connect_timeout <= 0:
                    raise ValueError
            except ValueError:
                print(f"  Error: --connect-timeout must be a positive integer.")
                sys.exit(1)
            i += 2
        else:
            filtered.append(args[i])
            i += 1
    args = filtered

    if not args:
        print("  Use 'send' or 'recv'.  Run with -h for help.")
        sys.exit(1)

    cmd = args[0].lower()

    if cmd == "send":
        if len(args) < 2:
            print("  Usage: python p2p.py send <file>")
            sys.exit(1)
        cmd_send(args[1], connect_timeout=connect_timeout)

    elif cmd in ("recv", "receive"):
        cmd_recv(connect_timeout=connect_timeout)

    else:
        print(f"  Unknown command: {cmd}")
        print("  Use 'send' or 'recv'.")
        sys.exit(1)


if __name__ == "__main__":
    main()