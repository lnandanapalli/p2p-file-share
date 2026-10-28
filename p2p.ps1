<#
  p2p.ps1 -- encrypted peer-to-peer file transfer for Windows (and anywhere
  PowerShell runs). Drop-in companion to p2p.py: same codes, same protocol,
  same relay, so either side can be Python or PowerShell.

  Needs nothing installed: works on the Windows PowerShell 5.1 that ships with
  Windows 10/11, and on PowerShell 7+ (pwsh) on Windows, macOS and Linux.

  Usage (same flags as p2p.py):
    .\p2p.ps1 send <file> [-6] [--relay] [--long-code] [--connect-timeout SECONDS] [--verbose]
    .\p2p.ps1 recv        [-6] [--relay] [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]

  If Windows blocks the script ("running scripts is disabled on this system"):
    powershell -ExecutionPolicy Bypass -File .\p2p.ps1 recv --relay

  How it works: the protocol engine is C# embedded below, compiled in memory
  by PowerShell's built-in Add-Type on first run (a second or two). Plain
  PowerShell loops are far too slow for per-packet crypto.
#>

$ErrorActionPreference = 'Stop'

$P2PEngineSource = @'
// p2p.ps1 engine -- a wire-compatible C# port of p2p.py.
//
// Compiled on the fly by PowerShell's built-in Add-Type, so it needs nothing
// installed. Deliberately restricted to C# 5 and .NET Framework 4.5 APIs so
// it compiles on stock Windows PowerShell 5.1 as well as PowerShell 7+.
// (No $"" strings, ?., nameof, out var, tuples, expression-bodied members.)
//
// Every byte on the wire, every code format and every packet type matches
// p2p.py, so either side can be Python or PowerShell.

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace P2PShellV2
{
    // ========================================================================
    // Configuration (mirrors p2p.py)
    // ========================================================================
    internal static class Cfg
    {
        public static readonly string[][] StunServers = new string[][] {
            new string[] { "stun.l.google.com",  "19302" },
            new string[] { "stun1.l.google.com", "19302" },
            new string[] { "stun2.l.google.com", "19302" },
            new string[] { "stun3.l.google.com", "19302" },
            new string[] { "stun4.l.google.com", "19302" },
        };

        public const int    DirectChunkSize  = 1400;
        public const int    DirectWindowSize = 32;
        public const double DirectAckTimeout = 2.5;

        public const int    RelayChunkSize   = 32 * 1024;
        public const int    RelayWindowSize  = 96;
        public const double RelayAckTimeout  = 15.0;
        public const int    RelayBatchBytes  = 2 * 1024 * 1024;
        public const double RelayMinPostGap  = 0.06;   // <= ~42 requests/s per peer (relay allows 50/IP)
        public const double RelayMinGetGap   = 0.04;
        public const double RelayCloseFlush  = 2.0;

        public static int    ChunkSize  = DirectChunkSize;
        public static int    WindowSize = DirectWindowSize;
        public static double AckTimeout = DirectAckTimeout;

        public const int    MaxRetries       = 200;
        public const int    DefaultConnectTimeout = 3600;
        public const double PunchInterval    = 0.25;
        public const double DoneTimeout      = 120;
        public const double StallTimeout     = 300;
        public const long   MaxFileSize      = 1L << 40;   // 1 TB
        public const int    ResumeChunksPerBin = 18000;    // in 1400-byte chunks (~25 MB)

        public const string DefaultRelayHost = "relay.nlpdf.site";
        public static string RelayHost       = DefaultRelayHost;
        public const double RelayHttpTimeout = 25;
        public const double RelayFlushWait   = 0.02;
        public const double RelayRetrySleep  = 0.25;
        public const double RelaySendTimeout = 8;
        public const double RelayBackoffMax  = 10;
        public const int    DirectHintAfter  = 30;
        public const int    RelayCodeWords   = 13;

        public const byte T_HELLO = 1, T_META = 2, T_DATA = 3, T_ACK = 4, T_DONE = 5,
                          T_DONEACK = 6, T_ABORT = 7, T_HASHQ = 8, T_HASHR = 9;

        public static bool Verbose, UseIPv6, UseRelay;

        public const string DirectHint =
            "\n  Taking a while. If this keeps failing (strict NAT, CG-NAT, VM networking),\n" +
            "  run BOTH sides again with --relay to connect through the relay instead.";

        public static void UseRelayMode()
        {
            UseRelay = true; ChunkSize = RelayChunkSize; WindowSize = RelayWindowSize; AckTimeout = RelayAckTimeout;
        }

        public static void Reset()
        {
            ChunkSize = DirectChunkSize; WindowSize = DirectWindowSize; AckTimeout = DirectAckTimeout;
            RelayHost = DefaultRelayHost; Verbose = false; UseIPv6 = false; UseRelay = false;
        }
    }

    internal class ExitException : Exception
    {
        public int Code;
        public ExitException(int code) { Code = code; }
    }

    internal class CancelledException : Exception { }

    // ========================================================================
    // Small helpers: clock, console, byte packing, Ctrl+C
    // ========================================================================
    internal static class U
    {
        static readonly Stopwatch clock = Stopwatch.StartNew();
        public static double Now() { return clock.Elapsed.TotalSeconds; }

        public static volatile bool CancelRequested;
        public static void CheckCancel() { if (CancelRequested) throw new CancelledException(); }

        public static void Out(string s) { Console.Write(s); Console.Out.Flush(); }
        public static void Line(string s) { Console.WriteLine(s); }
        public static void Line() { Console.WriteLine(); }
        public static void V(string s) { if (Cfg.Verbose) Console.WriteLine(s); }

        public static void Die(int code) { throw new ExitException(code); }

        public static void Sleep(double seconds)
        {
            // Interruptible sleep so Ctrl+C is noticed promptly.
            double end = Now() + seconds;
            while (true)
            {
                CheckCancel();
                double left = end - Now();
                if (left <= 0) return;
                Thread.Sleep((int)Math.Max(1, Math.Min(left * 1000, 50)));
            }
        }

        public static byte[] Cat(params byte[][] parts)
        {
            int n = 0;
            foreach (byte[] p in parts) n += p.Length;
            byte[] r = new byte[n];
            int o = 0;
            foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
            return r;
        }

        public static byte[] Slice(byte[] b, int start, int len)
        {
            byte[] r = new byte[len];
            Buffer.BlockCopy(b, start, r, 0, len);
            return r;
        }

        public static byte[] BE16(int v) { return new byte[] { (byte)(v >> 8), (byte)v }; }
        public static byte[] BE32(uint v) { return new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }; }
        public static byte[] BE64(ulong v)
        {
            byte[] r = new byte[8];
            for (int i = 7; i >= 0; i--) { r[i] = (byte)v; v >>= 8; }
            return r;
        }
        public static int RdBE16(byte[] b, int o) { return (b[o] << 8) | b[o + 1]; }
        public static uint RdBE32(byte[] b, int o)
        {
            return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
        }
        public static ulong RdBE64(byte[] b, int o)
        {
            ulong v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | b[o + i];
            return v;
        }

        public static bool ConstEq(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }

        static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        public static byte[] Rand(int n) { byte[] b = new byte[n]; lock (rng) rng.GetBytes(b); return b; }

        public static string Hex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        // Same output as p2p.py's _fmt()
        public static string Fmt(double n)
        {
            string[] units = { "B", "KB", "MB", "GB" };
            foreach (string u in units)
            {
                if (n < 1024)
                    return u == "B" ? ((long)n).ToString(CultureInfo.InvariantCulture) + " B"
                                    : n.ToString("0.0", CultureInfo.InvariantCulture) + " " + u;
                n /= 1024;
            }
            return n.ToString("0.0", CultureInfo.InvariantCulture) + " TB";
        }

        public static string Elapsed(int secs)
        {
            int m = secs / 60, s = secs % 60;
            return m > 0 ? (m + "m " + s + "s") : (s + "s");
        }

        public static SHA256 NewSha()
        {
            // Native implementation where available (much faster than SHA256Managed on .NET Framework).
            // (looked up by name to avoid an "obsolete" compile warning on PowerShell 7)
            try
            {
                SHA256 h = CryptoConfig.CreateFromName("System.Security.Cryptography.SHA256CryptoServiceProvider") as SHA256;
                if (h != null) return h;
            }
            catch { }
            return SHA256.Create();
        }

        public static byte[] Sha256(byte[] data) { using (SHA256 h = NewSha()) return h.ComputeHash(data); }

        public static byte[] Hmac(byte[] key, byte[] data)
        {
            using (HMACSHA256 h = new HMACSHA256(key)) return h.ComputeHash(data);
        }

        public static byte[] Hmac16(byte[] key, byte[] data) { return Slice(Hmac(key, data), 0, 16); }
    }

    // ========================================================================
    // Minimal flat JSON (META only has string/int fields)
    // ========================================================================
    internal static class Json
    {
        // Python's json.dumps default style: ASCII-only output, ", " and ": " separators.
        public static string Str(string s)
        {
            StringBuilder sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20 || c > 0x7e) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            return sb.Append('"').ToString();
        }

        // Parses one flat JSON object. Values: string -> string, number -> long
        // (or double), true/false -> bool, null -> null. Returns null if invalid.
        public static Dictionary<string, object> ParseObject(string s)
        {
            try
            {
                int i = 0;
                Dictionary<string, object> d = new Dictionary<string, object>();
                Ws(s, ref i);
                if (s[i] != '{') return null;
                i++; Ws(s, ref i);
                if (s[i] == '}') return d;
                while (true)
                {
                    Ws(s, ref i);
                    string k = ReadStr(s, ref i);
                    Ws(s, ref i);
                    if (s[i] != ':') return null;
                    i++; Ws(s, ref i);
                    object v;
                    char c = s[i];
                    if (c == '"') v = ReadStr(s, ref i);
                    else if (c == 't' && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { v = true; i += 4; }
                    else if (c == 'f' && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { v = false; i += 5; }
                    else if (c == 'n' && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { v = null; i += 4; }
                    else if (c == '-' || (c >= '0' && c <= '9'))
                    {
                        int st = i;
                        while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
                        string num = s.Substring(st, i - st);
                        long lv;
                        if (num.IndexOfAny(new char[] { '.', 'e', 'E' }) < 0 &&
                            long.TryParse(num, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out lv))
                            v = lv;
                        else
                            v = double.Parse(num, CultureInfo.InvariantCulture);
                    }
                    else return null;   // nested objects/arrays are not used by META
                    d[k] = v;
                    Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == '}') return d;
                    return null;
                }
            }
            catch { return null; }
        }

        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

        static string ReadStr(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException();
            i++;
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4; break;
                    default: throw new FormatException();
                }
            }
        }
    }

    // ========================================================================
    // Cipher -- identical construction to p2p.py's Cipher
    // ========================================================================
    internal class Cipher
    {
        readonly byte[] ek, mk, dk, dmk;
        readonly HMACSHA256 encMac, decMac;
        readonly SHA256 sha = U.NewSha();
        readonly byte[] ksIn = new byte[48];     // key(32) + nonce(8) + blk(8)
        ulong ctr;
        long maxNonce = -1;
        HashSet<ulong> window = new HashSet<ulong>();
        const int NonceWindow = 65536;

        public Cipher(byte[] secret, byte[] salt, bool isSender)
        {
            byte[] km = Pbkdf2Sha256(secret, salt, 100000, 128);
            byte[] s2rEnc = U.Slice(km, 0, 32), s2rMac = U.Slice(km, 32, 32);
            byte[] r2sEnc = U.Slice(km, 64, 32), r2sMac = U.Slice(km, 96, 32);
            if (isSender) { ek = s2rEnc; mk = s2rMac; dk = r2sEnc; dmk = r2sMac; }
            else          { ek = r2sEnc; mk = r2sMac; dk = s2rEnc; dmk = s2rMac; }
            encMac = new HMACSHA256(mk);
            decMac = new HMACSHA256(dmk);
        }

        // RFC 8018 PBKDF2 with HMAC-SHA256 (Rfc2898DeriveBytes only supports
        // SHA-256 on .NET 4.7.2+, so do it by hand for 4.5 compatibility).
        static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            byte[] outp = new byte[dkLen];
            using (HMACSHA256 h = new HMACSHA256(password))
            {
                int blocks = (dkLen + 31) / 32;
                for (int bi = 1; bi <= blocks; bi++)
                {
                    byte[] u = h.ComputeHash(U.Cat(salt, U.BE32((uint)bi)));
                    byte[] t = (byte[])u.Clone();
                    for (int it = 1; it < iterations; it++)
                    {
                        u = h.ComputeHash(u);
                        for (int j = 0; j < 32; j++) t[j] ^= u[j];
                    }
                    int off = (bi - 1) * 32;
                    Buffer.BlockCopy(t, 0, outp, off, Math.Min(32, dkLen - off));
                }
            }
            return outp;
        }

        // XOR data[offset..offset+len) in place with SHA-256-CTR keystream.
        void XorKeystream(byte[] key, byte[] nonce, byte[] data, int offset, int len)
        {
            Buffer.BlockCopy(key, 0, ksIn, 0, 32);
            Buffer.BlockCopy(nonce, 0, ksIn, 32, 8);
            ulong blk = 0;
            for (int pos = 0; pos < len; pos += 32, blk++)
            {
                ulong b = blk;
                for (int i = 47; i >= 40; i--) { ksIn[i] = (byte)b; b >>= 8; }
                byte[] ks = sha.ComputeHash(ksIn);
                int n = Math.Min(32, len - pos);
                for (int i = 0; i < n; i++) data[offset + pos + i] ^= ks[i];
            }
        }

        public byte[] Encrypt(byte ptype, byte[] plaintext)
        {
            byte[] nonce = U.BE64(ctr);
            ctr++;
            byte[] pkt = new byte[9 + plaintext.Length + 16];
            pkt[0] = ptype;
            Buffer.BlockCopy(nonce, 0, pkt, 1, 8);
            Buffer.BlockCopy(plaintext, 0, pkt, 9, plaintext.Length);
            XorKeystream(ek, nonce, pkt, 9, plaintext.Length);
            byte[] mac = encMac.ComputeHash(pkt, 0, 9 + plaintext.Length);
            Buffer.BlockCopy(mac, 0, pkt, 9 + plaintext.Length, 16);
            return pkt;
        }

        // Returns false for anything forged, malformed or replayed.
        public bool Decrypt(byte[] raw, out byte ptype, out byte[] payload)
        {
            ptype = 0; payload = null;
            if (raw == null || raw.Length < 9 + 16) return false;
            int ctLen = raw.Length - 25;
            byte[] expected = decMac.ComputeHash(raw, 0, 9 + ctLen);
            int diff = 0;
            for (int i = 0; i < 16; i++) diff |= expected[i] ^ raw[9 + ctLen + i];
            if (diff != 0) return false;

            ulong nv = U.RdBE64(raw, 1);
            long floor = Math.Max(maxNonce - NonceWindow + 1, 0);
            if (nv > (ulong)long.MaxValue) return false;
            if ((long)nv < floor) return false;
            if (window.Contains(nv)) return false;
            window.Add(nv);
            if ((long)nv > maxNonce)
            {
                maxNonce = (long)nv;
                if (window.Count > 2 * NonceWindow)
                {
                    long nf = Math.Max(maxNonce - NonceWindow + 1, 0);
                    HashSet<ulong> keep = new HashSet<ulong>();
                    foreach (ulong x in window) if ((long)x >= nf) keep.Add(x);
                    window = keep;
                }
            }
            ptype = raw[0];
            payload = U.Slice(raw, 9, ctLen);
            XorKeystream(dk, U.Slice(raw, 1, 8), payload, 0, ctLen);
            return true;
        }
    }

    // ========================================================================
    // Diffie-Hellman (RFC 3526 group 14) and big-endian BigInteger helpers
    // ========================================================================
    internal static class DH
    {
        public static readonly BigInteger P = BigInteger.Parse("0" +
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        public const int KeyBytes = 256;

        public static BigInteger FromBE(byte[] b)
        {
            byte[] le = new byte[b.Length + 1];      // trailing 0 keeps it positive
            for (int i = 0; i < b.Length; i++) le[i] = b[b.Length - 1 - i];
            return new BigInteger(le);
        }

        public static byte[] ToBE(BigInteger v, int len)
        {
            byte[] le = v.ToByteArray();
            byte[] r = new byte[len];
            for (int i = 0; i < len && i < le.Length; i++) r[len - 1 - i] = le[i];
            return r;
        }

        public static void Keypair(out BigInteger priv, out byte[] pub)
        {
            priv = FromBE(U.Rand(32));
            pub = ToBE(BigInteger.ModPow(2, priv, P), KeyBytes);
        }

        public static byte[] Shared(BigInteger priv, byte[] peerPub)
        {
            BigInteger pp = FromBE(peerPub);
            if (pp < 2 || pp >= P - 1) throw new ArgumentException("Invalid DH public key");
            return U.Sha256(ToBE(BigInteger.ModPow(pp, priv, P), KeyBytes));
        }
    }

    // ========================================================================
    // Word codes (same 1024-word list, 10 bits per word)
    // ========================================================================
    internal static class Codes
    {
        const string WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby balance bamboo banana banner barely bargain barrel base basic basket battle beach beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone book boost border boring borrow boss bottom bounce box boy bracket brain brand brave breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude exercise exhaust exhibit exile exist exit exotic expand expire explain expose express extend extra eye fable face faculty faint faith fall false fame family famous fan fancy fantasy far fashion fat fatal father fatigue fault favorite feature february federal fee feed feel feet fellow felt fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garbage garden garlic garment gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grasp grass gravity great green grid grief grit grocery group grow grunt guard guide guilt guitar gun gym habit hair half hammer hamster hand happy harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole hollow home honey hood hope horn hospital host hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon ignore ill illegal image imitate immense immune impact impose improve impulse inbox income increase index indicate indoor industry infant inflict inform inhale inject inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab ladder lamp language laptop large later laugh laundry lava law lawn lawsuit layer lazy leader learn leave lecture left leg legal legend lemon lend length lens leopard lesson letter level liar liberty library license life lift like limb lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury mad magic magnet maid main mammoth manage maple marble march";
        public static readonly string[] List = WORDS.Split(' ');
        static readonly Dictionary<string, int> Index = BuildIndex();

        static Dictionary<string, int> BuildIndex()
        {
            Dictionary<string, int> d = new Dictionary<string, int>();
            for (int i = 0; i < List.Length; i++) d[List[i]] = i;
            return d;
        }

        public static bool IsWord(string w) { return Index.ContainsKey(w); }

        public static string[] Split(string phrase)
        {
            return phrase.Trim().ToLowerInvariant().Split(new char[] { ' ', '\t', '\r', '\n', '\f', '\v' },
                                                        StringSplitOptions.RemoveEmptyEntries);
        }

        public static string BytesToWords(byte[] data)
        {
            int bits = data.Length * 8;
            int nWords = (bits + 9) / 10;
            BigInteger n = DH.FromBE(data) << (nWords * 10 - bits);
            string[] words = new string[nWords];
            for (int i = nWords - 1; i >= 0; i--) { words[i] = List[(int)(n & 1023)]; n >>= 10; }
            return string.Join(" ", words);
        }

        public static byte[] WordsToBytes(string phrase, int expectedBytes)
        {
            string[] words = Split(phrase);
            int nWords = (expectedBytes * 8 + 9) / 10;
            if (words.Length != nWords)
                throw new FormatException("Expected " + nWords + " words, got " + words.Length);
            BigInteger n = BigInteger.Zero;
            foreach (string w in words)
            {
                int idx;
                if (!Index.TryGetValue(w, out idx)) throw new FormatException("Unknown word: '" + w + "'");
                n = (n << 10) | idx;
            }
            n >>= (nWords * 10 - expectedBytes * 8);
            return DH.ToBE(n, expectedBytes);
        }

        public static byte[] IpPack(IPAddress ip) { return ip.GetAddressBytes(); }

        public static string EncodeSender(byte[] secret, byte[] salt, IPEndPoint pub, IPEndPoint local)
        {
            return BytesToWords(U.Cat(secret, salt, IpPack(pub.Address), U.BE16(pub.Port),
                                      IpPack(local.Address), U.BE16(local.Port)));
        }

        public static void DecodeSender(string code, out byte[] secret, out byte[] salt,
                                        out IPEndPoint pub, out IPEndPoint local, out bool ipv6)
        {
            int nw = Split(code).Length;
            int total;
            if (nw == 36) { total = 44; ipv6 = false; }
            else if (nw == 55) { total = 68; ipv6 = true; }
            else throw new FormatException("Invalid sender code: expected 36 or 55 words, got " + nw);
            byte[] d = WordsToBytes(code, total);
            secret = U.Slice(d, 0, 16);
            salt = U.Slice(d, 16, 16);
            int al = ipv6 ? 16 : 4;
            pub = new IPEndPoint(new IPAddress(U.Slice(d, 32, al)), U.RdBE16(d, 32 + al));
            local = new IPEndPoint(new IPAddress(U.Slice(d, 34 + al, al)), U.RdBE16(d, 34 + 2 * al));
        }

        public static string EncodeRecv(IPEndPoint pub, IPEndPoint local, byte[] secret)
        {
            byte[] raw = U.Cat(IpPack(pub.Address), U.BE16(pub.Port), IpPack(local.Address), U.BE16(local.Port));
            return BytesToWords(U.Cat(raw, U.Hmac16(secret, raw)));
        }

        // Returns false on HMAC failure or unknown word count.
        public static bool DecodeRecv(string code, byte[] secret, out IPEndPoint pub, out IPEndPoint local)
        {
            pub = null; local = null;
            int nw = Split(code).Length;
            int total, al;
            if (nw == 23) { total = 28; al = 4; }
            else if (nw == 42) { total = 52; al = 16; }
            else return false;
            byte[] d = WordsToBytes(code, total);
            int rawLen = total - 16;
            byte[] raw = U.Slice(d, 0, rawLen), tag = U.Slice(d, rawLen, 16);
            if (!U.ConstEq(tag, U.Hmac16(secret, raw))) return false;
            pub = new IPEndPoint(new IPAddress(U.Slice(raw, 0, al)), U.RdBE16(raw, al));
            local = new IPEndPoint(new IPAddress(U.Slice(raw, al + 2, al)), U.RdBE16(raw, 2 * al + 2));
            return true;
        }

        public static byte[] RelaySalt(byte[] secret)
        {
            return U.Hmac16(secret, Encoding.ASCII.GetBytes("p2p-relay-salt-v1"));
        }

        public static string RelayToken(byte[] secret)
        {
            return U.Hex(U.Hmac(secret, Encoding.ASCII.GetBytes("p2p-relay-session-v1"))).Substring(0, 32);
        }
    }

    // ========================================================================
    // Packet sockets: real UDP, or the HTTPS relay pretending to be UDP
    // ========================================================================
    internal interface IPktSock
    {
        void SendTo(byte[] data, IPEndPoint ep);
        // Wait up to timeout seconds (0 = just check) for one datagram.
        bool Recv(double timeout, out byte[] data, out IPEndPoint from);
        void Close();
    }

    internal class UdpSock : IPktSock
    {
        public readonly Socket S;
        readonly byte[] buf = new byte[65536];

        public UdpSock(bool ipv6)
        {
            S = new Socket(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,
                           SocketType.Dgram, ProtocolType.Udp);
            if (ipv6) { try { S.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true); } catch { } }
            // Windows: stop ICMP "port unreachable" from surfacing as
            // WSAECONNRESET (10054) on later receives. No-op elsewhere.
            try { S.IOControl(unchecked((int)0x9800000C), new byte[] { 0, 0, 0, 0 }, null); } catch { }
            try { S.ReceiveBufferSize = 1 << 20; } catch { }
            S.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
        }

        public int LocalPort { get { return ((IPEndPoint)S.LocalEndPoint).Port; } }

        public void SendTo(byte[] data, IPEndPoint ep)
        {
            try { S.SendTo(data, ep); } catch (SocketException) { } catch (ObjectDisposedException) { }
        }

        public bool Recv(double timeout, out byte[] data, out IPEndPoint from)
        {
            data = null; from = null;
            try
            {
                int us = (int)Math.Min(Math.Max(timeout, 0) * 1e6, int.MaxValue);
                if (!S.Poll(us, SelectMode.SelectRead)) return false;
                EndPoint ep = new IPEndPoint(S.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                int n = S.ReceiveFrom(buf, ref ep);
                data = U.Slice(buf, 0, n);
                from = (IPEndPoint)ep;
                return true;
            }
            catch (SocketException) { return false; }
            catch (ObjectDisposedException) { return false; }
        }

        public void Close() { try { S.Close(); } catch { } }
    }

    internal static class Http
    {
        static HttpClient client;

        public static string BaseUrl()
        {
            string h = Cfg.RelayHost;
            if (h.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                h.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return h.TrimEnd('/');
            return "https://" + h;
        }

        public static HttpClient Client
        {
            get
            {
                if (client == null)
                {
                    try
                    {
                        // Windows PowerShell 5.1 may default to TLS 1.0 only.
                        ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                    }
                    catch { }
                    ServicePointManager.Expect100Continue = false;    // no extra round trip per POST
                    ServicePointManager.DefaultConnectionLimit = Math.Max(ServicePointManager.DefaultConnectionLimit, 16);
                    ServicePointManager.UseNagleAlgorithm = false;
                    HttpClient c = new HttpClient();
                    c.Timeout = TimeSpan.FromSeconds(120);           // per-call deadlines are set below
                    c.DefaultRequestHeaders.ExpectContinue = false;
                    client = c;
                }
                return client;
            }
        }

        // Returns HTTP status; throws on network failure / timeout.
        public static int Request(HttpMethod method, string path, byte[] body, double timeout,
                                  CancellationToken stop, out byte[] respBody, out double retryAfter)
        {
            respBody = null; retryAfter = -1;
            using (CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(stop))
            {
                cts.CancelAfter(TimeSpan.FromSeconds(timeout));
                using (HttpRequestMessage req = new HttpRequestMessage(method, BaseUrl() + path))
                {
                    if (body != null)
                    {
                        req.Content = new ByteArrayContent(body);
                        req.Content.Headers.ContentType =
                            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                    }
                    using (HttpResponseMessage resp = Client.SendAsync(req, cts.Token).Result)
                    {
                        respBody = resp.Content.ReadAsByteArrayAsync().Result;
                        if (resp.Headers.RetryAfter != null && resp.Headers.RetryAfter.Delta.HasValue)
                            retryAfter = resp.Headers.RetryAfter.Delta.Value.TotalSeconds;
                        return (int)resp.StatusCode;
                    }
                }
            }
        }

        public static bool Reachable()
        {
            try
            {
                byte[] b; double ra;
                return Request(HttpMethod.Get, "/healthz", null, 8, CancellationToken.None, out b, out ra) == 200;
            }
            catch { return false; }
        }
    }

    internal class RelaySock : IPktSock
    {
        public static readonly IPEndPoint PeerAddr = new IPEndPoint(IPAddress.Parse("127.255.255.1"), 1);

        readonly string token, sendDir, recvDir;
        readonly BlockingCollection<byte[]> outQ = new BlockingCollection<byte[]>();
        readonly BlockingCollection<byte[]> inQ = new BlockingCollection<byte[]>();
        readonly CancellationTokenSource stop = new CancellationTokenSource();

        readonly Thread sendThread;
        volatile bool closing;

        public RelaySock(string token, string sendDir, string recvDir)
        {
            this.token = token; this.sendDir = sendDir; this.recvDir = recvDir;
            sendThread = new Thread(SendLoop); sendThread.IsBackground = true; sendThread.Start();
            Thread tr = new Thread(RecvLoop); tr.IsBackground = true; tr.Start();
        }

        public void SendTo(byte[] data, IPEndPoint ep)
        {
            try { outQ.Add(data); } catch (InvalidOperationException) { }
        }

        public bool Recv(double timeout, out byte[] data, out IPEndPoint from)
        {
            from = PeerAddr;
            int ms = (int)Math.Min(Math.Max(timeout, 0) * 1000, int.MaxValue);
            try { return inQ.TryTake(out data, ms); }
            catch (Exception) { data = null; return false; }
        }

        public void Close()
        {
            // Flush what's still queued (e.g. the final DONEACK) before stopping,
            // or the peer waits out its whole DONE timeout.
            closing = true;
            try { sendThread.Join(TimeSpan.FromSeconds(Cfg.RelayCloseFlush)); } catch { }
            try { stop.Cancel(); } catch { }
            try { outQ.CompleteAdding(); } catch { }
        }

        static double Backoff(double retryAfter)
        {
            if (retryAfter < 0) retryAfter = 1.0;
            return Math.Max(Cfg.RelayRetrySleep, Math.Min(retryAfter, Cfg.RelayBackoffMax));
        }

        void Wait(double s) { try { stop.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(s)); } catch { } }

        static byte[] EncodeBatch(List<byte[]> pkts)
        {
            int size = 2;
            foreach (byte[] p in pkts) size += 2 + p.Length;
            byte[] o = new byte[size];
            o[0] = (byte)(pkts.Count >> 8); o[1] = (byte)pkts.Count;
            int off = 2;
            foreach (byte[] p in pkts)
            {
                o[off] = (byte)(p.Length >> 8); o[off + 1] = (byte)p.Length; off += 2;
                Buffer.BlockCopy(p, 0, o, off, p.Length); off += p.Length;
            }
            return o;
        }

        static List<byte[]> DecodeBatch(byte[] body)
        {
            List<byte[]> r = new List<byte[]>();
            if (body == null || body.Length < 2) return r;
            int count = U.RdBE16(body, 0), off = 2;
            for (int i = 0; i < count; i++)
            {
                if (off + 2 > body.Length) break;
                int l = U.RdBE16(body, off); off += 2;
                if (off + l > body.Length) break;
                r.Add(U.Slice(body, off, l)); off += l;
            }
            return r;
        }

        void SendLoop()
        {
            string path = "/relay/" + token + "/" + sendDir + "/send";
            double lastPost = -1;
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    byte[] first;
                    try
                    {
                        if (!outQ.TryTake(out first, (int)(Cfg.RelayFlushWait * 1000), stop.Token))
                        {
                            if (closing) return;    // everything flushed
                            continue;
                        }
                    }
                    catch (OperationCanceledException) { return; }
                    catch (InvalidOperationException) { return; }
                    // Pace POSTs to stay under the relay's per-IP rate limit;
                    // packets queued during the pause join this batch.
                    if (lastPost >= 0)
                    {
                        double gap = Cfg.RelayMinPostGap - (U.Now() - lastPost);
                        if (gap > 0) Wait(gap);
                    }
                    List<byte[]> batch = new List<byte[]>();
                    batch.Add(first);
                    int nbytes = first.Length;
                    byte[] more;
                    while (batch.Count < Cfg.WindowSize && nbytes < Cfg.RelayBatchBytes && outQ.TryTake(out more))
                    {
                        batch.Add(more); nbytes += more.Length;
                    }
                    byte[] body = EncodeBatch(batch);
                    // Retry THIS batch on throttling / network errors instead of
                    // dropping it: a drop costs a full ACK timeout in the ARQ layer.
                    while (!stop.IsCancellationRequested)
                    {
                        lastPost = U.Now();
                        int status; byte[] rb; double ra;
                        try
                        {
                            status = Http.Request(HttpMethod.Post, path, body, Cfg.RelaySendTimeout,
                                                  stop.Token, out rb, out ra);
                        }
                        catch (Exception)
                        {
                            if (stop.IsCancellationRequested) return;
                            U.V("  [relay] send batch failed, retrying");
                            Wait(Cfg.RelayRetrySleep);
                            continue;
                        }
                        if (status == 200) break;
                        if (status == 429 || status == 503)
                        {
                            double delay = Backoff(ra);
                            U.V("  [relay] send throttled (HTTP " + status + "), backing off " +
                                delay.ToString("0.0", CultureInfo.InvariantCulture) + "s");
                            Wait(delay);
                            continue;
                        }
                        // 400/413...: retrying won't help; drop and let the ARQ resend.
                        U.V("  [relay] send rejected (HTTP " + status + ")");
                        Wait(Cfg.RelayRetrySleep);
                        break;
                    }
                }
            }
            catch (Exception) { }
        }

        void RecvLoop()
        {
            string path = "/relay/" + token + "/" + recvDir + "/recv";
            double lastGet = -1;
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    if (lastGet >= 0)
                    {
                        double gap = Cfg.RelayMinGetGap - (U.Now() - lastGet);
                        if (gap > 0) Wait(gap);
                    }
                    lastGet = U.Now();
                    int status; byte[] body; double ra;
                    try
                    {
                        status = Http.Request(HttpMethod.Get, path, null, Cfg.RelayHttpTimeout,
                                              stop.Token, out body, out ra);
                    }
                    catch (Exception)
                    {
                        if (stop.IsCancellationRequested) return;
                        Wait(Cfg.RelayRetrySleep);
                        continue;
                    }
                    if (status != 200)
                    {
                        double delay;
                        if (status == 429 || status == 503)
                        {
                            delay = Backoff(ra);
                            U.V("  [relay] recv throttled (HTTP " + status + "), backing off " +
                                delay.ToString("0.0", CultureInfo.InvariantCulture) + "s");
                        }
                        else
                        {
                            delay = Cfg.RelayRetrySleep;
                            U.V("  [relay] recv rejected (HTTP " + status + ")");
                        }
                        Wait(delay);
                        continue;
                    }
                    foreach (byte[] p in DecodeBatch(body)) inQ.Add(p);
                }
            }
            catch (Exception) { }
        }
    }

    // ========================================================================
    // Short codes: SPAKE2 password-authenticated key exchange (the default)
    // ========================================================================
    //
    // Same scheme as p2p.py. The sender gets a code such as
    // "4821-apple-river-ocean": the number only picks a mailbox on the relay
    // (not secret); the words are a short password that SPAKE2 (RFC 9382)
    // turns into a strong key. The relay can't brute-force it offline, and
    // a wrong guess aborts both sides. SPAKE2 runs in RFC 3526 group 14: 2
    // generates the subgroup of prime order q = (p-1)/2, and M, N are hashed
    // into it (hash, then square). In direct mode the two sides then swap
    // their addresses, encrypted under the new key, and leave the relay.
    internal class PakeMismatchException : Exception { }

    internal static class Pake
    {
        public const int Words = 3;
        public const double Resend = 5.0;      // seconds between rendezvous resends
        public const double ReplyGap = 1.0;    // min gap between replies to a peer's repeats
        public const byte Version = 1, FRelay = 1, FIPv6 = 2;
        public static readonly byte[] Magic = Encoding.ASCII.GetBytes("SPK1");
        public static readonly BigInteger Q = (DH.P - 1) / 2;
        public static readonly BigInteger M = HashToGroup("p2p-spake2-M-v1");
        public static readonly BigInteger N = HashToGroup("p2p-spake2-N-v1");

        static BigInteger HashToGroup(string label)
        {
            byte[] l = Encoding.ASCII.GetBytes(label);
            List<byte> o = new List<byte>();
            for (uint ctr = 0; o.Count < DH.KeyBytes + 32; ctr++) o.AddRange(U.Sha256(U.Cat(l, U.BE32(ctr))));
            return BigInteger.ModPow(DH.FromBE(o.ToArray()) % DH.P, 2, DH.P);
        }

        public static BigInteger RandBelow(BigInteger n)
        {
            return DH.FromBE(U.Rand(DH.KeyBytes + 16)) % n;     // 128 extra bits: negligible bias
        }

        public static string MakeCode()
        {
            List<string> parts = new List<string>();
            parts.Add((1000 + (int)RandBelow(9000)).ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < Words; i++) parts.Add(Codes.List[(int)RandBelow(Codes.List.Length)]);
            return string.Join("-", parts.ToArray());
        }

        // "4821-apple-river-ocean" (dashes or spaces, any case). Returns false if
        // this isn't a short code at all (the caller then tries the long formats);
        // throws FormatException if it looks like one but is malformed.
        public static bool ParseCode(string code, out string nameplate, out byte[] password)
        {
            nameplate = null; password = null;
            string[] parts = Codes.Split(code.Replace('-', ' '));
            if (parts.Length == 0) return false;
            foreach (char ch in parts[0]) if (ch < '0' || ch > '9') return false;
            if (parts[0].Length > 6 || parts.Length != 1 + Words)
                throw new FormatException("A short code is a number and " + Words + " words, like 4821-apple-river-ocean.");
            for (int i = 1; i < parts.Length; i++)
                if (!Codes.IsWord(parts[i])) throw new FormatException("Unknown word: '" + parts[i] + "'");
            nameplate = int.Parse(parts[0], CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
            parts[0] = nameplate;
            password = Encoding.ASCII.GetBytes(string.Join("-", parts));
            return true;
        }

        // From the nameplate only: the relay must never see anything derived
        // from the password, or it could test guesses offline.
        public static string Token(string nameplate)
        {
            return U.Hex(U.Sha256(Encoding.ASCII.GetBytes("p2p-pake-nameplate-v1:" + nameplate))).Substring(0, 32);
        }

        public static byte[] Salt(byte[] secret)
        {
            return U.Hmac16(secret, Encoding.ASCII.GetBytes("p2p-pake-salt-v1"));
        }

        public static byte[] Kdf(byte[] h, string label) { return U.Hmac(h, Encoding.ASCII.GetBytes(label)); }

        // SHA-256-CTR keystream, same as p2p.py's Cipher._keystream with a
        // fixed nonce of 8 x kind. Each (key, kind) seals exactly one message.
        static void XorKs(byte[] key, byte kind, byte[] data)
        {
            byte[] nonce = new byte[8];
            for (int i = 0; i < 8; i++) nonce[i] = kind;
            ulong blk = 0;
            for (int pos = 0; pos < data.Length; pos += 32, blk++)
            {
                byte[] ks = U.Sha256(U.Cat(key, nonce, U.BE64(blk)));
                int n = Math.Min(32, data.Length - pos);
                for (int i = 0; i < n; i++) data[pos + i] ^= ks[i];
            }
        }

        // key = { encKey, macKey }. Encrypt-then-MAC with a full 32-byte tag.
        public static byte[] Seal(byte[][] key, byte kind, byte[] payload)
        {
            byte[] ct = (byte[])payload.Clone();
            XorKs(key[0], kind, ct);
            byte[] k1 = new byte[] { kind };
            return U.Cat(Magic, k1, ct, U.Hmac(key[1], U.Cat(k1, ct)));
        }

        public static byte[] Open(byte[][] key, byte kind, byte[] body)
        {
            if (body.Length < 32) return null;
            byte[] ct = U.Slice(body, 0, body.Length - 32), tag = U.Slice(body, body.Length - 32, 32);
            byte[] k1 = new byte[] { kind };
            if (!U.ConstEq(tag, U.Hmac(key[1], U.Cat(k1, ct)))) return null;
            XorKs(key[0], kind, ct);
            return ct;
        }
    }

    // One side of SPAKE2. The sender plays A (uses M), the receiver B (uses N).
    internal class Spake2
    {
        readonly BigInteger w, x, theirs;
        readonly bool isSender;
        public readonly byte[] Msg;

        public Spake2(byte[] password, bool isSender)
        {
            this.isSender = isSender;
            byte[] h;
            using (HMACSHA512 hm = new HMACSHA512(Encoding.ASCII.GetBytes("p2p-spake2-pw-v1"))) h = hm.ComputeHash(password);
            w = DH.FromBE(h) % (Pake.Q - 1) + 1;
            x = Pake.RandBelow(Pake.Q - 1) + 1;
            BigInteger mine = isSender ? Pake.M : Pake.N;
            theirs = isSender ? Pake.N : Pake.M;
            Msg = DH.ToBE(BigInteger.ModPow(2, x, DH.P) * BigInteger.ModPow(mine, w, DH.P) % DH.P, DH.KeyBytes);
        }

        // Returns the 32-byte transcript hash. Throws ArgumentException on a bad element.
        public byte[] Finish(byte[] peerMsg)
        {
            if (peerMsg.Length != DH.KeyBytes) throw new ArgumentException("bad SPAKE2 element length");
            BigInteger y = DH.FromBE(peerMsg);
            if (y <= 1 || y >= DH.P - 1 || !BigInteger.ModPow(y, Pake.Q, DH.P).IsOne)
                throw new ArgumentException("SPAKE2 element not in the group");
            // Strip the peer's password mask (theirs^-w = theirs^(q-w)), then DH.
            BigInteger unmasked = y * BigInteger.ModPow(theirs, Pake.Q - w, DH.P) % DH.P;
            BigInteger k = BigInteger.ModPow(unmasked, x, DH.P);
            byte[][] parts = {
                Encoding.ASCII.GetBytes("p2p-sender"), Encoding.ASCII.GetBytes("p2p-receiver"),
                isSender ? Msg : peerMsg, isSender ? peerMsg : Msg,
                DH.ToBE(k, DH.KeyBytes), DH.ToBE(w, DH.KeyBytes) };
            List<byte[]> tt = new List<byte[]>();
            foreach (byte[] p in parts) { tt.Add(U.BE64((ulong)p.Length)); tt.Add(p); }
            return U.Sha256(U.Cat(tt.ToArray()));
        }
    }

    // SPAKE2 + small authenticated messages over the relay mailbox.
    internal class PakeSession
    {
        readonly bool isSender;
        readonly Spake2 spake;
        readonly byte[] elemPkt;
        readonly RelaySock sock;
        byte[] confPkt;
        byte[][] mine, theirs;
        public byte[] Secret;

        public PakeSession(string nameplate, byte[] password, bool isSender)
        {
            this.isSender = isSender;
            spake = new Spake2(password, isSender);
            elemPkt = U.Cat(Pake.Magic, new byte[] { (byte)'E' }, spake.Msg);
            sock = new RelaySock(Pake.Token(nameplate), isSender ? "s2r" : "r2s", isSender ? "r2s" : "s2r");
        }

        public void Close() { sock.Close(); }

        void Send(params byte[][] pkts)
        {
            foreach (byte[] p in pkts) if (p != null) sock.SendTo(p, RelaySock.PeerAddr);
        }

        bool Recv(double timeout, out byte kind, out byte[] body)
        {
            kind = 0; body = null;
            byte[] pkt; IPEndPoint from;
            if (!sock.Recv(timeout, out pkt, out from)) return false;
            if (pkt.Length < 5) return false;
            for (int i = 0; i < 4; i++) if (pkt[i] != Pake.Magic[i]) return false;
            kind = pkt[4];
            body = U.Slice(pkt, 5, pkt.Length - 5);
            return true;
        }

        // Run SPAKE2 and key confirmation. Returns the peer's flags, or -1 on
        // timeout. Throws PakeMismatchException if the codes differ.
        public int Handshake(byte myFlags, double timeout, string status, string hint)
        {
            byte[] info = new byte[] { Pake.Version, myFlags };
            double start = U.Now(), lastSend = start, lastReply = start;
            int lastShown = -1;
            bool hintShown = false;
            Send(elemPkt);
            while (U.Now() - start < timeout)
            {
                U.CheckCancel();
                double now = U.Now();
                if (now - lastSend >= Pake.Resend) { Send(elemPkt, confPkt); lastSend = now; }
                int elapsed = (int)(now - start);
                if (elapsed != lastShown)
                {
                    lastShown = elapsed;
                    if (hint != null && !hintShown && elapsed >= Cfg.DirectHintAfter) { hintShown = true; U.Out("\n" + hint + "\n"); }
                    U.Out("\r  " + status + " " + U.Elapsed(elapsed) + "  ");
                }

                byte kind; byte[] body;
                if (!Recv(0.25, out kind, out body)) continue;
                if (kind == (byte)'E')
                {
                    if (Secret == null)
                    {
                        byte[] h;
                        try { h = spake.Finish(body); }
                        catch (ArgumentException) { continue; }
                        byte[][] s2r = { Pake.Kdf(h, "p2p-pake-enc-s2r"), Pake.Kdf(h, "p2p-pake-mac-s2r") };
                        byte[][] r2s = { Pake.Kdf(h, "p2p-pake-enc-r2s"), Pake.Kdf(h, "p2p-pake-mac-r2s") };
                        mine = isSender ? s2r : r2s;
                        theirs = isSender ? r2s : s2r;
                        Secret = Pake.Kdf(h, "p2p-pake-session");
                        confPkt = Pake.Seal(mine, (byte)'C', info);
                        Send(elemPkt, confPkt);
                        lastSend = lastReply = now;
                    }
                    else if (now - lastReply >= Pake.ReplyGap)
                    {
                        // The peer is still repeating itself: maybe it missed ours.
                        Send(elemPkt, confPkt);
                        lastReply = now;
                    }
                }
                else if (kind == (byte)'C' && Secret != null)
                {
                    byte[] peerInfo = Pake.Open(theirs, (byte)'C', body);
                    if (peerInfo == null || peerInfo.Length < 2 || peerInfo[0] != Pake.Version)
                        throw new PakeMismatchException();
                    U.Line();
                    return peerInfo[1];
                }
            }
            U.Line();
            return -1;
        }

        // Swap one encrypted message of `kind` with the peer (after Handshake).
        public byte[] Exchange(byte kind, byte[] payload, double timeout)
        {
            byte[] pkt = Pake.Seal(mine, kind, payload);
            double start = U.Now(), lastSend = double.NegativeInfinity;
            while (U.Now() - start < timeout)
            {
                U.CheckCancel();
                double now = U.Now();
                if (now - lastSend >= Pake.Resend)
                {
                    Send(confPkt, pkt);     // our confirmation too, in case the peer missed it
                    lastSend = now;
                }
                byte k; byte[] body;
                if (!Recv(0.25, out k, out body) || k != kind) continue;
                byte[] p = Pake.Open(theirs, kind, body);
                if (p != null) return p;
            }
            return null;
        }
    }

    // ========================================================================
    // Network helpers: STUN, local IP, address comparison
    // ========================================================================
    internal static class Net
    {
        const uint StunMagic = 0x2112A442;

        public static bool SameAddr(IPEndPoint a, IPEndPoint b)
        {
            if (a == null || b == null || a.Port != b.Port) return false;
            return U.ConstEq(a.Address.GetAddressBytes(), b.Address.GetAddressBytes());
        }

        public static string FmtAddr(IPEndPoint ep)
        {
            return Cfg.UseIPv6 ? ("[" + ep.Address + "]:" + ep.Port) : (ep.Address + ":" + ep.Port);
        }

        static IPEndPoint StunTransact(UdpSock sock, string host, int port)
        {
            IPAddress target = null;
            try
            {
                AddressFamily fam = Cfg.UseIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                foreach (IPAddress a in Dns.GetHostAddresses(host))
                    if (a.AddressFamily == fam) { target = a; break; }
            }
            catch { return null; }
            if (target == null) return null;

            byte[] txn = U.Rand(12);
            byte[] req = U.Cat(U.BE16(0x0001), U.BE16(0), U.BE32(StunMagic), txn);
            sock.SendTo(req, new IPEndPoint(target, port));

            byte[] data; IPEndPoint from;
            if (!sock.Recv(2.0, out data, out from)) return null;
            if (data.Length < 20) return null;
            if (U.RdBE16(data, 0) != 0x0101) return null;
            int msgLen = U.RdBE16(data, 2);
            if (!U.ConstEq(U.Slice(data, 8, 12), txn)) return null;

            int pos = 20;
            while (pos + 4 <= 20 + msgLen && pos + 4 <= data.Length)
            {
                int atype = U.RdBE16(data, pos), alen = U.RdBE16(data, pos + 2);
                if (pos + 4 + alen > data.Length) break;
                int v = pos + 4;
                if (atype == 0x0020)               // XOR-MAPPED-ADDRESS
                {
                    if (alen >= 8 && data[v + 1] == 0x01)
                    {
                        int xport = U.RdBE16(data, v + 2) ^ (int)(StunMagic >> 16);
                        uint xip = U.RdBE32(data, v + 4) ^ StunMagic;
                        return new IPEndPoint(new IPAddress(U.BE32(xip)), xport);
                    }
                    if (alen >= 20 && data[v + 1] == 0x02)
                    {
                        int xport = U.RdBE16(data, v + 2) ^ (int)(StunMagic >> 16);
                        byte[] key = U.Cat(U.BE32(StunMagic), txn);
                        byte[] ip = new byte[16];
                        for (int i = 0; i < 16; i++) ip[i] = (byte)(data[v + 4 + i] ^ key[i]);
                        return new IPEndPoint(new IPAddress(ip), xport);
                    }
                }
                else if (atype == 0x0001)          // MAPPED-ADDRESS
                {
                    if (alen >= 8 && data[v + 1] == 0x01)
                        return new IPEndPoint(new IPAddress(U.Slice(data, v + 4, 4)), U.RdBE16(data, v + 2));
                    if (alen >= 20 && data[v + 1] == 0x02)
                        return new IPEndPoint(new IPAddress(U.Slice(data, v + 4, 16)), U.RdBE16(data, v + 2));
                }
                pos += 4 + alen + ((4 - alen % 4) % 4);
            }
            return null;
        }

        public static IPEndPoint StunDiscover(UdpSock sock)
        {
            foreach (string[] s in Cfg.StunServers)
            {
                U.CheckCancel();
                IPEndPoint r = StunTransact(sock, s[0], int.Parse(s[1]));
                if (r != null) return r;
            }
            return null;
        }

        public static IPAddress LocalIp()
        {
            try
            {
                using (Socket s = new Socket(Cfg.UseIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,
                                             SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect(Cfg.UseIPv6 ? new IPEndPoint(IPAddress.Parse("2001:4860:4860::8888"), 80)
                                          : new IPEndPoint(IPAddress.Parse("8.8.8.8"), 80));
                    IPAddress a = ((IPEndPoint)s.LocalEndPoint).Address;
                    if (a.AddressFamily == AddressFamily.InterNetworkV6) a.ScopeId = 0;
                    return a;
                }
            }
            catch { return Cfg.UseIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback; }
        }

        public static bool IsCgnat(IPAddress ip)
        {
            if (Cfg.UseIPv6 || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
            return false;
        }

        public static string CgnatWarning(IPAddress ip)
        {
            return "  *** CG-NAT detected ***\n" +
                   "  Your STUN-reported public IP (" + ip + ") is a private/CG-NAT address.\n" +
                   "  Your ISP is sharing one real public IP across many customers, so\n" +
                   "  direct UDP hole-punching cannot reach your machine and will time out.\n" +
                   "  A relay-capable transfer tool is required in this configuration.\n" +
                   "  Continuing anyway -- direct connection may succeed on some networks.\n";
        }
    }

    // ========================================================================
    // Protocol: hole punch, reliable send/recv, resume
    // ========================================================================
    internal static class Proto
    {
        public static void SendAbort(IPktSock sock, Cipher c, IPEndPoint peer, string reason)
        {
            if (peer == null) return;
            byte[] pkt;
            try { pkt = c.Encrypt(Cfg.T_ABORT, Encoding.UTF8.GetBytes(reason)); } catch { return; }
            for (int i = 0; i < 6; i++) { sock.SendTo(pkt, peer); Thread.Sleep(50); }
        }

        public static void Drain(IPktSock sock)
        {
            byte[] d; IPEndPoint f;
            while (sock.Recv(0, out d, out f)) { }
        }

        // Wait for a packet of type `want` from `peer`, discarding everything else.
        public static byte[] RecvTyped(IPktSock sock, Cipher c, IPEndPoint peer, byte want, double timeout)
        {
            double deadline = U.Now() + timeout;
            while (true)
            {
                U.CheckCancel();
                double rem = deadline - U.Now();
                if (rem <= 0) return null;
                byte[] raw; IPEndPoint from;
                if (!sock.Recv(Math.Min(rem, 0.25), out raw, out from)) continue;
                do
                {
                    if (!Net.SameAddr(from, peer)) continue;
                    byte pt; byte[] pl;
                    if (c.Decrypt(raw, out pt, out pl) && pt == want) return pl;
                } while (sock.Recv(0, out raw, out from));
            }
        }

        public static bool PunchHole(IPktSock sock, Cipher c, IPEndPoint pub, IPEndPoint local,
                                     byte[] dhPub, double timeout, string hint,
                                     out IPEndPoint peer, out byte[] peerDhPub)
        {
            peer = null; peerDhPub = null;
            List<IPEndPoint> targets = new List<IPEndPoint>();
            targets.Add(pub);
            if (local != null && !Net.SameAddr(local, pub)) targets.Add(local);

            Drain(sock);
            byte[] hello = c.Encrypt(Cfg.T_HELLO, U.Cat(Encoding.ASCII.GetBytes("DH1:"), dhPub));
            double start = U.Now();
            string status = Cfg.Verbose ? "Punching through NAT..." : "Connecting...";
            U.Out("  " + status);
            bool hintShown = false;

            while (U.Now() - start < timeout)
            {
                foreach (IPEndPoint t in targets) sock.SendTo(hello, t);
                double deadline = U.Now() + Cfg.PunchInterval;
                while (U.Now() < deadline)
                {
                    U.CheckCancel();
                    double wait = Math.Max(deadline - U.Now(), 0);
                    byte[] data; IPEndPoint from;
                    if (!sock.Recv(Math.Min(wait, 0.05), out data, out from)) continue;
                    IPEndPoint match = null;
                    foreach (IPEndPoint t in targets) if (Net.SameAddr(t, from)) { match = t; break; }
                    if (match == null) continue;
                    byte pt; byte[] pl;
                    if (!c.Decrypt(data, out pt, out pl)) continue;
                    if (pt == Cfg.T_HELLO && pl.Length >= 4 && pl[0] == 'D' && pl[1] == 'H' && pl[2] == '1' && pl[3] == ':')
                    {
                        if (pl.Length - 4 != DH.KeyBytes) continue;
                        peerDhPub = U.Slice(pl, 4, DH.KeyBytes);
                        for (int i = 0; i < 5; i++) { sock.SendTo(hello, from); Thread.Sleep(50); }
                        if (Cfg.Verbose) U.Line("\n  Connected to " + Net.FmtAddr(from));
                        else U.Line("\n  Connected.");
                        peer = from;
                        return true;
                    }
                }
                int elapsed = (int)(U.Now() - start);
                if (hint != null && !hintShown && elapsed >= Cfg.DirectHintAfter)
                {
                    hintShown = true;
                    U.Out("\n" + hint + "\n");
                }
                U.Out("\r  " + status + " " + U.Elapsed(elapsed) + "  ");
            }
            U.Line(Cfg.Verbose ? "\n  Hole punch timed out." : "\n  Connection timed out.");
            return false;
        }

        static long Ceil(long a, long b) { return a == 0 ? 0 : (a + b - 1) / b; }

        // A simple growable-free bit set (BitArray caps at int.MaxValue bits, which is plenty).
        sealed class Bits
        {
            readonly byte[] b;
            public Bits(long n) { b = new byte[(n + 7) / 8 + 1]; }
            public bool Get(long i) { return (b[i >> 3] & (1 << (int)(i & 7))) != 0; }
            public void Set(long i) { b[i >> 3] |= (byte)(1 << (int)(i & 7)); }
        }

        public static string PrefixSha256Chunks(string path, long nChunks)
        {
            using (SHA256 h = U.NewSha())
            using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                long remaining = nChunks * Cfg.ChunkSize;
                byte[] buf = new byte[65536];
                while (remaining > 0)
                {
                    int n = f.Read(buf, 0, (int)Math.Min(buf.Length, remaining));
                    if (n <= 0) break;
                    h.TransformBlock(buf, 0, n, null, 0);
                    remaining -= n;
                }
                h.TransformFinalBlock(new byte[0], 0, 0);
                return U.Hex(h.Hash);
            }
        }

        static byte[] PrefixSha256Bytes(string path, long nChunks)
        {
            string hex = PrefixSha256Chunks(path, nChunks);
            byte[] r = new byte[32];
            for (int i = 0; i < 32; i++) r[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber);
            return r;
        }

        static void ProgressLine(long doneBytes, long total)
        {
            long pct = total > 0 ? Math.Min(100, doneBytes * 100 / total) : 100;
            U.Out("\r  Progress: " + pct.ToString().PadLeft(3) + "%  (" + U.Fmt(doneBytes) + " / " + U.Fmt(total) + ")");
        }

        // ---------------------------------------------------------------- send
        public static bool SendFile(IPktSock sock, IPEndPoint peer, Cipher c, string filepath,
                                    long filesize, string filehash, double connectTimeout)
        {
            long total = Ceil(filesize, Cfg.ChunkSize);
            string meta = "{\"name\": " + Json.Str(Path.GetFileName(filepath)) +
                          ", \"size\": " + filesize.ToString(CultureInfo.InvariantCulture) +
                          ", \"hash\": " + Json.Str(filehash) +
                          ", \"chunk\": " + Cfg.ChunkSize + "}";
            byte[] metaBytes = Encoding.UTF8.GetBytes(meta);

            bool acked = false, declined = false;
            double metaStart = U.Now(), lastPrint = 0;
            long resumeSeq = 0;
            try
            {
                while (U.Now() < metaStart + connectTimeout)
                {
                    U.CheckCancel();
                    sock.SendTo(c.Encrypt(Cfg.T_META, metaBytes), peer);
                    byte[] raw; IPEndPoint from;
                    if (sock.Recv(0.5, out raw, out from))
                    {
                        byte pt; byte[] pl;
                        if (c.Decrypt(raw, out pt, out pl))
                        {
                            if (pt == Cfg.T_ACK)
                            {
                                acked = true;
                                if (pl.Length >= 4)
                                {
                                    uint v = U.RdBE32(pl, 0);
                                    resumeSeq = v == 0xFFFFFFFF ? 0 : v;
                                }
                                break;
                            }
                            if (pt == Cfg.T_ABORT) { declined = true; break; }
                            if (pt == Cfg.T_HASHQ && pl.Length >= 8)
                            {
                                ulong n = U.RdBE64(pl, 0);
                                byte[] hv = PrefixSha256Bytes(filepath, (long)n);
                                sock.SendTo(c.Encrypt(Cfg.T_HASHR, U.Cat(U.BE64(n), hv)), peer);
                                Drain(sock);
                            }
                        }
                    }
                    double el = U.Now() - metaStart;
                    if (el - lastPrint >= 30)
                    {
                        lastPrint = el;
                        U.Out("\r  Waiting for receiver... " + (int)el + "s  ");
                    }
                }
            }
            catch (CancelledException)
            {
                U.Line("\n  Cancelled.");
                SendAbort(sock, c, peer, "CANCEL");
                return false;
            }

            if (declined) { U.Line("\n  Receiver declined the transfer."); return false; }
            if (!acked) { U.Line("\n  Receiver did not respond to file info -- timed out."); return false; }

            if (total == 0)
            {
                for (int i = 0; i < 10; i++) { sock.SendTo(c.Encrypt(Cfg.T_DONE, Encoding.ASCII.GetBytes("DONE")), peer); Thread.Sleep(50); }
                return true;
            }

            U.Line("  Sending " + total + " chunks (" + U.Fmt(filesize) + ")");

            FileStream fh;
            try { fh = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch (Exception e) { U.Line("\n  Cannot open file for reading: " + e.Message); return false; }

            Bits ackedBits = new Bits(total);
            long ackedCount = 0;
            Dictionary<long, byte[]> cache = new Dictionary<long, byte[]>();
            Dictionary<long, double> sentTime = new Dictionary<long, double>();
            Dictionary<long, int> retries = new Dictionary<long, int>();
            long nextSeq = 0;
            if (resumeSeq > 0)
            {
                if (resumeSeq > total) resumeSeq = total;
                for (long i = 0; i < resumeSeq; i++) ackedBits.Set(i);
                ackedCount = resumeSeq;
                nextSeq = resumeSeq;
                U.Line("  Skipping " + resumeSeq + " already-received chunks (" +
                       U.Fmt(Math.Min(resumeSeq * Cfg.ChunkSize, filesize)) + " already at receiver).");
            }

            long lastAckedCount = ackedCount;
            double lastProgressT = -1, lastDraw = 0;

            try
            {
                while (ackedCount < total)
                {
                    U.CheckCancel();
                    double now = U.Now();
                    if (ackedCount > lastAckedCount) { lastAckedCount = ackedCount; lastProgressT = now; }
                    else if (lastProgressT >= 0 && now - lastProgressT > Cfg.StallTimeout)
                    {
                        U.Line("\n  Transfer stalled -- no progress for " + (int)Cfg.StallTimeout +
                               "s. Receiver may have disconnected.");
                        return false;
                    }

                    while (nextSeq < total && (nextSeq - ackedCount) < Cfg.WindowSize)
                    {
                        SendData(sock, peer, c, nextSeq, GetChunk(fh, cache, nextSeq));
                        sentTime[nextSeq] = now;
                        if (!retries.ContainsKey(nextSeq)) retries[nextSeq] = 0;
                        if (lastProgressT < 0) lastProgressT = now;
                        nextSeq++;
                    }

                    List<long> keys = new List<long>(sentTime.Keys);
                    foreach (long seq in keys)
                    {
                        if (ackedBits.Get(seq)) { sentTime.Remove(seq); retries.Remove(seq); continue; }
                        if (now - sentTime[seq] > Cfg.AckTimeout)
                        {
                            retries[seq]++;
                            if (retries[seq] > Cfg.MaxRetries)
                            {
                                U.Line("\n  Chunk " + seq + " hit the retry limit (" + Cfg.MaxRetries +
                                       " attempts). Network may be too lossy or receiver disconnected.");
                                return false;
                            }
                            SendData(sock, peer, c, seq, GetChunk(fh, cache, seq));
                            sentTime[seq] = now;
                        }
                    }

                    byte[] raw; IPEndPoint from;
                    while (sock.Recv(0.01, out raw, out from))
                    {
                        byte pt; byte[] pl;
                        if (!c.Decrypt(raw, out pt, out pl)) continue;
                        if (pt == Cfg.T_ACK && pl.Length >= 4)
                        {
                            uint a = U.RdBE32(pl, 0);
                            if (a != 0xFFFFFFFF && a < total && !ackedBits.Get(a))
                            {
                                ackedBits.Set(a); ackedCount++;
                                cache.Remove(a);
                            }
                        }
                        else if (pt == Cfg.T_ABORT)
                        {
                            U.Line("\n  Receiver cancelled the transfer.");
                            return false;
                        }
                    }

                    if (U.Now() - lastDraw >= 0.1)
                    {
                        lastDraw = U.Now();
                        ProgressLine(Math.Min(ackedCount * Cfg.ChunkSize, filesize), filesize);
                    }
                }
            }
            catch (CancelledException)
            {
                U.Line("\n  Cancelled.");
                SendAbort(sock, c, peer, "CANCEL");
                return false;
            }
            catch (IOException e)
            {
                U.Line("\n  I/O error during transfer: " + e.Message);
                return false;
            }
            finally { fh.Close(); }

            byte[] donePkt = c.Encrypt(Cfg.T_DONE, Encoding.ASCII.GetBytes("DONE"));
            double doneDeadline = U.Now() + Cfg.DoneTimeout;
            bool gotDoneAck = false;
            try
            {
                while (U.Now() < doneDeadline)
                {
                    U.CheckCancel();
                    sock.SendTo(donePkt, peer);
                    byte[] raw; IPEndPoint from;
                    if (!sock.Recv(0.5, out raw, out from)) continue;
                    byte pt; byte[] pl;
                    if (!c.Decrypt(raw, out pt, out pl)) continue;
                    if (pt == Cfg.T_DONEACK) { gotDoneAck = true; break; }
                    if (pt == Cfg.T_ABORT) { U.Line("\n  Receiver cancelled the transfer."); return false; }
                }
            }
            catch (CancelledException)
            {
                U.Line("\n  Cancelled.");
                SendAbort(sock, c, peer, "CANCEL");
                return false;
            }

            U.Line("\r  Progress: 100%  (" + U.Fmt(filesize) + " / " + U.Fmt(filesize) + ")");
            if (!gotDoneAck)
                U.Line("  Warning: receiver did not acknowledge completion (no DONEACK within " +
                       (int)Cfg.DoneTimeout + "s). The file was fully transferred but the receiver may still be processing.");
            return true;
        }

        static byte[] GetChunk(FileStream fh, Dictionary<long, byte[]> cache, long seq)
        {
            byte[] ch;
            if (cache.TryGetValue(seq, out ch)) return ch;
            fh.Seek(seq * Cfg.ChunkSize, SeekOrigin.Begin);
            byte[] buf = new byte[Cfg.ChunkSize];
            int got = 0;
            while (got < buf.Length)
            {
                int n = fh.Read(buf, got, buf.Length - got);
                if (n <= 0) break;
                got += n;
            }
            ch = got == buf.Length ? buf : U.Slice(buf, 0, got);
            cache[seq] = ch;
            return ch;
        }

        static void SendData(IPktSock sock, IPEndPoint peer, Cipher c, long seq, byte[] chunk)
        {
            sock.SendTo(c.Encrypt(Cfg.T_DATA, U.Cat(U.BE32((uint)seq), chunk)), peer);
        }

        // ---------------------------------------------------------------- recv
        public class RecvResult { public string FileName, TempPath, Hash; }

        public static string ResumeCommand(string workingPath)
        {
            return ".\\p2p.ps1 recv" + (Cfg.UseIPv6 ? " -6" : "") + (Cfg.UseRelay ? " --relay" : "") +
                   " --resume \"" + workingPath + "\"";
        }

        static void PartialSaved(string workingPath)
        {
            U.Line("  Partial file saved: " + workingPath);
            U.Line("  To resume:          " + ResumeCommand(workingPath));
        }

        static string SafeFileName(string raw)
        {
            int cut = Math.Max(raw.LastIndexOf('/'), raw.LastIndexOf('\\'));
            string name = cut >= 0 ? raw.Substring(cut + 1) : raw;
            // Windows rejects some characters that are fine on Linux/macOS (e.g. ':' '?' '*').
            StringBuilder sb = new StringBuilder();
            char[] bad = { '<', '>', ':', '"', '/', '\\', '|', '?', '*' };
            foreach (char ch in name)
                sb.Append((ch < 32 || Array.IndexOf(bad, ch) >= 0) ? '_' : ch);
            return sb.ToString().TrimEnd(' ');
        }

        static string NewTempPath()
        {
            const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_";
            for (int attempt = 0; attempt < 100; attempt++)
            {
                byte[] r = U.Rand(8);
                StringBuilder sb = new StringBuilder("tmp");
                foreach (byte b in r) sb.Append(alphabet[b % alphabet.Length]);
                string p = Path.Combine(".", sb.ToString());
                if (!File.Exists(p)) return p;
            }
            throw new IOException("cannot create a temporary file name");
        }

        static long ResumeSearch(IPktSock sock, IPEndPoint peer, Cipher c, string partialPath,
                                 long partialChunks, long chunksPerBin)
        {
            if (partialChunks == 0) return 0;
            U.Line("  Verifying partial file for resume...");

            Func<long, int> verify = delegate(long n)
            {
                // 1 = match, 0 = mismatch, -1 = no sender response
                byte[] req = U.BE64((ulong)n);
                byte[] senderSha = null;
                for (int i = 0; i < 5 && senderSha == null; i++)
                {
                    sock.SendTo(c.Encrypt(Cfg.T_HASHQ, req), peer);
                    byte[] pl = RecvTyped(sock, c, peer, Cfg.T_HASHR, 8.0);
                    if (pl != null && pl.Length >= 40 && U.RdBE64(pl, 0) == (ulong)n) senderSha = U.Slice(pl, 8, 32);
                }
                if (senderSha == null) return -1;
                return U.ConstEq(senderSha, PrefixSha256Bytes(partialPath, n)) ? 1 : 0;
            };

            int res = verify(partialChunks);
            if (res < 0) { U.Line("  Resume verification failed -- no response from sender."); return 0; }
            if (res > 0)
            {
                U.Line("  Prefix verified. Resuming from chunk " + partialChunks + " (" +
                       U.Fmt(partialChunks * Cfg.ChunkSize) + ").");
                return partialChunks;
            }
            U.Line("  Prefix mismatch at chunk " + partialChunks + ". Trying go-back-N...");

            List<long> cands = new List<long>();
            for (int k = 1; k < 4; k++)
            {
                long cand = partialChunks - k * chunksPerBin;
                if (cand <= 0) break;
                cands.Add(cand);
            }
            long lastFailed = partialChunks;
            for (int i = 0; i < cands.Count; i++)
            {
                res = verify(cands[i]);
                if (res < 0) { U.Line("  No response from sender at chunk " + cands[i] + ". Aborting."); return 0; }
                if (res > 0)
                {
                    U.Line("  Go-back-N matched at chunk " + cands[i] + " (" + U.Fmt(cands[i] * Cfg.ChunkSize) +
                           ") after " + (i + 1) + " step(s).");
                    return cands[i];
                }
                lastFailed = cands[i];
                U.Line("  Mismatch at chunk " + cands[i] + " (step " + (i + 1) + "/" + cands.Count + ").");
            }
            if (cands.Count < 3)
            {
                U.Line("  File has " + cands.Count + " bin(s). All go-back steps exhausted. Cannot resume.");
                return 0;
            }
            U.Line("  All go-back-N steps failed. Running binary search...");
            long lo = 0, hi = lastFailed;
            while (hi - lo > 1)
            {
                long mid = (lo + hi) / 2;
                res = verify(mid);
                if (res < 0) { U.Line("  No sender response at chunk " + mid + ". Aborting binary search."); return 0; }
                if (res > 0) lo = mid; else hi = mid;
            }
            if (lo == 0) { U.Line("  Binary search found no verified prefix. Cannot resume."); return 0; }
            U.Line("  Binary search found verified prefix at chunk " + lo + " (" + U.Fmt(lo * Cfg.ChunkSize) + ").");
            return lo;
        }

        public static RecvResult RecvFile(IPktSock sock, IPEndPoint peer0, Cipher c, double connectTimeout,
                                          long maxSize, string resumePath)
        {
            U.Line("  Waiting for file info (you will approve before transfer starts)...");
            double t0 = U.Now(), lastPrint = 0;
            string filename = null, filehash = null;
            long filesize = 0, confirmed = 0;
            bool usingResume = false, accepted = false;
            IPEndPoint peer = null;

            while (!accepted)
            {
                U.CheckCancel();
                if (U.Now() > t0 + connectTimeout) { U.Line("\n  Timed out waiting for sender to send file info."); return null; }
                double el = U.Now() - t0;
                if (el - lastPrint >= 30)
                {
                    lastPrint = el;
                    U.Out("\r  Still waiting for sender... " + U.Elapsed((int)el) + "  ");
                }
                byte[] raw; IPEndPoint addr;
                if (!sock.Recv(2.0, out raw, out addr)) continue;
                byte pt; byte[] pl;
                if (!c.Decrypt(raw, out pt, out pl)) continue;
                if (pt == Cfg.T_ABORT)
                {
                    string reason = pl.Length > 0 ? Encoding.UTF8.GetString(pl, 0, Math.Min(200, pl.Length)) : "ABORT";
                    U.Line("\n  Sender cancelled before transfer started (" + reason + ").");
                    return null;
                }
                if (pt != Cfg.T_META || pl.Length == 0) continue;

                Dictionary<string, object> meta = Json.ParseObject(Encoding.UTF8.GetString(pl));
                if (meta == null) continue;
                object oName, oSize, oHash, oChunk;
                if (!meta.TryGetValue("name", out oName) || !(oName is string) || ((string)oName).Length == 0) continue;
                if (!meta.TryGetValue("size", out oSize) || !(oSize is long) || (long)oSize < 0) continue;
                if (!meta.TryGetValue("hash", out oHash) || !(oHash is string) || ((string)oHash).Length != 64) continue;

                string rawName = (string)oName;
                filename = SafeFileName(rawName);
                if (filename.Length == 0 || filename.StartsWith("."))
                {
                    U.Line("\n  Sender provided an invalid filename: '" + rawName + "'");
                    return null;
                }
                filesize = (long)oSize;
                filehash = ((string)oHash).ToLowerInvariant();

                long peerChunk = 1400;   // old senders don't send "chunk"
                if (meta.TryGetValue("chunk", out oChunk) && oChunk is long) peerChunk = (long)oChunk;
                if (peerChunk != Cfg.ChunkSize)
                {
                    U.Line("\n  Version mismatch: sender uses " + peerChunk + "-byte chunks, this side uses " +
                           Cfg.ChunkSize + ".\n  Update p2p.py / p2p.ps1 on BOTH machines to the same version.");
                    SendAbort(sock, c, addr, "VERSION");
                    return null;
                }

                if (filesize > maxSize)
                {
                    U.Line("\n  File too large (" + U.Fmt(filesize) + "). Limit is " + U.Fmt(maxSize) + ".");
                    SendAbort(sock, c, addr, "SIZE");
                    return null;
                }

                U.Line("\n  Incoming file : " + filename + "  (" + U.Fmt(filesize) + ")");
                U.Out("  Accept this file? [y/N]: ");
                string ans = App.ReadLine();
                if (ans == null) { SendAbort(sock, c, addr, "CANCEL"); U.Line("\n  Cancelled."); return null; }
                ans = ans.Trim().ToLowerInvariant();
                if (ans != "y" && ans != "yes")
                {
                    SendAbort(sock, c, addr, "NO");
                    U.Line("  Transfer declined.");
                    return null;
                }

                if (resumePath != null)
                {
                    if (!File.Exists(resumePath))
                    {
                        U.Line("  Resume error: '" + resumePath + "' not found.");
                        SendAbort(sock, c, addr, "ABORT");
                        return null;
                    }
                    long psize = new FileInfo(resumePath).Length;
                    if (psize == 0) U.Line("  Partial file is empty -- starting fresh.");
                    else if (psize > filesize)
                    {
                        U.Line("  Resume error: partial file (" + U.Fmt(psize) + ") is larger than incoming file (" +
                               U.Fmt(filesize) + "). Wrong file?");
                        SendAbort(sock, c, addr, "ABORT");
                        return null;
                    }
                    else
                    {
                        long pchunks = Ceil(psize, Cfg.ChunkSize);
                        long perBin = Math.Max(1, ((long)Cfg.ResumeChunksPerBin * 1400) / Cfg.ChunkSize);
                        confirmed = ResumeSearch(sock, addr, c, resumePath, pchunks, perBin);
                        if (confirmed == 0)
                        {
                            U.Line("  Partial file does not match this transfer -- cannot resume. Run recv without --resume to start over.");
                            SendAbort(sock, c, addr, "ABORT");
                            return null;
                        }
                        usingResume = true;
                    }
                }

                uint ackSeq = usingResume ? (uint)confirmed : 0xFFFFFFFF;
                sock.SendTo(c.Encrypt(Cfg.T_ACK, U.BE32(ackSeq)), addr);
                peer = addr;
                accepted = true;
            }

            long total = Ceil(filesize, Cfg.ChunkSize);
            U.Line("  Receiving: " + filename + "  (" + U.Fmt(filesize) + ")");

            if (total == 0)
            {
                string ep = NewTempPath();
                File.WriteAllBytes(ep, new byte[0]);
                RecvResult e0 = new RecvResult(); e0.FileName = filename; e0.TempPath = ep; e0.Hash = filehash;
                return e0;
            }

            FileStream tmp;
            string working;
            try
            {
                if (usingResume)
                {
                    working = resumePath;
                    tmp = new FileStream(resumePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                    tmp.SetLength(confirmed * Cfg.ChunkSize);   // discard anything past the verified boundary
                }
                else
                {
                    working = NewTempPath();
                    tmp = new FileStream(working, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
                }
            }
            catch (Exception e)
            {
                U.Line("\n  Cannot " + (usingResume ? "open partial file for resume" : "create temp file") + ": " + e.Message);
                return null;
            }

            Bits got = new Bits(total);
            long gotCount = 0;
            if (usingResume) { for (long i = 0; i < confirmed; i++) got.Set(i); gotCount = confirmed; }
            bool done = false;
            double lastRecvT = U.Now(), lastDraw = 0;

            try
            {
                while (gotCount < total || !done)
                {
                    U.CheckCancel();
                    if (U.Now() - lastRecvT > Cfg.StallTimeout)
                    {
                        U.Line("\n  Transfer stalled -- no data received for " + (int)Cfg.StallTimeout +
                               "s. Sender may have disconnected.");
                        SendAbort(sock, c, peer, "STALL");
                        tmp.Close(); PartialSaved(working);
                        return null;
                    }
                    byte[] raw; IPEndPoint addr;
                    if (!sock.Recv(0.25, out raw, out addr))
                    {
                        if (gotCount >= total && U.Now() - lastRecvT > 2.0) break;   // have everything, missed DONE
                        continue;
                    }
                    bool fromPeer = Net.SameAddr(addr, peer);
                    if (fromPeer) lastRecvT = U.Now();
                    byte pt; byte[] pl;
                    if (!c.Decrypt(raw, out pt, out pl)) continue;
                    if (!fromPeer) continue;

                    if (pt == Cfg.T_DATA && pl.Length > 4)
                    {
                        uint seq = U.RdBE32(pl, 0);
                        if (seq >= total) continue;
                        if (!got.Get(seq))
                        {
                            try
                            {
                                tmp.Seek((long)seq * Cfg.ChunkSize, SeekOrigin.Begin);
                                tmp.Write(pl, 4, pl.Length - 4);
                            }
                            catch (IOException e)
                            {
                                U.Line("\n  Disk write error: " + e.Message);
                                SendAbort(sock, c, peer, "ERROR");
                                tmp.Close(); PartialSaved(working);
                                return null;
                            }
                            got.Set(seq); gotCount++;
                        }
                        sock.SendTo(c.Encrypt(Cfg.T_ACK, U.BE32(seq)), addr);
                        if (U.Now() - lastDraw >= 0.1)
                        {
                            lastDraw = U.Now();
                            ProgressLine(Math.Min(gotCount * Cfg.ChunkSize, filesize), filesize);
                        }
                    }
                    else if (pt == Cfg.T_DONE)
                    {
                        sock.SendTo(c.Encrypt(Cfg.T_DONEACK, Encoding.ASCII.GetBytes("OK")), addr);
                        done = true;
                        if (gotCount >= total) break;
                    }
                    else if (pt == Cfg.T_META)
                    {
                        uint ackSeq = usingResume ? (uint)confirmed : 0xFFFFFFFF;
                        sock.SendTo(c.Encrypt(Cfg.T_ACK, U.BE32(ackSeq)), addr);
                    }
                    else if (pt == Cfg.T_ABORT)
                    {
                        string reason = pl.Length > 0 ? Encoding.UTF8.GetString(pl, 0, Math.Min(200, pl.Length)) : "ABORT";
                        U.Line("\n  Sender cancelled the transfer (" + reason + ").");
                        tmp.Close(); PartialSaved(working);
                        return null;
                    }
                }
                tmp.SetLength(filesize);
                tmp.Close();
            }
            catch (CancelledException)
            {
                SendAbort(sock, c, peer, "CANCEL");
                tmp.Close();
                U.Line("\n  Cancelled by receiver.");
                PartialSaved(working);
                return null;
            }
            catch (IOException e)
            {
                U.Line("\n  Disk error finalising file: " + e.Message);
                try { tmp.Close(); } catch { }
                PartialSaved(working);
                return null;
            }

            U.Line("\r  Progress: 100%  (" + U.Fmt(filesize) + " / " + U.Fmt(filesize) + ")");

            string actual;
            try { actual = FileSha256(working); }
            catch (Exception e)
            {
                U.Line("\n  Cannot read temp file for verification: " + e.Message);
                PartialSaved(working);
                return null;
            }
            if (actual != filehash)
            {
                U.Line("  ERROR: SHA-256 mismatch -- file is corrupted or tampered!");
                U.Line("    expected " + filehash);
                U.Line("    got      " + actual);
                U.Line("  The partial data is preserved. You can retry with the resume");
                U.Line("  command shown below.");
                PartialSaved(working);
                return null;
            }
            RecvResult r = new RecvResult(); r.FileName = filename; r.TempPath = working; r.Hash = filehash;
            return r;
        }

        public static string FileSha256(string path)
        {
            using (SHA256 h = U.NewSha())
            using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
                return U.Hex(h.ComputeHash(f));
        }
    }

    // ========================================================================
    // CLI
    // ========================================================================
    public static class App
    {
        const string Banner =
            "\n" +
            "  +-----------------------------------------+\n" +
            "  |   p2p.ps1 -- encrypted hole-punch xfer  |\n" +
            "  |   short PAKE codes . p2p.py compatible  |\n" +
            "  +-----------------------------------------+\n";

        static bool handlerInstalled;

        static void OnCancel(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;            // never kill the hosting PowerShell window
            U.CancelRequested = true;
        }

        internal static string ReadLine()
        {
            U.CheckCancel();
            string s = Console.ReadLine();
            if (U.CancelRequested) return null;
            return s;
        }

        static void Usage()
        {
            U.Line("  Usage:");
            U.Line("    .\\p2p.ps1 send <file> [-6] [--relay] [--long-code] [--connect-timeout SECONDS] [--verbose]");
            U.Line("    .\\p2p.ps1 recv        [-6] [--relay] [--connect-timeout SECONDS] [--resume PARTIAL_FILE] [--verbose]");
            U.Line();
            U.Line("  Works with p2p.py on the other side (either side can be Python or PowerShell).");
            U.Line();
            U.Line("  The sender gets a short code like 4821-apple-river-ocean; the receiver");
            U.Line("  types it in. Both sides meet briefly at the relay to verify the code");
            U.Line("  (SPAKE2) and swap addresses, then the file goes directly peer-to-peer.");
            U.Line();
            U.Line("  -6                 Use IPv6 (both sides must agree). Bypasses NAT");
            U.Line("                     entirely -- works wherever IPv6 is available.");
            U.Line("  --connect-timeout  Seconds to wait during hole-punch and");
            U.Line("                     handshake phases (default: " + Cfg.DefaultConnectTimeout + ").");
            U.Line("  --resume FILE      Resume a dropped transfer. Point to the partial");
            U.Line("                     file from a previous recv. The script will verify");
            U.Line("                     how much was received correctly and resume from there.");
            U.Line("  --verbose          Show technical connection details such as IP");
            U.Line("                     addresses, STUN status, and handshake status.");
            U.Line("  --relay            Send the file itself through the HTTPS relay instead");
            U.Line("                     of direct hole punching. With short codes, one side");
            U.Line("                     using it is enough.");
            U.Line("  --long-code        (send) Use the old long word codes instead: no relay");
            U.Line("                     at all in direct mode, but the receiver has to send");
            U.Line("                     a code back. With --relay: one 13-word code, and");
            U.Line("                     both sides must use --relay.");
            U.Line("  --relay-host HOST  Override the relay server (default: " + Cfg.DefaultRelayHost + ").");
        }

        public static int Run(string[] argv, string scriptDir)
        {
            Cfg.Reset();
            U.CancelRequested = false;
            if (!handlerInstalled) { Console.CancelKeyPress += OnCancel; handlerInstalled = true; }
            try
            {
                return RunInner(argv);
            }
            catch (ExitException e) { return e.Code; }
            catch (CancelledException) { U.Line("\n  Interrupted."); return 0; }
            catch (Exception e)
            {
                Exception inner = e;
                while (inner is AggregateException && inner.InnerException != null) inner = inner.InnerException;
                string log = Path.Combine(string.IsNullOrEmpty(scriptDir) ? "." : scriptDir, "p2p_error.log");
                try
                {
                    File.WriteAllText(log, e.ToString());
                    U.Line("\n  Unexpected error: " + inner.Message);
                    U.Line("  Details written to: " + log);
                }
                catch { U.Line("\n  Unexpected error: " + e); }
                return 1;
            }
            finally
            {
                Console.CancelKeyPress -= OnCancel;
                handlerInstalled = false;
            }
        }

        static int RunInner(string[] argv)
        {
            U.Line(Banner);
            foreach (string a in argv)
                if (a == "-h" || a == "--help") { Usage(); return 0; }
            if (argv.Length < 1) { Usage(); return 0; }

            int connectTimeout = Cfg.DefaultConnectTimeout;
            string resumePath = null;
            bool oldNoRelay = false, longCode = false;
            List<string> args = new List<string>();
            for (int i = 0; i < argv.Length; i++)
            {
                string a = argv[i];
                if (a == "--connect-timeout" && i + 1 < argv.Length)
                {
                    if (!int.TryParse(argv[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out connectTimeout) || connectTimeout <= 0)
                    {
                        U.Line("  Error: --connect-timeout must be a positive integer.");
                        return 1;
                    }
                    i++;
                }
                else if (a == "--resume" && i + 1 < argv.Length) { resumePath = argv[++i]; }
                else if (a == "--verbose") Cfg.Verbose = true;
                else if (a == "-6" || a == "--ipv6") Cfg.UseIPv6 = true;
                else if (a == "--relay") Cfg.UseRelay = true;
                else if (a == "--long-code") longCode = true;
                else if (a == "--no-relay") oldNoRelay = true;
                else if (a == "--relay-host" && i + 1 < argv.Length) Cfg.RelayHost = argv[++i];
                else args.Add(a);
            }
            if (Cfg.UseRelay) Cfg.UseRelayMode();
            if (oldNoRelay) U.Line("  Note: --no-relay is no longer needed; the relay is only used with --relay.");
            if (Cfg.UseRelay && oldNoRelay) { U.Line("  Error: --relay and --no-relay cannot be used together."); return 1; }
            if (args.Count == 0) { U.Line("  Use 'send' or 'recv'.  Run with -h for help."); return 1; }

            string cmd = args[0].ToLowerInvariant();
            // Short codes always meet at the relay; a receiver only knows which kind
            // of code it has once it is pasted, so CmdRecv checks that case itself.
            if ((Cfg.UseRelay && (cmd == "send" || cmd == "recv" || cmd == "receive")) || (cmd == "send" && !longCode))
            {
                if (!Http.Reachable())
                {
                    U.Line("  Error: cannot reach the relay at " + Cfg.RelayHost + ".");
                    U.Line("  Check your internet connection, or point at another relay with --relay-host.");
                    if (!Cfg.UseRelay) U.Line("  Or use --long-code for a direct transfer that never contacts the relay.");
                    return 1;
                }
            }
            if (cmd == "send")
            {
                if (args.Count < 2) { U.Line("  Usage: .\\p2p.ps1 send <file> [-6]"); return 1; }
                return CmdSend(args[1], connectTimeout, longCode);
            }
            if (cmd == "recv" || cmd == "receive") return CmdRecv(connectTimeout, resumePath);
            U.Line("  Unknown command: '" + args[0] + "'");
            U.Line("  Use 'send' or 'recv'.");
            return 1;
        }

        static void BindUdp(out UdpSock sock, out IPEndPoint local)
        {
            try { sock = new UdpSock(Cfg.UseIPv6); }
            catch (Exception e) { U.Line("  Error: cannot create UDP socket: " + e.Message); throw new ExitException(1); }
            local = new IPEndPoint(Net.LocalIp(), sock.LocalPort);
        }

        // STUN (skipped in relay mode). Returns the public endpoint.
        static IPEndPoint Discover(UdpSock sock, IPEndPoint local)
        {
            IPEndPoint stun = null, pub;
            if (Cfg.UseRelay) U.V("  Relay mode: skipping STUN and hole punching.");
            else { U.V("  Discovering public endpoint via STUN..."); stun = Net.StunDiscover(sock); }

            AddressFamily fam = Cfg.UseIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            if (stun != null && stun.Address.AddressFamily == fam)
            {
                pub = stun;
                U.V("  Public : " + Net.FmtAddr(pub));
            }
            else
            {
                pub = local;
                if (stun != null) U.V("  STUN returned wrong-family address -- using local address.");
                else if (!Cfg.UseRelay)
                    U.V(Cfg.UseIPv6 ? "  STUN failed -- using local IPv6 address (IPv6 has no NAT)."
                                    : "  STUN failed -- using local address (LAN-only transfer).");
            }
            U.V("  Local  : " + Net.FmtAddr(local));
            if (!Cfg.UseRelay && Net.IsCgnat(pub.Address)) U.Line(Net.CgnatWarning(pub.Address));
            return pub;
        }

        // Short-code flow: meet the peer at the relay, run SPAKE2, agree on the
        // mode and (direct mode only) swap addresses. The peer addresses stay
        // null in relay mode. Throws ExitException on failure.
        static void PakeConnect(string code, bool isSender, UdpSock sock, IPEndPoint local, int connectTimeout,
                                out byte[] secret, out byte[] salt, out IPEndPoint peerPub, out IPEndPoint peerLocal)
        {
            secret = null; salt = null; peerPub = null; peerLocal = null;
            string nameplate; byte[] password;
            Pake.ParseCode(code, out nameplate, out password);
            byte myFlags = (byte)((Cfg.UseRelay ? Pake.FRelay : 0) | (Cfg.UseIPv6 ? Pake.FIPv6 : 0));
            string other = isSender ? "receiver" : "sender";
            PakeSession sess = new PakeSession(nameplate, password, isSender);
            try
            {
                string status = isSender ? "Waiting for the receiver to enter the code..." : "Finding the sender...";
                string hint = isSender ? null :
                    "\n  Taking a while. Check that the sender is still waiting and that the\n" +
                    "  number at the start of the code is right.";
                int peerFlags;
                try { peerFlags = sess.Handshake(myFlags, connectTimeout, status, hint); }
                catch (PakeMismatchException)
                {
                    U.Line("\n  Error: the codes didn't match.");
                    U.Line("  Check the code for typos. Each code allows only one attempt, so the");
                    U.Line("  sender has to run 'send' again for a new code.");
                    throw new ExitException(1);
                }
                if (peerFlags < 0) { U.Line("  Timed out: the " + other + " never showed up."); throw new ExitException(1); }
                U.Line("  Code verified.");

                if (((myFlags | peerFlags) & Pake.FRelay) != 0)
                {
                    if (!Cfg.UseRelay) U.Line("  The " + other + " asked for --relay, so the transfer goes through the relay.");
                    Cfg.UseRelayMode();
                    secret = sess.Secret;
                    salt = Pake.Salt(secret);
                    return;
                }

                bool peerV6 = (peerFlags & Pake.FIPv6) != 0;
                if (peerV6 != Cfg.UseIPv6)
                {
                    U.Line("  Error: address-family mismatch.");
                    U.Line("  The " + other + " is using " + (peerV6 ? "IPv6 (-6)" : "IPv4") +
                           ". Both sides must agree on -6 (or neither), or use --relay.");
                    throw new ExitException(1);
                }

                // STUN only now, with both sides present, so the NAT mapping is
                // fresh when hole punching starts.
                IPEndPoint pub = Discover(sock, local);
                byte[] mine = U.Cat(Codes.IpPack(pub.Address), U.BE16(pub.Port),
                                    Codes.IpPack(local.Address), U.BE16(local.Port));
                byte[] theirs = sess.Exchange((byte)'A', mine, connectTimeout);
                if (theirs == null || theirs.Length != mine.Length)
                {
                    U.Line("  Error: lost contact with the " + other + " while exchanging addresses.");
                    throw new ExitException(1);
                }
                int al = Cfg.UseIPv6 ? 16 : 4;
                peerPub = new IPEndPoint(new IPAddress(U.Slice(theirs, 0, al)), U.RdBE16(theirs, al));
                peerLocal = new IPEndPoint(new IPAddress(U.Slice(theirs, al + 2, al)), U.RdBE16(theirs, 2 * al + 2));
                U.V("  Peer public : " + Net.FmtAddr(peerPub));
                U.V("  Peer local  : " + Net.FmtAddr(peerLocal));
                secret = sess.Secret;
                salt = Pake.Salt(secret);
            }
            catch (CancelledException) { U.Line("\n  Cancelled."); throw new ExitException(0); }
            finally { sess.Close(); }
        }

        static int CmdSend(string filepath, int connectTimeout, bool longCode)
        {
            if (!File.Exists(filepath)) { U.Line("  Error: '" + filepath + "' not found or is not a file."); return 1; }
            string filename = Path.GetFileName(filepath);
            long filesize;
            try { filesize = new FileInfo(filepath).Length; }
            catch (Exception e) { U.Line("  Error: cannot stat file: " + e.Message); return 1; }
            U.Line("  File : " + filename);
            U.Line("  Size : " + U.Fmt(filesize));
            U.Line("  Hashing file...");
            string filehash;
            try { filehash = Proto.FileSha256(filepath); }
            catch (Exception e) { U.Line("  Error: cannot read file: " + e.Message); return 1; }

            UdpSock sock; IPEndPoint local;
            BindUdp(out sock, out local);
            RelaySock relay = null;
            try
            {
                byte[] secret = null, salt = null;
                string code;
                if (!longCode) code = Pake.MakeCode();
                else
                {
                    IPEndPoint pub = Discover(sock, local);
                    secret = U.Rand(16);
                    if (Cfg.UseRelay) { salt = Codes.RelaySalt(secret); code = Codes.BytesToWords(secret); }
                    else { salt = U.Rand(16); code = Codes.EncodeSender(secret, salt, pub, local); }
                }

                U.Line();
                U.Line("  +==========================================================+");
                U.Line("  |  SEND CODE -- give this to the receiver:                 |");
                U.Line("  +==========================================================+");
                U.Line();
                U.Line("  " + code);
                U.Line();

                IPEndPoint peerPub = null, peerLocal = null;
                if (!longCode)
                {
                    // Short code: the receiver types it in and both sides meet at
                    // the relay; there is nothing to paste back.
                    PakeConnect(code, true, sock, local, connectTimeout, out secret, out salt, out peerPub, out peerLocal);
                }
                else if (Cfg.UseRelay)
                    U.Line("  Relay mode: nothing to paste back. The receiver needs only the code above.");
                else
                {
                    U.Out("  Paste receiver's code: ");
                    string rcode = ReadLine();
                    if (rcode == null) { U.Line("\n  Cancelled."); return 0; }
                    rcode = rcode.Trim();
                    if (rcode.Length == 0) { U.Line("  No code entered."); return 1; }
                    int nw = Codes.Split(rcode).Length;
                    int expect = Cfg.UseIPv6 ? 42 : 23;
                    if (nw != expect)
                    {
                        U.Line("  Error: invalid receiver code.");
                        if (!Cfg.UseIPv6 && nw == 42) U.Line("  The receiver is using IPv6 (-6). Re-run: .\\p2p.ps1 send <file> -6 --long-code");
                        else if (Cfg.UseIPv6 && nw == 23) U.Line("  The receiver is using IPv4. Both sides must agree on -6 (or neither).");
                        else U.Line("  Make sure you copied the entire RECV CODE from the receiver's screen.");
                        return 1;
                    }
                    bool ok;
                    try { ok = Codes.DecodeRecv(rcode, secret, out peerPub, out peerLocal); }
                    catch (FormatException e) { ok = false; U.V("  " + e.Message); }
                    if (!ok)
                    {
                        U.Line("  Error: invalid receiver code.");
                        U.Line("  Make sure you copied the entire RECV CODE from the receiver's screen,");
                        U.Line("  and that the receiver used the SEND CODE you gave them (not an old one).");
                        return 1;
                    }
                    U.V("  Peer public : " + Net.FmtAddr(peerPub));
                    U.V("  Peer local  : " + Net.FmtAddr(peerLocal));
                }

                U.V("  Deriving handshake keys (PBKDF2, 100k rounds)...");
                Cipher hs = new Cipher(secret, salt, true);
                BigInteger dhPriv; byte[] dhPub;
                DH.Keypair(out dhPriv, out dhPub);

                IPEndPoint peer; byte[] peerDh;
                IPktSock xfer;
                try
                {
                    if (Cfg.UseRelay)
                    {
                        U.Line("  Relay mode: connecting through the relay" + (longCode ? " (receiver must also use --relay)." : "."));
                        relay = new RelaySock(Codes.RelayToken(secret), "s2r", "r2s");
                        xfer = relay;
                        if (!Proto.PunchHole(relay, hs, RelaySock.PeerAddr, RelaySock.PeerAddr, dhPub, connectTimeout, null, out peer, out peerDh))
                        {
                            U.Line("  Could not reach the receiver through the relay.");
                            U.Line("  Possible causes:");
                            U.Line("    - The receiver is not running 'recv --relay' right now");
                            U.Line("    - The receiver pasted a different (old) send code");
                            U.Line("    - The relay server became unreachable");
                            return 1;
                        }
                    }
                    else
                    {
                        xfer = sock;
                        if (!Proto.PunchHole(sock, hs, peerPub, peerLocal, dhPub, connectTimeout, Cfg.DirectHint, out peer, out peerDh))
                        {
                            U.Line("  Could not reach the receiver.");
                            U.Line("  Possible causes:");
                            U.Line("    - The receiver is not running 'recv' right now");
                            U.Line("    - The recv code is from a different session (try again from the start)");
                            U.Line("    - One or both sides are behind CG-NAT or symmetric NAT");
                            U.Line("  If direct connection keeps failing, run both sides with --relay.");
                            return 1;
                        }
                    }
                }
                catch (CancelledException) { U.Line("\n  Cancelled during connection."); return 0; }

                byte[] dhShared;
                try { dhShared = DH.Shared(dhPriv, peerDh); }
                catch (ArgumentException e) { U.Line("  Handshake error: " + e.Message); return 1; }
                U.V("  Forward-secret session keys established (DH + PBKDF2).");
                Cipher session = new Cipher(U.Cat(secret, dhShared), salt, true);

                bool sent = Proto.SendFile(xfer, peer, session, filepath, filesize, filehash, connectTimeout);
                if (!sent) return 1;
                U.Line("  Done -- file sent successfully!");
                return 0;
            }
            finally
            {
                if (relay != null) relay.Close();
                sock.Close();
            }
        }

        static int CmdRecv(int connectTimeout, string resumePath)
        {
            UdpSock sock; IPEndPoint local;
            BindUdp(out sock, out local);
            RelaySock relay = null;
            try
            {
                U.Line();
                U.Out("  Paste sender's code: ");
                string scode = ReadLine();
                if (scode == null) { U.Line("\n  Cancelled."); return 0; }
                scode = scode.Trim();
                if (scode.Length == 0) { U.Line("  No code entered."); return 1; }

                bool longCode;
                try
                {
                    string np; byte[] pw;
                    longCode = !Pake.ParseCode(scode, out np, out pw);
                }
                catch (FormatException e)
                {
                    U.Line("  Error: invalid sender code.");
                    U.Line("  " + e.Message + (e.Message.StartsWith("Unknown word") ? " (check the spelling)" : ""));
                    return 1;
                }

                int nw = Codes.Split(scode).Length;
                byte[] secret = null, salt = null;
                IPEndPoint pub = null, peerPub = null, peerLocal = null;
                if (!longCode)
                {
                    if (!Cfg.UseRelay && !Http.Reachable())    // RunInner already checked with --relay
                    {
                        U.Line("  Error: cannot reach the relay at " + Cfg.RelayHost + " to look up the code.");
                        U.Line("  Check your internet connection, or point at another relay with --relay-host.");
                        return 1;
                    }
                    PakeConnect(scode, false, sock, local, connectTimeout, out secret, out salt, out peerPub, out peerLocal);
                }
                else if (Cfg.UseRelay)
                {
                    if (nw == 36 || nw == 55)
                    {
                        U.Line("  Error: this is a direct-mode code (the sender did not use --relay).");
                        U.Line("  Both sides must use --relay, or neither.");
                        return 1;
                    }
                    try { secret = Codes.WordsToBytes(scode, 16); }
                    catch (FormatException e)
                    {
                        U.Line("  Error: invalid sender code.");
                        U.Line("  A relay code is " + Cfg.RelayCodeWords + " words. Make sure you copied the whole SEND CODE.");
                        if (e.Message.StartsWith("Unknown word")) U.Line("  " + e.Message + " (check the spelling)");
                        return 1;
                    }
                    salt = Codes.RelaySalt(secret);
                    U.Line();
                    U.Line("  Relay mode: nothing to send back. You only need the sender's code.");
                }
                else
                {
                    pub = Discover(sock, local);
                    if (nw == Cfg.RelayCodeWords)
                    {
                        U.Line("  Error: this is a relay code (the sender used --relay).");
                        U.Line("  Both sides must use --relay, or neither. Re-run: .\\p2p.ps1 recv --relay");
                        return 1;
                    }
                    bool codeV6;
                    try { Codes.DecodeSender(scode, out secret, out salt, out peerPub, out peerLocal, out codeV6); }
                    catch (FormatException e)
                    {
                        U.Line("  Error: invalid sender code.");
                        U.Line("  Make sure you copied the entire SEND CODE from the sender's screen.");
                        if (e.Message.StartsWith("Unknown word")) U.Line("  " + e.Message + " (check the spelling)");
                        return 1;
                    }
                    if (codeV6 != Cfg.UseIPv6)
                    {
                        U.Line("  Error: address-family mismatch.");
                        if (codeV6) U.Line("  The sender is using IPv6 (-6). Re-run: .\\p2p.ps1 recv -6");
                        else U.Line("  The sender is using IPv4. Both sides must agree on -6 (or neither).");
                        return 1;
                    }
                    U.V("  Peer public : " + Net.FmtAddr(peerPub));
                    U.V("  Peer local  : " + Net.FmtAddr(peerLocal));

                    string rcode = Codes.EncodeRecv(pub, local, secret);
                    U.Line();
                    U.Line("  +==========================================================+");
                    U.Line("  |  RECV CODE -- give this back to the sender:              |");
                    U.Line("  +==========================================================+");
                    U.Line();
                    U.Line("  " + rcode);
                    U.Line();
                }

                U.V("  Deriving handshake keys (PBKDF2, 100k rounds)...");
                Cipher hs = new Cipher(secret, salt, false);
                BigInteger dhPriv; byte[] dhPub;
                DH.Keypair(out dhPriv, out dhPub);

                IPEndPoint peer; byte[] peerDh;
                IPktSock xfer;
                try
                {
                    if (Cfg.UseRelay)
                    {
                        U.Line("  Relay mode: connecting through the relay" + (longCode ? " (sender must also use --relay)." : "."));
                        relay = new RelaySock(Codes.RelayToken(secret), "r2s", "s2r");
                        xfer = relay;
                        if (!Proto.PunchHole(relay, hs, RelaySock.PeerAddr, RelaySock.PeerAddr, dhPub, connectTimeout, null, out peer, out peerDh))
                        {
                            U.Line("  Could not reach the sender through the relay.");
                            U.Line("  Possible causes:");
                            U.Line("    - The sender is not running 'send --relay' right now");
                            U.Line("    - The send code you used is from a different (old) session");
                            U.Line("    - The relay server became unreachable");
                            return 1;
                        }
                    }
                    else
                    {
                        xfer = sock;
                        if (!Proto.PunchHole(sock, hs, peerPub, peerLocal, dhPub, connectTimeout, Cfg.DirectHint, out peer, out peerDh))
                        {
                            U.Line("  Could not reach the sender.");
                            U.Line("  Possible causes:");
                            U.Line("    - The sender has not yet pasted your recv code");
                            U.Line("    - The send code you used is from a different session");
                            U.Line("    - One or both sides are behind CG-NAT or symmetric NAT");
                            U.Line("  If direct connection keeps failing, run both sides with --relay.");
                            return 1;
                        }
                    }
                }
                catch (CancelledException) { U.Line("\n  Cancelled during connection."); return 0; }

                byte[] dhShared;
                try { dhShared = DH.Shared(dhPriv, peerDh); }
                catch (ArgumentException e) { U.Line("  Handshake error: " + e.Message); return 1; }
                U.V("  Forward-secret session keys established (DH + PBKDF2).");
                Cipher session = new Cipher(U.Cat(secret, dhShared), salt, false);

                Proto.RecvResult res = Proto.RecvFile(xfer, peer, session, connectTimeout, Cfg.MaxFileSize, resumePath);
                if (res == null) return 1;

                string savePath = Path.Combine(".", res.FileName);
                if (string.Equals(Path.GetFullPath(res.TempPath), Path.GetFullPath(savePath), StringComparison.OrdinalIgnoreCase))
                {
                    U.Line("  Saved: " + savePath);
                    U.Line("  Done -- file received successfully!");
                    return 0;
                }
                if (File.Exists(savePath) || Directory.Exists(savePath))
                {
                    if (resumePath == null) { try { File.Delete(res.TempPath); } catch { } }
                    U.Line("  Error: '" + savePath + "' already exists. Will not overwrite.");
                    if (resumePath != null) U.Line("  The received data is in: " + res.TempPath);
                    return 1;
                }
                try { File.Move(res.TempPath, savePath); }
                catch (Exception e)
                {
                    U.Line("  Error saving file to '" + savePath + "': " + e.Message);
                    U.Line("  The received data is in: " + res.TempPath);
                    return 1;
                }
                U.Line("  Saved: " + savePath);
                U.Line("  Done -- file received successfully!");
                return 0;
            }
            finally
            {
                if (relay != null) relay.Close();
                sock.Close();
            }
        }
    }
}

'@

if (-not ('P2PShellV2.App' -as [type])) {
    $addTypeArgs = @{
        TypeDefinition = $P2PEngineSource
        Language       = 'CSharp'
        IgnoreWarnings = $true
        WarningAction  = 'SilentlyContinue'
    }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 (.NET Framework) needs these spelled out.
        $addTypeArgs.ReferencedAssemblies = @('System.Numerics', 'System.Net.Http')
    }
    try {
        Add-Type @addTypeArgs
    } catch {
        Write-Host ""
        Write-Host "  Error: could not compile the transfer engine."
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
            Write-Host "  PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode on this machine"
            Write-Host "  (usually an AppLocker / Device Guard policy), which blocks Add-Type."
            Write-Host "  Ask your admin, or use p2p.py with Python instead."
        } else {
            Write-Host "  $($_.Exception.Message)"
        }
        exit 1
    }
}

# .NET resolves relative paths against the process directory, not PowerShell's
# current location, so line them up before handing over.
[Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath

$argv = [string[]]@($args | ForEach-Object { "$_" })
$code = [P2PShellV2.App]::Run($argv, $PSScriptRoot)
exit $code
