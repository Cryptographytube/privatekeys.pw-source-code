#!/usr/bin/env python3
"""
keygen.py - the crypto engine behind the CryptographyTube key directory.

Pure standard library. Given a private key (an integer 1..N-1) it derives, for
each supported coin, the public key and address(es) exactly the way
privatekeys.pw does, then renders the directory / key-detail / CSV pages that
serve.py serves.

This is deterministic enumeration of the key space for education (keys 1,2,3,...)
- the same thing the mirror demonstrates. Balances need a live backend and stay
empty offline.

Run `python keygen.py` to execute the self-tests (crypto is validated against
known mirror addresses before anything renders).
"""
import hashlib
import html
import os
import re
import secrets

# --------------------------------------------------------------------------
# secp256k1
# --------------------------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

PER_PAGE = 45
TOTAL_PAGES = -(-(N - 1) // PER_PAGE)   # ceil((N-1)/45)


def _inv(a):
    return pow(a, P - 2, P)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        m = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, point=G):
    """k*point via double-and-add."""
    k %= N
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def sha256(b):
    return hashlib.sha256(b).digest()


def ripemd160(b):
    return hashlib.new("ripemd160", b).digest()


def hash160(b):
    return ripemd160(sha256(b))


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def keccak256(data):
    """Original Keccak-256 (Ethereum's hash; NOT SHA3-256)."""
    rate = 136  # 1088-bit rate, 512-bit capacity
    m = bytearray(data)
    m.append(0x01)
    while len(m) % rate != 0:
        m.append(0x00)
    m[-1] ^= 0x80

    A = [[0] * 5 for _ in range(5)]

    def rol(v, n):
        n %= 64
        return ((v << n) | (v >> (64 - n))) & _MASK64

    for off in range(0, len(m), rate):
        for i in range(rate // 8):
            lane = int.from_bytes(m[off + i * 8: off + i * 8 + 8], "little")
            A[i % 5][i // 5] ^= lane
        for rnd in range(24):
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    A[x][y] ^= D[x]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], _KECCAK_ROT[x][y])
            for x in range(5):
                for y in range(5):
                    A[x][y] = (B[x][y] ^ ((~B[(x + 1) % 5][y] & _MASK64) & B[(x + 2) % 5][y])) & _MASK64
            A[0][0] ^= _KECCAK_RC[rnd]

    out = bytearray()
    for i in range(4):  # first 32 bytes of the rate
        out += (A[i % 5][i // 5] & _MASK64).to_bytes(8, "little")
    return bytes(out)


# --------------------------------------------------------------------------
# Base58 / Base58Check
# --------------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + s


def b58check(payload):
    return b58encode(payload + sha256(sha256(payload))[:4])


# --------------------------------------------------------------------------
# bech32 / bech32m (BIP173 / BIP350)
# --------------------------------------------------------------------------
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data, spec):
    const = 0x2bc830a3 if spec == "bech32m" else 1
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
    combined = data + _bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(_BECH32[d] for d in combined)


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_encode(hrp, witver, witprog):
    spec = "bech32" if witver == 0 else "bech32m"
    return bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)


# --------------------------------------------------------------------------
# CashAddr (Bitcoin Cash)
# --------------------------------------------------------------------------
def _cash_polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        if c0 & 0x01:
            c ^= 0x98f2bc8e61
        if c0 & 0x02:
            c ^= 0x79b76d99e2
        if c0 & 0x04:
            c ^= 0xf33e5fb3c4
        if c0 & 0x08:
            c ^= 0xae2eabe2a8
        if c0 & 0x10:
            c ^= 0x1e4f43e470
    return c ^ 1


def cashaddr_encode(prefix, version_byte, payload):
    data = bytes([version_byte]) + payload
    bits = convertbits(data, 8, 5)
    prefix_lower = [ord(x) & 0x1f for x in prefix] + [0]
    chk = _cash_polymod(prefix_lower + bits + [0] * 8)
    checksum = [(chk >> 5 * (7 - i)) & 0x1f for i in range(8)]
    return "".join(_BECH32[d] for d in bits + checksum)


# --------------------------------------------------------------------------
# Ethereum EIP-55
# --------------------------------------------------------------------------
def eip55(addr20):
    h = addr20.hex()
    k = keccak256(h.encode()).hex()
    out = ""
    for i, c in enumerate(h):
        if c in "0123456789":
            out += c
        else:
            out += c.upper() if int(k[i], 16) >= 8 else c
    return "0x" + out


# --------------------------------------------------------------------------
# Taproot (BIP341) - key-path only tweak
# --------------------------------------------------------------------------
def _tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def taproot_output_key(point):
    x, y = point
    if y % 2 != 0:                       # lift_x -> even Y internal key
        point = (x, P - y)
    t = int.from_bytes(_tagged_hash("TapTweak", x.to_bytes(32, "big")), "big") % N
    q = point_add(point, scalar_mul(t))
    return q[0].to_bytes(32, "big")


# --------------------------------------------------------------------------
# Public key serialization
# --------------------------------------------------------------------------
def ser_compressed(point):
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def ser_uncompressed(point):
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --------------------------------------------------------------------------
# Coin table (fixed tab order)
# --------------------------------------------------------------------------
COIN_ORDER = [
    "bitcoin", "bitcoin-testnet", "bitcoin-cash", "bitcoin-sv", "bitcoin-gold",
    "litecoin", "dogecoin", "dash", "zcash", "clams", "ethereum",
]

COINS = {
    "bitcoin":         dict(name="Bitcoin",         pub=b"\x00",     p2sh=b"\x05", wif=0x80, hrp="bc",  seg=True),
    "bitcoin-testnet": dict(name="Bitcoin Testnet", pub=b"\x6f",     p2sh=b"\xc4", wif=0xef, hrp="tb",  seg=True),
    "bitcoin-cash":    dict(name="Bitcoin Cash",    pub=b"\x00",     p2sh=b"\x05", wif=0x80, cash="bitcoincash"),
    "bitcoin-sv":      dict(name="Bitcoin SV",      pub=b"\x00",     p2sh=b"\x05", wif=0x80),
    "bitcoin-gold":    dict(name="Bitcoin Gold",    pub=b"\x26",     p2sh=b"\x17", wif=0x80),
    "litecoin":        dict(name="Litecoin",        pub=b"\x30",     p2sh=b"\x32", wif=0xb0, hrp="ltc", seg=True),
    "dogecoin":        dict(name="Dogecoin",        pub=b"\x1e",     p2sh=b"\x16", wif=0x9e),
    "dash":            dict(name="Dash",            pub=b"\x4c",     p2sh=b"\x10", wif=0xcc),
    "zcash":           dict(name="Zcash",           pub=b"\x1c\xb8", p2sh=b"\x1c\xbd", wif=0x80),
    "clams":           dict(name="Clams",           pub=b"\x89",     p2sh=b"\x0d", wif=0x85),
    "ethereum":        dict(name="Ethereum",        eth=True),
}


def wif(coin, d, compressed):
    c = COINS[coin]
    payload = bytes([c["wif"]]) + d.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check(payload)


def legacy_address(coin, h160):
    return b58check(COINS[coin]["pub"] + h160)


# --------------------------------------------------------------------------
# Known solved Bitcoin-puzzle private keys (public data). Puzzle number for a
# key k is simply k.bit_length(). Used only for the cosmetic "Puzzle #n" badge.
# --------------------------------------------------------------------------
PUZZLE_KEYS = {
    1, 3, 7, 8, 21, 49, 76, 224, 467, 514, 1155, 2683, 5216, 10544, 26867,
    51510, 95823, 198669, 357535, 863317, 1811764, 3007503, 5598802, 14428676,
    33185509, 54538862, 111949941, 227634408, 400708894, 1033162084, 2102388551,
    3093472814, 7137437912, 14133072157, 20112871792, 42387769980, 100251560595,
    146971536592, 323724968937, 1003651412950, 1458252205147, 2895374552463,
    7409811047825, 15404761757071, 19996463086597, 51408670348612, 119666659114170,
    191206974700443, 409118905032525, 611140496167764, 2058769515153876,
    4216495639600700, 6763683971478124, 9974455244496707, 30045390491869460,
    44218742292676575, 138245758910846492, 199976667976342049, 525070384258266191,
    1135041350219496382, 1425787542618654982, 3908372542507822062,
    8993229949524469768, 17799667357578236628, 30568377312064202855,
    46346217550346335726, 132656943602386256302,
}


def is_puzzle(k):
    return k in PUZZLE_KEYS


# --------------------------------------------------------------------------
# Address derivation for the directory table
# --------------------------------------------------------------------------
def directory_rows(coin, point, d, addr_type):
    """Return a list of (icon_html, icon_title, address) for one key."""
    c = COINS[coin]
    comp = ser_compressed(point)
    unc = ser_uncompressed(point)

    if c.get("eth"):
        body = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        addr = eip55(keccak256(body)[12:])
        return [("blockies", addr.lower(), addr)]

    if c.get("cash"):
        return [
            ("C", "Legacy (compressed)", cashaddr_encode(c["cash"], 0, hash160(comp))),
            ("U", "Legacy (uncompressed)", cashaddr_encode(c["cash"], 0, hash160(unc))),
        ]

    if c.get("seg") and addr_type == "segwit":
        return [("C", "SegWit (P2WPKH)", segwit_encode(c["hrp"], 0, hash160(comp)))]
    if c.get("seg") and addr_type == "segwit-p2sh":
        redeem = b"\x00\x14" + hash160(comp)
        return [("C", "Script (P2WPKH-in-P2SH)", b58check(c["p2sh"] + hash160(redeem)))]
    if c.get("seg") and addr_type == "taproot":
        return [("X", "Taproot (P2TR)", segwit_encode(c["hrp"], 1, taproot_output_key(point)))]

    # default: legacy P2PKH compressed + uncompressed
    return [
        ("C", "Legacy (compressed)", legacy_address(coin, hash160(comp))),
        ("U", "Legacy (uncompressed)", legacy_address(coin, hash160(unc))),
    ]


def detail_addresses(coin, point):
    """Every address type a coin supports, for the /key detail page."""
    c = COINS[coin]
    comp = ser_compressed(point)
    unc = ser_uncompressed(point)
    if c.get("eth"):
        body = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        a = eip55(keccak256(body)[12:])
        return [("blockies", a.lower(), a)]
    if c.get("cash"):
        return [
            ("C", "Legacy (compressed)", cashaddr_encode(c["cash"], 0, hash160(comp))),
            ("U", "Legacy (uncompressed)", cashaddr_encode(c["cash"], 0, hash160(unc))),
        ]
    rows = [
        ("C", "Legacy (compressed)", legacy_address(coin, hash160(comp))),
        ("U", "Legacy (uncompressed)", legacy_address(coin, hash160(unc))),
    ]
    if c.get("seg"):
        redeem = b"\x00\x14" + hash160(comp)
        rows.append(("S", "Script", b58check(c["p2sh"] + hash160(redeem))))
        rows.append(("W", "SegWit", segwit_encode(c["hrp"], 0, hash160(comp))))
        rows.append(("T", "Taproot", segwit_encode(c["hrp"], 1, taproot_output_key(point))))
    return rows


# ==========================================================================
# HTML rendering
# ==========================================================================
ROOT = os.path.dirname(os.path.abspath(__file__))
_SHELL = None

_FALLBACK_PREFIX = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    '<title>Keys</title><meta name="description" content="">'
    '<link rel="stylesheet" href="/assets/app-F7rovCNy.css">'
    '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">'
    "</head><body>"
)
_FALLBACK_SUFFIX = (
    '<link rel="modulepreload" href="/assets/app-DERGi70t.js" />'
    '<script type="module" src="/assets/app-DERGi70t.js"></script></body></html>'
)


def _load_shell():
    """head+navbar / footer+scripts, taken from a mirror page so styling matches."""
    global _SHELL
    if _SHELL is None:
        try:
            with open(os.path.join(ROOT, "keys", "bitcoin", "1.html"), encoding="utf-8") as f:
                doc = f.read()
            i = doc.index('<main role="main">')
            j = doc.index("</main>") + len("</main>")
            _SHELL = (doc[:i], doc[j:])
        except Exception:
            _SHELL = (_FALLBACK_PREFIX, _FALLBACK_SUFFIX)
    return _SHELL


def _page(title, description, main_inner):
    prefix, suffix = _load_shell()
    prefix = re.sub(r"<title>.*?</title>",
                    lambda m: "<title>" + html.escape(title) + "</title>",
                    prefix, count=1, flags=re.S)
    prefix = re.sub(r'(<meta name="description" content=")[^"]*(">)',
                    lambda m: m.group(1) + html.escape(description, quote=True) + m.group(2),
                    prefix, count=1)
    return prefix + '<main role="main">' + main_inner + "</main>" + suffix


def _big_display(m):
    s = str(m)
    if len(s) <= 7:
        return s
    return "%s.%s×10<sup>%d</sup>…%s" % (s[0], s[1:4], len(s) - 1, s[-3:])


def _pct(page, total):
    val = page / total * 100.0
    if val >= 100:
        return "100"
    s = ("%.5f" % round(val, 5)).rstrip("0").rstrip(".")
    return s if s and s != "0" else "0"


def _coin_tabs(active):
    out = []
    for slug in COIN_ORDER:
        cls = "nav-link  active " if slug == active else "nav-link "
        out.append('<li class="nav-item"><a class="%s" href="/keys/%s/1">%s</a></li>'
                   % (cls, slug, COINS[slug]["name"]))
    return "\n".join(out)


def _nav_query(addr_type, extra):
    parts = []
    if extra:
        parts.append(extra)
    if addr_type and addr_type != "legacy":
        parts.append("type=" + addr_type)
    return ("?" + "&".join(parts)) if parts else ""


def _pagination(coin, page, addr_type):
    rnd = secrets.randbelow(TOTAL_PAGES) + 1

    def li(enabled, href, icon, label):
        cls = "page-item flex-fill" if enabled else "page-item flex-fill disabled"
        target = href if enabled else "#"
        return ('<li class="%s"><a class="page-link text-center" href="%s">'
                '<i class="fa %s" aria-hidden="true"></i> %s</a></li>'
                % (cls, target, icon, label))

    return "\n".join([
        li(page > 1, "/keys/%s/1%s" % (coin, _nav_query(addr_type, None)), "fa-fast-backward", "First"),
        li(page > 1, "/keys/%s/%d%s" % (coin, page - 1, _nav_query(addr_type, "previous=1")), "fa-step-backward", "Previous"),
        li(True, "/keys/%s/%d%s" % (coin, rnd, _nav_query(addr_type, "random=1")), "fa-random", "Random"),
        li(page < TOTAL_PAGES, "/keys/%s/%d%s" % (coin, page + 1, _nav_query(addr_type, "next=1")), "fa-step-forward", "Next"),
        li(page < TOTAL_PAGES, "/keys/%s/%d%s" % (coin, TOTAL_PAGES, _nav_query(addr_type, "last=1")), "fa-fast-forward", "Last"),
    ])


def _addr_header(coin, page, addr_type):
    name = COINS[coin]["name"]
    if not COINS[coin].get("seg"):
        return "%s Address" % name
    types = [("legacy", "Legacy (P2PKH)"), ("segwit", "SegWit (P2WPKH)"),
             ("segwit-p2sh", "Script (P2WPKH-in-P2SH)"), ("taproot", "Taproot (P2TR)")]
    cur = dict(types).get(addr_type, "Legacy (P2PKH)")
    items = []
    for tid, label in types:
        active = " active " if (addr_type or "legacy") == tid else ""
        q = "" if tid == "legacy" else "?type=" + tid
        items.append('<li><a class="dropdown-item %s" href="/keys/%s/%s%s">%s</a></li>'
                     % (active, coin, page, q, label))
    return ('<div class="d-flex align-items-center gap-2">%s Address'
            '<div class="dropdown"><a class="dropdown-toggle fw-normal text-decoration-none" '
            'type="button" data-bs-toggle="dropdown" aria-expanded="false">%s</a>'
            '<ul class="dropdown-menu">%s</ul></div></div>' % (name, cur, "".join(items)))


def _addr_html(coin, icon, title, addr):
    a = html.escape(addr, quote=True)
    if icon == "blockies":
        icon_html = ('<span class="js-blockies" data-seed="%s" title="Ethereum" '
                     'data-bs-toggle="tooltip"></span>' % title)
    else:
        icon_html = ('<span class="icon" title="%s" data-bs-toggle="tooltip">%s</span>'
                     % (title, icon))
    return (
        '<span class="d-flex"><span class="me-1">%s</span>'
        '<span class="d-flex flex-wrap"><span class="hover me-1">'
        '<span class="wrap">%s</span><span class="buttons">'
        '<a href="/address/%s/%s" title="Info" data-bs-toggle="tooltip"><i class="fas fa-info"></i></a>'
        '<button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="%s"><i class="far fa-copy"></i></button>'
        '</span></span><span class="js-balance-%s" data-address="%s"></span></span></span>'
        % (icon_html, a, coin, a, a, coin, a)
    )


def _key_cell(coin, page, k):
    hexk = "%064x" % k
    badges = ""
    if k == 1:
        badges += ('<span class="badge bg-secondary" title="" data-bs-toggle="tooltip">'
                   "Key range start</span>")
    if is_puzzle(k):
        badges += ('<span class="badge bg-secondary" title="Bitcoin Puzzle Transaction" '
                   'data-bs-toggle="tooltip">Puzzle #%d</span>' % k.bit_length())
    return (
        '<span class="d-flex"><span class="me-1">'
        '<i class="fas fa-key" aria-hidden="true" title="Private Key" data-bs-toggle="tooltip"></i></span>'
        '<span class="d-flex flex-column"><span class="hover">'
        '<a href="/key/%s" class="wrap">%s</a><span class="buttons">'
        '<a href="/keys/%s/%s#%s" title="Navigate" data-bs-toggle="tooltip"><i class="fas fa-link"></i></a>'
        '<button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="%s"><i class="far fa-copy"></i></button>'
        '</span></span><span>%s</span></span></span>'
        % (hexk, hexk, coin, page, hexk, hexk, badges)
    )


def render_directory(coin, page, addr_type="legacy"):
    if coin not in COINS:
        return None
    page = max(1, min(int(page), TOTAL_PAGES))
    if not COINS[coin].get("seg"):
        addr_type = "legacy"
    name = COINS[coin]["name"]
    start = (page - 1) * PER_PAGE + 1
    end = min(start + PER_PAGE - 1, N - 1)

    point = scalar_mul(start)
    rows = []
    k = start
    while k <= end:
        divs = "".join("<div>%s</div>" % _addr_html(coin, ic, ti, ad)
                       for ic, ti, ad in directory_rows(coin, point, k, addr_type))
        rows.append('<tr id="%064x"><td>%s</td><td>%s</td></tr>'
                    % (k, _key_cell(coin, page, k), divs))
        if k < end:
            point = point_add(point, G)
        k += 1

    pct = _pct(page, TOTAL_PAGES)
    main_inner = (
        '\n        <div class="container">\n'
        '        <ul class="nav nav-underline mb-3">\n' + _coin_tabs(coin) + "\n    </ul>\n\n"
        "        <h1>" + name + " Private Keys Directory</h1>\n\n"
        "        <p>A complete list of all possible " + name +
        " private keys, including their addresses and balances.</p>\n\n"
        '        <p>Page <span class="fw-bold" data-bs-toggle="tooltip" title="' + str(page) + '">#'
        + _big_display(page) + "</span> of\n"
        '    <span class="fw-bold" data-bs-toggle="tooltip" title="' + str(TOTAL_PAGES) + '">'
        + _big_display(TOTAL_PAGES) + "</span>\n    (" + pct + "%).</p>\n\n"
        '        <div class="row mb-3">\n'
        '    <div class="col-md mb-3 mb-md-0 align-items-center d-flex">\n'
        '        <div style="display: none">\n            Total balance on the page:\n'
        '            <span class="js-balances-' + coin + '"></span>\n        </div>\n    </div>\n'
        '    <div class="col-md-auto"><nav><ul class="pagination mb-0">\n'
        + _pagination(coin, page, addr_type) + "\n    </ul></nav></div>\n</div>\n\n"
        '        <div class="progress" role="progressbar" aria-valuenow="' + pct +
        '" aria-valuemin="0" aria-valuemax="100" title="' + pct +
        '%" data-bs-toggle="tooltip" style="height: 2px">\n'
        '    <div class="progress-bar" style="width: ' + pct + '%;"></div>\n</div>\n\n'
        '        <div class="table-adaptive">\n'
        '    <table class="table table-borderless table-striped table-hover">\n'
        "        <thead><tr>\n            <th>Private Key (HEX)</th>\n            <th>"
        + _addr_header(coin, page, addr_type) + "</th>\n        </tr></thead>\n        <tbody>\n"
        + "\n".join(rows) + "\n        </tbody>\n    </table>\n</div>\n\n"
        '        <div class="row mb-3">\n'
        '    <div class="col-md mb-2 mb-md-0"><div class="btn-group d-flex d-md-inline-flex" role="group">\n'
        '        <a href="/keys/' + coin + "/" + str(page) + '/export" class="btn btn-outline-success">'
        '<i class="fas fa-download"></i> Export as CSV</a>\n    </div></div>\n'
        '    <div class="col-md mb-2 mb-md-0">\n'
        '        <form action="/keys/' + coin + "/" + str(page) + '" method="get" role="form" class="d-flex">\n'
        '            <div class="input-group w-auto flex-fill flex-md-grow-0">\n'
        '                <input class="form-control" type="number" name="page" min="1" placeholder="Page Number" aria-label="Page Number" required>\n'
        '                <input type="hidden" name="jump" value="1">\n'
        '                <button class="btn border bg-body-secondary" type="submit">Jump</button>\n'
        "            </div>\n        </form>\n    </div>\n"
        '    <div class="col-md-auto"><nav><ul class="pagination mb-0">\n'
        + _pagination(coin, page, addr_type) + "\n    </ul></nav></div>\n</div>\n    </div>"
    )
    return _page(name + " Private Keys Directory",
                 "Explore the complete database of " + name +
                 " private keys in decimal, hex or WIF format", main_inner)


def render_csv(coin, page):
    if coin not in COINS:
        return None
    page = max(1, min(int(page), TOTAL_PAGES))
    start = (page - 1) * PER_PAGE + 1
    end = min(start + PER_PAGE - 1, N - 1)
    point = scalar_mul(start)
    out = ["private_key_hex,private_key_dec,type,address"]
    k = start
    while k <= end:
        hexk = "%064x" % k
        for ic, ti, ad in detail_addresses(coin, point):
            out.append("%s,%d,%s,%s" % (hexk, k, ti.replace(",", " "), ad))
        if k < end:
            point = point_add(point, G)
        k += 1
    return ("\n".join(out) + "\n").encode("utf-8")


def _copy_line(label, value, disp=None):
    disp = disp if disp is not None else html.escape(value)
    return ('<li class="list-group-item"><div class="fw-bold">%s</div>'
            '<span class="wrap"><span class="hover">%s<span class="buttons">'
            '<button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="%s">'
            '<i class="far fa-copy"></i></button></span></span></span></li>'
            % (label, disp, html.escape(value, quote=True)))


def _icon_value(icon, title, value):
    v = html.escape(value, quote=True)
    return ('<span class="d-flex"><span class="me-1">'
            '<span class="icon" title="%s" data-bs-toggle="tooltip">%s</span></span>'
            '<span class="d-flex flex-wrap"><span class="hover me-1"><span class="wrap">%s</span>'
            '<span class="buttons"><button class="copy" title="Copy" data-bs-toggle="tooltip" '
            'data-clipboard-text="%s"><i class="far fa-copy"></i></button></span></span></span></span>'
            % (title, icon, v, v))


def render_key_detail(hexkey):
    try:
        k = int(hexkey, 16)
    except (ValueError, TypeError):
        return None
    if not (1 <= k < N):
        return None
    import base64
    hexk = "%064x" % k
    point = scalar_mul(k)
    comp = ser_compressed(point)
    unc = ser_uncompressed(point)
    kb = k.to_bytes(32, "big")
    page = (k - 1) // PER_PAGE + 1
    pct = _pct(page, TOTAL_PAGES)
    first, last = "%064x" % 1, "%064x" % (N - 1)
    prev = "%064x" % (k - 1) if k > 1 else first
    nxt = "%064x" % (k + 1) if k < N - 1 else last
    rnd = "%064x" % (secrets.randbelow(N - 1) + 1)
    ascii_html = "".join("&#x%02x;" % b for b in kb)
    binary = " ".join(format(b, "08b") for b in kb)
    b64 = base64.b64encode(kb).decode()

    overview = (
        '<div class="card"><div class="card-header">Overview</div>'
        '<ul class="list-group list-group-flush">'
        + _copy_line("HEX:", hexk)
        + _copy_line("Decimal:", str(k))
        + _copy_line("ASCII:", ascii_html, ascii_html)
        + _copy_line("Binary:", binary, binary)
        + _copy_line("Base64:", b64)
        + ('<li class="list-group-item"><div class="fw-bold">Page:</div>'
           '<a href="/keys/bitcoin/%d#%s">%d</a> (%s%%)</li>' % (page, hexk, page, pct))
        + "</ul></div>"
    )

    def tab(tid, label, active):
        cls = "nav-link  active " if active else "nav-link "
        sel = "true" if active else "false"
        return ('<li class="nav-item" role="presentation"><a id="%s-tab" href="#%s" role="tab" '
                'class="%s" data-bs-toggle="tab" data-bs-target="#%s" aria-controls="%s" '
                'aria-selected="%s">%s</a></li>' % (tid, tid, cls, tid, tid, sel, label))

    tabs = ('<ul class="nav nav-tabs" role="tablist">'
            + tab("addresses", "Public Addresses", True)
            + tab("public", "Public Keys", False)
            + tab("wif", "Wallet Import Format (WIF)", False) + "</ul>")

    # Public Addresses pane
    addr_items = []
    for slug in COIN_ORDER:
        divs = "".join('<div class="wrap">%s</div>' % _addr_html(slug, ic, ti, ad)
                       for ic, ti, ad in detail_addresses(slug, point))
        addr_items.append('<li class="list-group-item"><div class="fw-bold">%s Address:</div>%s</li>'
                          % (COINS[slug]["name"], divs))
    addr_pane = ('<div id="addresses" class="tab-pane  active " role="tabpanel" '
                 'aria-labelledby="addresses-tab"><ul class="list-group balance-autoload">'
                 + "".join(addr_items) + "</ul></div>")

    # Public Keys pane
    body = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    pub_items = [
        '<li class="list-group-item"><div class="fw-bold">Public Key:</div>%s%s</li>'
        % (_icon_value("C", "Compressed", comp.hex()), _icon_value("U", "Uncompressed", unc.hex())),
        '<li class="list-group-item"><div class="fw-bold">Public Key Hash (HASH160):</div>%s%s</li>'
        % (_icon_value("C", "Compressed", hash160(comp).hex()), _icon_value("U", "Uncompressed", hash160(unc).hex())),
        '<li class="list-group-item"><div class="fw-bold">Public Key Hash (Keccak 256):</div>%s</li>'
        % _icon_value("U", "Uncompressed", keccak256(body).hex()),
        '<li class="list-group-item"><div class="fw-bold">Taproot Public Key:</div>%s</li>'
        % _icon_value("X", "Compressed", taproot_output_key(point).hex()),
    ]
    pub_pane = ('<div id="public" class="tab-pane " role="tabpanel" aria-labelledby="public-tab">'
                '<ul class="list-group">' + "".join(pub_items) + "</ul></div>")

    # WIF pane
    wif_items = []
    for slug in COIN_ORDER:
        if COINS[slug].get("eth"):
            continue
        wif_items.append('<li class="list-group-item"><div class="fw-bold">%s WIF:</div>'
                         '<div class="wrap">%s</div><div class="wrap">%s</div></li>'
                         % (COINS[slug]["name"],
                            _icon_value("C", "Compressed", wif(slug, k, True)),
                            _icon_value("U", "Uncompressed", wif(slug, k, False))))
    wif_pane = ('<div id="wif" class="tab-pane " role="tabpanel" aria-labelledby="wif-tab">'
                '<ul class="list-group">' + "".join(wif_items) + "</ul></div>")

    nav = ('<div class="mb-3 btn-group btn-group-sm">'
           '<a href="/key/%s?first=1" class="btn btn-outline-secondary"><i class="fa fa-fast-backward"></i> First</a>'
           '<a href="/key/%s?prev=1" class="btn btn-outline-secondary"><i class="fa fa-step-backward"></i> Previous</a>'
           '<a href="/key/%s?random=1" class="btn btn-outline-secondary"><i class="fa fa-random"></i> Random</a>'
           '<a href="/key/%s?next=1" class="btn btn-outline-secondary"><i class="fa fa-step-forward"></i> Next</a>'
           '<a href="/key/%s?last=1" class="btn btn-outline-secondary"><i class="fa fa-fast-forward"></i> Last</a>'
           "</div>" % (first, prev, rnd, nxt, last))

    main_inner = (
        '<div class="container">'
        '<h1 class="h2 wrap"><i class="fas fa-key" title="Private Key"></i> ' + hexk + "</h1>"
        + nav
        + '<div class="row mb-3"><div class="col-md-9 mb-3 mb-md-0">' + overview + "</div>"
        '<div class="col col-md-3"><div class="card"><div class="card-header">QR Code</div>'
        '<div class="card-body d-flex flex-column align-items-center">'
        '<div class="qrcode" data-content="' + hexk + '"></div></div></div></div></div>'
        + tabs + '<div class="tab-content">' + addr_pane + pub_pane + wif_pane + "</div></div>"
    )
    return _page(hexk + " - Private Keys Directory",
                 "Bitcoin private key " + hexk +
                 " in WIF, decimal and hex format. Public key and address", main_inner)


# --------------------------------------------------------------------------
# Self tests
# --------------------------------------------------------------------------
def _selftest():
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak256 empty"

    pt1 = scalar_mul(1)
    comp = ser_compressed(pt1)
    unc = ser_uncompressed(pt1)

    checks = {
        ("bitcoin", "C"): "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        ("bitcoin", "U"): "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        ("bitcoin-testnet", "C"): "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
        ("bitcoin-sv", "C"): "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        ("bitcoin-gold", "C"): "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5",
        ("litecoin", "C"): "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
        ("dogecoin", "C"): "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE",
        ("dash", "C"): "XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE",
        ("zcash", "C"): "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs",
        ("clams", "C"): "xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx",
    }
    for (coin, kind), expect in checks.items():
        h = hash160(comp if kind == "C" else unc)
        got = legacy_address(coin, h)
        assert got == expect, f"{coin} {kind}: got {got} expect {expect}"

    # Bitcoin Cash cashaddr
    assert cashaddr_encode("bitcoincash", 0, hash160(comp)) == \
        "qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h", "BCH cashaddr C"

    # Ethereum
    body = pt1[0].to_bytes(32, "big") + pt1[1].to_bytes(32, "big")
    assert eip55(keccak256(body)[12:]) == \
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "ETH key1"

    # Page math matches the mirror
    assert TOTAL_PAGES == \
        2573157538607026564968244111304175730063056983979442319613448069811514699875, \
        f"TOTAL_PAGES={TOTAL_PAGES}"

    # SegWit / Taproot / Script, verified against the mirror's own /key detail page
    kv = 0x20f5df9cba8251e90a66d3aa1ca2849b12eaca135abb837671ac4a2bc2014e2b
    got = {ti: ad for ic, ti, ad in detail_addresses("bitcoin", scalar_mul(kv))}
    expect = {
        "Legacy (compressed)":   "1FzWgBzf5aHzWoHqjJeZa5nuGRS2mp2h7t",
        "Legacy (uncompressed)": "1JKb1617p68H5MPkoNaMtaJCqKDU3h8qSn",
        "Script":                "37tLj3YhnDU7LZQgdL63JVHA1RwcsBM27q",
        "SegWit":                "bc1q53eru2ynh8yx6yhpsatqd5qag7k27gpkpsva99",
        "Taproot":               "bc1phpdeqzpewx96frx3kjjzzem2spypxcn5mu2f6sfhjcpz3ktm3x9swfvhte",
    }
    for ti, ex in expect.items():
        assert got[ti] == ex, f"btc {ti}: got {got[ti]} expect {ex}"

    # Renderers produce pages without crashing and contain the right anchors
    d = render_directory("bitcoin", 1)
    assert d and 'id="0000000000000000000000000000000000000000000000000000000000000001"' in d
    assert "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" in d
    assert "/keys/bitcoin/2" in d and "page-item flex-fill disabled" in d  # First/Prev disabled
    last = render_directory("bitcoin", TOTAL_PAGES)
    assert last and f"/keys/bitcoin/{TOTAL_PAGES}" in last
    seg = render_directory("bitcoin", 1, "segwit")
    assert seg and "bc1q" in seg
    tap = render_directory("bitcoin", 1, "taproot")
    assert tap and "bc1p" in tap
    eth = render_directory("ethereum", 1)
    assert eth and "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" in eth
    kd = render_key_detail("%064x" % kv)
    assert kd and "1FzWgBzf5aHzWoHqjJeZa5nuGRS2mp2h7t" in kd and "WIF" in kd
    csv = render_csv("bitcoin", 1)
    assert csv and csv.startswith(b"private_key_hex") and b"1BgGZ9" in csv

    print("keygen self-test: ALL PASS")
    print("  TOTAL_PAGES =", TOTAL_PAGES)


if __name__ == "__main__":
    _selftest()
