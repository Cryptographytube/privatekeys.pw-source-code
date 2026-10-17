// search-core.js — pure (no DOM) key parsing and derivation behind the Search
// pages (/search/<coin>) and the navbar Quick Search (/quick-search): SHA-512,
// HMAC, PBKDF2, BIP39, BIP32, Electrum seeds (new and legacy), WIF / mini /
// extended keys, and the list of interpretations the site shows for a query.
// Used by search.js in the browser and by the Node verifier.
import { sha256, base58, intToBytes32, hex64 } from "./keygen-core.js";
import { getPublicKey } from "./secp256k1.js";

export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const MAX_KEYS = 45;

const enc = new TextEncoder();
const utf8 = (s) => enc.encode(s);

function concat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const HEX = "0123456789abcdef";
export function toHex(bytes) { let s = ""; for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15]; return s; }
export function bytesToInt(b) { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; }
const reversed = (b) => Uint8Array.from(b).reverse();
export const validKey = (n) => n > 0n && n < N;

/* ---- SHA-512 (64-bit words as hi/lo 32-bit pairs) ---- */
const K512 = new Int32Array([0x428a2f98,0xd728ae22,0x71374491,0x23ef65cd,0xb5c0fbcf,0xec4d3b2f,0xe9b5dba5,0x8189dbbc,0x3956c25b,0xf348b538,0x59f111f1,0xb605d019,0x923f82a4,0xaf194f9b,0xab1c5ed5,0xda6d8118,0xd807aa98,0xa3030242,0x12835b01,0x45706fbe,0x243185be,0x4ee4b28c,0x550c7dc3,0xd5ffb4e2,0x72be5d74,0xf27b896f,0x80deb1fe,0x3b1696b1,0x9bdc06a7,0x25c71235,0xc19bf174,0xcf692694,0xe49b69c1,0x9ef14ad2,0xefbe4786,0x384f25e3,0x0fc19dc6,0x8b8cd5b5,0x240ca1cc,0x77ac9c65,0x2de92c6f,0x592b0275,0x4a7484aa,0x6ea6e483,0x5cb0a9dc,0xbd41fbd4,0x76f988da,0x831153b5,0x983e5152,0xee66dfab,0xa831c66d,0x2db43210,0xb00327c8,0x98fb213f,0xbf597fc7,0xbeef0ee4,0xc6e00bf3,0x3da88fc2,0xd5a79147,0x930aa725,0x06ca6351,0xe003826f,0x14292967,0x0a0e6e70,0x27b70a85,0x46d22ffc,0x2e1b2138,0x5c26c926,0x4d2c6dfc,0x5ac42aed,0x53380d13,0x9d95b3df,0x650a7354,0x8baf63de,0x766a0abb,0x3c77b2a8,0x81c2c92e,0x47edaee6,0x92722c85,0x1482353b,0xa2bfe8a1,0x4cf10364,0xa81a664b,0xbc423001,0xc24b8b70,0xd0f89791,0xc76c51a3,0x0654be30,0xd192e819,0xd6ef5218,0xd6990624,0x5565a910,0xf40e3585,0x5771202a,0x106aa070,0x32bbd1b8,0x19a4c116,0xb8d2d0c8,0x1e376c08,0x5141ab53,0x2748774c,0xdf8eeb99,0x34b0bcb5,0xe19b48a8,0x391c0cb3,0xc5c95a63,0x4ed8aa4a,0xe3418acb,0x5b9cca4f,0x7763e373,0x682e6ff3,0xd6b2b8a3,0x748f82ee,0x5defb2fc,0x78a5636f,0x43172f60,0x84c87814,0xa1f0ab72,0x8cc70208,0x1a6439ec,0x90befffa,0x23631e28,0xa4506ceb,0xde82bde9,0xbef9a3f7,0xb2c67915,0xc67178f2,0xe372532b,0xca273ece,0xea26619c,0xd186b8c7,0x21c0c207,0xeada7dd6,0xcde0eb1e,0xf57d4f7f,0xee6ed178,0x06f067aa,0x72176fba,0x0a637dc5,0xa2c898a6,0x113f9804,0xbef90dae,0x1b710b35,0x131c471b,0x28db77f5,0x23047d84,0x32caab7b,0x40c72493,0x3c9ebe0a,0x15c9bebc,0x431d67c4,0x9c100d4c,0x4cc5d4be,0xcb3e42b6,0x597f299c,0xfc657e2a,0x5fcb6fab,0x3ad6faec,0x6c44198c,0x4a475817]);
const IV512 = new Int32Array([0x6a09e667,0xf3bcc908,0xbb67ae85,0x84caa73b,0x3c6ef372,0xfe94f82b,0xa54ff53a,0x5f1d36f1,0x510e527f,0xade682d1,0x9b05688c,0x2b3e6c1f,0x1f83d9ab,0xfb41bd6b,0x5be0cd19,0x137e2179]);
const W = new Int32Array(160);
const TWO32 = 4294967296;

function compress512(H, m, off) {
  for (let i = 0; i < 32; i++) {
    const j = off + 4 * i;
    W[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
  }
  for (let i = 32; i < 160; i += 2) {
    let xh = W[i - 30], xl = W[i - 29];                       // W[t-15]
    const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
    const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
    xh = W[i - 4]; xl = W[i - 3];                              // W[t-2]
    const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
    const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
    const l = (s1l >>> 0) + (W[i - 13] >>> 0) + (s0l >>> 0) + (W[i - 31] >>> 0);
    W[i] = s1h + W[i - 14] + s0h + W[i - 32] + ((l / TWO32) | 0);
    W[i + 1] = l;
  }
  let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
  let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
  for (let i = 0; i < 160; i += 2) {
    const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
    const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
    const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
    const t1 = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K512[i + 1] >>> 0) + (W[i + 1] >>> 0);
    const T1l = t1 >>> 0, T1h = (hh + S1h + chh + K512[i] + W[i] + ((t1 / TWO32) | 0)) | 0;
    const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
    const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
    const mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
    const t2 = (S0l >>> 0) + (mjl >>> 0);
    const T2l = t2 >>> 0, T2h = (S0h + mjh + ((t2 / TWO32) | 0)) | 0;
    const ne = (dl >>> 0) + T1l, na = T1l + T2l;
    hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
    eh = (dh + T1h + ((ne / TWO32) | 0)) | 0; el = ne | 0;
    dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
    ah = (T1h + T2h + ((na / TWO32) | 0)) | 0; al = na | 0;
  }
  const v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
  for (let k = 0; k < 16; k += 2) {
    const l = (H[k + 1] >>> 0) + (v[k + 1] >>> 0);
    H[k] = H[k] + v[k] + ((l / TWO32) | 0);
    H[k + 1] = l;
  }
}

function digest512(H) {
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    out[4 * i] = H[i] >>> 24; out[4 * i + 1] = H[i] >>> 16; out[4 * i + 2] = H[i] >>> 8; out[4 * i + 3] = H[i];
  }
  return out;
}

export function sha512(msg) {
  const len = msg.length;
  const buf = new Uint8Array(Math.ceil((len + 17) / 128) * 128);
  buf.set(msg); buf[len] = 0x80;
  const bits = len * 8, hi = Math.floor(bits / TWO32), e = buf.length;
  buf[e - 1] = bits; buf[e - 2] = bits >>> 8; buf[e - 3] = bits >>> 16; buf[e - 4] = bits >>> 24;
  buf[e - 5] = hi; buf[e - 6] = hi >>> 8; buf[e - 7] = hi >>> 16; buf[e - 8] = hi >>> 24;
  const H = Int32Array.from(IV512);
  for (let o = 0; o < buf.length; o += 128) compress512(H, buf, o);
  return digest512(H);
}

function hmacPads(key) {
  const k = new Uint8Array(128);
  k.set(key.length > 128 ? sha512(key) : key);
  const ip = new Uint8Array(128), op = new Uint8Array(128);
  for (let i = 0; i < 128; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
  return [ip, op];
}

export function hmacSha512(key, msg) {
  const [ip, op] = hmacPads(key);
  return sha512(concat(op, sha512(concat(ip, msg))));
}

// PBKDF2-HMAC-SHA512 with a 64-byte output (one block), as BIP39 and Electrum use.
export function pbkdf2Sha512(pass, salt, iterations) {
  const [ip, op] = hmacPads(pass);
  const iS = Int32Array.from(IV512), oS = Int32Array.from(IV512);
  compress512(iS, ip, 0); compress512(oS, op, 0);
  // one more block after the key pad: a 64-byte message, total length 192 bytes
  const blk = new Uint8Array(128); blk[64] = 0x80; blk[126] = 0x06;
  const H = new Int32Array(16);
  const step = (state, msg) => { H.set(state); blk.set(msg); compress512(H, blk, 0); return digest512(H); };
  let u = hmacSha512(pass, concat(salt, Uint8Array.of(0, 0, 0, 1)));
  const t = Uint8Array.from(u);
  for (let i = 1; i < iterations; i++) {
    u = step(oS, step(iS, u));
    for (let j = 0; j < 64; j++) t[j] ^= u[j];
  }
  return t;
}

/* ---- Base58Check decode ---- */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = new Map([...B58].map((c, i) => [c, i]));
export function base58Decode(s) {
  if (!s) return null;
  const bytes = [0];
  for (const c of s) {
    let carry = B58_MAP.get(c);
    if (carry === undefined) return null;
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  let zeros = 0; while (zeros < s.length && s[zeros] === "1") zeros++;
  if (bytes.length === 1 && bytes[0] === 0) bytes.length = 0;
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes.reverse()]);
}
export function base58CheckDecode(s) {
  const b = base58Decode(s);
  if (!b || b.length < 5) return null;
  const payload = b.subarray(0, b.length - 4), chk = sha256(sha256(payload));
  for (let i = 0; i < 4; i++) if (chk[i] !== b[b.length - 4 + i]) return null;
  return payload;
}
export { base58 };

/* ---- single-key formats ---- */

// Hex: up to 64 digits, optional 0x, left-padded with zeros.
export function parseHex(s) {
  const m = s.match(/^(?:0x)?([0-9a-fA-F]{1,64})$/);
  return m ? BigInt("0x" + m[1]) : null;
}
// What "Auto" treats as hex: a full 64-digit key, or anything written with 0x.
export function looksHex(s) {
  return /^(?:0x)?[0-9a-fA-F]{64}$/.test(s) || /^0x[0-9a-fA-F]{1,64}$/.test(s);
}
export function parseDecimal(s) {
  return /^\d+$/.test(s) ? BigInt(s) : null;
}
// WIF (any network version byte), compressed or not.
export function parseWIF(s) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{50,53}$/.test(s)) return null;
  const p = base58CheckDecode(s);
  if (!p) return null;
  if (p.length === 33) return { n: bytesToInt(p.subarray(1)), compressed: false, version: p[0] };
  if (p.length === 34 && p[33] === 0x01) return { n: bytesToInt(p.subarray(1, 33)), compressed: true, version: p[0] };
  return null;
}
// Casascius mini private key (22, 26 or 30 chars starting with S).
export function parseMini(s) {
  if (!/^S[1-9A-HJ-NP-Za-km-z]{21}(?:[1-9A-HJ-NP-Za-km-z]{4}){0,2}$/.test(s)) return null;
  if (sha256(utf8(s + "?"))[0] !== 0) return null;
  return bytesToInt(sha256(utf8(s)));
}
// BIP32 extended private key (xprv / tprv / yprv / zprv / Ltpv ...).
export function parseExtended(s) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{100,120}$/.test(s)) return null;
  const p = base58CheckDecode(s);
  if (!p || p.length !== 78 || p[45] !== 0) return null;
  const k = bytesToInt(p.subarray(46));
  return validKey(k) ? { k, c: p.slice(13, 45) } : null;
}
export function passphraseKey(s) {
  return bytesToInt(sha256(utf8(s)));
}

/* ---- BIP32 ---- */
const HARD = 0x80000000;
export function parsePath(path) {
  const s = String(path).replace(/\s+/g, "");
  if (!/^[mM](?:\/\d+['hH]?)*$/.test(s)) return null;
  const out = [];
  for (const part of s.split("/").slice(1)) {
    const n = parseInt(part, 10);
    if (!(n < HARD)) return null;
    out.push(/['hH]$/.test(part) ? n + HARD : n);
  }
  return out;
}
export function formatPath(indices) {
  return "m" + indices.map((i) => "/" + (i >= HARD ? (i - HARD) + "'" : i)).join("");
}
export function hdMaster(seed) {
  const I = hmacSha512(utf8("Bitcoin seed"), seed);
  return { k: bytesToInt(I.subarray(0, 32)), c: I.slice(32) };
}
function ser32(i) { return Uint8Array.of(i >>> 24, i >>> 16, i >>> 8, i); }
export function hdChild(node, index) {
  const kb = intToBytes32(node.k);
  const data = index >= HARD ? concat(Uint8Array.of(0), kb, ser32(index))
                             : concat(getPublicKey(kb, true), ser32(index));
  const I = hmacSha512(node.c, data);
  return { k: (bytesToInt(I.subarray(0, 32)) + node.k) % N, c: I.slice(32) };
}
export function hdDerive(node, indices) {
  for (const i of indices) node = hdChild(node, i);
  return node;
}

/* ---- BIP39 ---- */
const BIP39 = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split(" ");
const BIP39_INDEX = new Map(BIP39.map((w, i) => [w, i]));

// A valid BIP39 mnemonic (English, checksum ok) -> its normalized form, else null.
export function bip39Mnemonic(phrase) {
  const words = phrase.normalize("NFKD").toLowerCase().trim().split(/\s+/);
  if (![12, 15, 18, 21, 24].includes(words.length)) return null;
  let bits = "";
  for (const w of words) {
    const i = BIP39_INDEX.get(w);
    if (i === undefined) return null;
    bits += i.toString(2).padStart(11, "0");
  }
  const csLen = words.length / 3, entLen = bits.length - csLen;
  const ent = new Uint8Array(entLen / 8);
  for (let i = 0; i < ent.length; i++) ent[i] = parseInt(bits.slice(8 * i, 8 * i + 8), 2);
  const cs = sha256(ent)[0].toString(2).padStart(8, "0").slice(0, csLen);
  return cs === bits.slice(entLen) ? words.join(" ") : null;
}
export function bip39Seed(mnemonic, passphrase = "") {
  return pbkdf2Sha512(utf8(mnemonic.normalize("NFKD")), utf8(("mnemonic" + passphrase).normalize("NFKD")), 2048);
}

/* ---- Electrum (2.x+ seeds) ---- */
function electrumNormalize(s) {
  return s.normalize("NFKD").toLowerCase().replace(/\p{M}/gu, "").trim().split(/\s+/).join(" ");
}
export function electrumSeedType(phrase) {
  const s = electrumNormalize(phrase);
  if (!s) return null;
  const h = toHex(hmacSha512(utf8("Seed version"), utf8(s)));
  if (h.startsWith("01")) return "standard";
  if (h.startsWith("100")) return "segwit";
  if (h.startsWith("101")) return "2fa";
  if (h.startsWith("102")) return "2fa_segwit";
  return null;
}
export function electrumSeed(phrase, passphrase = "") {
  return pbkdf2Sha512(utf8(electrumNormalize(phrase)), utf8("electrum" + electrumNormalize(passphrase)), 2048);
}

/* ---- Electrum 1.x ("legacy") seeds ---- */
const OLD_WORDS = "like just love know never want time out there make look eye down only think heart back then into about more away still them take thing even through long always world too friend tell try hand thought over here other need smile again much cry been night ever little said end some those around mind people girl leave dream left turn myself give nothing really off before something find walk wish good once place ask stop keep watch seem everything wait got yet made remember start alone run hope maybe believe body hate after close talk stand own each hurt help home god soul new many two inside should true first fear mean better play another gone change use wonder someone hair cold open best any behind happen water dark laugh stay forever name work show sky break came deep door put black together upon happy such great white matter fill past please burn cause enough touch moment soon voice scream anything stare sound red everyone hide kiss truth death beautiful mine blood broken very pass next forget tree wrong air mother understand lip hit wall memory sleep free high realize school might skin sweet perfect blue kill breath dance against fly between grow strong under listen bring sometimes speak pull person become family begin ground real small father sure feet rest young finally land across today different guy line fire reason reach second slowly write eat smell mouth step learn three floor promise breathe darkness push earth guess save song above along both color house almost sorry anymore brother okay dear game fade already apart warm beauty heard notice question shine began piece whole shadow secret street within finger point morning whisper child moon green story glass kid silence since soft yourself empty shall angel answer baby bright dad path worry hour drop follow power war half flow heaven act chance fact least tired children near quite afraid rise sea taste window cover nice trust lot sad cool force peace return blind easy ready roll rose drive held music beneath hang mom paint emotion quiet clear cloud few pretty bird outside paper picture front rock simple anyone meant reality road sense waste bit leaf thank happiness meet men smoke truly decide self age book form alive carry escape damn instead able ice minute throw catch leg ring course goodbye lead poem sick corner desire known problem remind shoulder suppose toward wave drink jump woman pretend sister week human joy crack grey pray surprise dry knee less search bleed caught clean embrace future king son sorrow chest hug remain sat worth blow daddy final parent tight also create lonely safe cross dress evil silent bone fate perhaps anger class scar snow tiny tonight continue control dog edge mirror month suddenly comfort given loud quickly gaze plan rush stone town battle ignore spirit stood stupid yours brown build dust hey kept pay phone twist although ball beyond hidden nose taken fail float pure somehow wash wrap angry cheek creature forgotten heat rip single space special weak whatever yell anyway blame job choose country curse drift echo figure grew laughter neck suffer worse yeah disappear foot forward knife mess somewhere stomach storm beg idea lift offer breeze field five often simply stuck win allow confuse enjoy except flower seek strength calm grin gun heavy hill large ocean shoe sigh straight summer tongue accept crazy everyday exist grass mistake sent shut surround table ache brain destroy heal nature shout sign stain choice doubt glance glow mountain queen stranger throat tomorrow city either fish flame rather shape spin spread ash distance finish image imagine important nobody shatter warmth became feed flesh funny lust shirt trouble yellow attention bare bite money protect amaze appear born choke completely daughter fresh friendship gentle probably six deserve expect grab middle nightmare river thousand weight worst wound barely bottle cream regret relationship stick test crush endless fault itself rule spill art circle join kick mask master passion quick raise smooth unless wander actually broke chair deal favorite gift note number sweat box chill clothes lady mark park poor sadness tie animal belong brush consume dawn forest innocent pen pride stream thick clay complete count draw faith press silver struggle surface taught teach wet bless chase climb enter letter melt metal movie stretch swing vision wife beside crash forgot guide haunt joke knock plant pour prove reveal steal stuff trip wood wrist bother bottom crawl crowd fix forgive frown grace loose lucky party release surely survive teacher gently grip speed suicide travel treat vein written cage chain conversation date enemy however interest million page pink proud sway themselves winter church cruel cup demon experience freedom pair pop purpose respect shoot softly state strange bar birth curl dirt excuse lord lovely monster order pack pants pool scene seven shame slide ugly among blade blonde closet creek deny drug eternity gain grade handle key linger pale prepare swallow swim tremble wheel won cast cigarette claim college direction dirty gather ghost hundred loss lung orange present swear swirl twice wild bitter blanket doctor everywhere flash grown knowledge numb pressure radio repeat ruin spend unknown buy clock devil early false fantasy pound precious refuse sheet teeth welcome add ahead block bury caress content depth despite distant marry purple threw whenever bomb dull easily grasp hospital innocence normal receive reply rhyme shade someday sword toe visit asleep bought center consider flat hero history ink insane muscle mystery pocket reflection shove silently smart soldier spot stress train type view whether bus energy explain holy hunger inch magic mix noise nowhere prayer presence shock snap spider study thunder trail admit agree bag bang bound butterfly cute exactly explode familiar fold further pierce reflect scent selfish sharp sink spring stumble universe weep women wonderful action ancient attempt avoid birthday branch chocolate core depress drunk especially focus fruit honest match palm perfectly pillow pity poison roar shift slightly thump truck tune twenty unable wipe wrote coat constant dinner drove egg eternal flight flood frame freak gasp glad hollow motion peer plastic root screen season sting strike team unlike victim volume warn weird attack await awake built charm crave despair fought grant grief horse limit message ripple sanity scatter serve split string trick annoy blur boat brave clearly cling connect fist forth imagination iron jock judge lesson milk misery nail naked ourselves poet possible princess sail size snake society stroke torture toss trace wise bloom bullet cell check cost darling during footstep fragile hallway hardly horizon invisible journey midnight mud nod pause relax shiver sudden value youth abuse admire blink breast bruise constantly couple creep curve difference dumb emptiness gotta honor plain planet recall rub ship slam soar somebody tightly weather adore approach bond bread burst candle coffee cousin crime desert flutter frozen grand heel hello language level movement pleasure powerful random rhythm settle silly slap sort spoken steel threaten tumble upset aside awkward bee blank board button card carefully complain crap deeply discover drag dread effort entire fairy giant gotten greet illusion jeans leap liquid march mend nervous nine replace rope spine stole terror accident apple balance boom childhood collect demand depression eventually faint glare goal group honey kitchen laid limb machine mere mold murder nerve painful poetry prince rabbit shelter shore shower soothe stair steady sunlight tangle tease treasure uncle begun bliss canvas cheer claw clutch commit crimson crystal delight doll existence express fog football gay goose guard hatred illuminate mass math mourn rich rough skip stir student style support thorn tough yard yearn yesterday advice appreciate autumn bank beam bowl capture carve collapse confusion creation dove feather girlfriend glory government harsh hop inner loser moonlight neighbor neither peach pig praise screw shield shimmer sneak stab subject throughout thrown tower twirl wow army arrive bathroom bump cease cookie couch courage dim guilt howl hum husband insult led lunch mock mostly natural nearly needle nerd peaceful perfection pile price remove roam sanctuary serious shiny shook sob stolen tap vain void warrior wrinkle affection apologize blossom bounce bridge cheap crumble decision descend desperately dig dot flip frighten heartbeat huge lazy lick odd opinion process puzzle quietly retreat score sentence separate situation skill soak square stray taint task tide underneath veil whistle anywhere bedroom bid bloody burden careful compare concern curtain decay defeat describe double dreamer driver dwell evening flare flicker grandma guitar harm horrible hungry indeed lace melody monkey nation object obviously rainbow salt scratch shown shy stage stun third tickle useless weakness worship worthless afternoon beard boyfriend bubble busy certain chin concrete desk diamond doom drawn due felicity freeze frost garden glide harmony hopefully hunt jealous lightning mama mercy peel physical position pulse punch quit rant respond salty sane satisfy savior sheep slept social sport tuck utter valley wolf aim alas alter arrow awaken beaten belief brand ceiling cheese clue confidence connection daily disguise eager erase essence everytime expression fan flag flirt foul fur giggle glorious ignorance law lifeless measure mighty muse north opposite paradise patience patient pencil petal plate ponder possibly practice slice spell stock strife strip suffocate suit tender tool trade velvet verse waist witch aunt bench bold cap certainly click companion creator dart delicate determine dish dragon drama drum dude everybody feast forehead former fright fully gas hook hurl invite juice manage moral possess raw rebel royal scale scary several slight stubborn swell talent tea terrible thread torment trickle usually vast violence weave acid agony ashamed awe belly blend blush character cheat common company coward creak danger deadly defense define depend desperate destination dew duck dusty embarrass engine example explore foe freely frustrate generation glove guilty health hurry idiot impossible inhale jaw kingdom mention mist moan mumble mutter observe ode pathetic pattern pie prefer puff rape rare revenge rude scrape spiral squeeze strain sunset suspend sympathy thigh throne total unseen weapon weary".split(" ");
const OLD_INDEX = new Map(OLD_WORDS.map((w, i) => [w, i]));

// 12/24 old-style words or 32/64 hex digits -> the hex seed, else null.
export function electrumOldSeed(phrase) {
  const s = electrumNormalize(phrase);
  if (/^[0-9a-f]+$/.test(s) && (s.length === 32 || s.length === 64)) return s;
  const words = s.split(" "), n = OLD_WORDS.length;
  if (words.length !== 12 && words.length !== 24) return null;
  let out = "";
  for (let i = 0; i < words.length; i += 3) {
    const w1 = OLD_INDEX.get(words[i]), w2 = OLD_INDEX.get(words[i + 1]), w3 = OLD_INDEX.get(words[i + 2]);
    if (w1 === undefined || w2 === undefined || w3 === undefined) return null;
    const x = w1 + n * (((w2 - w1) % n + n) % n) + n * n * (((w3 - w2) % n + n) % n);
    out += x.toString(16).padStart(8, "0");
  }
  return out;
}
// Private key of receiving address #index (change=1: change address).
export function electrumOldKey(seedHex, index = 0, change = 0) {
  const seed = utf8(seedHex);
  let x = sha256(concat(seed, seed));
  const buf = new Uint8Array(32 + seed.length);
  buf.set(seed, 32);
  for (let i = 1; i < 100000; i++) { buf.set(x, 0); x = sha256(buf); }
  const secexp = bytesToInt(x);
  const mpk = getPublicKey(intToBytes32(secexp % N), false).subarray(1);
  const z = bytesToInt(sha256(sha256(concat(utf8(`${index}:${change}:`), mpk))));
  return (secexp + z) % N;
}

/* ---- per-coin data ---- */
// SLIP-44 coin types, used in the BIP44 paths.
export const COIN_TYPE = {
  "bitcoin": 0, "bitcoin-testnet": 1, "litecoin": 2, "dogecoin": 3, "dash": 5, "clams": 23,
  "ethereum": 60, "zcash": 133, "bitcoin-cash": 145, "bitcoin-gold": 156, "bitcoin-sv": 236,
};
const PURPOSE = { "": 44, "segwit": 84, "segwit-p2sh": 49, "taproot": 86 };
export function defaultBip39Path(coin, type) {
  return `m/${PURPOSE[type] || 44}'/${COIN_TYPE[coin] ?? 0}'/0'/0/0`;
}

/* ---- Search form: one line in a given format ---- */
export const FORMATS = ["auto", "hex", "int", "wif", "extended", "mini", "pass", "bip39", "bip39_electrum", "electrum"];
const AUTO = ["hex", "int", "wif", "mini", "extended", "bip39", "bip39_electrum", "pass"];

function asKey(label, n) {
  return { label, hex: hex64(n), n };
}

// -> {label, hex, n} for a key, or null when the line isn't valid in that format.
// `path` (optional) overrides the derivation path of BIP39 / Electrum / extended keys.
export function searchLine(line, format, opts = {}) {
  const { coin = "bitcoin", type = "", path = "" } = opts;
  const indices = path ? parsePath(path) : null;
  switch (format) {
    case "auto":
      for (const f of AUTO) {
        if (f === "hex" && !looksHex(line)) continue;
        const r = searchLine(line, f, opts);
        if (r) return r;
      }
      return null;
    case "hex": {
      const n = parseHex(line);
      return n !== null && validKey(n) ? asKey("HEX", n) : null;
    }
    case "int": {
      const n = parseDecimal(line);
      return n !== null && validKey(n) ? asKey("Decimal", n) : null;
    }
    case "wif": {
      const w = parseWIF(line);
      return w && validKey(w.n) ? asKey("WIF", w.n) : null;
    }
    case "mini": {
      const n = parseMini(line);
      return n !== null && validKey(n) ? asKey("Mini", n) : null;
    }
    case "extended": {
      const x = parseExtended(line);
      if (!x) return null;
      if (!indices || !indices.length) return asKey("Extended", x.k);
      return asKey(`Extended (${formatPath(indices)})`, hdDerive(x, indices).k);
    }
    case "pass":
      return line ? asKey("Passphrase", passphraseKey(line)) : null;
    case "bip39": {
      const m = bip39Mnemonic(line);
      if (!m) return null;
      const p = indices || parsePath(defaultBip39Path(coin, type));
      return asKey(`BIP39 (${formatPath(p)})`, hdDerive(hdMaster(bip39Seed(m)), p).k);
    }
    case "bip39_electrum": {
      const t = electrumSeedType(line);
      if (!t) return null;
      const p = indices || parsePath(/segwit/.test(t) ? "m/0'/0/0" : "m/0/0");
      return asKey(`BIP39 Electrum (${formatPath(p)})`, hdDerive(hdMaster(electrumSeed(line)), p).k);
    }
    case "electrum": {
      const s = electrumOldSeed(line);
      return s ? asKey("Electrum (legacy)", electrumOldKey(s)) : null;
    }
  }
  return null;
}

/* ---- Quick Search: every interpretation of one query ---- */
export function quickSearch(query, coin = "bitcoin") {
  const rows = [];
  const add = (label, n) => rows.push({ label, hex: hex64(n), n });
  const addBytes = (label, b) => add(label, bytesToInt(b));

  if (/^\d+$/.test(query)) {
    const n = BigInt(query);
    if (validKey(n)) add("Decimal", n);
  }
  if (/^[0-9a-fA-F]{64}$/.test(query)) {
    add("HEX", BigInt("0x" + query));
    addBytes("HEX (reversed)", reversed(hexBytes(query)));
  } else if (/^[0-9a-fA-F]{1,63}$/.test(query)) {
    add("HEX (left padded)", BigInt("0x" + query.padStart(64, "0")));
    add("HEX (right padded)", BigInt("0x" + query.padEnd(64, "0")));
  }
  const bytes = utf8(query);
  if (bytes.length === 32) {
    addBytes("Binary", bytes);
  } else if (bytes.length > 0 && bytes.length < 32) {
    const left = new Uint8Array(32), right = new Uint8Array(32);
    left.set(bytes, 32 - bytes.length); right.set(bytes, 0);
    addBytes("Binary (left padded)", left);
    addBytes("Binary (right padded)", right);
  }
  const w = parseWIF(query);
  if (w) add("WIF", w.n);
  const m = bip39Mnemonic(query);
  if (m) {
    const root = hdMaster(bip39Seed(m));
    const ct = COIN_TYPE[coin] ?? 0;
    for (const p of ["m/0'/0/0", "m/0'/0'/0", `m/44'/${ct}'/0'/0`, `m/44'/${ct}'/0'/0/0`]) {
      add(`HD wallet (${p})`, hdDerive(root, parsePath(p)).k);
    }
    const eroot = hdMaster(electrumSeed(query));
    for (const p of ["m/0/0", "m/0'/0/0"]) {
      add(`Electrum HD wallet (${p})`, hdDerive(eroot, parsePath(p)).k);
    }
  }
  const h = sha256(bytes), hx = toHex(h);
  addBytes("Brainwallet", h);
  addBytes("Brainwallet (reversed)", reversed(h));
  addBytes("Brainwallet 2x (lowercase)", sha256(utf8(hx)));
  addBytes("Brainwallet 2x (uppercase)", sha256(utf8(hx.toUpperCase())));
  addBytes("Brainwallet 2x (binary)", sha256(h));
  return rows;
}

function hexBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
  return out;
}
