// keygen-core.js — pure Bitcoin key derivation (no DOM).
// Used by the in-browser page generator (keygen.js) and by the Node verifier.
// EC math comes from the vetted, dependency-free @noble/secp256k1 (bundled locally).
import { getPublicKey } from "./secp256k1.js";

/* ---- SHA-256 (sync, Uint8Array -> Uint8Array(32)) ---- */
const K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
export function sha256(msg){
  const l = msg.length;
  const withOne = l + 1;
  const k = (56 - (withOne % 64) + 64) % 64;
  const total = withOne + k + 8;
  const m = new Uint8Array(total);
  m.set(msg); m[l] = 0x80;
  const bits = l * 8;
  // 64-bit big-endian length (high 32 bits are 0 for our sizes)
  m[total-4] = (bits>>>24)&0xff; m[total-3] = (bits>>>16)&0xff;
  m[total-2] = (bits>>>8)&0xff;  m[total-1] = bits&0xff;
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for(let off=0; off<total; off+=64){
    for(let i=0;i<16;i++){
      w[i]=(m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|(m[off+i*4+3]);
    }
    for(let i=16;i<64;i++){
      const s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
      const s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for(let i=0;i<64;i++){
      const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K256[i]+w[i])|0;
      const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;
    h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
  }
  const out=new Uint8Array(32);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i)=>{
    out[i*4]=(v>>>24)&0xff;out[i*4+1]=(v>>>16)&0xff;out[i*4+2]=(v>>>8)&0xff;out[i*4+3]=v&0xff;
  });
  return out;
}

/* ---- RIPEMD-160 (sync, Uint8Array -> Uint8Array(20)) ---- */
const rL=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
const rR=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
const sL=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
const sR=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
function rol(x,n){ return ((x<<n)|(x>>>(32-n)))>>>0; }
export function ripemd160(msg){
  const l=msg.length;
  const withOne=l+1;
  const k=(56-(withOne%64)+64)%64;
  const total=withOne+k+8;
  const m=new Uint8Array(total);
  m.set(msg); m[l]=0x80;
  const bits=l*8;
  m[total-8]=bits&0xff; m[total-7]=(bits>>>8)&0xff; m[total-6]=(bits>>>16)&0xff; m[total-5]=(bits>>>24)&0xff;
  let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  const x=new Uint32Array(16);
  for(let off=0;off<total;off+=64){
    for(let i=0;i<16;i++){
      x[i]=(m[off+i*4])|(m[off+i*4+1]<<8)|(m[off+i*4+2]<<16)|(m[off+i*4+3]<<24);
    }
    let al=h0,bl=h1,cl=h2,dl=h3,el=h4;
    let ar=h0,br=h1,cr=h2,dr=h3,er=h4;
    for(let j=0;j<80;j++){
      const round=Math.floor(j/16);
      let fl,kl,fr,kr;
      if(round===0){fl=(bl^cl^dl);kl=0x00000000;}
      else if(round===1){fl=((bl&cl)|(~bl&dl));kl=0x5a827999;}
      else if(round===2){fl=((bl|~cl)^dl);kl=0x6ed9eba1;}
      else if(round===3){fl=((bl&dl)|(cl&~dl));kl=0x8f1bbcdc;}
      else {fl=(bl^(cl|~dl));kl=0xa953fd4e;}
      if(round===0){fr=(br^(cr|~dr));kr=0x50a28be6;}
      else if(round===1){fr=((br&dr)|(cr&~dr));kr=0x5c4dd124;}
      else if(round===2){fr=((br|~cr)^dr);kr=0x6d703ef3;}
      else if(round===3){fr=((br&cr)|(~br&dr));kr=0x7a6d76e9;}
      else {fr=(br^cr^dr);kr=0x00000000;}
      let t=(((al+(fl>>>0)+x[rL[j]]+kl)>>>0));
      t=(rol(t>>>0,sL[j])+el)>>>0;
      al=el;el=dl;dl=rol(cl,10);cl=bl;bl=t;
      t=(((ar+(fr>>>0)+x[rR[j]]+kr)>>>0));
      t=(rol(t>>>0,sR[j])+er)>>>0;
      ar=er;er=dr;dr=rol(cr,10);cr=br;br=t;
    }
    const t=(h1+cl+dr)>>>0;
    h1=(h2+dl+er)>>>0;
    h2=(h3+el+ar)>>>0;
    h3=(h4+al+br)>>>0;
    h4=(h0+bl+cr)>>>0;
    h0=t;
  }
  const out=new Uint8Array(20);
  [h0,h1,h2,h3,h4].forEach((v,i)=>{
    out[i*4]=v&0xff;out[i*4+1]=(v>>>8)&0xff;out[i*4+2]=(v>>>16)&0xff;out[i*4+3]=(v>>>24)&0xff;
  });
  return out;
}

/* ---- Base58 ---- */
const B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58(bytes){
  let zeros=0; while(zeros<bytes.length && bytes[zeros]===0) zeros++;
  const digits=[0];
  for(let i=zeros;i<bytes.length;i++){
    let carry=bytes[i];
    for(let j=0;j<digits.length;j++){ carry+=digits[j]<<8; digits[j]=carry%58; carry=(carry/58)|0; }
    while(carry>0){ digits.push(carry%58); carry=(carry/58)|0; }
  }
  let out="1".repeat(zeros);
  for(let i=digits.length-1;i>=0;i--) out+=B58[digits[i]];
  return out;
}

function concat(...arrs){
  let n=0; for(const a of arrs) n+=a.length;
  const out=new Uint8Array(n); let o=0;
  for(const a of arrs){ out.set(a,o); o+=a.length; }
  return out;
}
export function hash160(bytes){ return ripemd160(sha256(bytes)); }
function check(payload){ return sha256(sha256(payload)).subarray(0,4); }
export function p2pkh(pubkey, version=0x00){
  return p2pkhV(pubkey, [version]);
}
// Base58Check P2PKH with a 1- or 2-byte version prefix (Zcash t-addrs use two).
export function p2pkhV(pubkey, verBytes){
  const payload=concat(Uint8Array.from(verBytes), hash160(pubkey));
  return base58(concat(payload, check(payload)));
}
export function toWIF(priv32, compressed, version=0x80){
  const body = compressed
    ? concat(Uint8Array.of(version), priv32, Uint8Array.of(0x01))
    : concat(Uint8Array.of(version), priv32);
  return base58(concat(body, check(body)));
}

/* ---- key int -> 32-byte big-endian ---- */
export function intToBytes32(n){
  const out=new Uint8Array(32);
  let i=31;
  while(n>0n && i>=0){ out[i]=Number(n & 0xffn); n>>=8n; i--; }
  return out;
}
export function hex64(n){ return n.toString(16).padStart(64,"0"); }

/* ---- full derivation for one private-key integer ---- */
export function deriveKey(n){
  const priv=intToBytes32(n);
  const pubC=getPublicKey(priv, true);
  const pubU=getPublicKey(priv, false);
  return {
    hex: hex64(n),
    addrC: p2pkh(pubC),
    addrU: p2pkh(pubU),
    wifC: toWIF(priv, true),
    wifU: toWIF(priv, false),
  };
}

/* ---- Keccak-256 (Ethereum; NOT the FIPS SHA3 padding) ---- */
const KECCAK_RC=[0x1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,
  0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,
  0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
  0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,
  0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
const KECCAK_R=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const U64=(1n<<64n)-1n;
const krotl=(x,n)=> n===0n ? x : ((x<<n)|(x>>(64n-n)))&U64;
export function keccak256(msg){
  const S=new Array(25).fill(0n);
  const rate=136; // keccak-256 rate in bytes
  const pad=[...msg]; pad.push(0x01);
  while(pad.length%rate!==0) pad.push(0x00);
  pad[pad.length-1]|=0x80;
  for(let off=0; off<pad.length; off+=rate){
    for(let i=0;i<rate/8;i++){
      let lane=0n; for(let b=0;b<8;b++) lane|=BigInt(pad[off+i*8+b])<<BigInt(8*b);
      S[i]^=lane;
    }
    for(let round=0;round<24;round++){
      const C=new Array(5);
      for(let x=0;x<5;x++) C[x]=S[x]^S[x+5]^S[x+10]^S[x+15]^S[x+20];
      const D=new Array(5);
      for(let x=0;x<5;x++) D[x]=C[(x+4)%5]^krotl(C[(x+1)%5],1n);
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) S[x+5*y]^=D[x];
      const B=new Array(25);
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) B[y+5*((2*x+3*y)%5)]=krotl(S[x+5*y],BigInt(KECCAK_R[x+5*y]));
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) S[x+5*y]=B[x+5*y]^((~B[((x+1)%5)+5*y])&B[((x+2)%5)+5*y]);
      S[0]^=KECCAK_RC[round];
    }
  }
  const out=new Uint8Array(32);
  for(let i=0;i<4;i++){ let lane=S[i]; for(let b=0;b<8;b++) out[i*8+b]=Number((lane>>BigInt(8*b))&0xffn); }
  return out;
}
const HEX="0123456789abcdef";
function toHex(bytes){ let s=""; for(const b of bytes) s+=HEX[b>>4]+HEX[b&15]; return s; }
// Ethereum address with EIP-55 mixed-case checksum, from the uncompressed pubkey.
export function ethAddress(pubU){
  const addr=toHex(keccak256(pubU.subarray(1)).subarray(12)); // last 20 bytes, lowercase hex
  const hh=toHex(keccak256(new TextEncoder().encode(addr)));
  let out="0x";
  for(let i=0;i<40;i++) out += parseInt(hh[i],16)>=8 ? addr[i].toUpperCase() : addr[i];
  return out;
}

/* ---- CashAddr (Bitcoin Cash), returned WITHOUT the "bitcoincash:" prefix ---- */
const CASH_CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CASH_GEN=[0x98f2bc8e61n,0x79b76d99e2n,0xf33e5fb3c4n,0xae2eabe2a8n,0x1e4f43e470n];
export function cashaddr(h160){
  const payload=[0, ...h160]; // version byte 0 = P2KH, 160-bit hash
  let acc=0, bits=0; const data=[];
  for(const b of payload){ acc=(acc<<8)|b; bits+=8; while(bits>=5){ bits-=5; data.push((acc>>bits)&31); } }
  if(bits) data.push((acc<<(5-bits))&31);
  const pre=[]; for(const c of "bitcoincash") pre.push(c.charCodeAt(0)&31); pre.push(0);
  const values=[...pre, ...data, 0,0,0,0,0,0,0,0];
  let c=1n;
  for(const d of values){
    const top=c>>35n;
    c=((c&0x07ffffffffn)<<5n)^BigInt(d);
    for(let i=0;i<5;i++) if((top>>BigInt(i))&1n) c^=CASH_GEN[i];
  }
  c^=1n;
  const chk=[]; for(let i=0;i<8;i++) chk.push(Number((c>>BigInt(5*(7-i)))&31n));
  return data.concat(chk).map(v=>CASH_CHARSET[v]).join("");
}

// Per-coin config. `ver` is the base58 version prefix (1 or 2 bytes); `kind`
// selects the address scheme. All share the same secp256k1 private-key space.
export const COINS={
  "bitcoin":         {kind:"base58", ver:[0x00]},
  "bitcoin-sv":      {kind:"base58", ver:[0x00]},
  "bitcoin-gold":    {kind:"base58", ver:[0x26]},
  "litecoin":        {kind:"base58", ver:[0x30]},
  "dogecoin":        {kind:"base58", ver:[0x1e]},
  "dash":            {kind:"base58", ver:[0x4c]},
  "bitcoin-testnet": {kind:"base58", ver:[0x6f]},
  "clams":           {kind:"base58", ver:[0x89]},
  "zcash":           {kind:"base58", ver:[0x1c,0xb8]},
  "bitcoin-cash":    {kind:"cashaddr"},
  "ethereum":        {kind:"eth"},
};

// Derive the row data a key page shows for one private-key integer and coin:
// Ethereum -> one 0x address; everything else -> compressed + uncompressed.
export function deriveForCoin(n, coin){
  const cfg=COINS[coin] || COINS.bitcoin;
  const priv=intToBytes32(n);
  const hex=hex64(n);
  if(cfg.kind==="eth"){
    return {hex, eth:true, addr: ethAddress(getPublicKey(priv,false))};
  }
  const pubC=getPublicKey(priv,true), pubU=getPublicKey(priv,false);
  if(cfg.kind==="cashaddr"){
    return {hex, eth:false, addrC: cashaddr(hash160(pubC)), addrU: cashaddr(hash160(pubU))};
  }
  return {hex, eth:false, addrC: p2pkhV(pubC,cfg.ver), addrU: p2pkhV(pubU,cfg.ver)};
}

/* ---- Bech32 / Bech32m (BIP173 / BIP350) ---- */
const BECH32_GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
function bech32Polymod(values){
  let chk=1;
  for(const v of values){
    const top=chk>>>25;
    chk=((chk&0x1ffffff)<<5)^v;
    for(let i=0;i<5;i++) if((top>>>i)&1) chk^=BECH32_GEN[i];
  }
  return chk>>>0;
}
function convertBits(data, from, to){
  let acc=0, bits=0; const out=[]; const maxv=(1<<to)-1;
  for(const v of data){
    acc=((acc<<from)|v)&0xffff; bits+=from;
    while(bits>=to){ bits-=to; out.push((acc>>bits)&maxv); }
  }
  if(bits) out.push((acc<<(to-bits))&maxv);
  return out;
}
// Native SegWit address: witness v0 -> bech32, v1+ (Taproot) -> bech32m.
export function segwitAddress(hrp, version, program){
  const data=[version, ...convertBits(program,8,5)];
  const exp=[]; for(const c of hrp) exp.push(c.charCodeAt(0)>>5);
  exp.push(0); for(const c of hrp) exp.push(c.charCodeAt(0)&31);
  const mod=(bech32Polymod([...exp, ...data, 0,0,0,0,0,0]) ^ (version===0 ? 1 : 0x2bc830a3))>>>0;
  const chk=[]; for(let i=0;i<6;i++) chk.push((mod>>>(5*(5-i)))&31);
  return hrp+"1"+data.concat(chk).map(v=>CASH_CHARSET[v]).join(""); // same 32-char alphabet
}

/* ---- Taproot (BIP86 key-path: Q = P + H_TapTweak(x(P))·G, P with even y) ---- */
const SECP_N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function bytesToInt(b){ let n=0n; for(const x of b) n=(n<<8n)|BigInt(x); return n; }
function taggedHash(tag, msg){
  const t=sha256(new TextEncoder().encode(tag));
  return sha256(concat(t, t, msg));
}
export function taprootAddress(priv32, hrp){
  const pubC=getPublicKey(priv32, true);
  let d=bytesToInt(priv32);
  if(pubC[0]===0x03) d=SECP_N-d;                 // use the even-y internal key
  const tweak=bytesToInt(taggedHash("TapTweak", pubC.subarray(1))) % SECP_N;
  const q=(d+tweak) % SECP_N;                    // Q = (d+t)·G
  return segwitAddress(hrp, 1, getPublicKey(intToBytes32(q), true).subarray(1));
}

// Address types offered by the brainwallet "address type" dropdown. Only Bitcoin
// (SegWit, SegWit-in-P2SH, Taproot) and Litecoin (SegWit, SegWit-in-P2SH) have it;
// every other coin shows legacy addresses only.
export const SEGWIT={
  "bitcoin":  {hrp:"bc",  p2sh:0x05, types:["segwit","segwit-p2sh","taproot"]},
  "litecoin": {hrp:"ltc", p2sh:0x32, types:["segwit","segwit-p2sh"]},
};
export function typesForCoin(coin){ return SEGWIT[coin] ? SEGWIT[coin].types : []; }

// One address of the given non-legacy type, from the compressed public key.
export function deriveTyped(n, coin, type){
  const cfg=SEGWIT[coin];
  const priv=intToBytes32(n);
  const hex=hex64(n);
  if(type==="taproot") return {hex, eth:false, addr: taprootAddress(priv, cfg.hrp)};
  const h=hash160(getPublicKey(priv, true));
  if(type==="segwit") return {hex, eth:false, addr: segwitAddress(cfg.hrp, 0, h)};
  // segwit-p2sh: P2SH of the redeem script OP_0 <20-byte key hash>
  return {hex, eth:false, addr: p2pkhV(concat(Uint8Array.of(0x00, 0x14), h), [cfg.p2sh])};
}

// WIF version byte the site uses in its CSV export (uncompressed WIF). Ethereum
// exports the HEX key only.
export const WIF_VER={
  "bitcoin":0x80, "bitcoin-cash":0x80, "bitcoin-sv":0x80, "bitcoin-gold":0x80, "zcash":0x80,
  "bitcoin-testnet":0xef, "litecoin":0xb0, "dogecoin":0x9e, "dash":0xcc, "clams":0x85,
};

// "Export as CSV" body for a list of 64-hex keys, byte-identical to the site's.
export function exportCSV(hexes, coin){
  if(!(coin in WIF_VER)) return "Private Key (HEX)\n" + hexes.map(h=>h+"\n").join("");
  const ver=WIF_VER[coin];
  return "Private Key (HEX),Private Key (WIF)\n" +
    hexes.map(h=>h+","+toWIF(intToBytes32(BigInt("0x"+h)), false, ver)+"\n").join("");
}
