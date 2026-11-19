"use strict";
// Implémentation indépendante de GCR-0001 v0.1, écrite d'après le seul texte de la norme.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const OUTLEN = { sha224: 224n, sha256: 256n, sha384: 384n, sha512: 512n };

const ceilDiv = (a, b) => (a + b - 1n) / b;
const pgcd = (a, b) => { a = a < 0n ? -a : a; while (b) { [a, b] = [b, a % b]; } return a; };
const modpow = (b, e, m) => {
  let r = 1n; b %= m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
};
const isqrt = (n) => {
  if (n < 2n) return n;
  let x = 1n << BigInt((n.toString(2).length + 1) >> 1);
  for (;;) { const y = (x + n / x) >> 1n; if (y >= x) return x; x = y; }
};
const modinv = (a, m) => {
  let [r0, r1, s0, s1] = [m, a % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  if (r0 !== 1n) throw new Error("pas d'inverse");
  return ((s0 % m) + m) % m;
};
const bitlen = (n) => BigInt(n.toString(2).length);

class Echec extends Error {}

// 6.1 — flux de graine
class Flux {
  constructor(graine, hash) {
    this.w = graine.length;
    this.s = BigInt("0x" + graine.toString("hex"));
    this.hash = hash;
    this.outlen = OUTLEN[hash];
    this.mod = 1n << BigInt(8 * this.w);
  }
  hacher(j) {
    const v = (this.s + BigInt(j)) % this.mod;
    const octets = Buffer.from(v.toString(16).padStart(2 * this.w, "0"), "hex");
    return BigInt("0x" + crypto.createHash(this.hash).update(octets).digest("hex"));
  }
  avancer(k) { this.s += BigInt(k); }
  tirer(k) {
    let somme = 0n;
    for (let i = 0n; i <= k; i++) somme += this.hacher(i) << (i * this.outlen);
    this.avancer(k + 1n);
    return somme;
  }
}

// 6.2
function estPremierParDivision(c) {
  const r = isqrt(c);
  for (let d = 2n; d <= r; d++) if (c % d === 0n) return false;
  return true;
}
function petitPremier(f, L) {
  let compteur = 0n;
  for (;;) {
    let c = f.hacher(0) ^ f.hacher(1);
    c = (1n << (L - 1n)) + (c % (1n << (L - 1n)));
    c = 2n * (c / 2n) + 1n;
    compteur += 1n;
    f.avancer(2);
    if (estPremierParDivision(c)) return [c, compteur];
    if (compteur > 4n * L) throw new Echec("PetitPremier");
  }
}

// 6.3
function premierProuvable(f, L) {
  if (L <= 32n) return petitPremier(f, L);
  let [c0, compteur] = premierProuvable(f, ceilDiv(L, 2n) + 1n);
  const k = ceilDiv(L, f.outlen) - 1n;
  const ancien = compteur;
  let x = f.tirer(k);
  x = (1n << (L - 1n)) + (x % (1n << (L - 1n)));
  let t = ceilDiv(x, 2n * c0);
  for (;;) {
    if (2n * t * c0 + 1n > (1n << L)) t = ceilDiv(1n << (L - 1n), 2n * c0);
    const c = 2n * t * c0 + 1n;
    compteur += 1n;
    const a = 2n + (f.tirer(k) % (c - 3n));
    const z = modpow(a, 2n * t, c);
    if (pgcd(z - 1n, c) === 1n && modpow(z, c0, c) === 1n) return [c, compteur];
    if (compteur >= 4n * L + ancien) throw new Echec("PremierProuvable");
    t += 1n;
  }
}

// 6.4
function premierRSA(f, L, e) {
  const [p0] = premierProuvable(f, ceilDiv(L, 2n) + 1n);
  const k = ceilDiv(L, f.outlen) - 1n;
  const B = isqrt(1n << (2n * L - 1n));
  let x = f.tirer(k);
  x = B + (x % ((1n << L) - B));
  let t = ceilDiv(2n * p0 + x, 2n * p0);
  let compteur = 0n;
  for (;;) {
    if (2n * (t - 1n) * p0 + 1n > (1n << L)) t = ceilDiv(2n * p0 + B, 2n * p0);
    const p = 2n * (t - 1n) * p0 + 1n;
    compteur += 1n;
    if (pgcd(p - 1n, e) === 1n) {
      const a = 2n + (f.tirer(k) % (p - 3n));
      const z = modpow(a, 2n * (t - 1n), p);
      if (pgcd(z - 1n, p) === 1n && modpow(z, p0, p) === 1n) return p;
    }
    if (compteur >= 5n * L) throw new Echec("PremierRSA");
    t += 1n;
  }
}

// 7
function genererCle(nlen, hash, e, graine) {
  const f = new Flux(graine, hash);
  const L = BigInt(nlen) / 2n;
  const p = premierRSA(f, L, e);
  let q = premierRSA(f, L, e);
  const abs = (v) => (v < 0n ? -v : v);
  while (abs(p - q) <= (1n << (L - 100n))) q = premierRSA(f, L, e);
  const ppcm = ((p - 1n) * (q - 1n)) / pgcd(p - 1n, q - 1n);
  const d = modinv(e, ppcm);
  if (d <= (1n << L)) throw new Echec("d trop petit");
  const n = p * q;
  if (bitlen(n) !== BigInt(nlen)) throw new Echec("taille de n");
  return { p, q, n, d, dP: d % (p - 1n), dQ: d % (q - 1n), qInv: modinv(q, p) };
}

module.exports = { Flux, petitPremier, premierProuvable, premierRSA, genererCle };

if (require.main === module) {
  const cas = JSON.parse(fs.readFileSync(path.join(__dirname, "cas.json"), "utf8"));
  let i = 0;
  for (const c of cas.cas_norme) {
    i++;
    try {
      const k = genererCle(c.bits, c.hash, BigInt(c.e), Buffer.from(c.graine_hex, "hex"));
      const ok = k.n.toString(16) === c.n_hex_attendu;
      console.log(`cas_norme ${i} (${c.bits}, ${c.hash}) : ${ok ? "CONCORDE" : "DIVERGE"}`);
    } catch (err) { console.log(`cas_norme ${i} : ECHEC ${err.message}`); }
  }
  i = 0;
  for (const c of cas.cas_nist_mode_epreuve) {
    i++;
    try {
      const k = genererCle(c.bits, c.hash, BigInt("0x" + c.e_hex), Buffer.from(c.graine_hex, "hex"));
      const okP = k.p === BigInt("0x" + c.p_hex_attendu);
      const okQ = k.q === BigInt("0x" + c.q_hex_attendu);
      console.log(`cas_nist ${i} : p ${okP ? "CONCORDE" : "DIVERGE"}, q ${okQ ? "CONCORDE" : "DIVERGE"}`);
    } catch (err) { console.log(`cas_nist ${i} : ECHEC ${err.message}`); }
  }
}
