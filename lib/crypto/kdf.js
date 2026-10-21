// KDF + private-key wrapping. The master password is stretched with scrypt into
// a 32-byte key that wraps (AES-256-GCM) a secp256k1 private key. Only the
// wrapped blob + the (public) KDF params reach the server; the password and the
// derived key never leave the client.
//
// Runs CLIENT-SIDE. A server storing `encPrivateKey` + `kdf` can never
// reconstruct the key without the password.

import crypto from 'crypto';
import { promisify } from 'util';
import { gcmEncrypt, gcmDecrypt } from './aes.js';

// scrypt N=2^15 needs ~32MB; bump maxmem so Node doesn't refuse the cost.
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

export function defaultKdfParams() {
  return {
    algo: 'scrypt',
    salt: crypto.randomBytes(16).toString('hex'),
    N: 32768,
    r: 8,
    p: 1,
    keylen: 32,
  };
}

// ── KDF floor — the downgrade guard ───────────────────────────────────────────
// A client derives under params it did NOT choose: `authKdf` comes from
// `GET /auth/prelogin`, `kdf` from the keyring row — both SERVER-supplied. Without
// a floor, a compromised (or impersonated) server answers `{ N: 2 }`, receives a
// verifier stretched by almost nothing, brute-forces the master password offline,
// and then unwraps `encPrivateKey` under the REAL params. That turns "the server
// was breached" into "every vault whose owner logged in meanwhile is plaintext" —
// the exact event zero-knowledge exists to survive.
//
// So the floor is enforced where the password is stretched, not where params are
// stored: `deriveKey` refuses anything weaker than what `defaultKdfParams` mints.
// Raising the defaults later means raising this floor with them (older rows then
// need a re-wrap, which is what `POST /keyring/rotate` is for).
export const KDF_FLOOR = Object.freeze({
  scrypt: Object.freeze({ N: 32768, r: 8, p: 1 }),
  pbkdf2: Object.freeze({ iterations: 600000, digests: Object.freeze(['sha256', 'sha512']) }),
  saltBytes: 16,
  keylen: 32,
});

const isInt = (n) => Number.isInteger(n) && n > 0;

// Throws on params a client must refuse to stretch a password under. Pure — also
// used server-side to reject weak params at write time (sharedenv keyring).
export function assertKdfParams(params) {
  if (!params || typeof params !== 'object') throw new Error('KDF params missing');
  const { algo = 'scrypt', salt, keylen = KDF_FLOOR.keylen } = params;

  if (typeof salt !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(salt)) {
    throw new Error('KDF salt must be a hex string');
  }
  if (salt.length / 2 < KDF_FLOOR.saltBytes) {
    throw new Error(`KDF salt too short (< ${KDF_FLOOR.saltBytes} bytes)`);
  }
  if (keylen !== KDF_FLOOR.keylen) throw new Error(`KDF keylen must be ${KDF_FLOOR.keylen}`);

  if (algo === 'scrypt') {
    const { N = KDF_FLOOR.scrypt.N, r = KDF_FLOOR.scrypt.r, p = KDF_FLOOR.scrypt.p } = params;
    if (!isInt(N) || (N & (N - 1)) !== 0) throw new Error('scrypt N must be a power of two');
    if (N < KDF_FLOOR.scrypt.N || !isInt(r) || r < KDF_FLOOR.scrypt.r || !isInt(p)) {
      throw new Error('scrypt params below the accepted floor');
    }
    return;
  }
  if (algo === 'pbkdf2') {
    const { iterations = KDF_FLOOR.pbkdf2.iterations, digest = 'sha256' } = params;
    if (!isInt(iterations) || iterations < KDF_FLOOR.pbkdf2.iterations) {
      throw new Error('pbkdf2 iterations below the accepted floor');
    }
    if (!KDF_FLOOR.pbkdf2.digests.includes(digest)) throw new Error('pbkdf2 digest not accepted');
    return;
  }
  throw new Error(`Unknown KDF algo "${algo}"`);
}

// → [node:crypto function name, its arguments], shared by both flavours below.
// Refuses params below `KDF_FLOOR` (see above) before stretching anything.
function kdfCall(password, params) {
  assertKdfParams(params);
  const { algo, salt, keylen = 32 } = params;
  const saltBuf = Buffer.from(salt, 'hex');

  if (algo === 'pbkdf2') {
    const { iterations = 600000, digest = 'sha256' } = params;
    return ['pbkdf2', [password, saltBuf, iterations, keylen, digest]];
  }

  // default: scrypt
  const { N = 32768, r = 8, p = 1 } = params;
  return ['scrypt', [password, saltBuf, keylen, { N, r, p, maxmem: SCRYPT_MAXMEM }]];
}

const ASYNC_KDF = { pbkdf2: promisify(crypto.pbkdf2), scrypt: promisify(crypto.scrypt) };

// password: string. params: { algo, salt(hex), ... }. → Buffer(keylen).
// SYNC: ~75 ms of the calling thread. Fine for a CLI or a test; a server on a
// request path takes `deriveKeyAsync`.
export function deriveKey(password, params) {
  const [algo, args] = kdfCall(password, params);
  return algo === 'pbkdf2' ? crypto.pbkdf2Sync(...args) : crypto.scryptSync(...args);
}

// The same key, derived on the libuv pool: the event loop keeps serving the
// process's other requests meanwhile.
export async function deriveKeyAsync(password, params) {
  const [algo, args] = kdfCall(password, params);
  return ASYNC_KDF[algo](...args);
}

// ── Login verifier ────────────────────────────────────────────────────────────
// Never the raw scrypt output: that is what a wrap key is made of, and `authKdf` is
// chosen by the server (GET /auth/prelogin) — a compromised server could serve the
// keyring's `kdf` as `authKdf` and receive the wrap key as the "verifier".
// HMAC-SHA256 keyed by scrypt(password, authKdf), over AUTH_VERIFIER_LABEL: every
// client derives the same bytes.
export const AUTH_VERIFIER_LABEL = 'sharedenv/auth-verifier/v2';

// Login params a client mints.
export function defaultAuthKdfParams() {
  return { ...defaultKdfParams(), v: 2 };
}

// → the verifier a client sends for `params` as prelogin serves them. Async: scrypt
// on the libuv pool.
export async function deriveAuthVerifier(password, params) {
  const stretched = await deriveKeyAsync(password, params);
  return crypto.createHmac('sha256', stretched).update(AUTH_VERIFIER_LABEL).digest('hex');
}

// privateKeyHex: string. password: string. params: optional KDF params.
// → { encPrivateKey: { ciphertext, iv, authTag }, kdf: params }.
export function wrapPrivateKey(privateKeyHex, password, params = defaultKdfParams()) {
  const key = deriveKey(password, params);
  const encPrivateKey = gcmEncrypt(key, Buffer.from(privateKeyHex, 'utf8'));
  return { encPrivateKey, kdf: params };
}

// → privateKeyHex string. Throws if the password is wrong (GCM tag fails).
export function unwrapPrivateKey(encPrivateKey, password, kdf) {
  const key = deriveKey(password, kdf);
  return gcmDecrypt(key, encPrivateKey).toString('utf8');
}

// A one-time recovery code shown to the user once, at keyring creation. It is a
// SECOND passphrase the private key is wrapped under (`wrapPrivateKey(pk, code)`)
// so a forgotten password no longer orphans the vault: after a password reset,
// the client unwraps with this code and re-wraps under the new password. Runs
// CLIENT-SIDE; the server never sees it. 160 bits, grouped for transcription.
export function generateRecoveryCode() {
  const hex = crypto.randomBytes(20).toString('hex').toUpperCase(); // 40 chars
  return hex.match(/.{5}/g).join('-'); // 8 groups of 5
}
