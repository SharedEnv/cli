// Detached ECDSA signatures over a TEXT message, with the same secp256k1 key pair a
// sharedenv account already holds (Keypass). No new key, no new trust root.
//
// Why not `Keypass.sign`: it signs SHA-256(JSON.stringify(payload)), the quirk the seal
// format is built on (a Buffer serialises as {"type":"Buffer","data":[...]}), and it is
// the signature INSIDE every sealed envelope. Reusing it for a detached statement would
// let a signature lifted from an envelope be read as a statement, or the reverse. This
// one is domain-separated instead:
//
//   digest    = SHA-256( utf8(DETACHED_SIG_DOMAIN) || 0x00 || utf8(message) )
//   signature = r(32) || s(32), lowercase hex (128 chars), low-S (canonical)
//
// Deterministic (RFC 6979) and canonical: `@noble/curves` with `prehash: false` here and in
// the browser (`platform/next/src/crypto/signature.js`) produces the SAME bytes for the same
// key and message. Both suites pin one shared vector. A high-S signature is refused even
// though it is mathematically valid: one statement, one encoding.
//
// `verifyDetached` never throws — malformed key, signature or message all read `false`.

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { privateKeyBytes } from './keypass.js';

export const DETACHED_SIG_DOMAIN = 'sharedenv/detached-sig/v1';

const SIG_HEX = /^[0-9a-f]{128}$/;
const PUBLIC_KEY_HEX = /^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/i;

export function detachedDigest(message) {
  if (typeof message !== 'string')
    throw new TypeError('detached signature: message must be a string');
  return crypto
    .createHash('sha256')
    .update(Buffer.from(DETACHED_SIG_DOMAIN, 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(message, 'utf8'))
    .digest();
}

// privateKeyHex: the signer's secp256k1 private key. → 128-char lowercase hex r||s.
export function signDetached(privateKeyHex, message) {
  const sig = secp256k1.sign(detachedDigest(message), privateKeyBytes(privateKeyHex), {
    prehash: false, // the digest is already SHA-256: sign it as is
    format: 'compact', // r(32) || s(32), low-S
  });
  return Buffer.from(sig).toString('hex');
}

// publicKeyHex: compressed (66) or uncompressed (130) hex. → boolean, never throws.
export function verifyDetached(publicKeyHex, message, signatureHex) {
  try {
    if (typeof message !== 'string') return false;
    if (typeof signatureHex !== 'string' || !SIG_HEX.test(signatureHex)) return false;
    if (typeof publicKeyHex !== 'string' || !PUBLIC_KEY_HEX.test(publicKeyHex)) return false;
    // Default lowS: true — canonical only, the high-S twin is refused.
    return secp256k1.verify(
      Buffer.from(signatureHex, 'hex'),
      detachedDigest(message),
      Buffer.from(publicKeyHex, 'hex'),
      { prehash: false }
    );
  } catch {
    return false;
  }
}
