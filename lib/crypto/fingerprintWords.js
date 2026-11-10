// The spoken form of `fingerprintOf`: same SHA-256 digest, first 16 bytes read as one
// big-endian integer, then six base-7776 digits (least significant first) into the EFF
// large wordlist. Either form names the key: the words can be read back from the hex.

import crypto from 'crypto';
import { EFF_LARGE_WORDLIST } from './effLargeWordlist.js';

const WORDS = 6;
const BASE = BigInt(EFF_LARGE_WORDLIST.length);

export function fingerprintWords(publicKeyHex) {
  const digest = crypto
    .createHash('sha256')
    .update(Buffer.from(String(publicKeyHex).toLowerCase(), 'hex'))
    .digest();
  return spoken(digest.subarray(0, 16).toString('hex'));
}

// The words of a `fingerprintOf` value (32 hex, spaces allowed). → null when it is not one.
export function wordsOfFingerprint(fingerprint) {
  const hex = String(fingerprint).replace(/\s+/g, '');
  return /^[0-9a-fA-F]{32}$/.test(hex) ? spoken(hex) : null;
}

function spoken(hex) {
  let n = BigInt('0x' + hex);
  const words = [];
  for (let i = 0; i < WORDS; i++) {
    words.push(EFF_LARGE_WORDLIST[Number(n % BASE)]);
    n /= BASE;
  }
  return `${words.slice(0, 3).join(' ')} · ${words.slice(3).join(' ')}`;
}
