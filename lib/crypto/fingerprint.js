// A short, comparable digest of a PUBLIC key — what two people read to each other to
// check they hold the same one. The server is the key directory, and a directory can
// lie: clients pin the keys they have seen and show these digests when one changes.
// SHA-256 of the key bytes, first 16 bytes, uppercase hex, grouped by 4 — every client
// computes the same characters for the same key.

import crypto from 'crypto';

export function fingerprintOf(publicKeyHex) {
  const digest = crypto
    .createHash('sha256')
    .update(Buffer.from(String(publicKeyHex).toLowerCase(), 'hex'))
    .digest('hex');
  return digest.slice(0, 32).toUpperCase().match(/.{4}/g).join(' ');
}
