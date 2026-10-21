// AES-256-GCM helper — the symmetric primitive shared by the framework's
// zero-knowledge crypto: private-key wrap under the KDF key, secret values under
// a DEK, and the ECIES inner cipher in keypass. Envelopes are emitted as hex so
// they serialize cleanly into opaque `json` Vault fields.
//
// Isomorphic note: this uses Node's `crypto`. A browser bundle swaps this one
// file for a WebCrypto/@noble implementation with the same { ciphertext, iv,
// authTag } hex contract — nothing else in the lib changes.

import crypto from 'crypto';

const IV_BYTES = 12; // 96-bit nonce, the GCM standard

// key: Buffer(32). data: Buffer. aad (optional): Buffer, authenticated, not encrypted.
// → { ciphertext, iv, authTag } as hex strings.
export function gcmEncrypt(key, data, aad) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
  };
}

// key: Buffer(32). envelope: { ciphertext, iv, authTag } hex. aad: as sealed. → Buffer.
// Throws if the auth tag does not verify (wrong key, tampered ciphertext or other aad).
export function gcmDecrypt(key, { ciphertext, iv, authTag }, aad) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]);
}
