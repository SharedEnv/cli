// Safe DEK helper. A "safe" is a container with one random 256-bit data
// encryption key (DEK). Every secret value is AES-256-GCM encrypted under that
// DEK, bound to its place (secretBlob.js); the DEK itself only ever travels sealed
// (see Wallet.seal).
//
// Runs CLIENT-SIDE. A server only ever sees the resulting ciphertext blobs.

import crypto from 'crypto';

// → 32-byte DEK as a hex string.
export function generateSafeKey() {
  return crypto.randomBytes(32).toString('hex');
}
