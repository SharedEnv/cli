// Secret blobs of the zero-knowledge vault — every client (Node, browser) writes and reads
// the same bytes.
//
//   { v: 2, ciphertext, iv, authTag, ctx } — ctx = { safeId, key, kind } is the secret's
//   place, authenticated as AES-GCM additional data. A reader that knows where it found the
//   blob compares and refuses a stranger; without that, the blob is read at the place it
//   names. Any other shape is refused: a ciphertext with no place would be valid wherever a
//   server put it (two values of a safe swapped, a sealed meta served as a value).

import { gcmDecrypt, gcmEncrypt } from './aes.js';

const LABELS = { value: 'sharedenv/secret/v2', meta: 'sharedenv/meta/v2' };

// → the canonical ctx. Throws on anything but { safeId, key, kind? }.
function placeOf(ctx) {
  const kind = ctx?.kind || 'value';
  if (!LABELS[kind] || ctx?.safeId == null || ctx?.key == null) {
    throw new Error('A secret context is { safeId, key, kind: value|meta }');
  }
  return { safeId: String(ctx.safeId), key: String(ctx.key), kind };
}

const aadOf = (place) =>
  Buffer.from([LABELS[place.kind], place.safeId, place.key].join('\u0000'), 'utf8');

// dekHex, plaintext: strings. ctx: the place the blob is bound to. → a v2 blob.
export function sealSecret(dekHex, plaintext, ctx) {
  const place = placeOf(ctx);
  const blob = gcmEncrypt(
    Buffer.from(dekHex, 'hex'),
    Buffer.from(String(plaintext), 'utf8'),
    aadOf(place)
  );
  return { v: 2, ...blob, ctx: place };
}

// → plaintext. `expected` (optional): where the caller found the blob — a blob from
// anywhere else is refused. Throws when no key opens it (AES-GCM authenticates).
export function openSecret(dekHex, blob, expected) {
  if (blob?.v !== 2) throw new Error('Not a secret blob: { v: 2, ..., ctx } expected');
  const place = placeOf(blob.ctx);
  if (expected) {
    const want = placeOf(expected);
    if (want.safeId !== place.safeId || want.key !== place.key || want.kind !== place.kind) {
      throw new Error(`This blob belongs to ${place.kind} "${place.key}" of safe ${place.safeId}`);
    }
  }
  return gcmDecrypt(Buffer.from(dekHex, 'hex'), blob, aadOf(place)).toString('utf8');
}
