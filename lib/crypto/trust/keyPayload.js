// Rule D: what a sealed key says it belongs to. The sealed bytes are no longer the bare key
// but this ASCII JSON, in this exact order and nothing else:
//
//   {"t":"sharedenv/safe-key/v1","safe":"<24 hex>","v":<n>,"k":"<64 hex>"}
//   {"t":"sharedenv/team-key/v1","team":"<24 hex>","v":<n>,"k":"<64 hex>"}
//
// The seal signs and encrypts it, so the sealer vouches for the object and the version
// too: a key lifted from another safe, another version, or the old bare format is refused.
//
// No import outside this folder (copied byte for byte into API/src/tools/crypto/trust/):
// bytes travel as hex.

import { isVersion } from './memory.js';

const TYPES = { safe: 'sharedenv/safe-key/v1', team: 'sharedenv/team-key/v1' };
const ID = /^[0-9a-f]{24}$/;
const KEY = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})*$/;

const canonical = (kind, id, version, key) =>
  `{"t":"${TYPES[kind]}","${kind}":"${id}","v":${version},"k":"${key}"}`;

const asciiToHex = (text) =>
  Array.from(text, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');

// -> the text, or null when a byte is not printable ASCII.
function hexToAscii(hex) {
  let text = '';
  for (let i = 0; i < hex.length; i += 2) {
    const code = parseInt(hex.slice(i, i + 2), 16);
    if (code < 0x20 || code > 0x7e) return null;
    text += String.fromCharCode(code);
  }
  return text;
}

// -> the hex of the bytes to seal. kind: 'safe' | 'team'; key: 64 hex.
export function encodeKeyPayload({ kind, id, version, key }) {
  const objectId = String(id).toLowerCase();
  const keyHex = String(key).toLowerCase();
  const valid = TYPES[kind] && ID.test(objectId) && KEY.test(keyHex) && isVersion(version);
  if (!valid) throw new Error('Invalid key payload.');
  return asciiToHex(canonical(kind, objectId, version, keyHex));
}

// What an opened seal holds, checked against where it was found. `version`: the one the row
// declares (omitted: any). -> { version, key } | null
export function readKeyPayload(hex, { kind, id, version }) {
  if (!TYPES[kind] || typeof hex !== 'string' || !HEX.test(hex)) return null;
  const text = hexToAscii(hex);
  if (text === null) return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const { v, k } = parsed;
  if (!isVersion(v) || typeof k !== 'string' || !KEY.test(k)) return null;
  if (version !== undefined && v !== version) return null;
  return text === canonical(kind, String(id).toLowerCase(), v, k) ? { version: v, key: k } : null;
}

// keyFp = the first 16 bytes of SHA-256 of this text, as 32 hex: the digest the memory keeps
// of a key, never the key.
export const keyFpInput = (keyHex) => `sharedenv/key-fp/v1|${String(keyHex).toLowerCase()}`;
