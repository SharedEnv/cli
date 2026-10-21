// Keypass — secp256k1 primitives (@noble/curves): key pairs, ECDSA sign/verify, and the
// authenticated box Wallet builds on (ECDH shared secret → SHA-256 → AES-256-GCM, with a
// 65-byte signature appended to the payload). The signature proves who sealed the
// message; the GCM tag proves it was not altered.
//
// The byte format is shared by every client (Node, browser, extension):
//   - private key: hex, 32 bytes. Keys minted by older clients may have dropped their
//     leading zeros, so input is padded before use.
//   - public key: compressed point (33 bytes), hex.
//   - signed digest: SHA-256 of JSON.stringify(message). For a Buffer that is the UTF-8
//     of {"type":"Buffer","data":[...]} — odd, but every sealed envelope carries it.
//   - signature: r(32) || s(32) || recovery(1), deterministic (RFC 6979), low-S when
//     signed here. Verification accepts both halves of s: envelopes sealed by older
//     clients carry high-S signatures.
//
// The private-key operations (keyPair, sign, the ECDH of encrypt/decrypt) run CLIENT-SIDE;
// a zero-knowledge server only ever calls `verify`.

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const SIG_BYTES = 65; // r(32) + s(32) + recovery(1)

// hex (possibly unpadded) → the 32 bytes of a private key.
export function privateKeyBytes(privateKeyHex) {
  const hex = String(privateKeyHex);
  if (!/^[0-9a-fA-F]{1,64}$/.test(hex)) throw new Error('A private key is up to 64 hex characters');
  return Buffer.from(hex.padStart(64, '0'), 'hex');
}

function digest(message) {
  return crypto.createHash('sha256').update(JSON.stringify(message)).digest();
}

const hex64 = (n) => n.toString(16).padStart(64, '0');

// r or s as a bigint, a hex string or a bn.js-like value → 64 hex characters.
function scalarHex(value) {
  const hex = typeof value === 'string' ? value : value.toString(16);
  if (!/^[0-9a-fA-F]{1,64}$/.test(hex)) throw new Error('Malformed signature scalar');
  return hex.padStart(64, '0');
}

export class Keypass {
  keyPair() {
    const secretKey = secp256k1.utils.randomSecretKey();
    return {
      privateKey: Buffer.from(secretKey).toString('hex'),
      publicKey: Buffer.from(secp256k1.getPublicKey(secretKey, true)).toString('hex'),
    };
  }

  publicFromPrivate(privateKey) {
    return Buffer.from(secp256k1.getPublicKey(privateKeyBytes(privateKey), true)).toString('hex');
  }

  // → { r, s, recoveryParam }, r and s as bigints.
  sign(privateKey, message) {
    const sig = secp256k1.sign(digest(message), privateKeyBytes(privateKey), {
      prehash: false, // the digest is already SHA-256: sign it as is
      format: 'recovered', // recovery(1) || r(32) || s(32)
    });
    const hex = Buffer.from(sig).toString('hex');
    return {
      r: BigInt(`0x${hex.slice(2, 66)}`),
      s: BigInt(`0x${hex.slice(66, 130)}`),
      recoveryParam: sig[0],
    };
  }

  // signature: { r, s } (bigints or hex). → boolean, never throws.
  verify(publicKey, message, signature) {
    try {
      const rs = Buffer.from(scalarHex(signature.r) + scalarHex(signature.s), 'hex');
      return secp256k1.verify(rs, digest(message), Buffer.from(publicKey, 'hex'), {
        prehash: false,
        lowS: false,
      });
    } catch {
      return false;
    }
  }

  // senderPrivateKey, recipientPublicKey: hex. packet: { signature, payload: Buffer }.
  // → { encrypted, iv, authTag } as Buffers.
  encrypt(senderPrivateKey, recipientPublicKey, { signature, payload }) {
    const sigBuffer = Buffer.concat([
      Buffer.from(hex64(signature.r) + hex64(signature.s), 'hex'),
      Buffer.from([signature.recoveryParam || 0]),
    ]);
    const messageBuffer = Buffer.concat([payload, sigBuffer]);

    const encryptionKey = this.#sharedKey(senderPrivateKey, recipientPublicKey);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(messageBuffer), cipher.final()]);

    return { encrypted, iv, authTag: cipher.getAuthTag() };
  }

  // recipientPrivateKey, senderPublicKey: hex. encryptedData: { encrypted, iv, authTag } Buffers.
  // → { payload: Buffer, signature } — throws if the GCM tag fails (altered or wrong key).
  decrypt(recipientPrivateKey, senderPublicKey, { encrypted, iv, authTag }) {
    const decryptionKey = this.#sharedKey(recipientPrivateKey, senderPublicKey);
    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    const payload = decrypted.subarray(0, decrypted.length - SIG_BYTES);
    const sigHex = decrypted.subarray(decrypted.length - SIG_BYTES).toString('hex');
    const signature = {
      r: BigInt(`0x${sigHex.slice(0, 64)}`),
      s: BigInt(`0x${sigHex.slice(64, 128)}`),
      recoveryParam: parseInt(sigHex.slice(128, 130), 16),
    };

    return { payload, signature };
  }

  // ECDH shared secret (its X coordinate) → SHA-256 → 32-byte symmetric key.
  #sharedKey(privateKey, publicKey) {
    const point = secp256k1.getSharedSecret(
      privateKeyBytes(privateKey),
      Buffer.from(publicKey, 'hex'),
      true
    );
    return crypto.createHash('sha256').update(point.subarray(1)).digest();
  }
}
