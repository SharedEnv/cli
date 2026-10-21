// Wallet — the seal/open layer on top of Keypass. `seal`/`open` exchange a
// self-contained, JSON-serializable hex envelope { ciphertext, iv, authTag,
// senderPublicKey } that drops straight into opaque `json` Vault fields. `open`
// returns `false` (never throws) on any tamper or wrong key.

import { Keypass } from './keypass.js';

export class Wallet {
  constructor() {
    this.keypass = new Keypass();
  }

  create() {
    return this.keypass.keyPair();
  }

  // senderPrivateKey, recipientPublicKey: hex. payload: Buffer.
  // → { ciphertext, iv, authTag, senderPublicKey } as hex strings.
  seal(senderPrivateKey, recipientPublicKey, payload) {
    const signature = this.keypass.sign(senderPrivateKey, payload);
    const { encrypted, iv, authTag } = this.keypass.encrypt(senderPrivateKey, recipientPublicKey, {
      payload,
      signature,
    });
    return {
      ciphertext: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      senderPublicKey: this.keypass.publicFromPrivate(senderPrivateKey),
    };
  }

  // recipientPrivateKey: hex. envelope: { ciphertext, iv, authTag, senderPublicKey }.
  // → payload Buffer, or `false` if decryption or signature verification fails.
  //
  // The signature only proves the envelope was sealed by the key it NAMES itself, and
  // any key can seal a payload of its choosing to ours. `from` (a public key, or a
  // list) is the sender the caller expects: an envelope from anyone else is refused
  // like a tampered one. Every client implements the same contract.
  open(recipientPrivateKey, envelope, { from } = {}) {
    const { ciphertext, iv, authTag, senderPublicKey } = envelope;
    if (from) {
      const expected = (Array.isArray(from) ? from : [from]).map((k) => String(k).toLowerCase());
      if (!expected.includes(String(senderPublicKey).toLowerCase())) return false;
    }
    let decrypted;
    try {
      decrypted = this.keypass.decrypt(recipientPrivateKey, senderPublicKey, {
        encrypted: Buffer.from(ciphertext, 'hex'),
        iv: Buffer.from(iv, 'hex'),
        authTag: Buffer.from(authTag, 'hex'),
      });
    } catch {
      return false; // GCM tag failed → ciphertext or key tampered
    }

    const { payload, signature } = decrypted;
    if (!this.keypass.verify(senderPublicKey, payload, signature)) {
      return false; // signature does not match the claimed sender
    }
    return payload;
  }
}
