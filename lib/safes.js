// Reading a safe: find it, recover its key (DEK), decrypt every secret — locally. The
// server only ever returns ciphertext.

import { Wallet, openSecret } from './crypto.js';
import { expectOk, listAll } from './api.js';
import { PendingShareError, listPendingShares } from './shares.js';

const wallet = new Wallet();
const SAFE_ID = /^[a-f0-9]{24}$/i;

// Secret names the API accepts. Checked again here: the server is the party
// zero-knowledge does not trust, and a name lands in a .env line or an environment.
const SECRET_NAME = /^[A-Za-z0-9_-]+$/;

// A safe by id, or by (case-insensitive) name. A share still waiting for the caller's
// answer is not in their list: it is named as such rather than reported missing.
export async function resolveSafe(client, ref) {
  if (SAFE_ID.test(ref)) return ref;
  const name = ref.toLowerCase();
  const safes = await listAll(client, '/safes', 'safes');
  const match = safes.find((s) => s.name?.toLowerCase() === name);
  if (match) return String(match._id);
  const pending = (await listPendingShares(client)).direct.find(
    (p) => p.safe?.name?.toLowerCase() === name
  );
  if (pending) throw new PendingShareError(pending);
  throw new Error(`no safe named "${ref}"`);
}

// Every DEK the caller's paths to a safe yield, CURRENT first: a direct envelope, or a
// team grant (own key → team key → DEK). More than one only while a key rotation is in
// flight: each row then also carries the blob it held before (`previous…`), and secrets
// may sit under either key.
export function resolveDeks(privateKey, safe) {
  const deks = [];
  const add = (opened) => {
    const hex = opened ? opened.toString('hex') : null;
    if (hex && !deks.includes(hex)) deks.push(hex);
  };
  const m = safe.membership;
  for (const blob of [m?.sealedSafeKey, m?.previousSealedSafeKey]) {
    if (blob) add(wallet.open(privateKey, blob));
  }
  for (const grant of safe.teamAccess || []) {
    const teamKeys = [grant.sealedTeamKey, grant.previousSealedTeamKey]
      .filter(Boolean)
      .map((blob) => wallet.open(privateKey, blob))
      .filter(Boolean)
      .map((opened) => opened.toString('utf8'));
    for (const blob of [grant.sealedSafeKey, grant.previousSealedSafeKey]) {
      if (!blob) continue;
      const opened = teamKeys.map((teamKey) => wallet.open(teamKey, blob)).find(Boolean);
      if (opened) add(opened);
    }
  }
  return deks;
}

// AES-GCM authenticates: the first key that opens a value is the one it was written
// under. `place` is where the value was read: a blob moved there from another secret or
// another safe is refused.
function decryptWithAny(deks, blob, place) {
  let misplaced = null;
  for (const dek of deks) {
    try {
      return openSecret(dek, blob, place);
    } catch (err) {
      if (/belongs to/.test(err.message)) misplaced = err;
    }
  }
  if (misplaced) throw new Error(`refusing "${place.key}": ${misplaced.message}`);
  throw new Error(
    `cannot decrypt "${place.key}" — a key rotation may be in progress, retry shortly`
  );
}

// → { KEY: value } — every secret of the safe, decrypted. All or nothing: one value that
// cannot be read fails the pull, so `run` never starts a process with a variable missing.
export async function pullSecrets(client, privateKey, safeId) {
  const res = await client.call('GET', `/safes/${safeId}`);
  if (res.status === 403 && res.body?.key === 'sharePending') {
    const pending = (await listPendingShares(client)).direct.find(
      (p) => String(p.safeId) === String(safeId)
    );
    throw pending
      ? new PendingShareError(pending)
      : new Error('this safe is shared with you but waits for your answer: run `sharedenv list`');
  }
  const safe = expectOk(res, 'cannot open the safe');

  const deks = resolveDeks(privateKey, safe);
  if (deks.length === 0) {
    throw new Error('no key to this safe on your account (not a member, or not provisioned yet)');
  }

  const secrets = {};
  for (const row of await listAll(client, `/secrets/${safeId}`, 'secrets')) {
    if (typeof row.key !== 'string' || !SECRET_NAME.test(row.key)) {
      throw new Error(`refusing a secret named ${JSON.stringify(row.key)}: not a variable name`);
    }
    if (Object.hasOwn(secrets, row.key)) throw new Error(`the safe served "${row.key}" twice`);
    secrets[row.key] = decryptWithAny(deks, row.ciphertextValue, { safeId, key: row.key });
  }
  return secrets;
}
