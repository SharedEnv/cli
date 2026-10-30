// Vaults: find one, open it (recover its key, the DEK, locally), read and write its
// secrets, create one. The server only ever holds ciphertext.

import { Buffer } from 'buffer';
import { Wallet, generateSafeKey, openSecret, sealSecret } from './crypto.js';
import { expectOk, listAll } from './api.js';
import { publicKeyOf } from './auth.js';
import { PendingShareError, listPendingShares, personLabel } from './shares.js';

const wallet = new Wallet();
const SAFE_ID = /^[a-f0-9]{24}$/i;

// Secret names the API accepts. Checked again here: the server is the party
// zero-knowledge does not trust, and a name lands in a .env line or an environment.
export const SECRET_NAME = /^[A-Za-z0-9_-]+$/;

export const LEVELS = { read: 10, write: 50, admin: 90 };
export const levelName = (level) =>
  Object.keys(LEVELS).find((name) => LEVELS[name] === level) || String(level);

export const listVaults = (client) => listAll(client, '/safes', 'vaults');

// One line that tells a vault from another of the same name: its id, your access, whose
// it is, and through which of your teams you reach it. `me`: your user id, when known.
export function describeVault(row, me) {
  const mine = me && String(row.ownerId) === String(me);
  const owner = mine ? 'you' : row.owner ? personLabel(row.owner) : String(row.ownerId);
  const teams = (row.teams || []).map((t) => (t.org?.name ? `${t.name} (${t.org.name})` : t.name));
  return [
    row.name,
    String(row._id),
    levelName(row.level),
    `owner ${owner}`,
    ...(teams.length ? [`team ${teams.join(', ')}`] : []),
  ].join('  ');
}

// A vault by id, or by (case-insensitive) name among every vault you can open. A name
// that several vaults answer to picks none of them: the candidates are listed. A share
// still waiting for your answer is named as such rather than reported missing.
// → the vault id.
export async function resolveSafe(client, ref) {
  if (SAFE_ID.test(ref)) return ref.toLowerCase();
  const name = ref.toLowerCase();
  const matches = (await listVaults(client)).filter((s) => s.name?.toLowerCase() === name);
  if (matches.length === 1) return String(matches[0]._id);
  if (matches.length > 1) {
    throw Object.assign(
      new Error(
        [
          `"${ref}" names ${matches.length} vaults: give its id (-v <id>)`,
          ...matches.map((row) => `  ${describeVault(row)}`),
        ].join('\n')
      ),
      { exitCode: 2 }
    );
  }
  const pending = (await listPendingShares(client)).direct.find(
    (p) => p.safe?.name?.toLowerCase() === name
  );
  if (pending) throw new PendingShareError(pending);
  throw new Error(`no vault named "${ref}" (sharedenv vaults lists yours)`);
}

// GET /safes/:id — the vault, your paths to its key, its owner and your teams on it. A
// share waiting for your answer opens nothing yet: said as such.
export async function readVault(client, safeId) {
  const res = await client.call('GET', `/safes/${safeId}`);
  if (res.status === 403 && res.body?.key === 'sharePending') {
    const pending = (await listPendingShares(client)).direct.find(
      (p) => String(p.safeId) === String(safeId)
    );
    throw pending
      ? new PendingShareError(pending)
      : new Error(
          'this vault is shared with you but waits for your answer: run `sharedenv vaults`'
        );
  }
  return expectOk(res, 'cannot open the vault');
}

// Your access to a vault, from what GET /safes/:id says of your paths to it.
export function accessOf(vault) {
  const levels = [vault.membership?.level, ...(vault.teamAccess || []).map((t) => t.level)];
  return Math.max(0, ...levels.filter((l) => typeof l === 'number'));
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

// → the vault (readVault) and its `deks`, current first.
export async function openVault(client, privateKey, safeId) {
  const vault = await readVault(client, safeId);
  const deks = resolveDeks(privateKey, vault);
  if (deks.length === 0) {
    throw new Error('no key to this vault on your account (not a member, or not provisioned yet)');
  }
  return { ...vault, deks };
}

// Every secret row of a vault: names in clear, values sealed. Names are checked: one
// that is not a variable name, or twice the same, is refused.
export async function listSecretRows(client, safeId) {
  const seen = new Set();
  const rows = await listAll(client, `/secrets/${safeId}`, 'secrets');
  for (const row of rows) {
    if (typeof row.key !== 'string' || !SECRET_NAME.test(row.key)) {
      throw new Error(`refusing a secret named ${JSON.stringify(row.key)}: not a variable name`);
    }
    if (seen.has(row.key)) throw new Error(`the server sent "${row.key}" twice for this vault`);
    seen.add(row.key);
  }
  return rows;
}

// AES-GCM authenticates: the first key that opens a value is the one it was written
// under. The value must have been sealed where it was read (this vault, this name): a
// blob moved there from another secret or another vault is refused.
function decryptRow(deks, safeId, row) {
  const place = { safeId, key: row.key };
  let misplaced = null;
  for (const dek of deks) {
    try {
      return openSecret(dek, row.ciphertextValue, place);
    } catch (err) {
      if (/belongs to/.test(err.message)) misplaced = err;
    }
  }
  if (misplaced) throw new Error(`refusing "${row.key}": ${misplaced.message}`);
  throw new Error(`cannot decrypt "${row.key}" — a key rotation may be in progress, retry shortly`);
}

// → { safe, secrets: { KEY: value } } — every secret of the vault, decrypted. All or
// nothing: one value that cannot be read fails the pull, so `run` never starts a process
// with a variable missing.
export async function pullSecrets(client, privateKey, safeId) {
  const vault = await openVault(client, privateKey, safeId);
  const secrets = {};
  for (const row of await listSecretRows(client, safeId)) {
    secrets[row.key] = decryptRow(vault.deks, safeId, row);
  }
  return { safe: vault.safe, secrets };
}

// → { safe, value } — one secret, decrypted.
export async function readSecret(client, privateKey, safeId, key) {
  const vault = await openVault(client, privateKey, safeId);
  const row = (await listSecretRows(client, safeId)).find((r) => r.key === key);
  if (!row) throw new Error(`no key "${key}" in vault "${vault.safe.name}"`);
  return { safe: vault.safe, value: decryptRow(vault.deks, safeId, row) };
}

// Adds or replaces secrets, sealed here under the vault's current key and bound to their
// place. A vault someone lost access to still runs under the key they held: nothing new
// is written under it until its key has changed — and that rotation re-encrypts every
// secret, which the web app does.
// `entries`: [[KEY, value]]. → { safe, added: [KEY], replaced: [KEY] }
export async function setSecrets(client, privateKey, safeId, entries) {
  const vault = await openVault(client, privateKey, safeId);
  const { safe } = vault;
  if (safe.pendingRotation) {
    throw new Error(
      `"${safe.name}" must change its key first (someone lost access to it): an admin of ` +
        'the vault opens it in the web app, which does it - then retry'
    );
  }
  const [dek] = vault.deks;
  const keyVersion = safe.keyVersion || 1;
  const existing = new Map((await listSecretRows(client, safeId)).map((r) => [r.key, r]));
  const added = [];
  const replaced = [];
  for (const [key, value] of entries) {
    const ciphertextValue = JSON.stringify(sealSecret(dek, value, { safeId, key }));
    const row = existing.get(key);
    if (row) {
      expectOk(
        await client.call('PUT', `/secrets/${safeId}/${row._id}`, { ciphertextValue, keyVersion }),
        `cannot replace "${key}"`
      );
      replaced.push(key);
    } else {
      expectOk(
        await client.call('POST', `/secrets/${safeId}`, { key, ciphertextValue, keyVersion }),
        `cannot add "${key}"`
      );
      added.push(key);
    }
  }
  return { safe, added, replaced };
}

// Removes secrets by name; every name must exist, or nothing is removed. No key needed:
// the server only drops ciphertext.
export async function unsetSecrets(client, safeId, keys) {
  const rows = new Map((await listSecretRows(client, safeId)).map((r) => [r.key, r]));
  const missing = keys.filter((key) => !rows.has(key));
  if (missing.length) {
    throw new Error(`no key ${missing.map((k) => `"${k}"`).join(', ')} in this vault`);
  }
  for (const key of keys) {
    expectOk(
      await client.call('DELETE', `/secrets/${safeId}/${rows.get(key)._id}`),
      `cannot remove "${key}"`
    );
  }
}

// A new vault, yours: a fresh DEK, sealed to your own key here. A name you already see
// is refused — it would stop telling the two vaults apart. → the vault ({ _id, name }).
export async function createVault(client, privateKey, name) {
  const taken = (await listVaults(client)).find(
    (s) => s.name?.toLowerCase() === String(name).toLowerCase()
  );
  if (taken) {
    throw new Error(
      `you already have a vault named "${taken.name}" (${taken._id}): pick another name`
    );
  }
  const dek = generateSafeKey();
  const sealedSafeKey = wallet.seal(privateKey, publicKeyOf(privateKey), Buffer.from(dek, 'hex'));
  const body = expectOk(
    await client.call('POST', '/safes', { name, sealedSafeKey: JSON.stringify(sealedSafeKey) }),
    'cannot create the vault'
  );
  return body.safe;
}
