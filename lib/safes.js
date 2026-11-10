// Vaults: find one, open it (recover its key, the DEK, locally), read and write its
// secrets, create one. The server only ever holds ciphertext.

import { randomBytes } from 'crypto';
import { Wallet, generateSafeKey, openSecret, readKeyPayload, sealSecret } from './crypto.js';
import { expectOk, freshTries, listAll } from './api.js';
import { PendingShareError, listPendingShares, personLabel, printable } from './shares.js';
import { keyFpOf } from './transparency.js';
import { TrustRefusal, sealKey } from './trust.js';

const wallet = new Wallet();
const SAFE_ID = /^[a-f0-9]{24}$/i;

// Secret names the API accepts. Checked again here: the server is the party
// zero-knowledge does not trust, and a name lands in a .env line or an environment.
export const SECRET_NAME = /^[A-Za-z0-9_-]+$/;
// What the server stores (`secrets.key`): read wider, written as it is.
export const WRITABLE_NAME = /^[A-Z0-9_-]{2,}$/;

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
  if (res.status === 403 && res.body?.key === 'SHARE_PENDING') {
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

// One envelope, opened and read. → null (absent, or it does not open), or what it holds: a
// path for the guard, `unbound` when it does not name the vault or team it was found on, or
// the version `where` asks (rule D). `from`: who the server says sealed it.
function sealedPath(recipientKey, blob, where, from) {
  const opened = blob && wallet.open(recipientKey, blob);
  if (!opened) return null;
  const payload = readKeyPayload(opened.toString('hex'), where);
  return {
    unbound: !payload,
    version: payload?.version,
    key: payload?.key,
    keyFp: payload && keyFpOf(payload.key),
    sealer: {
      publicKey: String(blob.senderPublicKey).toLowerCase(),
      subject: from?._id ? `user:${from._id}` : undefined,
      label: personLabel(from),
    },
  };
}

const usable = (path) => path && !path.unbound;

// The team's official version, what tells a team key in flight from a settled one.
async function officialTeamVersion(client, teamId) {
  const res = await client.call('GET', `/team-keys/${encodeURIComponent(teamId)}/me`);
  // Unknown reads as behind whatever was opened: that opens, and is not remembered (decideOpen).
  return (res.status === 200 && res.body?.teamKeyVersion) || 0;
}

// Own key → team key, by the guard, for this team only. A previous team key (a rotation leaves
// grants where they are) is asked about by nobody: it passes or it is left out.
// → { keys, decision }
async function teamKeysOf(client, trust, grant, context, refused) {
  const teamId = String(grant.teamId);
  const scope = `team:${teamId}`;
  const version = grant.teamKeyVersion || 1;
  const where = { kind: 'team', id: teamId };
  const current = sealedPath(
    trust.privateKey,
    grant.sealedTeamKey,
    { ...where, version },
    grant.teamKeyFrom
  );
  if (current?.unbound) throw refused();
  const keys = [];
  let decision = null;
  if (current) {
    decision = await trust.open({
      scope,
      paths: [current],
      official: await officialTeamVersion(client, teamId),
      context,
    });
    keys.push(current.key);
  }
  const previous = sealedPath(trust.privateKey, grant.previousSealedTeamKey, where);
  const older = usable(previous) && (!current || previous.version < version);
  if (older && (await trust.openQuietly({ scope, paths: [previous] }))) keys.push(previous.key);
  return { keys, decision };
}

// Own key → team key → the vault's key: the first team key that opens it.
function grantPath(keys, blob, where, from) {
  for (const key of keys) {
    const path = sealedPath(key, blob, where, from);
    if (path) return path;
  }
  return null;
}

// What the guard says to whom it cannot answer for a seal (F2). `renewable`: the server says
// whether anyone can still renew the key.
function whoRenews(vault) {
  if (accessOf(vault) >= LEVELS.admin) return 'self';
  return vault.safe.renewable === false ? 'nobody' : 'other';
}

// → the vault (readVault), its `deks`, current first, the `keyVersion` and `keyFp` of the first,
// and `commit()`: what the caller calls once everything went through (rule C). The guard decides
// on the highest version among your paths to the key, for this vault only (sujet 1): a seal
// nobody answers for refuses the vault, even next to a path that opens. A row behind that one,
// or the blob a row held before a rotation, is asked about by nobody: it reads what a rotation
// left behind if the guard lets it pass, nothing more.
export async function openVault(client, trust, safeId) {
  const vault = await readVault(client, safeId);
  const { safe } = vault;
  const name = printable(safe.name);
  const official = safe.keyVersion || 1;
  const refused = () => new TrustRefusal('SEALER_REFUSED', { vault: name });
  const where = { kind: 'safe', id: safeId };
  const paths = [];
  const leftBehind = [];
  const decisions = [];
  let holdsTeamKey = false;
  const add = (path) => {
    if (path?.unbound) throw refused();
    if (path) paths.push(path);
  };

  const m = vault.membership;
  if (m) {
    const version = m.keyVersion || 1;
    add(sealedPath(trust.privateKey, m.sealedSafeKey, { ...where, version }, m.from));
    leftBehind.push(
      sealedPath(trust.privateKey, m.previousSealedSafeKey, { ...where, version: official })
    );
  }
  const teamOf = (teamId) => (safe.teams || []).find((t) => String(t._id) === String(teamId));
  for (const grant of vault.teamAccess || []) {
    const team = teamOf(grant.teamId);
    const context = { vault: `${name} (team ${printable(team?.name || grant.teamId)})` };
    const { keys, decision } = await teamKeysOf(client, trust, grant, context, refused);
    if (decision) decisions.push(decision);
    holdsTeamKey ||= keys.length > 0;
    const version = grant.keyVersion || 1;
    add(grantPath(keys, grant.sealedSafeKey, { ...where, version }, grant.from));
    leftBehind.push(grantPath(keys, grant.previousSealedSafeKey, { ...where, version: official }));
  }
  if (paths.length === 0) {
    if (holdsTeamKey) throw refused();
    const [waiting] = vault.teamAccess || [];
    throw waiting
      ? new TrustRefusal('TEAM_KEY_NOT_PROVISIONED', { team: teamOf(waiting.teamId)?.name })
      : new TrustRefusal('ACCESS_DENIED');
  }

  const scope = `safe:${safeId}`;
  const decision = await trust.open({
    scope,
    paths,
    official,
    renew: whoRenews(vault),
    context: { vault: name },
  });
  decisions.push(decision);
  const deks = [paths.find((path) => path.version === decision.version).key];
  const below = paths.filter((path) => path.version < decision.version);
  for (const path of [...below, ...leftBehind.filter(usable)]) {
    const passes = await trust.openQuietly({ scope, paths: [path] });
    if (passes && !deks.includes(path.key)) deks.push(path.key);
  }
  return {
    ...vault,
    deks,
    keyVersion: decision.version,
    keyFp: decision.keyFp,
    commit: () => decisions.forEach((d) => trust.commitOpen(d)),
  };
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
// blob moved there from another secret or another vault is refused. Whatever `unreadable` says
// (the database's word, #illisible): a value that opens is read.
function decryptRow(deks, safeId, row) {
  const place = { safeId, key: row.key };
  let misplaced = false;
  for (const dek of deks) {
    try {
      return openSecret(dek, row.ciphertextValue, place);
    } catch (err) {
      misplaced ||= /belongs to/.test(err.message);
    }
  }
  throw Object.assign(new TrustRefusal('SECRET_SET_ASIDE', { secret: row.key }), { misplaced });
}

// One of the caller's rows is ahead of the vault: a rotation that never ended.
export function rotationUnfinished({ safe, membership, teamAccess }) {
  const official = safe.keyVersion || 1;
  return [membership, ...(teamAccess || [])].some((row) => (row?.keyVersion || 1) > official);
}

// An old key someone who left still holds can be put back on a row. Ahead of its vault, the
// row is a rotation that never ended and either blob may hold it: both read, neither writes
// nor goes to anyone new. At the vault's version, it does not open the secrets listed. A line
// a rotation set aside does not count (#illisible); one not marked yet does, and the renewal
// that would mark it is an admin's: writing it again here could be under the old key.
// → the vault (openVault), its secret `rows` and `writeDek`, the only key to write with or
// seal to someone.
export async function openVaultToWrite(client, trust, safeId) {
  const vault = await openVault(client, trust, safeId);
  const { safe } = vault;
  const name = printable(safe.name);
  if (rotationUnfinished(vault)) {
    throw new TrustRefusal(
      accessOf(vault) >= LEVELS.admin ? 'ROTATION_UNFINISHED' : 'WRITE_BLOCKED_DEBT_NOTICE'
    );
  }
  // A row behind its vault: the version bound to its key says it is not the current one.
  if (vault.keyVersion !== (safe.keyVersion || 1)) {
    throw new TrustRefusal('SEALER_REFUSED', { vault: name });
  }
  const [writeDek] = vault.deks;
  const rows = await listSecretRows(client, safeId);
  for (const row of rows.filter((r) => !r.unreadable)) {
    try {
      decryptRow([writeDek], safeId, row);
    } catch (err) {
      if (err.misplaced) throw err;
      throw new TrustRefusal('SEALER_REFUSED', { vault: name });
    }
  }
  return { ...vault, rows, writeDek };
}

// → { safe, secrets: { KEY: value } } — every secret of the vault, decrypted. All or
// nothing: one value that cannot be read fails the pull, so `run` never starts a process
// with a variable missing.
export async function pullSecrets(client, trust, safeId) {
  const vault = await openVault(client, trust, safeId);
  const secrets = {};
  for (const row of await listSecretRows(client, safeId)) {
    secrets[row.key] = decryptRow(vault.deks, safeId, row);
  }
  vault.commit();
  return { safe: vault.safe, secrets };
}

// → { safe, value } — one secret, decrypted.
export async function readSecret(client, trust, safeId, key) {
  const vault = await openVault(client, trust, safeId);
  const row = (await listSecretRows(client, safeId)).find((r) => r.key === key);
  if (!row) throw new Error(`no key "${key}" in vault "${vault.safe.name}"`);
  const value = decryptRow(vault.deks, safeId, row);
  vault.commit();
  return { safe: vault.safe, value };
}

// Adds or replaces secrets, sealed here under the vault's current key and bound to their
// place. A vault someone lost access to still runs under the key they held: the server refuses
// anything new under it until its key has changed, and its first refusal is what mails the
// admins (sujet 6). A key that moved during the writes: what went through stays, the rest is
// sealed anew.
// `entries`: [[KEY, value]]. → { safe, added: [KEY], replaced: [KEY] }
export async function setSecrets(client, trust, safeId, entries) {
  const left = new Map(entries);
  const added = [];
  const replaced = [];
  const safe = await freshTries(async () => {
    const vault = await openVaultToWrite(client, trust, safeId);
    const { keyVersion, rows, writeDek: dek } = vault;
    const existing = new Map(rows.map((r) => [r.key, r]));
    for (const [key, value] of left) {
      const ciphertextValue = JSON.stringify(sealSecret(dek, value, { safeId, key }));
      const row = existing.get(key);
      if (row) {
        expectOk(
          await client.call('PUT', `/secrets/${safeId}/${row._id}`, {
            ciphertextValue,
            keyVersion,
          }),
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
      left.delete(key);
    }
    vault.commit();
    return vault.safe;
  });
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
export async function createVault(client, trust, name) {
  const taken = (await listVaults(client)).find(
    (s) => s.name?.toLowerCase() === String(name).toLowerCase()
  );
  if (taken) {
    throw new Error(
      `you already have a vault named "${taken.name}" (${taken._id}): pick another name`
    );
  }
  const dek = generateSafeKey();
  const safeId = randomBytes(12).toString('hex');
  const sealedSafeKey = sealKey(trust.privateKey, trust.ownKey, {
    kind: 'safe',
    id: safeId,
    version: 1,
    key: dek,
  });
  const body = expectOk(
    await client.call('POST', '/safes', {
      safeId,
      name,
      sealedSafeKey: JSON.stringify(sealedSafeKey),
    }),
    'cannot create the vault'
  );
  trust.commitSeal({
    scope: `safe:${safeId}`,
    version: 1,
    keyFp: keyFpOf(dek),
    to: [`user:${trust.userId}`],
    full: true,
  });
  return body.safe;
}
