// The public key log (key transparency). The server is the key directory, and the
// directory is rows in a database: whoever can write there could answer "Bob" with a key
// of their own. So every key it hands out is first written to a log that only grows,
// each entry chained to the previous one by its hash. This CLI:
//   - seals to, or starts trusting the seal of, a key only if it is the LAST one the log
//     holds for its owner: a substituted key would have to be logged, where its owner sees it ;
//   - watches the keys you hold - your own, and the key of every team sealed to you: a
//     key logged under one of their names that is not the one you hold is reported, and
//     the warning comes back at every unlock until `sharedenv log --ack` ;
//   - keeps what it checked, for this account on this server (lib/store.js), and refuses a
//     log that does not chain, rewrites what it already saw, or goes back.
// The arithmetic, and the rules of what is kept, are lib/crypto/kt.js.

import { createHash } from 'crypto';
import {
  Wallet,
  absorb,
  acknowledge,
  commitSeal,
  emptyMemory,
  fingerprintOf,
  forgetAfter,
  hasOwn,
  isLogged,
  keyFpInput,
  knownVersion,
  learn,
  readFrom,
  readKeyPayload,
  toRecord,
  verifyAnnouncement,
  versionsOf,
  wasLogged,
  wordsOfFingerprint,
} from './crypto.js';
import { expectOk, listAll, listOrgs } from './api.js';
import { TrustRefusal, message } from './messages.js';

const PAGE_LIMIT = 500;

const wallet = new Wallet();

const normalized = (fingerprint) => String(fingerprint).replace(/\s+/g, '').toUpperCase();
const wordsNormalized = (words) =>
  String(words).toLowerCase().replace(/·/g, ' ').trim().split(/\s+/).join(' ');
const spokenMatch = (given, fingerprint) => {
  const words = wordsOfFingerprint(fingerprint);
  return words !== null && wordsNormalized(given) === wordsNormalized(words);
};

// Either side may be the six words people read to each other; the other is then the hex.
export const sameFingerprint = (a, b) =>
  normalized(a) === normalized(b) || spokenMatch(a, b) || spokenMatch(b, a);

// `list`: fingerprints separated by commas (SHAREDENV_TRUSTED_SEALERS).
export const fingerprintListed = (list, fingerprint) =>
  String(list || '')
    .split(',')
    .some((listed) => sameFingerprint(listed, fingerprint));

// The digest the memory keeps of a key, never the key.
export const keyFpOf = (keyHex) =>
  createHash('sha256').update(keyFpInput(keyHex), 'utf8').digest('hex').slice(0, 32);

// What the log says of a key. → 'latest' | 'retired' | 'absent'
export function logAnswer(view, subject, publicKey) {
  if (isLogged(view, subject, publicKey)) return 'latest';
  return wasLogged(view, subject, publicKey) ? 'retired' : 'absent';
}

// Rule D: a version below the one seen here, or another key at a version seen here.
export function contradictsMemory(memory, scope, { version, keyFp }) {
  const seen = versionsOf(memory, scope)[version];
  return version < knownVersion(memory, scope) || Boolean(seen && seen.keyFp !== keyFp);
}

// Reads the log after what this machine checked, replays it, keeps the result.
//   store   lib/store.js forAccount (or none: replay from the start, keep nothing)
//   watch   { [subject]: publicKey } - EVERY key we hold (heldKeys). A sync that watches
//           nothing does not move what is kept: the entries it went past would never be
//           checked against anyone's name.
// → { view, foreign, unlogged, alerts }: `alerts`, what the watch found and nobody
// acknowledged yet, this sync included. Throws when the log cannot be read or does not
// add up.
export async function syncLog(client, { store, watch = {} } = {}) {
  const record = toRecord(store?.readLogView());
  const from = readFrom(record, watch);

  const read = async (to, page) => {
    const bound = to === null ? '' : `&to=${to}`;
    return expectOk(
      await client.call(
        'GET',
        `/transparency/log?from=${from}${bound}&page=${page}&limit=${PAGE_LIMIT}`
      ),
      'cannot read the public key log'
    );
  };
  const first = await read(null, 1);
  const { head } = first;
  if (!Number.isInteger(head?.seq) || typeof head?.hash !== 'string' || head.seq < record.seq) {
    throw new TrustRefusal('KEY_UNSAFE');
  }
  const entries = [...(first.data || [])];
  for (let page = 2; page <= (first.pagination?.pages ?? 1); page += 1) {
    entries.push(...((await read(head.seq, page)).data || []));
  }

  let result;
  try {
    result = absorb(record, from, entries, head, { watch });
  } catch {
    throw new TrustRefusal('KEY_UNSAFE');
  }
  if (store && result.changed) store.writeLogView(result.record);
  const { view, foreign, unlogged, alerts } = result;
  return { view, foreign, unlogged, alerts };
}

// The warnings kept on this machine and not acknowledged yet, without reading the log.
export const keptAlerts = (store) => toRecord(store.readLogView()).alerts;

// The owner has read them. → the warnings acknowledged. One still true comes back at
// the next unlock.
export function acknowledgeAlerts(store) {
  const record = toRecord(store.readLogView());
  if (record.alerts.length) store.writeLogView(acknowledge(record));
  return record.alerts;
}

const nothingToForget = ({ scopes, pins }) =>
  Object.keys(scopes).length === 0 && Object.keys(pins).length === 0;

const noted = (memory, id) => ({
  ...memory,
  announcements: {
    ...memory.announcements,
    applied: { ...memory.announcements.applied, [id]: null },
  },
});

function applied(memory, { id, type, logSeq, teamId, publicKey, teamKeyVersion }) {
  if (type === 'restore') return forgetAfter(memory, { id, logSeq });
  const held = memory.announcements.kubbler;
  if (nothingToForget(memory) || (held && teamKeyVersion <= held.teamKeyVersion)) {
    return noted(memory, id);
  }
  const pinned = commitSeal(
    memory,
    { people: [{ subject: `team:${teamId}`, publicKey }] },
    memory.log?.seq ?? 0
  );
  return noted(learn(pinned, { kubbler: { publicKey, teamKeyVersion } }), id);
}

// The signed announcements (#restauration), each applied once. A memory that is born has
// nothing to forget: the restores that exist are noted, so that one served again later does not
// take it back; nor does it take on an old key of Kubbler. A signature is checked before
// anything is noted: the server could otherwise burn the id of a restore to come.
export async function syncAnnouncements(client, store) {
  const rows = await listAll(client, '/transparency/announcements', 'announcements');
  const before = store.readMemory();
  let memory = before;
  for (const row of rows) {
    const announcement = row?.announcement;
    if (!verifyAnnouncement(row, { type: announcement?.type })) continue;
    if (hasOwn(memory.announcements.applied, announcement.id)) continue;
    memory = applied(memory, announcement);
  }
  if (memory === before) return;
  store.commit(memory);
  // A restore took the log back too, and the commit keeps the record on disk: its head would read
  // as a log that went back.
  if (before.log && !memory.log) store.writeLogView(null);
}

// The keys this account holds, as the log should hold them:
//   - its own, `user:<id>`, derived from the private key (never the server's copy) ;
//   - for every team whose key was sealed to it, `team:<id>`, DERIVED from the team
//     private key it opens, once this device can vouch for that seal. That key is watched
//     like our own: a team key swapped in the directory would receive every safe shared with
//     the team, and only those who hold the real one can tell.
// A team that does not answer is left out of this watch: it is read again from the start of
// the log the next time it is watched (kt.js `readFrom`). A team row this device cannot vouch
// for is in `doubts`: it says so, and the key watched stays the one pinned here, if any.
// → { watch: { [subject]: publicKey }, labels: { [subject]: name }, doubts: [subject] }
export async function heldKeys(client, { privateKey, userId }, memory = emptyMemory(userId)) {
  const watch = { [`user:${userId}`]: wallet.keypass.publicFromPrivate(privateKey) };
  const labels = {};
  const doubts = [];
  let orgs = [];
  try {
    orgs = await listOrgs(client);
  } catch {
    return { watch, labels, doubts };
  }
  const teams = new Map();
  for (const org of orgs) {
    try {
      const rows = await listAll(
        client,
        `/team/list?orgId=${encodeURIComponent(org._id)}`,
        'teams'
      );
      // Every team of the org: the server hands its key only to a member it was sealed to.
      for (const t of rows) teams.set(String(t._id), t.name);
    } catch {
      /* an org that does not answer: its teams wait for the next unlock */
    }
  }
  for (const [teamId, name] of teams) {
    const held = await teamKeyOf(client, privateKey, teamId, memory).catch(() => null);
    if (!held) continue;
    const subject = `team:${teamId}`;
    labels[subject] = name;
    if (held.key) watch[subject] = held.key;
    if (held.doubt) doubts.push(subject);
  }
  return { watch, labels, doubts };
}

// A rotation of the team key that has not reached its end: the row of `/team-keys/:id/me`
// already holds the next key.
export const teamKeyAhead = (row) => (row?.keyVersion || 1) > (row?.teamKeyVersion || 1);

// The team's OFFICIAL public key, derived from the team private key sealed to us, or null (not
// provisioned). While a team-key rotation is unfinished our row may already hold the next key:
// the official one is then the key it held before. Any key can seal a team key to ours: on a
// device that knows this team, the seal must be ours, one it accepted for this team or one listed
// in SHAREDENV_TRUSTED_SEALERS (the guard keeps no trace of those), and the version must not
// contradict what it saw (or the key is the one pinned here).
// → { key?, doubt } | null
export async function teamKeyOf(client, privateKey, teamId, memory) {
  const res = await client.call('GET', `/team-keys/${encodeURIComponent(teamId)}/me`);
  if (res.status !== 200 || !res.body?.sealedTeamKey) return null;
  const mine = res.body;
  const scope = `team:${teamId}`;
  const seen = versionsOf(memory, scope);
  const pinned = hasOwn(memory.pins, scope) ? memory.pins[scope].key : undefined;
  const doubtful = { key: pinned, doubt: true };

  const version = Math.min(mine.keyVersion || 1, mine.teamKeyVersion || 1);
  const blob = teamKeyAhead(mine) ? mine.previousSealedTeamKey : mine.sealedTeamKey;
  const opened = blob && wallet.open(privateKey, blob);
  const payload =
    opened && readKeyPayload(opened.toString('hex'), { kind: 'team', id: teamId, version });
  if (!payload) return doubtful;

  const key = wallet.keypass.publicFromPrivate(payload.key);
  const never = Object.keys(seen).length === 0 && !pinned;
  if (never || key === pinned) return { key, doubt: false };
  const sealers = [
    wallet.keypass.publicFromPrivate(privateKey),
    ...Object.values(seen).flatMap((entry) => entry.sealers),
  ];
  const sealer = String(blob.senderPublicKey).toLowerCase();
  const listed = fingerprintListed(process.env.SHAREDENV_TRUSTED_SEALERS, fingerprintOf(sealer));
  const vouched =
    (sealers.includes(sealer) || listed) &&
    !contradictsMemory(memory, scope, { version, keyFp: keyFpOf(payload.key) });
  return vouched ? { key, doubt: false } : doubtful;
}

// The warnings, as lines for stderr (none when all is well). `labels`: team names.
export function watchWarnings({ alerts = [] } = {}, labels = {}) {
  const bySubject = new Map();
  for (const alert of alerts) {
    bySubject.set(alert.subject, [...(bySubject.get(alert.subject) || []), alert]);
  }
  const lines = [...bySubject].map(([subject, list]) => {
    const seqs = list.filter((a) => a.kind === 'foreign').map((a) => a.seq);
    const where = seqs.length ? ` (public key log, entry ${seqs.join(', ')})` : '';
    const text = subject.startsWith('team:')
      ? message('TEAM_KEY_LOG_FOREIGN', {
          team: labels[subject] || subject.slice('team:'.length),
        })
      : message('KEY_LOG_FOREIGN');
    return `${text}${where}`;
  });
  if (lines.length) {
    lines.push('These warnings come back at every unlock until `sharedenv log --ack`.');
  }
  return lines;
}
