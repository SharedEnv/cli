// The public key log (key transparency). The server is the key directory, and the
// directory is rows in a database: whoever can write there could answer "Bob" with a key
// of their own. So every key it hands out is first written to a log that only grows,
// each entry chained to the previous one by its hash. This CLI:
//   - seals to, or trusts the seal of, a key only if it is the LAST one the log holds
//     for its owner: a substituted key would have to be logged, where its owner sees it ;
//   - watches the keys you hold - your own, and the key of every team sealed to you: a
//     key logged under one of their names that is not the one you hold is reported, and
//     the warning comes back at every unlock until `sharedenv log --ack` ;
//   - keeps what it checked (~/.sharedenv/log.json) and refuses a log that does not
//     chain, rewrites what it already saw, or goes back.
// The arithmetic, and the rules of what is kept, are lib/crypto/kt.js.

import { Wallet, absorb, acknowledge, readFrom, toRecord, isLogged } from './crypto.js';
import { expectOk, listAll, listOrgs } from './api.js';

const PAGE_LIMIT = 500;

const wallet = new Wallet();

// Reads the log after what this machine checked, replays it, keeps the result.
//   store   lib/store.js (or none: replay from the start, keep nothing)
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
  if (!Number.isInteger(head?.seq) || typeof head?.hash !== 'string') {
    throw new Error('the public key log sent no head');
  }
  if (head.seq < record.seq) {
    throw new Error('the public key log is shorter than what this machine already checked');
  }
  const entries = [...(first.data || [])];
  for (let page = 2; page <= (first.pagination?.pages ?? 1); page += 1) {
    entries.push(...((await read(head.seq, page)).data || []));
  }

  let result;
  try {
    result = absorb(record, from, entries, head, { watch });
  } catch (err) {
    throw new Error(`the public key log does not add up: ${err.message}`);
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

// The keys this account holds, as the log should hold them:
//   - its own, `user:<id>`, derived from the private key (never the server's copy) ;
//   - for every team whose key was sealed to it, `team:<id>`, DERIVED from the team
//     private key it opens. That key is watched like our own: a team key swapped in the
//     directory would receive every safe shared with the team, and only those who hold
//     the real one can tell.
// Teams that cannot be read are left out of this watch: they are read again from the
// start of the log the next time they are watched (kt.js `readFrom`).
// → { watch: { [subject]: publicKey }, labels: { [subject]: name } }
export async function heldKeys(client, { privateKey, userId }) {
  const watch = { [`user:${userId}`]: wallet.keypass.publicFromPrivate(privateKey) };
  const labels = {};
  let orgs = [];
  try {
    orgs = await listOrgs(client);
  } catch {
    return { watch, labels };
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
    const key = await teamKeyOf(client, privateKey, teamId).catch(() => null);
    if (key) {
      watch[`team:${teamId}`] = key;
      labels[`team:${teamId}`] = name;
    }
  }
  return { watch, labels };
}

// The team's OFFICIAL public key, derived from the team private key sealed to us, or
// null (not provisioned, or not readable). While a team-key rotation is unfinished our
// row may already hold the next key: the official one is then the key it held before.
async function teamKeyOf(client, privateKey, teamId) {
  const res = await client.call('GET', `/team-keys/${encodeURIComponent(teamId)}/me`);
  if (res.status !== 200 || !res.body?.sealedTeamKey) return null;
  const mine = res.body;
  const ahead = (mine.keyVersion || 1) > (mine.teamKeyVersion || 1);
  const blob = ahead ? mine.previousSealedTeamKey : mine.sealedTeamKey;
  const opened = blob && wallet.open(privateKey, blob);
  return opened ? wallet.keypass.publicFromPrivate(opened.toString('utf8')) : null;
}

// Every target's key must be the last one the log holds for its subject.
// targets: [{ subject, publicKey, label }]
export function assertLogged(view, targets) {
  const missing = targets.filter((t) => !isLogged(view, t.subject, t.publicKey));
  if (missing.length) {
    throw new Error(
      `the server handed out a key the public key log does not hold (${missing
        .map((t) => t.label || t.subject)
        .join(', ')}): refusing`
    );
  }
}

// The warnings, as lines for stderr (none when all is well). `labels`: team names.
export function watchWarnings({ alerts = [] } = {}, labels = {}) {
  const lines = [];
  const entries = (list) => list.map((a) => a.seq).join(', ');
  const bySubject = (kind) => {
    const groups = new Map();
    for (const a of alerts.filter((x) => x.kind === kind)) {
      groups.set(a.subject, [...(groups.get(a.subject) || []), a]);
    }
    return groups;
  };
  const teamName = (subject) => labels[subject] || subject.slice('team:'.length);
  for (const [subject, list] of bySubject('foreign')) {
    lines.push(
      subject.startsWith('team:')
        ? `WARNING: a key that is not the one you hold for team "${teamName(subject)}" was ` +
            `registered for it in the public key log (entry ${entries(list)}). Unless a lead ` +
            'of the team replaced its key, tell SharedEnv: it is the trace of an attack.'
        : 'WARNING: a key that is not yours was registered under your name in the public key ' +
            `log (entry ${entries(list)}). If you did not reset your vault, tell SharedEnv: it ` +
            'is the trace of an attack.'
    );
  }
  for (const [subject] of bySubject('unlogged')) {
    lines.push(
      subject.startsWith('team:')
        ? `WARNING: the key you hold for team "${teamName(subject)}" is not the last one the ` +
            'public key log holds for it: nobody can share with the team until it is. Tell ' +
            'SharedEnv.'
        : 'WARNING: your key is not the last one the public key log holds for you: nobody can ' +
            'share with you until it is. Tell SharedEnv.'
    );
  }
  if (lines.length) {
    lines.push('These warnings come back at every unlock until `sharedenv log --ack`.');
  }
  return lines;
}
