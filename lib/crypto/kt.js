// Key transparency — the public-key directory as a public, append-only log.
//
// The server is the key directory, and the directory is only rows in a database: whoever
// can write there (a leak, an insider, a bug) can answer "Bob" with a key of their own at
// the moment Alice seals to Bob. A client cannot tell a substituted key from a real one.
// What it CAN check is that every key is on the record, and that the record never
// changes behind its back:
//
//   1. Every key the server hands out is first written to a log of entries that only
//      grows. Entry n carries the hash of entry n-1, so the head hash sums up the whole
//      history: rewriting one past entry changes every hash after it.
//   2. A client seals to a key only if it is the LAST key the log holds for that
//      subject. A substituted key must therefore be logged, in public.
//   3. Each owner watches the log for their own name. A key logged under it that is
//      not theirs is reported: the substitution is caught, and the log is the proof.
//   4. Each client keeps the log it checked: a past entry rewritten, or a log shorter
//      than what it already saw, is refused.
//
// Entries hold HASHES of the subject and of the key, never the ids or the keys: the
// log is readable by anyone and only says "some key of some subject changed at entry
// n". Whoever already knows a subject and a key (the person sealing to them) computes
// the same hashes. Subjects: `user:<id>`, `team:<id>`.
//
// It only does arithmetic on hashes, and the bookkeeping of what a client checked (the
// record it keeps between two reads, below). No I/O: every client (browser, command
// line) reads the log its own way and computes the same results from the same entries.

import crypto from 'crypto';

export const KT_GENESIS = '0'.repeat(64);

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

export const subjectHash = (subject) => sha256(`sharedenv/kt/subject/v1|${subject}`);
export const keyHash = (publicKeyHex) =>
  sha256(`sharedenv/kt/key/v1|${String(publicKeyHex).toLowerCase()}`);
export const entryHash = ({ seq, prev, subject, key }) =>
  sha256(`sharedenv/kt/entry/v1|${seq}|${prev}|${subject}|${key}`);

// The next entry after `head` ({ seq, hash }), for a subject and a key.
export function nextEntry(head, subject, publicKeyHex) {
  const entry = {
    seq: head.seq + 1,
    prev: head.hash,
    subject: subjectHash(subject),
    key: keyHash(publicKeyHex),
  };
  return { ...entry, hash: entryHash(entry) };
}

export class KtError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'KtError';
    this.code = code;
  }
}

// What a client knows of the log: its head, the last key of every subject, and the keys
// each subject held before it.
const HASHED = /^[0-9a-f]{64}$/;

export const emptyView = () => ({ seq: 0, hash: KT_GENESIS, latest: {}, retired: {} });

// Replays `entries` (ascending, starting right after `view.seq`) onto a copy of `view`.
//   watch    { [subject]: publicKeyHex } — subjects whose key WE know (our own, a team
//            whose private key we hold). Once their key is in the log, any later entry
//            for them with another key is reported.
// -> { view, foreign, unlogged }
//   foreign    [{ subject, seq }] — a key that is not ours, logged under our name
//   unlogged   [subject] — isLogged refuses our key: not the last one the log holds for
//              us, or a team key that came back
// Throws KtError BROKEN: a gap, or a hash that does not chain.
export function replay(view, entries, { watch = {} } = {}) {
  const next = {
    seq: view.seq,
    hash: view.hash,
    latest: { ...view.latest },
    retired: { ...view.retired },
  };
  const watched = Object.entries(watch).map(([subject, publicKey]) => ({
    subject,
    hashed: subjectHash(subject),
    key: keyHash(publicKey),
    armed: false,
  }));
  // Armed once our key is in the log, last or not: a read that starts past a foreign key
  // still reports the next one, as a replay from the first entry does.
  for (const w of watched) {
    w.armed = next.latest[w.hashed] === w.key || Boolean(next.retired[w.hashed]?.includes(w.key));
  }

  const foreign = [];
  for (const e of entries) {
    if (e.seq !== next.seq + 1 || e.prev !== next.hash || entryHash(e) !== e.hash) {
      throw new KtError('BROKEN', `the log does not chain at entry ${e.seq}`);
    }
    // A subject is a hash: anything else could name a member every object inherits.
    if (!HASHED.test(e.subject)) {
      throw new KtError('BROKEN', `the log holds no subject at entry ${e.seq}`);
    }
    next.seq = e.seq;
    next.hash = e.hash;
    const replaced = next.latest[e.subject];
    if (replaced && replaced !== e.key) {
      next.retired[e.subject] = [...(next.retired[e.subject] || []), replaced];
    }
    next.latest[e.subject] = e.key;
    for (const w of watched) {
      if (e.subject !== w.hashed) continue;
      if (e.key === w.key) w.armed = true;
      else if (w.armed) foreign.push({ subject: w.subject, seq: e.seq });
    }
  }

  const unlogged = Object.keys(watch).filter((s) => !isLogged(next, s, watch[s]));
  return { view: next, foreign, unlogged };
}

// Is `publicKeyHex` the last key the log holds for `subject`? A team key replaced is over for
// good: a rotation mints a new one, so an old key that comes back was brought back by someone
// who kept it, and whoever left the team may hold it too. A person has one key:
// migration/sync.js logs it again after a substitution, and it stays.
export const isLogged = (view, subject, publicKeyHex) => {
  const hashed = subjectHash(subject);
  const key = keyHash(publicKeyHex);
  if (view.latest[hashed] !== key) return false;
  return !subject.startsWith('team:') || !view.retired[hashed]?.includes(key);
};

// Has the log ever held `publicKeyHex` for `subject`, last or not?
export const wasLogged = (view, subject, publicKeyHex) => {
  const hashed = subjectHash(subject);
  const key = keyHash(publicKeyHex);
  return view.latest[hashed] === key || Boolean(view.retired[hashed]?.includes(key));
};

// ── What a client keeps between two reads ────────────────────────────────────────
// One record per log: the view checked, how far each watched subject was checked (by
// its hash), and the alerts its owner has not acknowledged yet:
//   { seq, hash, latest, retired, watched: { [subjectHash]: seq }, alerts: [{ kind, subject, seq }] }
// kind 'foreign': entry `seq` logged a key that is not ours under `subject`.
// kind 'unlogged': when the log stood at `seq`, isLogged refused our key for `subject`.
// An alert stays until acknowledged, whatever later reads find: a substitution that was
// put back is still the trace of an attack, and a warning printed once (in a CI log, in
// a closed tab) is easily missed.

export const emptyRecord = () => ({ ...emptyView(), watched: {}, alerts: [] });

const isRetired = (retired) =>
  retired &&
  typeof retired === 'object' &&
  !Array.isArray(retired) &&
  Object.values(retired).every(Array.isArray);

const isAlert = (a) =>
  a &&
  (a.kind === 'foreign' || a.kind === 'unlogged') &&
  typeof a.subject === 'string' &&
  Number.isInteger(a.seq);

// -> the record in what storage gave back; anything unusable starts over (the next read
// replays the log from its first entry). A view kept by an earlier client, without
// `watched` or `retired`, is read again from the start once.
export function toRecord(stored) {
  const sane =
    stored &&
    Number.isInteger(stored.seq) &&
    stored.seq >= 0 &&
    typeof stored.hash === 'string' &&
    stored.latest &&
    typeof stored.latest === 'object';
  if (!sane) return emptyRecord();
  const watched = {};
  if (stored.watched && typeof stored.watched === 'object' && !Array.isArray(stored.watched)) {
    for (const [hashed, seq] of Object.entries(stored.watched)) {
      if (Number.isInteger(seq) && seq >= 0 && seq <= stored.seq) watched[hashed] = seq;
    }
  }
  return {
    seq: stored.seq,
    hash: stored.hash,
    latest: stored.latest,
    retired: isRetired(stored.retired) ? stored.retired : null,
    watched,
    alerts: Array.isArray(stored.alerts) ? stored.alerts.filter(isAlert) : [],
  };
}

const checkedUpTo = (record, subject) => record.watched[subjectHash(subject)] ?? 0;

// Where the next read of the log starts: right after what was checked, unless `watch`
// names a subject that was not checked that far (never watched, or left out of a read
// since). Nobody read that part of the log on its behalf, so it is read again from the
// first entry.
export function readFrom(record, watch = {}) {
  return record.retired &&
    Object.keys(watch).every((subject) => checkedUpTo(record, subject) === record.seq)
    ? record.seq
    : 0;
}

// Folds the entries read after `from` (readFrom) up to `head` into `record`.
// -> { record, changed, view, foreign, unlogged, alerts }
//   record    what to keep. A read that watched nothing gives back the record as it
//             was: had it moved the position, the entries it went past would never be
//             checked against anyone's name.
//   changed   whether `record` is worth writing back
//   view      the log as it now stands, kept or not (isLogged reads it)
//   foreign, unlogged   what this read found
//   alerts    every alert not acknowledged yet, those found by this read included
// Throws KtError BROKEN: entries that do not chain or do not reach `head`, a log
// shorter than what was checked, or a replay from the start that disagrees with it.
export function absorb(record, from, entries, head, { watch = {} } = {}) {
  if (head.seq < record.seq) {
    throw new KtError('BROKEN', 'the log is shorter than what was already checked');
  }
  const start = from === 0 ? emptyView() : record;
  const replayed = replay(start, entries, { watch });
  const { view } = replayed;
  if (view.seq !== head.seq || view.hash !== head.hash) {
    throw new KtError('BROKEN', 'the log head does not match its entries');
  }
  // Read again from the start: the entry already checked must still be the same one.
  if (from === 0 && record.seq > 0 && entries[record.seq - 1]?.hash !== record.hash) {
    throw new KtError('BROKEN', 'the log no longer agrees with what was already checked');
  }

  const subjects = Object.keys(watch);
  if (subjects.length === 0) {
    return { record, changed: false, view, foreign: [], unlogged: [], alerts: record.alerts };
  }

  // Read again from the start, what a subject already had checked is not news (and its
  // alerts may have been acknowledged since).
  const foreign = replayed.foreign.filter((f) => f.seq > checkedUpTo(record, f.subject));
  const { unlogged } = replayed;
  const alerts = [...record.alerts];
  const known = (a) =>
    alerts.some(
      (b) =>
        b.kind === a.kind && b.subject === a.subject && (a.kind === 'unlogged' || b.seq === a.seq)
    );
  const found = [
    ...foreign.map((f) => ({ kind: 'foreign', subject: f.subject, seq: f.seq })),
    ...unlogged.map((subject) => ({ kind: 'unlogged', subject, seq: head.seq })),
  ];
  for (const a of found) if (!known(a)) alerts.push(a);

  // The subjects watched now are checked up to the head; the others keep how far they
  // were, and the next read that watches them again starts over.
  const watched = { ...record.watched };
  for (const subject of subjects) watched[subjectHash(subject)] = view.seq;
  const next = { ...view, watched, alerts };
  const sameWatched =
    Object.keys(watched).length === Object.keys(record.watched).length &&
    Object.entries(watched).every(([hashed, seq]) => record.watched[hashed] === seq);
  const changed =
    !record.retired ||
    next.seq !== record.seq ||
    next.hash !== record.hash ||
    alerts.length !== record.alerts.length ||
    !sameWatched;
  return { record: next, changed, view, foreign, unlogged, alerts };
}

// The owner has read the alerts: the record without them. Whatever is still true is
// found again by the next read.
export const acknowledge = (record) => ({ ...record, alerts: [] });
