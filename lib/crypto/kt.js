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
// It only does arithmetic on hashes. Every client (browser, extension, command line)
// computes the same hashes for the same entries.

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

// What a client knows of the log: its head and the last key of every subject.
export const emptyView = () => ({ seq: 0, hash: KT_GENESIS, latest: {} });

// Replays `entries` (ascending, starting right after `view.seq`) onto a copy of `view`.
//   watch    { [subject]: publicKeyHex } — subjects whose key WE know (our own, a team
//            whose private key we hold). Once their key is in the log, any later entry
//            for them with another key is reported.
// -> { view, foreign, unlogged }
//   foreign    [{ subject, seq }] — a key that is not ours, logged under our name
//   unlogged   [subject] — our key is not the last one the log holds for us
// Throws KtError BROKEN: a gap, or a hash that does not chain.
export function replay(view, entries, { watch = {} } = {}) {
  const next = { seq: view.seq, hash: view.hash, latest: { ...view.latest } };
  const watched = Object.entries(watch).map(([subject, publicKey]) => ({
    subject,
    hashed: subjectHash(subject),
    key: keyHash(publicKey),
    armed: false,
  }));
  for (const w of watched) w.armed = next.latest[w.hashed] === w.key;

  const foreign = [];
  for (const e of entries) {
    if (e.seq !== next.seq + 1 || e.prev !== next.hash || entryHash(e) !== e.hash) {
      throw new KtError('BROKEN', `the log does not chain at entry ${e.seq}`);
    }
    next.seq = e.seq;
    next.hash = e.hash;
    next.latest[e.subject] = e.key;
    for (const w of watched) {
      if (e.subject !== w.hashed) continue;
      if (e.key === w.key) w.armed = true;
      else if (w.armed) foreign.push({ subject: w.subject, seq: e.seq });
    }
  }

  const unlogged = watched.filter((w) => next.latest[w.hashed] !== w.key).map((w) => w.subject);
  return { view: next, foreign, unlogged };
}

// Is `publicKeyHex` the last key the log holds for `subject`?
export const isLogged = (view, subject, publicKeyHex) =>
  view.latest[subjectHash(subject)] === keyHash(publicKeyHex);
