// The public key log (key transparency). The server is the key directory, and the
// directory is rows in a database: whoever can write there could answer "Bob" with a key
// of their own. So every key it hands out is first written to a log that only grows,
// each entry chained to the previous one by its hash. This CLI:
//   - seals to, or trusts the seal of, a key only if it is the LAST one the log holds
//     for its owner: a substituted key would have to be logged, where its owner sees it ;
//   - watches your own name: a key logged under it that is not yours is reported ;
//   - keeps what it checked (~/.sharedenv/log.json) and refuses a log that does not
//     chain, rewrites what it already saw, or goes back.
// The arithmetic is lib/crypto/kt.js.

import { emptyView, replay, isLogged } from './crypto.js';
import { expectOk } from './api.js';

const PAGE_LIMIT = 500;

const saneView = (v) =>
  v &&
  Number.isInteger(v.seq) &&
  typeof v.hash === 'string' &&
  v.latest &&
  typeof v.latest === 'object';

// Reads the log after what this machine checked, replays it, keeps the result.
//   store   lib/store.js (or none: replay from the start, keep nothing)
//   watch   { [subject]: publicKey } — the keys we hold
// → { view, foreign, unlogged }. Throws when the log cannot be read or does not add up.
export async function syncLog(client, { store, watch = {} } = {}) {
  const stored = store?.readLogView();
  const from = saneView(stored) ? stored : emptyView();

  const read = async (to, page) => {
    const bound = to === null ? '' : `&to=${to}`;
    return expectOk(
      await client.call(
        'GET',
        `/transparency/log?from=${from.seq}${bound}&page=${page}&limit=${PAGE_LIMIT}`
      ),
      'cannot read the public key log'
    );
  };
  const first = await read(null, 1);
  const { head } = first;
  if (!Number.isInteger(head?.seq) || typeof head?.hash !== 'string') {
    throw new Error('the public key log sent no head');
  }
  if (head.seq < from.seq) {
    throw new Error('the public key log is shorter than what this machine already checked');
  }
  const entries = [...(first.data || [])];
  for (let page = 2; page <= (first.pagination?.pages ?? 1); page += 1) {
    entries.push(...((await read(head.seq, page)).data || []));
  }

  let replayed;
  try {
    replayed = replay(from, entries, { watch });
  } catch (err) {
    throw new Error(`the public key log does not add up: ${err.message}`);
  }
  const { view, foreign, unlogged } = replayed;
  if (view.seq !== head.seq || view.hash !== head.hash) {
    throw new Error('the public key log does not add up: its head does not match its entries');
  }
  if (store && view.seq > from.seq) store.writeLogView(view);
  return { view, foreign, unlogged };
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

// What the watch found, as lines for stderr (none when all is well).
export function watchWarnings({ foreign = [], unlogged = [] }) {
  const lines = [];
  if (foreign.length) {
    lines.push(
      'WARNING: a key that is not yours was registered under your name in the public key log ' +
        `(entry ${foreign.map((f) => f.seq).join(', ')}). If you did not reset your vault, ` +
        'tell SharedEnv: it is the trace of an attack.'
    );
  }
  if (unlogged.length) {
    lines.push(
      'WARNING: your key is not the last one the public key log holds for you: nobody can ' +
        'share with you until it is. Tell SharedEnv.'
    );
  }
  return lines;
}
