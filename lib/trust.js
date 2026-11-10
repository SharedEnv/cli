// The CLI's side of the trust guard (rule C, lib/crypto/trust/guard.js). The server is the key
// directory, and a directory can lie; the guard decides, this module hands it what the CLI
// read (the public log's answer for each key, the version a seal names), passes its questions
// to `answer` (the bin, or a script's flags), and writes the memory only once everything went
// through: log, opening, sending.

import { Buffer } from 'buffer';
import {
  Wallet,
  approvalsOf,
  commitOpen,
  commitSeal,
  decideOpen,
  decideSeal,
  encodeKeyPayload,
  fingerprintOf,
  hasOwn,
  versionsOf,
} from './crypto.js';
import { TrustRefusal, onTheSite } from './messages.js';
import { fingerprintListed, logAnswer, sameFingerprint, syncLog } from './transparency.js';

export { TrustRefusal, sameFingerprint, fingerprintListed };

const wallet = new Wallet();

// → 'new' (never vouched for here) | 'match' | 'changed'
export function pinStatus(memory, subject, publicKey) {
  if (!hasOwn(memory.pins, subject)) return 'new';
  return memory.pins[subject].key === String(publicKey).toLowerCase() ? 'match' : 'changed';
}

// A person's key in a question. → 'accept' | 'ask' | 'refuse'
//   expected         — `--fingerprint`: the key must be this one, nothing else counts;
//   acceptKeyChange  — `--accept-key-change`: take a key that differs from the pin;
//   yes              — `--yes`: no question for a key already pinned, never for a new one (sujet 7).
export function senderVerdict(status, fingerprint, { expected, acceptKeyChange, yes } = {}) {
  if (expected) return sameFingerprint(expected, fingerprint) ? 'accept' : 'refuse';
  if (status === 'changed') return acceptKeyChange ? 'accept' : 'ask';
  return yes && status === 'match' ? 'accept' : 'ask';
}

// A team key a vault's key is about to move to: a planted key would receive it. Pinned, or
// confirmed by its fingerprint, by a human or by `--team-fingerprint`; no flag says yes
// blindly. → 'accept' | 'ask' | 'refuse'
export function teamKeyVerdict(status, fingerprint, { expected } = {}) {
  if (expected) return sameFingerprint(expected, fingerprint) ? 'accept' : 'refuse';
  return status === 'match' ? 'accept' : 'ask';
}

// A key sealed in the bound format: what the seal holds names its vault or team and its version.
export const sealKey = (privateKey, publicKey, payload) =>
  wallet.seal(privateKey, publicKey, Buffer.from(encodeKeyPayload(payload), 'hex'));

// #f2-cli: the CLI never asks the last resort, it cannot renew a key: only the web app does.
function refusalOf({ code }, { vault, team }) {
  if (code !== 'LAST_RESORT') return new TrustRefusal(code, { vault, team });
  const refusal = new TrustRefusal('LAST_RESORT_WAIT', { vault });
  refusal.message = onTheSite(refusal.message);
  return refusal;
}

//   store   lib/store.js forAccount, the memory of this account on this server
//   watch   what syncLog watches in this run (bin/sharedenv.js)
//   answer  async (decision, context, memory) → boolean; context: { vault?, team?, scripted? },
//           `scripted`: a flag may answer for this question
export function createTrust({
  client,
  store,
  privateKey,
  userId,
  watch = {},
  answer = async () => false,
  trustedSealers = process.env.SHAREDENV_TRUSTED_SEALERS,
}) {
  const ownKey = wallet.keypass.publicFromPrivate(privateKey);
  let memory = store.readMemory();
  let view = null;
  const logView = async ({ fresh = false } = {}) => {
    if (fresh || !view) ({ view } = await syncLog(client, { store, watch }));
    return view;
  };
  const seq = () => store.readLogView()?.seq ?? 0;
  const listed = (paths) =>
    paths
      .map((path) => path.sealer.publicKey)
      .filter((key) => fingerprintListed(trustedSealers, fingerprintOf(key)));

  // Only a seal this device has to judge reads the log: your own vault opens without it.
  async function withLog(scope, paths, trusted) {
    const top = Math.max(...paths.map((path) => path.version));
    const judged = paths.some(
      ({ sealer }) => sealer.publicKey !== ownKey && !trusted.includes(sealer.publicKey)
    );
    const current = judged && !versionsOf(memory, scope)[top] ? await logView() : null;
    return paths.map((path) => {
      const { subject, publicKey } = path.sealer;
      const log = current && subject ? logAnswer(current, subject, publicKey) : 'absent';
      return { ...path, sealer: { ...path.sealer, log } };
    });
  }

  return {
    privateKey,
    userId,
    ownKey,
    memory: () => memory,

    // A key opened for a scope. paths: [{ version, keyFp, sealer: { publicKey, subject?, label? } }].
    // → the guard's decision, or throws TrustRefusal.
    async open({ scope, paths, official, renew = 'other', context }) {
      const trusted = listed(paths);
      const read = await withLog(scope, paths, trusted);
      const approved = [];
      for (;;) {
        const decision = decideOpen(memory, {
          scope,
          paths: read,
          official,
          ownKey,
          trusted,
          renew,
          approved,
        });
        if (decision.ok) return decision;
        if (decision.code !== 'NEW_SEALERS') throw refusalOf(decision, context);
        if (!(await answer(decision, context, memory))) {
          throw new TrustRefusal('SEALER_DECLINED', { vault: context.vault });
        }
        approved.push(...approvalsOf(decision));
      }
    },

    // A key that serves only to read what a rotation left behind: it passes or it is left out,
    // nothing is asked. → the decision, or null.
    async openQuietly({ scope, paths }) {
      const trusted = listed(paths);
      try {
        const read = await withLog(scope, paths, trusted);
        const decision = decideOpen(memory, { scope, paths: read, ownKey, trusted });
        return decision.ok ? decision : null;
      } catch {
        return null;
      }
    },

    // Before sealing to one person or team. person: { subject, publicKey, label?, address? };
    // vouched: this key needs nobody's yes (a team key we sealed ourselves). → the decision, or
    // null: a no. Reads the log again: sealing is not reading.
    async sealTo({ person, context, vouched = false }) {
      const current = await logView({ fresh: true });
      const log = logAnswer(current, person.subject, person.publicKey);
      const approved = [];
      for (;;) {
        const decision = decideSeal(memory, { person, log, ownKey, approved });
        if (decision.ok) return decision;
        if (decision.code === 'KEY_UNSAFE') throw new TrustRefusal('KEY_UNSAFE');
        const free = vouched && decision.code === 'TEAM_KEY_UNKNOWN';
        if (!free && !(await answer(decision, context, memory))) return null;
        approved.push(...approvalsOf(decision));
      }
    },

    // A question that is not about a key: `code` is its catalogue entry.
    ask: (code, context) => answer({ code, people: [] }, context, memory),

    commitOpen(decision) {
      memory = store.commit(commitOpen(memory, decision, seq()));
    },

    commitSeal(sealed) {
      memory = store.commit(commitSeal(memory, sealed, seq()));
    },
  };
}
