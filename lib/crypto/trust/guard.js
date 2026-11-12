// The one trust guard of every client (rule C): browser, extension and CLI ask it before
// sealing a key to someone or accepting a key someone sealed. Order fixed: the public log
// first, then the question, and the memory is written only once everything succeeded (the
// caller commits after the log, the opening and the sending all went through).
//
//   - "I can seal to them" is per person (pins);
//   - "I accept their seal" is per safe and per team (sujet 1): a new sealer is asked about,
//     for this scope only, even someone known elsewhere;
//   - rule D: a version below the one seen here, or another key at a version seen here, is
//     refused; a key no longer the person's last is good only for the versions seen here;
//   - F2: on a device that never saw the scope, a seal nobody can confirm (an account gone,
//     a replaced key) is the last resort of whom can renew, and a wait for everyone else.
//
// Pure: it is handed what the caller computed (the log's answer per key: 'latest' |
// 'retired' | 'absent', key digests, versions read from the payload) and returns a decision,
// { ok: true, ... } or { ok: false, code, people, scope }. A yes is passed back as `approved`
// (approvalsOf): it answers that question, for those keys and that scope, in that run only.
//
// No import outside this folder (copied byte for byte into API/src/tools/crypto/trust/).

import { addressSubject, hasOwn, knownVersion, learn, versionsOf } from './memory.js';

const lower = (key) => String(key).toLowerCase();
const withKey = (person) => ({ ...person, publicKey: lower(person.publicKey) });
const refuse = (code, people, scope) => ({ ok: false, code, people, scope });
const pinOf = (memory, subject) =>
  hasOwn(memory.pins, subject) ? memory.pins[subject] : undefined;
const isTeam = (subject) => subject.startsWith('team:');
const changedCode = (subject) => (isTeam(subject) ? 'TEAM_KEY_UNKNOWN' : 'KEY_CHANGED');
const reached = (entry) => entry.to.filter((subject) => !entry.out.includes(subject));

export const approvalsOf = (decision) =>
  decision.people.map((p) => ({
    code: decision.code,
    scope: decision.scope,
    publicKey: p.publicKey,
  }));

const approvalTest = (approved, scope) => (code, publicKey) =>
  approved.some((a) => a.code === code && a.scope === scope && lower(a.publicKey) === publicKey);

// Before sealing to one person or team the human picked. person: { subject, publicKey, label?,
// address? }, `address` being what the human typed: it must have led to this very account here.
export function decideSeal(memory, { person, log, ownKey, approved = [] }) {
  const isApproved = approvalTest(approved, undefined);
  const p = withKey(person);
  if (p.publicKey === lower(ownKey)) return { ok: true, people: [p] };
  if (log !== 'latest') return refuse('KEY_UNSAFE', [p]);
  const pin = pinOf(memory, p.subject);
  const ledTo = p.address ? pinOf(memory, addressSubject(p.address))?.key : p.subject;
  const addressCode = ledTo ? 'FIRST_SEAL_MOVED' : 'FIRST_SEAL';
  const moved = ledTo !== p.subject;
  if (pin?.key !== p.publicKey) {
    // Someone new behind an address that led elsewhere is one question, the address's.
    const fresh = moved ? addressCode : 'FIRST_SEAL';
    const code = pin || isTeam(p.subject) ? changedCode(p.subject) : fresh;
    if (!isApproved(code, p.publicKey)) {
      return refuse(code, [{ ...p, pinnedKey: pin?.key }]);
    }
  }
  if (moved && !isApproved(addressCode, p.publicKey)) return refuse(addressCode, [p]);
  return { ok: true, people: [p] };
}

// The last version this device sealed in full (a full list of recipients); 0: none.
function lastSealed(memory, scope) {
  const versions = versionsOf(memory, scope);
  return Math.max(
    0,
    ...Object.keys(versions)
      .filter((v) => versions[v].to.length)
      .map(Number)
  );
}

// Before sealing to recipients the SERVER listed (a rotation, a re-seal "to every member").
// recipients: [{ subject, publicKey, label?, log }], the caller included.
export function decideRecipients(memory, { scope, recipients, ownKey, approved = [] }) {
  const isApproved = approvalTest(approved, scope);
  const others = recipients.map(withKey).filter((r) => r.publicKey !== lower(ownKey));
  const unsafe = others.filter((r) => r.log !== 'latest');
  if (unsafe.length) return refuse('KEY_UNSAFE', unsafe, scope);
  for (const r of others) {
    const pin = pinOf(memory, r.subject);
    const code = changedCode(r.subject);
    const changed = pin ? pin.key !== r.publicKey : isTeam(r.subject);
    if (changed && !isApproved(code, r.publicKey)) {
      return refuse(code, [{ ...r, pinnedKey: pin?.key }], scope);
    }
  }
  const fresh = others.filter(
    (r) => !pinOf(memory, r.subject) && !isApproved('NEW_RECIPIENTS', r.publicKey)
  );
  if (fresh.length) return refuse('NEW_RECIPIENTS', fresh, scope);
  const sealed = lastSealed(memory, scope);
  const known = sealed ? reached(versionsOf(memory, scope)[sealed]) : null;
  const strangers = known
    ? others.filter((r) => !known.includes(r.subject) && !isApproved('NEW_MEMBERS', r.publicKey))
    : [];
  if (strangers.length) return refuse('NEW_MEMBERS', strangers, scope);
  return { ok: true, scope, people: others };
}

// Sujet 4: those this device sealed the current version to, no longer listed while the key
// did not change. Non-empty: the key is to be renewed, whatever the server says is due.
export function missingRecipients(memory, scope, listed) {
  const entry = versionsOf(memory, scope)[knownVersion(memory, scope)];
  return entry ? reached(entry).filter((subject) => !listed.includes(subject)) : [];
}

// A human removed them from here, and this device has not sealed to them since.
export function removedHere(memory, scope, subject) {
  const versions = versionsOf(memory, scope);
  const sealedLast = versions[lastSealed(memory, scope)];
  if (sealedLast && reached(sealedLast).includes(subject)) return false;
  return Object.values(versions).some((e) => e.out.includes(subject));
}

const LAST_RESORT = { self: 'LAST_RESORT', other: 'LAST_RESORT_WAIT', nobody: 'NOBODY_CAN_ACT' };

// Before using a key opened for a scope. paths: [{ version, keyFp, sealer: { publicKey,
// subject?, label?, log } }], one per way the key reached us (direct row, team share), the
// version read from the payload. Only the highest version is used; every seal of it must
// pass. official: the version the server says the scope is at (a row ahead is a rotation in
// flight: it opens, it is not remembered). trusted: sealer keys listed on purpose.
// renew: 'self' (this account can renew the key) | 'other' | 'nobody'.
export function decideOpen(
  memory,
  { scope, paths, official, ownKey, trusted = [], renew = 'other', approved = [] }
) {
  const lastResort = LAST_RESORT[renew];
  if (!lastResort) throw new Error(`Unknown renew: ${renew}.`);
  const isApproved = approvalTest(approved, scope);
  if (!paths.length) return refuse('SEALER_REFUSED', [], scope);
  const top = Math.max(...paths.map((p) => p.version));
  const used = paths.filter((p) => p.version === top);
  const { keyFp } = used[0];
  if (used.some((p) => p.keyFp !== keyFp)) return refuse('SEALER_REFUSED', [], scope);
  const known = knownVersion(memory, scope);
  const versions = versionsOf(memory, scope);
  if (top < known || (versions[top] && versions[top].keyFp !== keyFp)) {
    return refuse('SEALER_REFUSED', [], scope);
  }
  const accepted = {
    ok: true,
    scope,
    version: top,
    keyFp,
    settled: official === undefined || top <= official,
    lastResort: false,
    people: [],
  };
  if (versions[top]) return accepted;

  const skip = new Set([lower(ownKey), ...trusted.map(lower)]);
  const sealers = [
    ...new Map(used.map(({ sealer }) => [lower(sealer.publicKey), withKey(sealer)])).values(),
  ].filter((s) => !skip.has(s.publicKey));
  const vouchedBefore = (s) =>
    !removedHere(memory, scope, s.subject) &&
    Object.values(versions).some((e) => e.sealers.includes(s.publicKey));
  const newSealers = [];
  const stranded = [];
  for (const s of sealers) {
    const confirmable = Boolean(s.subject) && s.log === 'latest';
    if (vouchedBefore(s)) {
      if (!confirmable) return refuse('SEALER_REFUSED', [], scope);
    } else if (confirmable) {
      if (!isApproved('NEW_SEALERS', s.publicKey)) {
        newSealers.push({ ...s, removed: removedHere(memory, scope, s.subject) });
      }
    } else if (known || (s.subject && s.log !== 'retired')) {
      return refuse('SEALER_REFUSED', [], scope);
    } else {
      stranded.push(s);
    }
  }
  const waiting = stranded.filter(
    (s) => lastResort !== 'LAST_RESORT' || !isApproved('LAST_RESORT', s.publicKey)
  );
  if (waiting.length) return refuse(lastResort, waiting, scope);
  if (newSealers.length) return refuse('NEW_SEALERS', newSealers, scope);
  return { ...accepted, lastResort: stranded.length > 0, people: sealers };
}

// `learn` checks, dedups and sorts what it is given.
const learnVersion = (memory, scope, version, { keyFp, learnedAt, ...sets }, pins) => {
  const entry = { keyFp, learnedAt, sealers: [], to: [], out: [], ...sets };
  return learn(memory, { scopes: { [scope]: { versions: { [version]: entry } } }, pins });
};

// After an opening that went through: the version, its key, who sealed it. Not a last resort:
// nobody vouched for that key, the renewal it promised is what gets remembered (commitSeal).
// seq: the head of the public log.
export function commitOpen(memory, decision, seq) {
  if (!decision.ok || !decision.settled || decision.lastResort) return memory;
  return learnVersion(memory, decision.scope, decision.version, {
    keyFp: decision.keyFp,
    learnedAt: seq,
    sealers: decision.people.map((p) => lower(p.publicKey)),
  });
}

// After a seal sent: the people vouched for (decideSeal / decideRecipients `people`), and, with
// a scope, who received this version. full: `to` is everyone (a creation, a rotation, a full
// re-seal); otherwise one more, kept only on a version already sealed here in full.
export function commitSeal(
  memory,
  { scope, version, keyFp, to = [], full = false, people = [] },
  seq
) {
  const pins = {};
  const pin = (subject, key) => {
    const before = pinOf(memory, subject);
    const learnedAt = before && before.key !== key ? Math.max(seq, before.learnedAt + 1) : seq;
    pins[subject] = { key, learnedAt };
  };
  for (const p of people) {
    pin(p.subject, lower(p.publicKey));
    const address = p.address && addressSubject(p.address);
    if (address) pin(address, p.subject);
  }
  if (!scope) return learn(memory, { pins });
  const sealedInFull = (versionsOf(memory, scope)[version]?.to.length || 0) > 0;
  const recipients = full || sealedInFull ? to : [];
  return learnVersion(memory, scope, version, { keyFp, learnedAt: seq, to: recipients }, pins);
}

// A human removed them from here: on the next re-seal, their row switched back on is asked about,
// and so is the next key they seal. Sealed here or only opened, the safe is known.
export function commitRemoved(memory, scope, subject) {
  const version = lastSealed(memory, scope) || knownVersion(memory, scope);
  if (!version) return memory;
  const { keyFp, learnedAt } = versionsOf(memory, scope)[version];
  return learnVersion(memory, scope, version, { keyFp, learnedAt, out: [subject] });
}

// A rotation this device started (D2o): resumed with that key only, and only while everyone it
// reached (`to`, optional) is still there.
export function commitPending(memory, scope, { version, keyFp, to }) {
  const pending = { version, keyFp, ...(to ? { to } : {}) };
  return learn(memory, { scopes: { [scope]: { versions: {}, pending } } });
}

// -> { version, keyFp, to? } of a rotation started here and not reached yet, or null.
export function pendingRotation(memory, scope) {
  const pending = hasOwn(memory.scopes, scope) ? memory.scopes[scope].pending : undefined;
  return pending && pending.version > knownVersion(memory, scope) ? pending : null;
}
