// The memory a device keeps for one account (#memoire): for each safe and each team, every
// version of its key seen here with the digest of that key (keyFp), who sealed it, and who
// this device sealed it to (`out`: removed from here since); the people it can seal to
// (pins); the public log it checked; the signed announcements it applied. No secret.
//
//   { v: 2, account,
//     scopes: { "safe:<id>" | "team:<id>": {
//       versions: { "<n>": { keyFp, learnedAt, sealers: [publicKey], to: [subject], out: [subject] } },
//       pending?: { version, keyFp, to?: [subject] } } },
//     pins: { "user:<id>" | "team:<id>": { key: publicKey, learnedAt },
//             "address:<email>": { key: subject, learnedAt } },
//     log: null | { seq, ... },
//     announcements: { applied: { "<id>": logSeq | null }, kubbler: null | { publicKey, teamKeyVersion } } }
//
// learnedAt is the entry of the public log when it was learned, not a clock: a signed restore
// names an entry, and what was learned after it is forgotten. The memory only grows
// otherwise: two copies merge into one that holds both, so two tabs never undo each other.
// Unreadable, or another account's: a fresh device.
//
// No import (copied byte for byte into API/src/tools/crypto/trust/).

const SCOPE = /^(safe|team):[0-9a-f]{24}$/;
const SUBJECT = /^(user|team):[0-9a-f]{24}$/;
const ADDRESS = /^address:\S{1,320}$/;
const PIN_SUBJECT = /^(?:(?:user|team):[0-9a-f]{24}|address:\S{1,320})$/;
const PUBLIC_KEY = /^[0-9a-f]{66}$/;
const KEY_FP = /^[0-9a-f]{32}$/;
const VERSION = /^[1-9][0-9]{0,8}$/;
const ANNOUNCEMENT = /^[0-9a-f]{32}$/;

const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isSeq = (value) => Number.isSafeInteger(value) && value >= 0;
export const isVersion = (value) => Number.isInteger(value) && value >= 1 && value <= 999999999;
export const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

export const emptyMemory = (account) => ({
  v: 2,
  account: String(account),
  scopes: {},
  pins: {},
  log: null,
  announcements: { applied: {}, kubbler: null },
});

export const addressSubject = (address) => {
  const subject = `address:${String(address).trim().toLowerCase()}`;
  return ADDRESS.test(subject) ? subject : null;
};

class Unreadable extends Error {}
const must = (ok) => {
  if (!ok) throw new Unreadable('Unreadable key memory.');
};

const readSet = (list, pattern) => {
  must(Array.isArray(list) && list.every((item) => matches(pattern, item)));
  return [...new Set(list)].sort();
};

const readMap = (object, keyPattern, readValue) => {
  must(isObject(object));
  const out = {};
  for (const [key, value] of Object.entries(object)) {
    must(keyPattern.test(key));
    out[key] = readValue(value, key);
  }
  return out;
};

const readVersion = (entry) => {
  must(isObject(entry) && matches(KEY_FP, entry.keyFp) && isSeq(entry.learnedAt));
  return {
    keyFp: entry.keyFp,
    learnedAt: entry.learnedAt,
    sealers: readSet(entry.sealers, PUBLIC_KEY),
    to: readSet(entry.to, SUBJECT),
    out: readSet(entry.out, SUBJECT),
  };
};

const readScope = (scope) => {
  must(isObject(scope));
  const out = { versions: readMap(scope.versions, VERSION, readVersion) };
  if (scope.pending !== undefined) {
    const { pending } = scope;
    must(isObject(pending) && isVersion(pending.version) && matches(KEY_FP, pending.keyFp));
    out.pending = {
      version: pending.version,
      keyFp: pending.keyFp,
      ...(pending.to === undefined ? {} : { to: readSet(pending.to, SUBJECT) }),
    };
  }
  return out;
};

const readPin = (pin, subject) => {
  must(isObject(pin) && isSeq(pin.learnedAt));
  must(matches(SUBJECT.test(subject) ? PUBLIC_KEY : SUBJECT, pin.key));
  return { key: pin.key, learnedAt: pin.learnedAt };
};

const readKubbler = (kubbler) => {
  if (kubbler === null) return null;
  must(isObject(kubbler) && matches(PUBLIC_KEY, kubbler.publicKey));
  must(isVersion(kubbler.teamKeyVersion));
  return { publicKey: kubbler.publicKey, teamKeyVersion: kubbler.teamKeyVersion };
};

const readLogSeq = (logSeq) => {
  must(logSeq === null || isSeq(logSeq));
  return logSeq;
};

// -> the memory, normalized; throws Unreadable.
function strict(memory, account) {
  must(isObject(memory) && memory.v === 2 && memory.account === String(account));
  must(memory.log === null || (isObject(memory.log) && isSeq(memory.log.seq)));
  must(isObject(memory.announcements));
  const { applied, kubbler } = memory.announcements;
  return {
    v: 2,
    account: memory.account,
    scopes: readMap(memory.scopes, SCOPE, readScope),
    pins: readMap(memory.pins, PIN_SUBJECT, readPin),
    log: memory.log,
    announcements: {
      applied: readMap(applied, ANNOUNCEMENT, readLogSeq),
      kubbler: readKubbler(kubbler),
    },
  };
}

// raw: what the storage gave back (text, object, or nothing).
export function readMemory(raw, account) {
  try {
    return strict(typeof raw === 'string' ? JSON.parse(raw) : raw, account);
  } catch {
    return emptyMemory(account);
  }
}

const union = (a, b) => [...new Set([...a, ...b])].sort();
const earlier = (a, b, field) =>
  a.learnedAt < b.learnedAt || (a.learnedAt === b.learnedAt && a[field] <= b[field]) ? a : b;

function mergeMap(a, b, mergeValue) {
  const out = { ...a };
  for (const [key, value] of Object.entries(b)) {
    out[key] = hasOwn(a, key) ? mergeValue(a[key], value) : value;
  }
  return out;
}

// Two keys at one version: one of them is an attack. The first learned stays.
const mergeVersion = (a, b) =>
  a.keyFp !== b.keyFp
    ? earlier(a, b, 'keyFp')
    : {
        keyFp: a.keyFp,
        learnedAt: Math.min(a.learnedAt, b.learnedAt),
        sealers: union(a.sealers, b.sealers),
        to: union(a.to, b.to),
        out: union(a.out, b.out),
      };

const higher = (a, b, field, tie) => {
  if (!a || !b) return a || b;
  if (a[field] !== b[field]) return a[field] > b[field] ? a : b;
  return a[tie] <= b[tie] ? a : b;
};

// On one key, whoever either note reached stays reached: a resumption needs all of them still there.
// On one key `higher` keeps `a`, its list with it: only a list `b` holds has to be joined.
function mergePending(a, b) {
  const pending = higher(a, b, 'version', 'keyFp');
  const sameKey = a && b && a.version === b.version && a.keyFp === b.keyFp;
  return sameKey && b.to ? { ...pending, to: union(a.to ?? [], b.to) } : pending;
}

function mergeScope(a, b) {
  const out = { versions: mergeMap(a.versions, b.versions, mergeVersion) };
  const pending = mergePending(a.pending, b.pending);
  if (pending) out.pending = pending;
  return out;
}

// A pin that changed: the one learned last is the human's latest yes.
const mergePin = (a, b) =>
  a.key === b.key
    ? { key: a.key, learnedAt: Math.min(a.learnedAt, b.learnedAt) }
    : higher(a, b, 'learnedAt', 'key');

// A copy that has not applied a restore the other one applied still holds what it forgets.
const catchUp = (memory, other) =>
  Object.entries(other.announcements.applied).reduce(
    (acc, [id, logSeq]) => (logSeq === null ? acc : forgetAfter(acc, { id, logSeq })),
    memory
  );

export function mergeMemory(a, b) {
  if (a.account !== b.account) return a;
  const left = catchUp(a, b);
  const right = catchUp(b, a);
  return {
    v: 2,
    account: a.account,
    scopes: mergeMap(left.scopes, right.scopes, mergeScope),
    pins: mergeMap(left.pins, right.pins, mergePin),
    log: higher(left.log, right.log, 'seq', 'seq'),
    announcements: {
      applied: { ...left.announcements.applied, ...right.announcements.applied },
      kubbler: higher(
        left.announcements.kubbler,
        right.announcements.kubbler,
        'teamKeyVersion',
        'publicKey'
      ),
    },
  };
}

// A signed restore ({ id, logSeq }, checked by the caller): forget what was learned after
// entry logSeq of the public log, the log read past it and any rotation in flight included.
// Once per announcement.
export function forgetAfter(memory, { id, logSeq }) {
  if (!matches(ANNOUNCEMENT, id) || !isSeq(logSeq)) throw new Error('Invalid announcement.');
  if (hasOwn(memory.announcements.applied, id)) return memory;
  const before = (entry) => entry.learnedAt <= logSeq;
  const scopes = {};
  for (const [scope, { versions }] of Object.entries(memory.scopes)) {
    const kept = Object.entries(versions).filter(([, entry]) => before(entry));
    if (kept.length) scopes[scope] = { versions: Object.fromEntries(kept) };
  }
  return {
    ...memory,
    scopes,
    pins: Object.fromEntries(Object.entries(memory.pins).filter(([, pin]) => before(pin))),
    log: memory.log && memory.log.seq > logSeq ? null : memory.log,
    announcements: {
      ...memory.announcements,
      applied: { ...memory.announcements.applied, [id]: logSeq },
    },
  };
}

// What a caller learned, in the memory's shape, checked as strictly as what is read back: a
// malformed entry would make the whole memory unreadable later. The delta counts as having
// seen the restores the memory applied: they forget what came before them, not what is new.
export function learn(memory, { scopes = {}, pins = {}, log = null, kubbler = null }) {
  const announcements = { applied: memory.announcements.applied, kubbler };
  const delta = { ...emptyMemory(memory.account), scopes, pins, log, announcements };
  return mergeMemory(memory, strict(delta, memory.account));
}

// Which account each key this device derived itself belongs to, apart from any account's memory:
// the server names the account, and a memory opened under another name knows nothing.
//   { "<publicKey>": "<userId>" }
// raw: what the storage gave back. Unreadable: a fresh device.
export function readOwnKeys(raw) {
  try {
    const owners = typeof raw === 'string' ? JSON.parse(raw) : raw;
    return readMap(owners, PUBLIC_KEY, (owner) => {
      must(typeof owner === 'string' && owner.length > 0);
      return owner;
    });
  } catch {
    return {};
  }
}

// -> what to keep from now on, or null: this key is known here under another account, or the
// server names none. A key never seen goes on as it did, filed once an account is named.
export function claimOwnKey(owners, publicKey, userId) {
  const key = String(publicKey).toLowerCase();
  const named = userId ? String(userId) : '';
  if (hasOwn(owners, key)) return owners[key] === named ? owners : null;
  return named ? { ...owners, [key]: named } : owners;
}

export const versionsOf = (memory, scope) =>
  hasOwn(memory.scopes, scope) ? memory.scopes[scope].versions : {};

// The highest version of a scope seen here; 0: never seen.
export const knownVersion = (memory, scope) =>
  Math.max(0, ...Object.keys(versionsOf(memory, scope)).map(Number));
