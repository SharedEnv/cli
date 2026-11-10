// Signed announcements (TUF model): a restore, or Kubbler's new team key, signed by an
// offline key only the operator holds. The browser runs the same code, and both test
// suites pin one shared vector.
//
//   canonical = JSON with the type's fields in a fixed order, no other field
//   message   = "sharedenv/announcement/v1|<type>|<canonical>"
//   signature = signDetached(offline key, message), low-S
//
// The type is in the signed message so a restore is never read as a new Kubbler key.
// `verifyAnnouncement` never throws.

import { verifyDetached } from './signature.js';

export const ANNOUNCEMENT_DOMAIN = 'sharedenv/announcement/v1';

// The public half of the offline key (forge-ops signer --creer), in both copies of this file. Until
// it is here no client takes any announcement, and neither the CLI nor the extension can be published.
export const ANNOUNCEMENT_KEYS = Object.freeze([
  Object.freeze({ publicKey: '031129d005200cbe8f962b04de201472f21c4efe7f08957f32635a25d376b546bb' }),
]);

let trustedKeys = ANNOUNCEMENT_KEYS;

// For the test suites, which sign with a key of their own. In-process code only: no answer of a
// server and no variable of the environment leads here.
export function setAnnouncementKeysForTests(keys) {
  trustedKeys = keys;
}

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const matches = (pattern) => (v) => typeof v === 'string' && pattern.test(v);
const isIsoShaped = matches(ISO_INSTANT);
const isInstant = (v) => {
  if (!isIsoShaped(v)) return false;
  const date = new Date(v);
  return !Number.isNaN(date.getTime()) && date.toISOString() === v;
};
const atLeast = (min) => (v) => Number.isSafeInteger(v) && v >= min;

const TYPE_FIELDS = {
  restore: { restoredTo: isInstant, logSeq: atLeast(0) },
  'kubbler-key': {
    teamId: matches(/^[0-9a-f]{24}$/),
    publicKey: matches(/^0[23][0-9a-f]{64}$/),
    teamKeyVersion: atLeast(1),
  },
};

const HEADER_FIELDS = {
  v: (v) => v === 1,
  id: matches(/^[0-9a-f]{32}$/),
  type: (v) => typeof v === 'string' && Object.hasOwn(TYPE_FIELDS, v),
  issuedAt: isInstant,
};

export function canonical(announcement) {
  if (!announcement || typeof announcement !== 'object' || Array.isArray(announcement))
    throw new TypeError('announcement: not an object');
  if (!HEADER_FIELDS.type(announcement.type)) throw new TypeError('announcement: bad type');
  const shape = { ...HEADER_FIELDS, ...TYPE_FIELDS[announcement.type] };
  const fields = Object.keys(shape);
  if (Object.keys(announcement).length !== fields.length)
    throw new TypeError('announcement: wrong set of fields');
  for (const field of fields) {
    if (!Object.hasOwn(announcement, field) || !shape[field](announcement[field]))
      throw new TypeError(`announcement: bad ${field}`);
  }
  return JSON.stringify(Object.fromEntries(fields.map((f) => [f, announcement[f]])));
}

export function messageOf(announcement) {
  const json = canonical(announcement);
  return `${ANNOUNCEMENT_DOMAIN}|${announcement.type}|${json}`;
}

// signed: { announcement, signature }. type is required: a caller always says which kind it
// is ready to act on.
export function verifyAnnouncement(signed, { type, keys = trustedKeys } = {}) {
  try {
    const { announcement, signature } = signed;
    if (typeof type !== 'string' || announcement.type !== type) return false;
    const message = messageOf(announcement);
    return keys.some((key) => verifyDetached(key?.publicKey, message, signature));
  } catch {
    return false;
  }
}
