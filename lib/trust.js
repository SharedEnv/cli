// Whose keys this machine believes. The server is the key directory, and a directory
// can lie; a key legitimately changes in one case only (its owner reset their keyring,
// or a team rotated its key) — exactly the event a lying server would fake. So:
//
//   - trust on first use: the first key seen for someone (`user:<id>`, `team:<id>`) is
//     pinned on this machine (~/.sharedenv/pins.json), and a DIFFERENT key later is
//     never taken silently;
//   - a fingerprint given on the command line (checked with its owner over another
//     channel) settles the question for scripts, instead of a blind yes.
//
// Pure functions: the bin asks the questions and persists the pins.

// → 'new' (never seen here) | 'match' | 'changed'
export function pinStatus(pins, subject, publicKey) {
  const pinned = pins?.[subject];
  if (!pinned) return 'new';
  return pinned === String(publicKey).toLowerCase() ? 'match' : 'changed';
}

export function pinKey(pins, subject, publicKey) {
  pins[subject] = String(publicKey).toLowerCase();
  return pins;
}

const normalized = (fingerprint) => String(fingerprint).replace(/\s+/g, '').toUpperCase();

export const sameFingerprint = (a, b) => normalized(a) === normalized(b);

// The sender of a share. → 'accept' | 'ask' | 'refuse'
//   expected         — `--fingerprint`: the key must be this one, nothing else counts;
//   acceptKeyChange  — `--accept-key-change`: take a key that differs from the pin;
//   yes              — `--yes`: no question for a key that is new or already pinned.
export function senderVerdict(status, fingerprint, { expected, acceptKeyChange, yes } = {}) {
  if (expected) return sameFingerprint(expected, fingerprint) ? 'accept' : 'refuse';
  if (status === 'changed') return acceptKeyChange ? 'accept' : 'ask';
  return yes ? 'accept' : 'ask';
}

// The team key a share moves to on accept, when no seal of ours vouches for it: a planted
// key would receive the safe's key. Pinned, or confirmed by its fingerprint — by a human
// or by `--team-fingerprint` — and no flag says yes blindly. → 'accept' | 'ask' | 'refuse'
export function teamKeyVerdict(status, fingerprint, { expected } = {}) {
  if (expected) return sameFingerprint(expected, fingerprint) ? 'accept' : 'refuse';
  return status === 'match' ? 'accept' : 'ask';
}
