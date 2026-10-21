// Shares received. A share someone sends waits for its recipient: until accepted it
// opens nothing. To accept, the envelope is opened with the SENDER's directory key —
// `open(…, { from })` — never with the key the envelope names itself (any key can seal
// a DEK to ours): a share not sealed by the person it claims to come from is refused.

import { Wallet, fingerprintOf } from './crypto.js';
import { expectOk, listAll } from './api.js';

const wallet = new Wallet();

export class PendingShareError extends Error {
  constructor(share) {
    super(
      `"${share.safe?.name || share.safeId}" is a share from ${senderLabel(share)} waiting for ` +
        `your answer: run \`sharedenv list\` to review it, then \`sharedenv accept ` +
        `${share.safeId}\` (or \`decline\`)`
    );
    this.code = 'SHARE_PENDING';
    this.share = share;
  }
}

export function senderLabel(share) {
  const from = share?.from || {};
  const name = [from.firstName, from.lastName].filter(Boolean).join(' ').trim();
  if (!from.username) return String(from._id || 'unknown');
  return name ? `${name} (${from.username})` : from.username;
}

// → { direct: [...], team: [...] }. Each row carries `from` (name + directory key) and
// `fingerprint`, computed here from that key, never taken from the server.
export async function listPendingShares(client) {
  const withFingerprint = (rows) =>
    rows.map((row) => ({
      ...row,
      fingerprint: row.from?.publicKey ? fingerprintOf(row.from.publicKey) : null,
    }));
  const direct = await listAll(client, '/shares', 'pending shares');
  const team = await listAll(client, '/team-shares', 'pending team shares');
  return { direct: withFingerprint(direct), team: withFingerprint(team) };
}

// A pending share by safe id, or by the name of its safe (`teamId`: among the shares to
// that team). → the safe id.
export async function resolvePendingShare(client, ref, teamId) {
  if (/^[a-f0-9]{24}$/i.test(ref)) return ref;
  const { direct, team } = await listPendingShares(client);
  const rows = teamId ? team.filter((p) => String(p.teamId) === String(teamId)) : direct;
  const match = rows.find((p) => p.safe?.name?.toLowerCase() === ref.toLowerCase());
  if (!match) throw new Error(`no pending share named "${ref}"${teamId ? ' for this team' : ''}`);
  return String(match.safeId);
}

function senderKeyOf(share) {
  const key = share?.from?.publicKey;
  if (!key) {
    throw new Error(
      `${senderLabel(share)} has no key on file any more (keyring reset?): ask them to share again, or decline`
    );
  }
  return String(key).toLowerCase();
}

// → { share, senderKey, fingerprint }; throws when the seal is not the sender's.
export async function openPendingShare(client, privateKey, safeId) {
  const { share } = expectOk(await client.call('GET', `/shares/${safeId}`), 'no pending share');
  const senderKey = senderKeyOf(share);
  if (!wallet.open(privateKey, share.sealedSafeKey, { from: senderKey })) {
    throw new Error(
      `this share was NOT sealed by ${senderLabel(share)} (key ${fingerprintOf(senderKey)}): decline it`
    );
  }
  return { share, senderKey, fingerprint: fingerprintOf(senderKey) };
}

// Check, then accept. `confirm(opened)` (async → boolean) is where a human compares the
// fingerprint; a no leaves the share pending.
export async function acceptShare(client, privateKey, safeId, { confirm } = {}) {
  const opened = await openPendingShare(client, privateKey, safeId);
  if (confirm && !(await confirm(opened))) return { ...opened, accepted: false };
  expectOk(await client.call('POST', `/shares/${safeId}/accept`), 'cannot accept the share');
  return { ...opened, accepted: true };
}

export async function declineShare(client, safeId) {
  expectOk(await client.call('POST', `/shares/${safeId}/decline`), 'cannot decline the share');
  return true;
}

// A pending TEAM grant, opened by someone who answers for the team and holds its key:
// own key → team key (current, or the previous one: a team-key rotation leaves pending
// grants where they are) → DEK, checked against the sender's key.
//
// → { share, dek, senderKey, fingerprint, teamPublicKey, teamKeyVouched }, where
// `teamPublicKey` is the team's CURRENT key, derived from the private key we hold.
// Holding it proves nothing on its own (any key can seal a team key to ours, and the
// keyring row is the server's): `teamKeyVouched` is false when the DEK opened with the
// PREVIOUS key and the current one was not sealed by us — the caller must then check
// it before the DEK moves to it (acceptTeamShare).
export async function openPendingTeamShare(client, privateKey, teamId, safeId) {
  const { share } = expectOk(
    await client.call('GET', `/team-shares/${teamId}/${safeId}`),
    'no pending team share'
  );
  const senderKey = senderKeyOf(share);
  const current = share.sealedTeamKey && wallet.open(privateKey, share.sealedTeamKey);
  if (!current) throw new Error('cannot open your team key for this team');
  const previous =
    share.previousSealedTeamKey && wallet.open(privateKey, share.previousSealedTeamKey);
  const teamKeys = [current, previous].filter(Boolean).map((key) => key.toString('utf8'));

  let dek = false;
  let openedWith = -1;
  for (const [i, teamKey] of teamKeys.entries()) {
    dek = wallet.open(teamKey, share.sealedSafeKey, { from: senderKey });
    if (dek) {
      openedWith = i;
      break;
    }
  }
  if (!dek) {
    const opensAnyway = teamKeys.some((key) => wallet.open(key, share.sealedSafeKey));
    throw new Error(
      opensAnyway
        ? `this share was NOT sealed by ${senderLabel(share)} (key ${fingerprintOf(senderKey)}): decline it`
        : 'this share is sealed to a team key replaced since: ask the sender to share it again, or decline'
    );
  }
  const ownKey = wallet.keypass.publicFromPrivate(privateKey);
  return {
    share,
    dek,
    senderKey,
    fingerprint: fingerprintOf(senderKey),
    teamPublicKey: wallet.keypass.publicFromPrivate(teamKeys[0]),
    teamKeyVouched:
      openedWith === 0 || Boolean(wallet.open(privateKey, share.sealedTeamKey, { from: ownKey })),
  };
}

// Check, re-seal to the team's current key (by us), accept. The grant version we opened
// travels with it: a rotation in between makes it a 409, never an old DEK.
export async function acceptTeamShare(client, privateKey, teamId, safeId, { confirm } = {}) {
  const opened = await openPendingTeamShare(client, privateKey, teamId, safeId);
  // The DEK never moves to a team key nobody vouched for: `confirm` must check it.
  if (!opened.teamKeyVouched && !confirm) {
    throw new Error(
      'the current team key is not vouched for on this machine: accept interactively'
    );
  }
  if (confirm && !(await confirm(opened))) return { ...opened, accepted: false };
  const sealedSafeKey = wallet.seal(privateKey, opened.teamPublicKey, opened.dek);
  expectOk(
    await client.call('POST', `/team-shares/${teamId}/${safeId}/accept`, {
      sealedSafeKey: JSON.stringify(sealedSafeKey),
      keyVersion: opened.share.keyVersion,
    }),
    'cannot accept the team share'
  );
  return { ...opened, accepted: true };
}

export async function declineTeamShare(client, teamId, safeId) {
  expectOk(
    await client.call('POST', `/team-shares/${teamId}/${safeId}/decline`),
    'cannot decline the team share'
  );
  return true;
}
