// Shares received. A share someone sends waits for its recipient: until accepted it
// opens nothing. To accept, the envelope is opened with the SENDER's directory key —
// `open(…, { from })` — never with the key the envelope names itself (any key can seal
// a DEK to ours): a share not sealed by the person it claims to come from is refused.

import { Wallet, fingerprintOf } from './crypto.js';
import { expectOk, listAll } from './api.js';
import { assertLogged, syncLog } from './transparency.js';

const wallet = new Wallet();

export class PendingShareError extends Error {
  constructor(share) {
    super(
      `"${share.safe?.name || share.safeId}" is a share from ${senderLabel(share)} waiting for ` +
        `your answer: run \`sharedenv vaults\` to review it, then \`sharedenv accept ` +
        `${share.safeId}\` (or \`decline\`)`
    );
    this.code = 'SHARE_PENDING';
    this.share = share;
  }
}

// "First Last (username)", as the API resolves a person (`{ _id, username, ... }`).
export function personLabel(person) {
  const p = person || {};
  const name = [p.firstName, p.lastName].filter(Boolean).join(' ').trim();
  if (!p.username) return String(p._id || 'unknown');
  return name ? `${name} (${p.username})` : p.username;
}

export const senderLabel = (share) => personLabel(share?.from);

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

// A pending share by its vault's id or name; `teamRef` (a team's id or name): among the
// shares to that team. Two that answer to the same names are listed, never one picked.
// → { safeId, teamId } (teamId null for a share to you).
export async function resolvePendingShare(client, ref, teamRef) {
  const { direct, team } = await listPendingShares(client);
  const same = (a, b) => String(a ?? '').toLowerCase() === String(b).toLowerCase();
  const rows = teamRef
    ? team.filter((p) => same(p.teamId, teamRef) || same(p.team?.name, teamRef))
    : direct;
  const matches = rows.filter((p) => same(p.safeId, ref) || same(p.safe?.name, ref));
  if (matches.length === 0) {
    throw new Error(`no pending share named "${ref}"${teamRef ? ` for team "${teamRef}"` : ''}`);
  }
  if (matches.length > 1) {
    throw Object.assign(
      new Error(
        [
          `"${ref}" names ${matches.length} pending shares: give the vault id` +
            (teamRef ? ' and the team id' : ''),
          ...matches.map(
            (p) =>
              `  ${p.safe?.name}  ${p.safeId}  from ${senderLabel(p)}` +
              (p.teamId ? `  for team ${p.team?.name} (${p.teamId})` : '')
          ),
        ].join('\n')
      ),
      { exitCode: 2 }
    );
  }
  const [match] = matches;
  return { safeId: String(match.safeId), teamId: teamRef ? String(match.teamId) : null };
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

// The sender's key (and the team key a team share moves to) is the directory's word:
// it must be the last key the public key log holds for them. `log`: { store, watch },
// the watch of the unlock (bin/sharedenv.js): this read checks the entries it goes past
// against every key we hold, like any other (lib/transparency.js `syncLog`).
async function assertSenderLogged(client, log, opened, team) {
  const { view } = await syncLog(client, log);
  assertLogged(view, [
    {
      subject: `user:${opened.share.from?._id}`,
      publicKey: opened.senderKey,
      label: senderLabel(opened.share),
    },
    ...(team
      ? [{ subject: `team:${team}`, publicKey: opened.teamPublicKey, label: 'the team' }]
      : []),
  ]);
}

// Check, then accept. `confirm(opened)` (async → boolean) is where a human compares the
// fingerprint; a no leaves the share pending.
export async function acceptShare(client, privateKey, safeId, { confirm, log } = {}) {
  const opened = await openPendingShare(client, privateKey, safeId);
  await assertSenderLogged(client, log, opened);
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
export async function acceptTeamShare(client, privateKey, teamId, safeId, { confirm, log } = {}) {
  const opened = await openPendingTeamShare(client, privateKey, teamId, safeId);
  await assertSenderLogged(client, log, opened, teamId);
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
