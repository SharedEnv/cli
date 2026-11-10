// Shares received. A share someone sends waits for its recipient: until accepted it
// opens nothing. To accept, the envelope is opened with the SENDER's directory key —
// `open(…, { from })` — never with the key the envelope names itself (any key can seal
// a DEK to ours): a share not sealed by the person it claims to come from is refused.

import { Wallet, fingerprintOf, readKeyPayload } from './crypto.js';
import { expectOk, freshTries, listAll } from './api.js';
import { message } from './messages.js';
import { contradictsMemory, keyFpOf, teamKeyAhead } from './transparency.js';
import { TrustRefusal, sealKey } from './trust.js';

const wallet = new Wallet();

export class PendingShareError extends Error {
  constructor(share) {
    super(
      `${message('SHARE_PENDING')} "${share.safe?.name || share.safeId}" comes from ` +
        `${senderLabel(share)}: run \`sharedenv vaults\` to review it, then \`sharedenv accept ` +
        `${share.safeId}\` (or \`decline\`)`
    );
    this.code = 'SHARE_PENDING';
    this.share = share;
  }
}

// A name from the server, for the terminal: a control character could redraw what a
// question about a key shows.
export const printable = (text) => String(text).replace(/[\p{Cc}\p{Cf}]/gu, '');

// "First Last (username)", as the API resolves a person (`{ _id, username, ... }`).
export function personLabel(person) {
  const p = person || {};
  const name = [p.firstName, p.lastName].filter(Boolean).join(' ').trim();
  if (!p.username) return printable(p._id || 'unknown');
  return printable(name ? `${name} (${p.username})` : p.username);
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
  if (!key) throw new TrustRefusal('SHARE_INVALID');
  return String(key).toLowerCase();
}

// What a share holds must name its vault and the version of its row (rule D).
function safeKeyIn(opened, share, safeId) {
  const payload = readKeyPayload(opened.toString('hex'), {
    kind: 'safe',
    id: safeId,
    version: share.keyVersion || 1,
  });
  if (!payload) throw new TrustRefusal('SHARE_INVALID');
  return { version: payload.version, key: payload.key, keyFp: keyFpOf(payload.key) };
}

// → { share, senderKey, fingerprint, version, key, keyFp }; throws when the seal is not the
// sender's.
export async function openPendingShare(client, privateKey, safeId) {
  const { share } = expectOk(await client.call('GET', `/shares/${safeId}`), 'no pending share');
  const senderKey = senderKeyOf(share);
  const opened = wallet.open(privateKey, share.sealedSafeKey, { from: senderKey });
  if (!opened) throw new TrustRefusal('SHARE_INVALID');
  return {
    share,
    senderKey,
    fingerprint: fingerprintOf(senderKey),
    ...safeKeyIn(opened, share, safeId),
  };
}

// The sender's seal, by the guard: a first for this vault is a question that holds for this
// vault only, the public log answers before it, and nothing is kept until the share is
// accepted. → the decision, or null: a no.
async function vouchForSender(trust, safeId, { share, senderKey, version, keyFp }) {
  try {
    return await trust.open({
      scope: `safe:${safeId}`,
      paths: [
        {
          version,
          keyFp,
          sealer: {
            publicKey: senderKey,
            subject: share.from?._id ? `user:${share.from._id}` : undefined,
            label: senderLabel(share),
          },
        },
      ],
      official: share.safe?.keyVersion,
      context: { vault: printable(share.safe?.name || safeId), scripted: true },
    });
  } catch (err) {
    if (err.code === 'SEALER_DECLINED') return null;
    throw err;
  }
}

// Check, then accept. `check(senderKey)` (→ boolean): a key the caller named; a no, or a no to
// a question, leaves the share pending.
export async function acceptShare(client, trust, safeId, { check } = {}) {
  const opened = await openPendingShare(client, trust.privateKey, safeId);
  if (check && !check(opened.senderKey)) return { ...opened, accepted: false };
  const decision = await vouchForSender(trust, safeId, opened);
  if (!decision) return { ...opened, accepted: false };
  expectOk(await client.call('POST', `/shares/${safeId}/accept`), 'cannot accept the share');
  trust.commitOpen(decision);
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
// → { share, senderKey, fingerprint, version, key, keyFp, teamPublicKey, teamKeyVouched, owed },
// where `teamPublicKey` is the team's CURRENT key, derived from the private key we hold.
// Holding it proves nothing on its own (any key can seal a team key to ours, and the keyring
// row is the server's): `teamKeyVouched` is false when the DEK opened with the PREVIOUS key and
// the current one was not sealed by us — the guard must then check it before the DEK moves to
// it (acceptTeamShare). `owed`: someone who left still holds the team key (N3).
export async function openPendingTeamShare(client, privateKey, teamId, safeId) {
  const { share } = expectOk(
    await client.call('GET', `/team-shares/${teamId}/${safeId}`),
    'no pending team share'
  );
  const team = printable(share.team?.name || teamId);
  const row = await client.call('GET', `/team-keys/${teamId}/me`);
  if (row.status === 404) throw new TrustRefusal('TEAM_KEY_NOT_PROVISIONED', { team });
  const mine = expectOk(row, 'no team key', { team });
  // Said as such: the next key is not in the log yet, which would read like an attack.
  if (teamKeyAhead(mine)) throw new TrustRefusal('TEAM_KEY_ROTATING', { team });
  const senderKey = senderKeyOf(share);
  const teamKeyIn = (blob, version) => {
    const opened = blob && wallet.open(privateKey, blob);
    const payload =
      opened && readKeyPayload(opened.toString('hex'), { kind: 'team', id: teamId, version });
    return payload ? payload.key : null;
  };
  const current = teamKeyIn(share.sealedTeamKey, mine.keyVersion || 1);
  if (!current) throw new TrustRefusal('KEY_UNSAFE');
  const previous = teamKeyIn(share.previousSealedTeamKey);
  const teamKeys = [current, previous].filter(Boolean);

  let dek = false;
  let openedWith = -1;
  for (const [i, teamKey] of teamKeys.entries()) {
    dek = wallet.open(teamKey, share.sealedSafeKey, { from: senderKey });
    if (dek) {
      openedWith = i;
      break;
    }
  }
  if (!dek) throw new TrustRefusal('SHARE_INVALID');
  const ownKey = wallet.keypass.publicFromPrivate(privateKey);
  return {
    share,
    senderKey,
    fingerprint: fingerprintOf(senderKey),
    ...safeKeyIn(dek, share, safeId),
    teamKeyHeld: { version: mine.keyVersion || 1, keyFp: keyFpOf(current) },
    teamPublicKey: wallet.keypass.publicFromPrivate(current),
    teamKeyVouched:
      openedWith === 0 || String(share.sealedTeamKey.senderPublicKey).toLowerCase() === ownKey,
    owed: mine.pendingKeyRotation === true,
  };
}

// Check, re-seal to the team's current key (by us), accept. The grant version we opened
// travels with it: a rotation in between is refused, never an old DEK, and the share is read again.
export const acceptTeamShare = (client, trust, teamId, safeId, options) =>
  freshTries(() => acceptTeamShareOnce(client, trust, teamId, safeId, options));

async function acceptTeamShareOnce(client, trust, teamId, safeId, { check } = {}) {
  const opened = await openPendingTeamShare(client, trust.privateKey, teamId, safeId);
  const left = { ...opened, accepted: false };
  if (check && !check(opened.senderKey)) return left;
  const decision = await vouchForSender(trust, safeId, opened);
  if (!decision) return left;
  const team = printable(opened.share.team?.name || teamId);
  const subject = `team:${teamId}`;
  // Rule D, as the browser: below the version seen here, or another key at that version.
  if (contradictsMemory(trust.memory(), subject, opened.teamKeyHeld)) {
    throw new TrustRefusal('SEALER_REFUSED', {
      vault: printable(opened.share.safe?.name || safeId),
    });
  }
  const sealing = await trust.sealTo({
    person: { subject, publicKey: opened.teamPublicKey, label: team },
    context: { team, scripted: true },
    vouched: opened.teamKeyVouched,
  });
  if (!sealing) return left;
  if (opened.owed && !(await trust.ask('TEAM_DEBT_SHARE', { team, scripted: true }))) return left;

  const sealedSafeKey = sealKey(trust.privateKey, opened.teamPublicKey, {
    kind: 'safe',
    id: safeId,
    version: opened.version,
    key: opened.key,
  });
  expectOk(
    await client.call('POST', `/team-shares/${teamId}/${safeId}/accept`, {
      sealedSafeKey: JSON.stringify(sealedSafeKey),
      keyVersion: opened.version,
      teamPublicKey: opened.teamPublicKey,
    }),
    'cannot accept the team share',
    { team }
  );
  trust.commitOpen(decision);
  // A version the vault has not reached is not one seen here: it would refuse what a rotation left
  // behind under the version before.
  trust.commitSeal(
    decision.settled
      ? {
          scope: `safe:${safeId}`,
          version: opened.version,
          keyFp: opened.keyFp,
          to: [subject],
          people: sealing.people,
        }
      : { people: sealing.people }
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
