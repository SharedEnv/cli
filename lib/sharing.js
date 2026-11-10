// Sharing a vault you administer. With a person: their key comes from the directory, so
// before anything is sealed to it, it goes through the trust guard: the last key the public
// log holds for them, and the one this machine knows for them (a new or changed one is
// asked about). With a team you belong to: its public key is derived from the team private key
// sealed to you, and any key can seal a team key to yours: it must also be the last key
// the log holds for the team, and sealed by you, or known here, or confirmed.

import { Wallet, readKeyPayload } from './crypto.js';
import { expectOk, freshTries, listAll, listOrgs } from './api.js';
import { openVaultToWrite } from './safes.js';
import { printable } from './shares.js';
import { contradictsMemory, keyFpOf, teamKeyAhead, teamKeyOf } from './transparency.js';
import { TrustRefusal, sealKey } from './trust.js';

const wallet = new Wallet();

// → { userId, publicKey, username } of the account behind an email.
export async function lookupPerson(client, email) {
  const res = await client.call('GET', `/keyring/lookup?email=${encodeURIComponent(email)}`);
  if (res.status === 404) throw new TrustRefusal('SHARE_TARGET_UNAVAILABLE');
  const person = expectOk(res, 'cannot look this person up');
  if (!person?.userId || !person?.publicKey) throw new TrustRefusal('SHARE_TARGET_UNAVAILABLE');
  return {
    ...person,
    userId: String(person.userId),
    publicKey: String(person.publicKey).toLowerCase(),
  };
}

// The vault's key as a seal for `publicKey`: it names the vault and its version.
const sealVaultKey = (trust, vault, publicKey) =>
  JSON.stringify(
    sealKey(trust.privateKey, publicKey, {
      kind: 'safe',
      id: String(vault.safe._id),
      version: vault.keyVersion,
      key: vault.writeDek,
    })
  );

// What went through is remembered: the vault as opened, and who received it.
function remember(trust, vault, subject, people) {
  vault.commit();
  trust.commitSeal({
    scope: `safe:${vault.safe._id}`,
    version: vault.keyVersion,
    keyFp: vault.keyFp,
    to: [subject],
    people,
  });
}

// The vault as the caller opened it, then, if the key moved in between, as it stands now.
const openedAgain = (client, trust, vault, tried) =>
  tried === 0 ? vault : openVaultToWrite(client, trust, String(vault.safe._id));

// Seals the vault's key to the person and adds them. `people`: the guard's decision about
// them (trust.sealTo). → 'pending' (until they accept).
export const shareWithPerson = (client, trust, opened, person, level, people) =>
  freshTries(async (tried) => {
    const vault = await openedAgain(client, trust, opened, tried);
    const body = expectOk(
      await client.call('POST', `/members/${vault.safe._id}`, {
        userId: person.userId,
        level,
        sealedSafeKey: sealVaultKey(trust, vault, person.publicKey),
        keyVersion: vault.keyVersion,
      }),
      'cannot share the vault'
    );
    remember(trust, vault, `user:${person.userId}`, people);
    return body?.status || 'pending';
  });

// Every team of every organization you are in. → [{ _id, name, org: { _id, name } }]
export async function listTeams(client) {
  const teams = [];
  for (const org of await listOrgs(client)) {
    const rows = await listAll(client, `/team/list?orgId=${encodeURIComponent(org._id)}`, 'teams');
    for (const t of rows) {
      teams.push({ _id: String(t._id), name: t.name, memberCount: t.memberCount, org });
    }
  }
  return teams;
}

export const teamLabel = (team) =>
  printable(team.org?.name ? `${team.name} (${team.org.name})` : team.name);

// A team by id or (case-insensitive) name; several answering to it pick none.
export async function resolveTeam(client, ref) {
  const want = String(ref).toLowerCase();
  const matches = (await listTeams(client)).filter(
    (t) => t._id.toLowerCase() === want || t.name?.toLowerCase() === want
  );
  if (matches.length === 1) return matches[0];
  if (matches.length === 0) throw new Error(`no team named "${ref}" (sharedenv teams lists yours)`);
  throw Object.assign(
    new Error(
      [
        `"${ref}" names ${matches.length} teams: give its id`,
        ...matches.map((t) => `  ${teamLabel(t)}  ${t._id}`),
      ].join('\n')
    ),
    { exitCode: 2 }
  );
}

// The key of a team as this account holds it, for a human to compare (`sharedenv fingerprint
// --team`): derived from what is sealed to it, never the server's word. Sealed by nobody this
// device answers for, it is the key pinned here; none: nothing to read out.
export async function teamKeyToCompare(client, trust, team) {
  const held = await teamKeyOf(client, trust.privateKey, team._id, trust.memory());
  if (!held) throw new TrustRefusal('TEAM_KEY_NOT_PROVISIONED', { team: teamLabel(team) });
  if (!held.key) throw new TrustRefusal('KEY_UNSAFE');
  return held.key;
}

// Seals the vault's key to the team's key, and grants it. `check(teamPublicKey)` (→ boolean): a
// key the caller named. The guard answers for the key; someone who left still holding it is
// a question of its own. → 'accepted', 'pending' until someone who answers for the team accepts
// it, or null: not shared.
export const shareWithTeam = (client, trust, opened, team, level, options) =>
  freshTries(async (tried) => {
    const vault = await openedAgain(client, trust, opened, tried);
    return shareWithTeamOnce(client, trust, vault, team, level, options);
  });

async function shareWithTeamOnce(client, trust, vault, team, level, { check } = {}) {
  const readRow = () => client.call('GET', `/team-keys/${encodeURIComponent(team._id)}/me`);
  const label = teamLabel(team);
  const replaced = () => new TrustRefusal('TEAM_KEY_ROTATING', { team: label });
  const res = await readRow();
  if (res.status === 404) throw new TrustRefusal('TEAM_KEY_NOT_PROVISIONED', { team: label });
  const mine = expectOk(res, 'cannot read your team key', { team: label });
  // Said as such: the next key is not in the log yet, which would read like an attack.
  if (teamKeyAhead(mine)) throw replaced();
  const opened = mine?.sealedTeamKey && wallet.open(trust.privateKey, mine.sealedTeamKey);
  if (!opened) throw new TrustRefusal('KEY_UNSAFE');
  const version = mine.keyVersion || 1;
  const subject = `team:${team._id}`;
  const payload = readKeyPayload(opened.toString('hex'), { kind: 'team', id: team._id, version });
  if (!payload) throw new TrustRefusal('KEY_UNSAFE');
  if (contradictsMemory(trust.memory(), subject, { version, keyFp: keyFpOf(payload.key) })) {
    throw new TrustRefusal('KEY_UNSAFE');
  }
  const teamPublicKey = wallet.keypass.publicFromPrivate(payload.key);
  if (check && !check(teamPublicKey)) return null;
  const ownSeal = String(mine.sealedTeamKey.senderPublicKey).toLowerCase() === trust.ownKey;
  const context = { vault: printable(vault.safe.name), team: label, scripted: true };
  const decision = await trust.sealTo({
    person: { subject, publicKey: teamPublicKey, label },
    context,
    vouched: ownSeal,
  });
  if (!decision) return null;
  if (mine.pendingKeyRotation === true) {
    if (!(await trust.ask('TEAM_DEBT_SHARE', context))) return null;
    // A lead may have replaced the key during the question: past this point the vault's key
    // would go to the old one, and nothing would flag it any more.
    if ((await readRow()).body?.keyVersion !== mine.keyVersion) throw replaced();
  }
  const posted = await client.call('POST', `/safes/${vault.safe._id}/share-team`, {
    teamId: team._id,
    level,
    sealedSafeKey: sealVaultKey(trust, vault, teamPublicKey),
    keyVersion: vault.keyVersion,
    teamPublicKey,
  });
  const body = expectOk(posted, 'cannot share the vault with the team', { team: label });
  remember(trust, vault, subject, decision.people);
  return body?.status || 'accepted';
}
