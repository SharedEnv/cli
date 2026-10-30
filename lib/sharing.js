// Sharing a vault you administer. With a person: their key comes from the directory, so
// before anything is sealed to it, it must be the last key the public key log holds for
// them, and the one this machine knows for them (the bin asks about a new or changed
// one). With a team you belong to: its public key is derived from the team private key
// sealed to you, never taken from the server.

import { Buffer } from 'buffer';
import { Wallet } from './crypto.js';
import { expectOk, listAll, listOrgs } from './api.js';
import { assertLogged, syncLog } from './transparency.js';

const wallet = new Wallet();

// → { userId, publicKey, username } of the account behind an email.
export async function lookupPerson(client, email) {
  const res = await client.call('GET', `/keyring/lookup?email=${encodeURIComponent(email)}`);
  if (res.status === 404) throw new Error(`no sharedenv account with a key for ${email}`);
  const person = expectOk(res, 'cannot look this person up');
  if (!person?.userId || !person?.publicKey) {
    throw new Error(`no sharedenv account with a key for ${email}`);
  }
  return {
    ...person,
    userId: String(person.userId),
    publicKey: String(person.publicKey).toLowerCase(),
  };
}

// The person's key must be the last one the log holds for them. `log`: { store, watch },
// the watch of the unlock, so this read checks what it goes past like any other.
export async function assertPersonLogged(client, log, person, label) {
  const { view } = await syncLog(client, log);
  assertLogged(view, [{ subject: `user:${person.userId}`, publicKey: person.publicKey, label }]);
}

// Seals the vault's key to the person and adds them. → 'pending' (until they accept) or
// 'accepted'.
export async function shareWithPerson(client, privateKey, vault, person, level) {
  const sealedSafeKey = wallet.seal(
    privateKey,
    person.publicKey,
    Buffer.from(vault.deks[0], 'hex')
  );
  const body = expectOk(
    await client.call('POST', `/members/${vault.safe._id}`, {
      userId: person.userId,
      level,
      sealedSafeKey: JSON.stringify(sealedSafeKey),
    }),
    'cannot share the vault'
  );
  return body?.status || 'pending';
}

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

export const teamLabel = (team) => (team.org?.name ? `${team.name} (${team.org.name})` : team.name);

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

// Seals the vault's key to the team's key — derived from the team private key sealed to
// you — and grants it. → 'accepted', or 'pending' until someone who answers for the team
// accepts it.
export async function shareWithTeam(client, privateKey, vault, team, level) {
  const res = await client.call('GET', `/team-keys/${encodeURIComponent(team._id)}/me`);
  if (res.status === 404) {
    throw new Error(
      `you hold no key for team ${teamLabel(team)}: only one of its members can share with it`
    );
  }
  const mine = expectOk(res, 'cannot read your team key');
  const opened = mine?.sealedTeamKey && wallet.open(privateKey, mine.sealedTeamKey);
  if (!opened) throw new Error(`cannot open your key for team ${teamLabel(team)}`);
  const teamPublicKey = wallet.keypass.publicFromPrivate(opened.toString('utf8'));
  const sealedSafeKey = wallet.seal(privateKey, teamPublicKey, Buffer.from(vault.deks[0], 'hex'));
  const body = expectOk(
    await client.call('POST', `/safes/${vault.safe._id}/share-team`, {
      teamId: team._id,
      level,
      sealedSafeKey: JSON.stringify(sealedSafeKey),
    }),
    'cannot share the vault with the team'
  );
  return body?.status || 'accepted';
}
