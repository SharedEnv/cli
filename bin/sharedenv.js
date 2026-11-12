#!/usr/bin/env node
// sharedenv — your zero-knowledge vaults in the terminal, decrypted locally. The master
// password and the private key never leave this process and never touch disk; only the
// session cookies and what this machine learned about keys are kept (~/.sharedenv).
//
// This file is the terminal: arguments, questions, output, exit codes. What happens to
// keys and secrets lives in ../lib.

import readline from 'readline';
import { Writable } from 'stream';
import { parseArgs } from 'util';
import { fingerprintOf, fingerprintWords } from '../lib/crypto.js';
import { VERSION, apiBase, createClient, expectOk, listAll } from '../lib/api.js';
import { login, publicKeyOf, unlockAccount, whoAmI } from '../lib/auth.js';
import { TrustRefusal, message } from '../lib/messages.js';
import {
  acknowledgeAlerts,
  heldKeys,
  keptAlerts,
  syncAnnouncements,
  syncLog,
  watchWarnings,
} from '../lib/transparency.js';
import { childEnv, splitUnsafeEnv } from '../lib/env.js';
import { FORMATS } from '../lib/format.js';
import { LINK_FILE, findLink, writeLink } from '../lib/link.js';
import { runChild } from '../lib/run.js';
import {
  LEVELS,
  WRITABLE_NAME,
  accessOf,
  createVault,
  describeVault,
  levelName,
  listSecretRows,
  listVaults,
  openVaultToWrite,
  pullSecrets,
  rotationUnfinished,
  readSecret,
  readVault,
  resolveSafe,
  setSecrets,
  unsetSecrets,
} from '../lib/safes.js';
import {
  acceptShare,
  acceptTeamShare,
  declineShare,
  declineTeamShare,
  listPendingShares,
  personLabel,
  printable,
  resolvePendingShare,
  senderLabel,
} from '../lib/shares.js';
import {
  listTeams,
  lookupPerson,
  resolveTeam,
  shareWithPerson,
  shareWithTeam,
  teamKeyToCompare,
  teamLabel,
} from '../lib/sharing.js';
import { createStore, writePrivate } from '../lib/store.js';
import {
  createTrust,
  pinStatus,
  sameFingerprint,
  senderVerdict,
  teamKeyVerdict,
} from '../lib/trust.js';

const DEFAULT_API = 'https://api.sharedenv.com';
const USER_AGENT = `sharedenv-cli/${VERSION}`;

const store = createStore();

// ── Terminal ────────────────────────────────────────────────────────────────────────
// Questions and notices go to stderr: stdout carries data only, so
// `sharedenv pull > .env` writes the secrets and nothing else. Names come from the server, and
// nothing it names reaches the terminal unfiltered; only a value, on its own way out, is as is.

const shown = (text) => String(text).split('\n').map(printable).join('\n');
const say = (text) => process.stdout.write(`${shown(text)}\n`);
const note = (text) => process.stderr.write(`${shown(text)}\n`);

class UsageError extends Error {
  exitCode = 2;
}

// → the answer, or null when there is no terminal to ask or it was closed (Ctrl-D).
function ask(question, { secret = false } = {}) {
  if (!process.stdin.isTTY) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    // readline echoes what is typed to its output: for a secret the output is a sink, so
    // nothing reaches the terminal. A secret is not trimmed (a password may end in a space).
    const output = secret
      ? new Writable({ write: (chunk, encoding, done) => done() })
      : process.stderr;
    const rl = readline.createInterface({ input: process.stdin, output, terminal: true });
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      rl.close();
      if (secret) process.stderr.write('\n');
      fn(value);
    };
    rl.on('SIGINT', () => finish(reject, Object.assign(new Error('cancelled'), { exitCode: 130 })));
    rl.on('close', () => finish(resolve, null));
    if (secret) process.stderr.write(question);
    rl.question(secret ? '' : question, (answer) =>
      finish(resolve, secret ? answer : answer.trim())
    );
  });
}

// A yes/no question. Without a terminal it is a no, and `hint` says how a script answers.
async function confirm(question, hint) {
  if (!process.stdin.isTTY) {
    note(`  No terminal to ask: ${hint}.`);
    return false;
  }
  return /^y(es)?$/i.test((await ask(question)) || '');
}

async function masterPassword() {
  const password =
    process.env.SHAREDENV_PASSWORD ?? (await ask('Master password: ', { secret: true }));
  if (!password) {
    throw new UsageError('no master password: run in a terminal, or set SHAREDENV_PASSWORD');
  }
  return password;
}

// Everything piped in, as text.
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

// ── Session ─────────────────────────────────────────────────────────────────────────

let connected = null; // { client, session } of this run, to save renewed cookies

function connect() {
  const session = store.readSession();
  if (!session?.baseUrl) throw new Error('not signed in — run `sharedenv login`');
  const baseUrl = apiBase(session.baseUrl);
  // The cookies belong to the server they came from: never send them to another one.
  if (process.env.SHAREDENV_API && apiBase(process.env.SHAREDENV_API) !== baseUrl) {
    throw new Error(
      `this session is for ${baseUrl}, SHAREDENV_API names another server: run \`sharedenv login\``
    );
  }
  const client = createClient({ baseUrl, cookies: session.cookies, userAgent: USER_AGENT });
  connected = { client, session };
  return client;
}

function saveSession() {
  if (!connected) return;
  const { client, session, userId = session.userId } = connected;
  const cookies = client.cookies();
  const same = JSON.stringify(cookies) === JSON.stringify(session.cookies);
  if (same && userId === session.userId) return;
  store.writeSession({ baseUrl: client.baseUrl, cookies, userId });
  session.cookies = cookies;
  session.userId = userId;
}

// Each time the vault opens: what the signed announcements say, and are the keys the public log
// holds for us - our own, and those of the teams whose key we hold - still the ones we hold? A
// warning, never a refusal: reading your own secrets seals nothing to anyone. What it found is
// kept (for this account on this server) and said again at every unlock until `sharedenv log
// --ack`, even when the log cannot be read this time.
// → the watch, for every later read of the log in this run (a read that watches less
// would let entries go by unchecked).
async function watchKeys(client, account, kept) {
  await syncAnnouncements(client, kept);
  const { watch, labels, doubts } = await heldKeys(client, account, kept.readMemory());
  let report;
  try {
    report = await syncLog(client, { store: kept, watch });
  } catch (err) {
    note(err.message);
    report = { alerts: keptAlerts(kept) };
  }
  for (const line of watchWarnings(report, labels)) note(line);
  for (const subject of doubts) {
    note(message('TEAM_KEY_LOG_FOREIGN', { team: printable(labels[subject]) }));
  }
  return watch;
}

// The account the server names opens a memory: it must be the one this machine knows for this key.
async function unlockClaimed(client, password) {
  const account = await unlockAccount(client, password);
  if (!store.claimOwnKey(client.baseUrl, publicKeyOf(account.privateKey), account.userId)) {
    throw new TrustRefusal('KEY_UNSAFE');
  }
  return account;
}

// `values`: the flags of the command, which may answer the guard's questions (guardAnswers).
async function unlock(client, values = {}) {
  const account = await unlockClaimed(client, await masterPassword());
  connected.userId = String(account.userId);
  const kept = store.forAccount(client.baseUrl, account.userId);
  const watch = await watchKeys(client, account, kept);
  return createTrust({
    client,
    store: kept,
    privateKey: account.privateKey,
    userId: String(account.userId),
    watch,
    answer: guardAnswers(values),
  });
}

// ── Which vault ─────────────────────────────────────────────────────────────────────
// `-v <name or id>`, else the vault this project is linked to (`sharedenv link`). A name
// several of your vaults answer to is refused with the candidates (lib/safes.js).

const VAULT_OPTION = { vault: { type: 'string', short: 'v' } };

async function targetVault(client, values) {
  if (values.vault) return resolveSafe(client, values.vault);
  const link = findLink();
  if (link) return link.vault;
  throw new UsageError('which vault? pass -v <vault>, or run `sharedenv link` in this project');
}

// Said by every command that works on a vault: a link you did not write yourself (a
// cloned repository) may name another vault than the one you expect.
const using = (safe) => note(`sharedenv: vault "${printable(safe.name)}" (${safe._id})`);

// The link of this directory, for display only: a broken one is not an error here.
function linkedHere() {
  try {
    return findLink()?.vault ?? null;
  } catch {
    return null;
  }
}

const byName = (a, b) => (a.name || '').toLowerCase().localeCompare((b.name || '').toLowerCase());

// ── Trust ───────────────────────────────────────────────────────────────────────────

// A fingerprint as it is read aloud, and as a script or SHAREDENV_TRUSTED_SEALERS names it.
const spoken = (key) => `${fingerprintWords(key)} (${fingerprintOf(key)})`;

const SEAL_HINT = 'pass --yes, or --fingerprint <fingerprint> checked with them';
const CHANGED_HINT = 'pass --fingerprint <fingerprint>, checked with them';
const SEALER_HINT = 'list this fingerprint in SHAREDENV_TRUSTED_SEALERS, checked with them';
const TEAM_HINT = 'pass --team-fingerprint <fingerprint>, checked with a lead of the team';

// The guard's questions. A flag answers only where it applies (`scripted`): opening a vault
// has no --yes, it would take any key. Without a terminal, and without a flag, it is a no. A key
// never seen is never answered by --yes (sujet 7): the first trust comes from a person, once.
function guardAnswers(values) {
  return async ({ code, people }, { vault, team, scripted }, memory) => {
    if (code === 'TEAM_DEBT_SHARE') {
      note(message(code, { team }));
      return (
        values.yes ||
        confirm('Share anyway? [y/N] ', 'pass --yes, or wait for a lead to replace the key')
      );
    }
    const flags = scripted ? values : {};
    const moved = code === 'FIRST_SEAL_MOVED';
    const statusOf = (p) => (moved ? 'changed' : pinStatus(memory, p.subject || '', p.publicKey));
    const verdicts = people.map((p) => {
      const subject = p.subject || '';
      const status = statusOf(p);
      const fingerprint = fingerprintOf(p.publicKey);
      note(
        message(p.removed && code === 'NEW_SEALERS' ? 'NEW_SEALERS_REMOVED' : code, {
          person: printable(p.label || subject),
          vault,
          team,
          fingerprint: spoken(p.publicKey),
        })
      );
      if (code === 'TEAM_KEY_UNKNOWN') {
        return teamKeyVerdict(status, fingerprint, { expected: flags['team-fingerprint'] });
      }
      return senderVerdict(status, fingerprint, {
        expected: flags.fingerprint,
        acceptKeyChange: flags['accept-key-change'],
        yes: flags.yes,
      });
    });
    if (verdicts.includes('refuse')) {
      note(message('FINGERPRINT_MISMATCH'));
      return false;
    }
    if (verdicts.every((verdict) => verdict === 'accept')) return true;
    if (code === 'TEAM_KEY_UNKNOWN') return confirm('Trust this team key? [y/N] ', TEAM_HINT);
    if (code === 'NEW_SEALERS' && !scripted) return confirm('Trust their key? [y/N] ', SEALER_HINT);
    if (code === 'KEY_CHANGED' || moved) return confirm('Go on? [y/N] ', CHANGED_HINT);
    if (!process.stdin.isTTY && people.some((p) => statusOf(p) === 'new')) {
      note(message('FINGERPRINT_REQUIRED'));
      return false;
    }
    return confirm('Go on? [y/N] ', SEAL_HINT);
  };
}

// A key the caller named on the command line must be this one, known here or not.
const namedKey = (expected) => (key) => {
  if (!expected || sameFingerprint(expected, fingerprintOf(key))) return true;
  note(message('FINGERPRINT_MISMATCH'));
  return false;
};

// ── Commands: session ───────────────────────────────────────────────────────────────

async function cmdLogin({ values }) {
  const previous = store.readSession();
  const baseUrl = apiBase(
    values.api || process.env.SHAREDENV_API || previous?.baseUrl || DEFAULT_API
  );
  const identifier =
    values.identifier || process.env.SHAREDENV_IDENTIFIER || (await ask('Email or username: '));
  if (!identifier) {
    throw new UsageError(
      'no identifier: run in a terminal, or pass --identifier (or set SHAREDENV_IDENTIFIER)'
    );
  }
  const password = await masterPassword();
  // Same server: sign in as the same device, so the server replaces the session it had
  // for this machine instead of keeping a second one alive.
  const cookies = previous?.baseUrl === baseUrl ? previous.cookies : {};
  const client = createClient({ baseUrl, cookies, userAgent: USER_AGENT });
  const otp =
    process.env.SHAREDENV_OTP ||
    (async ({ sent, channel, hint, refused }) => {
      if (sent) {
        note(
          `A code was sent by ${channel === 'sms' ? 'text message' : 'email'}${hint ? ` to ${hint}` : ''}.`
        );
      } else if (refused) {
        note(`No code could be sent (${refused}). An authenticator or recovery code still works.`);
      }
      return ask('Two-factor code: ');
    });
  await login(client, { identifier, password, otp });
  // The vault opens: only then is anything kept. The server just accepted this password,
  // so a vault it does not open was sealed under the one before a reset.
  const account = await unlockClaimed(client, password).catch((err) => {
    throw err.code === 'CREDENTIALS_INVALID' ? new TrustRefusal('VAULT_SEALED') : err;
  });
  const userId = String(account.userId);
  store.writeSession({ baseUrl, cookies: client.cookies(), userId });
  note(`Signed in to ${baseUrl}.`);
  await watchKeys(client, account, store.forAccount(baseUrl, userId));
}

async function cmdLogout() {
  const session = store.readSession();
  if (!session?.baseUrl) {
    note('Not signed in.');
    return;
  }
  try {
    const client = createClient({
      baseUrl: apiBase(session.baseUrl),
      cookies: session.cookies,
      userAgent: USER_AGENT,
    });
    const res = await client.call('POST', '/auth/sign-out');
    if (res.status !== 401) expectOk(res, 'sign-out refused'); // 401: already over
    note('Signed out.');
  } catch (err) {
    note(
      `sharedenv: the server did not close the session (${err.message}) — it stays valid ` +
        'there until it expires. Forgotten on this machine.'
    );
    process.exitCode = 1;
  }
  store.clearSession();
}

// ── Commands: vaults ────────────────────────────────────────────────────────────────

// Names only: no password needed (vault and key names are stored in clear).
async function cmdVaults() {
  const client = connect();
  const vaults = (await listVaults(client)).sort(byName);
  const me = await whoAmI(client);
  const { direct, team } = await listPendingShares(client);
  const linked = linkedHere();
  const lines = [vaults.length ? 'Vaults:' : 'No vaults yet: sharedenv create <name>.'];
  for (const row of vaults) {
    lines.push(`  ${describeVault(row, me)}${String(row._id) === linked ? '  (linked here)' : ''}`);
  }
  const pendingName = (p) => ({ name: p.safe?.name });
  const keyOf = (p) => (p.from?.publicKey ? spoken(p.from.publicKey) : 'none on file');
  if (direct.length || team.length) {
    lines.push('', 'Waiting for your answer (sharedenv accept|decline <vault>):');
    for (const p of direct.sort((a, b) => byName(pendingName(a), pendingName(b)))) {
      lines.push(
        `  ${p.safe?.name}  ${p.safeId}  ${levelName(p.level)}  from ${senderLabel(p)}` +
          `  key ${keyOf(p)}`
      );
    }
    for (const p of team.sort((a, b) => byName(pendingName(a), pendingName(b)))) {
      lines.push(
        `  ${p.safe?.name}  ${p.safeId}  for team ${p.team?.name} (--team ${p.teamId})` +
          `  from ${senderLabel(p)}  key ${keyOf(p)}` +
          (p.provisioned ? '' : '  [you do not hold this team key yet]')
      );
    }
  }
  say(lines.join('\n'));
}

async function cmdCreate({ positionals: [name] }) {
  const client = connect();
  const trust = await unlock(client);
  const safe = await createVault(client, trust, name);
  note(`Created vault "${safe.name}". Use it in a project: sharedenv link ${safe._id}`);
  say(String(safe._id));
}

// No argument: the vaults are listed and you pick one.
async function cmdLink({ positionals: [ref] }) {
  const client = connect();
  const safeId = ref ? await resolveSafe(client, ref) : await pickVault(client);
  const { safe } = await readVault(client, safeId); // you can open it, and its name
  const file = writeLink(process.cwd(), safe._id);
  note(
    `Linked to vault "${safe.name}" (${safe._id}). ${file} holds its id and no secret: ` +
      'commit it, and your team works on the same vault.'
  );
}

async function pickVault(client) {
  const vaults = (await listVaults(client)).sort(byName);
  if (vaults.length === 0) throw new Error('no vault yet: sharedenv create <name>');
  if (!process.stdin.isTTY) {
    throw new UsageError('no terminal to choose in: name the vault, sharedenv link <vault>');
  }
  const me = await whoAmI(client);
  vaults.forEach((row, i) => note(`  ${i + 1}. ${describeVault(row, me)}`));
  const n = Number(await ask(`Vault to link (1-${vaults.length}): `));
  if (!Number.isInteger(n) || n < 1 || n > vaults.length) throw new UsageError('no vault chosen');
  return String(vaults[n - 1]._id);
}

// Names only, like `vaults`: no password needed.
async function cmdShow({ values }) {
  const client = connect();
  const safeId = await targetVault(client, values);
  const vault = await readVault(client, safeId);
  const { safe } = vault;
  const me = await whoAmI(client);
  const members = await listAll(client, `/members/${safeId}`, 'members');
  const keys = (await listSecretRows(client, safeId)).map((r) => r.key).sort();

  // Admins see every team the vault is shared with; others, the teams they reach it by.
  const teams = vault.grants
    ? vault.grants.map((g) => ({
        label: g.teamName || String(g.teamId),
        level: g.level,
        pending: g.status === 'pending',
      }))
    : (safe.teams || []).map((t) => ({
        label: teamLabel(t),
        level: (vault.teamAccess || []).find((a) => String(a.teamId) === String(t._id))?.level,
      }));

  const owner = me && String(safe.ownerId) === me ? 'you' : personLabel(safe.owner);
  const waiting = '  (has not accepted yet)';
  const lines = [
    `${safe.name}  ${safe._id}`,
    `Owner: ${owner}    Your access: ${levelName(accessOf(vault))}`,
    '',
    'Members:',
    ...members.map(
      (m) =>
        `  ${String(m.userId) === me ? 'you' : personLabel(m.user)}  ${levelName(m.level)}` +
        (m.status === 'pending' ? waiting : '')
    ),
    ...(teams.length
      ? [
          'Teams:',
          ...teams.map((t) => `  ${t.label}  ${levelName(t.level)}${t.pending ? waiting : ''}`),
        ]
      : []),
    keys.length ? `Keys (${keys.length}):` : 'No keys yet: sharedenv set <KEY>=<value>.',
    ...keys.map((key) => `  ${key}`),
  ];
  say(lines.join('\n'));
  if (safe.pendingRotation) {
    note(
      'This vault must change its key (someone lost access to it): until an admin opens it ' +
        'in the web app, nothing new can be written to it.'
    );
  }
  if (rotationUnfinished(vault)) {
    note(
      'A key rotation of this vault did not finish: until an admin finishes it in the web app, ' +
        'nothing new can be written to it.'
    );
  }
}

// ── Commands: keys ──────────────────────────────────────────────────────────────────

async function cmdGet({ values, positionals: [key] }) {
  const client = connect();
  const safeId = await targetVault(client, values);
  const { safe, value } = await readSecret(client, await unlock(client), safeId, key);
  using(safe);
  // Nothing added to the value in a pipe or a file; a newline for the terminal's prompt.
  process.stdout.write(process.stdout.isTTY ? `${value}\n` : value);
}

// KEY=value pairs, and at most one KEY alone, whose value is asked (hidden) or read
// from stdin — so that it lands neither in the shell's history nor in `ps`.
function parseAssignments(args) {
  const entries = [];
  let bare = null;
  for (const arg of args) {
    const eq = arg.indexOf('=');
    const key = eq < 0 ? arg : arg.slice(0, eq);
    if (!WRITABLE_NAME.test(key)) {
      throw new UsageError(
        `"${key}" is not a key name: capital letters, digits, _ and -, 2 characters at least`
      );
    }
    if (entries.some(([k]) => k === key) || bare === key) {
      throw new UsageError(`"${key}" is given twice`);
    }
    if (eq >= 0) entries.push([key, arg.slice(eq + 1)]);
    else if (bare) throw new UsageError('one key without a value at most: its value is asked');
    else bare = key;
  }
  return { entries, bare };
}

async function valueOf(key) {
  if (process.stdin.isTTY) {
    const value = await ask(`Value of ${key}: `, { secret: true });
    if (value === null || value === '') throw new UsageError(`no value for ${key}`);
    return value;
  }
  // Piped: what came in, without the newline `echo` or a file ends with.
  const value = (await readStdin()).replace(/\r?\n$/, '');
  if (value === '') throw new UsageError(`no value for ${key} on stdin (an empty one: ${key}=)`);
  return value;
}

async function cmdSet({ values, positionals }) {
  const { entries, bare } = parseAssignments(positionals);
  const client = connect();
  const safeId = await targetVault(client, values);
  using((await readVault(client, safeId)).safe); // before a value is asked, and anything written
  const trust = await unlock(client);
  if (bare) entries.push([bare, await valueOf(bare)]);
  const { added, replaced } = await setSecrets(client, trust, safeId, entries);
  note(
    [
      ...(added.length ? [`added ${added.join(', ')}`] : []),
      ...(replaced.length ? [`replaced ${replaced.join(', ')}`] : []),
    ].join('; ')
  );
}

async function cmdUnset({ values, positionals: keys }) {
  const client = connect();
  const safeId = await targetVault(client, values);
  const { safe } = await readVault(client, safeId);
  using(safe);
  await unsetSecrets(client, safeId, keys);
  note(`removed ${keys.join(', ')}`);
}

async function cmdRun({ values, command: [cmd, ...args] }) {
  const client = connect();
  const safeId = await targetVault(client, values);
  const { safe: vault, secrets } = await pullSecrets(client, await unlock(client), safeId);
  using(vault);
  const { safe, blocked, kept } = splitUnsafeEnv(secrets, {
    base: process.env,
    allowUnsafe: values['allow-unsafe-env'],
    override: values['override-env'],
  });
  if (blocked.length) {
    note(
      `sharedenv: not injecting ${blocked.sort().join(', ')} — these variables can make the ` +
        'command run code or redirect its traffic (--allow-unsafe-env to inject them anyway).'
    );
  }
  if (kept.length) {
    note(
      `sharedenv: not overriding ${kept.sort().join(', ')} — your environment already sets ` +
        'them (--override-env to let the vault replace them).'
    );
  }
  saveSession(); // the command may run for days
  process.exitCode = await runChild(cmd, args, childEnv(process.env, safe));
}

async function cmdPull({ values }) {
  const render = FORMATS[values.format];
  if (!render) throw new UsageError(`unknown format "${values.format}": dotenv or json`);
  const client = connect();
  const safeId = await targetVault(client, values);
  const { safe, secrets } = await pullSecrets(client, await unlock(client), safeId);
  using(safe);
  const body = render(secrets);
  const text = body ? `${body}\n` : '';
  if (values.out) {
    writePrivate(values.out, text);
    note(`Wrote ${Object.keys(secrets).length} secrets to ${values.out}.`);
  } else {
    process.stdout.write(text);
  }
}

// ── Commands: sharing ───────────────────────────────────────────────────────────────

function levelOf(values) {
  const chosen = Object.keys(LEVELS).filter((name) => values[name]);
  if (chosen.length > 1) throw new UsageError('one of --read, --write, --admin');
  return LEVELS[chosen[0] || 'read'];
}

async function cmdShare({ values, positionals: [email] }) {
  if (Boolean(email) === Boolean(values.team)) {
    throw new UsageError('share with a person (an email) or a team (--team <team>), one of them');
  }
  if (values.team && (values.fingerprint || values['accept-key-change'])) {
    throw new UsageError('--team: the key of a team is checked with --team-fingerprint');
  }
  if (email && values['team-fingerprint']) {
    throw new UsageError('--team-fingerprint goes with --team');
  }
  const level = levelOf(values);
  const client = connect();
  const safeId = await targetVault(client, values);
  const trust = await unlock(client, values);
  const vault = await openVaultToWrite(client, trust, safeId);
  using(vault.safe);

  if (values.team) {
    const team = await resolveTeam(client, values.team);
    const status = await shareWithTeam(client, trust, vault, team, level, {
      check: namedKey(values['team-fingerprint']),
    });
    if (!status) {
      note('Not shared.');
      process.exitCode = 1;
      return;
    }
    note(
      `Shared with team ${teamLabel(team)} (${levelName(level)}).` +
        (status === 'pending' ? ' It waits for a lead of the team to accept it.' : '')
    );
    return;
  }

  const person = await lookupPerson(client, email);
  const who = person.username ? `${printable(person.username)} (${email})` : email;
  note(`Sharing "${printable(vault.safe.name)}" with ${who}`);
  const decision =
    namedKey(values.fingerprint)(person.publicKey) &&
    (await trust.sealTo({
      person: {
        subject: `user:${person.userId}`,
        publicKey: person.publicKey,
        label: who,
        address: email,
      },
      context: { vault: printable(vault.safe.name), scripted: true },
    }));
  if (!decision) {
    note('Not shared.');
    process.exitCode = 1;
    return;
  }
  const status = await shareWithPerson(client, trust, vault, person, level, decision.people);
  note(
    `Shared with ${who} (${levelName(level)}).` +
      (status === 'pending' ? ' It waits for their answer: sharedenv accept, on their side.' : '')
  );
}

async function cmdAccept({ values, positionals: [ref] }) {
  const client = connect();
  const { safeId, teamId } = await resolvePendingShare(client, ref, values.team);
  const trust = await unlock(client, values);
  const check = namedKey(values.fingerprint);
  const result = teamId
    ? await acceptTeamShare(client, trust, teamId, safeId, { check })
    : await acceptShare(client, trust, safeId, { check });
  note(result.accepted ? 'Accepted.' : 'Left pending.');
  if (!result.accepted) process.exitCode = 1;
}

async function cmdDecline({ values, positionals: [ref] }) {
  const client = connect();
  const { safeId, teamId } = await resolvePendingShare(client, ref, values.team);
  if (teamId) await declineTeamShare(client, teamId, safeId);
  else await declineShare(client, safeId);
  note('Declined.');
}

async function cmdTeams() {
  const client = connect();
  const teams = await listTeams(client);
  if (teams.length === 0) {
    say('No team yet: teams are made on the web app.');
    return;
  }
  const lines = [];
  const orgs = new Map();
  for (const team of teams) {
    const key = String(team.org._id);
    if (!orgs.has(key)) orgs.set(key, { org: team.org, teams: [] });
    orgs.get(key).teams.push(team);
  }
  for (const { org, teams: rows } of orgs.values()) {
    lines.push(`${org.name}  ${org._id}`);
    for (const t of rows.sort(byName)) {
      const count = t.memberCount === undefined ? '' : `  ${t.memberCount} member(s)`;
      lines.push(`  ${t.name}  ${t._id}${count}`);
    }
  }
  say(lines.join('\n'));
}

// ── Commands: trust ─────────────────────────────────────────────────────────────────

// Derived from YOUR private key, never the server's copy: the value a teammate checks a
// key against must not be one the server chose. The six words for a person, on stderr; the hex
// on stdout, for a script.
async function cmdFingerprint({ values }) {
  const client = connect();
  const trust = await unlock(client);
  let key = publicKeyOf(trust.privateKey);
  if (values.team) {
    const team = await resolveTeam(client, values.team);
    note(`sharedenv: team ${teamLabel(team)} (${team._id})`);
    key = await teamKeyToCompare(client, trust, team);
  }
  note(fingerprintWords(key));
  say(fingerprintOf(key));
}

// What the public key log check found on this machine and nobody acknowledged yet. Read
// from what is kept, without the network: the warnings are the data (stdout).
function cmdLog({ values }) {
  const session = store.readSession();
  if (!session?.baseUrl) throw new Error('not signed in — run `sharedenv login`');
  const kept = session.userId && store.forAccount(session.baseUrl, session.userId);
  const alerts = !kept ? [] : values.ack ? acknowledgeAlerts(kept) : keptAlerts(kept);
  if (alerts.length === 0) {
    note('No warning from the public key log on this machine.');
    return;
  }
  const lines = watchWarnings({ alerts });
  say(lines.slice(0, -1).join('\n'));
  note(
    values.ack
      ? 'Acknowledged: a warning that is still true comes back at the next unlock.'
      : lines[lines.length - 1]
  );
}

// ── The catalogue ───────────────────────────────────────────────────────────────────
// `positionals`: [min, max]. `takesCommand`: what follows `--` is the command to run.

const TRUST_OPTIONS = {
  yes: { type: 'boolean', short: 'y' },
  fingerprint: { type: 'string' },
  'accept-key-change': { type: 'boolean' },
};

const VAULT_DETAIL =
  'The vault: -v <name or id>, or the one this project is linked to (sharedenv link).';

const SEALER_DETAIL =
  'A key to the vault sealed by someone unknown here is shown and asked about, once. Without\n' +
  'a terminal it is refused, unless SHAREDENV_TRUSTED_SEALERS lists its fingerprint.';

const COMMANDS = {
  login: {
    group: 'Session',
    usage: 'login [--api <url>] [--identifier <email or username>]',
    summary: 'Sign in (keeps the session cookies only)',
    details:
      'Asks for what is missing. Without a terminal, nothing is asked: give --identifier\n' +
      '(or SHAREDENV_IDENTIFIER), SHAREDENV_PASSWORD, and SHAREDENV_OTP if the account\n' +
      'has a second factor.',
    options: { api: { type: 'string' }, identifier: { type: 'string' } },
    positionals: [0, 0],
    run: cmdLogin,
  },
  logout: {
    group: 'Session',
    usage: 'logout',
    summary: 'Close the session, on the server and here',
    options: {},
    positionals: [0, 0],
    run: cmdLogout,
  },
  vaults: {
    group: 'Vaults',
    usage: 'vaults',
    summary: 'Your vaults, and the shares waiting for your answer',
    details:
      'Each vault with its id, your access, its owner and the teams you reach it through:\n' +
      'what tells two vaults of the same name apart. No password asked.',
    options: {},
    positionals: [0, 0],
    run: cmdVaults,
  },
  create: {
    group: 'Vaults',
    usage: 'create <name>',
    summary: 'Create a vault (prints its id)',
    options: {},
    positionals: [1, 1],
    run: cmdCreate,
  },
  link: {
    group: 'Vaults',
    usage: 'link [<vault>]',
    summary: `Link this directory to a vault (${LINK_FILE})`,
    details:
      `Writes ${LINK_FILE} here: the vault's id, no secret. Every command run in this\n` +
      'directory or below then works on that vault without -v. Commit the file and your\n' +
      'team works on the same vault. Without <vault>, you pick one from the list.',
    options: {},
    positionals: [0, 1],
    run: cmdLink,
  },
  show: {
    group: 'Vaults',
    usage: 'show [-v <vault>]',
    summary: 'The vault: owner, members, teams, and the names of its keys',
    details: `${VAULT_DETAIL}\nNames only, never a value: no password asked.`,
    options: VAULT_OPTION,
    positionals: [0, 0],
    run: cmdShow,
  },
  get: {
    group: 'Keys',
    usage: 'get <KEY> [-v <vault>]',
    summary: 'Print the value of one key',
    details:
      `${VAULT_DETAIL}\n${SEALER_DETAIL}\n` +
      'The value is printed as is: nothing added in a pipe or a file, a newline in a terminal.',
    options: VAULT_OPTION,
    positionals: [1, 1],
    run: cmdGet,
  },
  set: {
    group: 'Keys',
    usage: 'set <KEY>=<value>... [<KEY>] [-v <vault>]',
    summary: 'Add or replace keys',
    details:
      `${VAULT_DETAIL}\n${SEALER_DETAIL}\n` +
      'A <KEY> given without a value has its value asked without echo, or read from stdin\n' +
      '(`sharedenv set TLS_CERT < cert.pem`): it lands neither in your shell history nor in\n' +
      'the process list. Values are encrypted here before they leave.',
    options: VAULT_OPTION,
    positionals: [1, Infinity],
    run: cmdSet,
  },
  unset: {
    group: 'Keys',
    usage: 'unset <KEY>... [-v <vault>]',
    summary: 'Remove keys',
    details: `${VAULT_DETAIL}\nEvery key must exist, or none is removed. No password asked.`,
    options: VAULT_OPTION,
    positionals: [1, Infinity],
    run: cmdUnset,
  },
  run: {
    group: 'Keys',
    usage: 'run [-v <vault>] [--allow-unsafe-env] [--override-env] -- <command> [args...]',
    summary: 'Run a command with the keys in its environment',
    details:
      `${VAULT_DETAIL}\n${SEALER_DETAIL}\n` +
      'The secrets reach the command in memory, never on disk. Held back unless asked:\n' +
      'variables that make the command run code or redirect its traffic (LD_*, PATH,\n' +
      'NODE_OPTIONS, *_PROXY...: --allow-unsafe-env), and variables your environment\n' +
      "already sets (--override-env). The exit code is the command's.",
    options: {
      ...VAULT_OPTION,
      'allow-unsafe-env': { type: 'boolean' },
      'override-env': { type: 'boolean' },
    },
    positionals: [0, 0],
    takesCommand: true,
    run: cmdRun,
  },
  pull: {
    group: 'Keys',
    usage: 'pull [-v <vault>] [--out <file>] [--format dotenv|json]',
    summary: 'Print or write every key, as a .env or JSON',
    details:
      `${VAULT_DETAIL}\n${SEALER_DETAIL}\n` +
      '--out writes the file readable by you only. A dotenv file is safe to source in a\n' +
      'shell: values are quoted so that none is expanded.',
    options: {
      ...VAULT_OPTION,
      out: { type: 'string' },
      format: { type: 'string', default: 'dotenv' },
    },
    positionals: [0, 0],
    run: cmdPull,
  },
  share: {
    group: 'Sharing',
    usage:
      'share <email> | --team <team>  [--read|--write|--admin] [-v <vault>]\n' +
      '                 [--yes] [--fingerprint <fp>] [--accept-key-change] [--team-fingerprint <fp>]',
    summary: 'Share the vault with a person or one of your teams',
    details:
      `${VAULT_DETAIL}\n${SEALER_DETAIL}\n` +
      'Read access unless --write or --admin. A person: their key fingerprint is shown and\n' +
      'asked about, as for accept (compare it with them). In a script, a key never seen here\n' +
      'needs --fingerprint: --yes is not enough; --accept-key-change takes a key that differs\n' +
      'from the one known here. The share then waits for their answer.\n' +
      '--team: a team you are a member of (name or id, see `sharedenv teams`); if its key\n' +
      'must be confirmed, only a human or --team-fingerprint can; a key someone who left still\n' +
      "holds is asked about (--yes shares anyway). Removing someone's access changes the\n" +
      "vault's key: that is done in the web app.",
    options: {
      ...VAULT_OPTION,
      ...TRUST_OPTIONS,
      team: { type: 'string' },
      'team-fingerprint': { type: 'string' },
      read: { type: 'boolean' },
      write: { type: 'boolean' },
      admin: { type: 'boolean' },
    },
    positionals: [0, 1],
    run: cmdShare,
  },
  accept: {
    group: 'Sharing',
    usage:
      'accept <vault> [--team <team>] [--yes] [--fingerprint <fp>] [--accept-key-change]\n' +
      '                 [--team-fingerprint <fp>]',
    summary: 'Accept a share after checking who sealed it',
    details:
      "Shows the sender and their key's fingerprint, and asks. --yes: no question for a key\n" +
      'already known here, never for a new one. --fingerprint: accept only if the key is this\n' +
      'one. --accept-key-change: take a key that differs from the one known here. --team:\n' +
      'a share to a team you lead (name or id); if its key must be confirmed, only a human\n' +
      'or --team-fingerprint can.',
    options: { ...TRUST_OPTIONS, team: { type: 'string' }, 'team-fingerprint': { type: 'string' } },
    positionals: [1, 1],
    run: cmdAccept,
  },
  decline: {
    group: 'Sharing',
    usage: 'decline <vault> [--team <team>]',
    summary: 'Decline a share',
    options: { team: { type: 'string' } },
    positionals: [1, 1],
    run: cmdDecline,
  },
  teams: {
    group: 'Sharing',
    usage: 'teams',
    summary: 'Your organizations and their teams',
    details: 'Teams and organizations are managed in the web app.',
    options: {},
    positionals: [0, 0],
    run: cmdTeams,
  },
  fingerprint: {
    group: 'Trust',
    usage: 'fingerprint [--team <team>]',
    summary: 'Your public-key fingerprint, or a team key you hold, to read to a teammate',
    details:
      'Six words to read aloud, on stderr, and the hexadecimal on stdout: --fingerprint,\n' +
      '--team-fingerprint and SHAREDENV_TRUSTED_SEALERS take either. --team: a team you are a member\n' +
      'of (name or id), from the key sealed to you, never from what the server says of it.',
    options: { team: { type: 'string' } },
    positionals: [0, 0],
    run: cmdFingerprint,
  },
  log: {
    group: 'Trust',
    usage: 'log [--ack]',
    summary: 'Warnings from the public key log, kept until acknowledged',
    details:
      'Each unlock checks that the keys the public key log holds for you and for your teams\n' +
      'are the ones you hold. What it finds is kept on this machine and repeated at every\n' +
      'unlock. --ack: you have read them (and told SharedEnv); a warning that is still\n' +
      'true comes back at the next unlock.',
    options: { ack: { type: 'boolean' } },
    positionals: [0, 0],
    run: cmdLog,
  },
};

function commandList() {
  const groups = new Map();
  for (const [name, c] of Object.entries(COMMANDS)) {
    if (!groups.has(c.group)) groups.set(c.group, []);
    groups.get(c.group).push(`  ${name.padEnd(12)} ${c.summary}`);
  }
  return [...groups].map(([group, lines]) => `${group}:\n${lines.join('\n')}`).join('\n\n');
}

const HELP = `sharedenv ${VERSION} — zero-knowledge secrets, decrypted locally

Usage: sharedenv <command> [options]

Commands:

${commandList()}

A command works on the vault named by -v <name or id>, or on the one the current
directory is linked to (sharedenv link). Run \`sharedenv help <command>\` for its options.

Environment:
  SHAREDENV_API              API URL (default ${DEFAULT_API})
  SHAREDENV_IDENTIFIER       email or username, for a login without questions
  SHAREDENV_PASSWORD         master password, for commands without questions
  SHAREDENV_OTP              second-factor code, for a login without questions
  SHAREDENV_TRUSTED_SEALERS  fingerprints allowed to have sealed a vault's key, comma separated
  SHAREDENV_HOME             where the session and what this machine learned about keys live
                             (default ~/.sharedenv)`;

function commandHelp(name) {
  const command = COMMANDS[name];
  if (!command) throw new UsageError(`unknown command "${name}" — see \`sharedenv help\``);
  return [`Usage: sharedenv ${command.usage}`, '', command.summary + '.', command.details]
    .filter((line) => line !== undefined)
    .join('\n');
}

async function main(argv) {
  const [name, ...rest] = argv;
  if (!name || name === 'help' || name === '-h' || name === '--help') {
    return say(name === 'help' && rest[0] ? commandHelp(rest[0]) : HELP);
  }
  if (name === 'version' || name === '--version') return say(VERSION);

  const command = COMMANDS[name];
  if (!command) throw new UsageError(`unknown command "${name}" — see \`sharedenv help\``);
  const sep = rest.indexOf('--');
  const own = command.takesCommand && sep >= 0 ? rest.slice(0, sep) : rest;
  if (own.includes('-h') || own.includes('--help')) return say(commandHelp(name));

  let parsed;
  try {
    parsed = parseArgs({ args: own, options: command.options, allowPositionals: true });
  } catch (err) {
    throw new UsageError(`${err.message.split('. ')[0]} — see \`sharedenv help ${name}\``);
  }
  const shell = command.takesCommand ? rest.slice(sep + 1) : [];
  const [min, max] = command.positionals;
  const count = parsed.positionals.length;
  if (count < min || count > max || (command.takesCommand && (sep < 0 || shell.length === 0))) {
    throw new UsageError(`usage: sharedenv ${command.usage}`);
  }
  try {
    await command.run({ values: parsed.values, positionals: parsed.positionals, command: shell });
  } finally {
    saveSession();
  }
}

main(process.argv.slice(2)).catch((err) => {
  note(`sharedenv: ${err.message}`);
  process.exitCode = err.exitCode ?? 1;
});
