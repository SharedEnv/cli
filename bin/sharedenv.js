#!/usr/bin/env node
// sharedenv — pull and run with your zero-knowledge secrets, decrypted locally. The
// master password and the private key never leave this process and never touch disk;
// only the session cookies and the public keys you vouched for are kept (~/.sharedenv).
//
// This file is the terminal: arguments, questions, output, exit codes. What happens to
// keys and secrets lives in ../lib.

import { readFileSync } from 'fs';
import readline from 'readline';
import { Writable } from 'stream';
import { parseArgs } from 'util';
import { fingerprintOf } from '../lib/crypto.js';
import { apiBase, createClient, expectOk, listAll } from '../lib/api.js';
import { login, publicKeyOf, unlockAccount } from '../lib/auth.js';
import { syncLog, watchWarnings } from '../lib/transparency.js';
import { childEnv, splitUnsafeEnv } from '../lib/env.js';
import { FORMATS } from '../lib/format.js';
import { runChild } from '../lib/run.js';
import { pullSecrets, resolveSafe } from '../lib/safes.js';
import {
  acceptShare,
  acceptTeamShare,
  declineShare,
  declineTeamShare,
  listPendingShares,
  resolvePendingShare,
  senderLabel,
} from '../lib/shares.js';
import { createStore, writePrivate } from '../lib/store.js';
import { pinKey, pinStatus, senderVerdict, teamKeyVerdict } from '../lib/trust.js';

const { version: VERSION } = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
);
const DEFAULT_API = 'https://api.sharedenv.com';
const USER_AGENT = `sharedenv-cli/${VERSION}`;
const LEVEL = { 10: 'read', 50: 'write', 90: 'admin' };

const store = createStore();

// ── Terminal ────────────────────────────────────────────────────────────────────────
// Questions and notices go to stderr: stdout carries data only, so
// `sharedenv pull prod > .env` writes the secrets and nothing else.

const say = (text) => process.stdout.write(`${text}\n`);
const note = (text) => process.stderr.write(`${text}\n`);

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
  const cookies = connected.client.cookies();
  if (JSON.stringify(cookies) === JSON.stringify(connected.session.cookies)) return;
  store.writeSession({ baseUrl: connected.client.baseUrl, cookies });
  connected.session.cookies = cookies;
}

// Each time the vault opens: is the key the public log holds for us still ours? A
// warning, never a refusal - reading your own secrets seals nothing to anyone.
async function watchOwnKey(client, { privateKey, userId }) {
  try {
    const report = await syncLog(client, {
      store,
      watch: { [`user:${userId}`]: publicKeyOf(privateKey) },
    });
    for (const line of watchWarnings(report)) note(line);
  } catch (err) {
    note(`WARNING: ${err.message}.`);
  }
}

async function unlock() {
  const client = connect();
  const account = await unlockAccount(client, await masterPassword());
  await watchOwnKey(client, account);
  return { client, privateKey: account.privateKey };
}

// ── Commands ────────────────────────────────────────────────────────────────────────

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
  const otp = async () => process.env.SHAREDENV_OTP || (await ask('Two-factor code: '));
  await login(client, { identifier, password, otp });
  const account = await unlockAccount(client, password); // the vault opens: only then is anything kept
  store.writeSession({ baseUrl, cookies: client.cookies() });
  note(`Signed in to ${baseUrl}.`);
  await watchOwnKey(client, account);
}

async function cmdPull({ values, positionals: [ref] }) {
  const render = FORMATS[values.format];
  if (!render) throw new UsageError(`unknown format "${values.format}": dotenv or json`);
  const { client, privateKey } = await unlock();
  const secrets = await pullSecrets(client, privateKey, await resolveSafe(client, ref));
  const body = render(secrets);
  const text = body ? `${body}\n` : '';
  if (values.out) {
    writePrivate(values.out, text);
    note(`Wrote ${Object.keys(secrets).length} secrets to ${values.out}.`);
  } else {
    process.stdout.write(text);
  }
}

async function cmdRun({ values, positionals: [ref], command: [cmd, ...args] }) {
  const { client, privateKey } = await unlock();
  const pulled = await pullSecrets(client, privateKey, await resolveSafe(client, ref));
  const { safe, blocked, kept } = splitUnsafeEnv(pulled, {
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

async function cmdList() {
  const client = connect();
  const nameOf = (row) => (row.safe?.name ?? row.name ?? '').toLowerCase();
  const byName = (a, b) => nameOf(a).localeCompare(nameOf(b));
  const safes = (await listAll(client, '/safes', 'safes')).sort(byName);
  const { direct, team } = await listPendingShares(client);
  const lines = [safes.length ? 'Vaults:' : 'No vaults yet.'];
  for (const s of safes) {
    const via = Array.isArray(s.via) && !s.via.includes('direct') ? '  (via team)' : '';
    lines.push(`  ${s.name}  ${s._id}  ${LEVEL[s.level] || s.level}${via}`);
  }
  if (direct.length || team.length) {
    lines.push('', 'Waiting for your answer (sharedenv accept|decline <vault>):');
    for (const p of direct.sort(byName)) {
      lines.push(
        `  ${p.safe?.name}  ${p.safeId}  ${LEVEL[p.level] || p.level}  from ${senderLabel(p)}` +
          `  key ${p.fingerprint || 'none on file'}`
      );
    }
    for (const p of team.sort(byName)) {
      lines.push(
        `  ${p.safe?.name}  ${p.safeId}  for team ${p.team?.name} (--team ${p.teamId})` +
          `  from ${senderLabel(p)}  key ${p.fingerprint || 'none on file'}` +
          (p.provisioned ? '' : '  [you do not hold this team key yet]')
      );
    }
  }
  say(lines.join('\n'));
}

// A team share sealed to the team's PREVIOUS key moves to its current key on accept.
// Unless we sealed that key ourselves, it must be the one this machine knows for the
// team, or its fingerprint is confirmed — by a human, or by --team-fingerprint.
async function confirmTeamKey(pins, { share, teamPublicKey }, values) {
  const subject = `team:${share.teamId}`;
  const status = pinStatus(pins, subject, teamPublicKey);
  const fingerprint = fingerprintOf(teamPublicKey);
  const verdict = teamKeyVerdict(status, fingerprint, { expected: values['team-fingerprint'] });
  if (verdict !== 'accept') {
    note(
      `  The share moves to the current key of team "${share.team?.name || share.teamId}", ` +
        `fingerprint ${fingerprint}` +
        (status === 'changed'
          ? `; this machine knew ANOTHER key for it (${fingerprintOf(pins[subject])}).`
          : ', never seen on this machine.')
    );
  }
  if (verdict === 'refuse') {
    note('  That is not the --team-fingerprint you gave.');
    return false;
  }
  if (
    verdict === 'ask' &&
    !(await confirm(
      'Trust this team key? Confirm it with a lead of the team first. [y/N] ',
      'pass --team-fingerprint <fingerprint>, checked with a lead of the team'
    ))
  ) {
    return false;
  }
  pinKey(pins, subject, teamPublicKey);
  return true;
}

// The human step of `accept`: who sealed the share, with what key, as this machine
// knows it — then yes or no. A key that CHANGED since it was pinned is never taken
// without an explicit yes (or --accept-key-change).
function confirmShare(values) {
  return async (opened) => {
    const { share, senderKey, fingerprint } = opened;
    const pins = store.readPins();
    const subject = `user:${share.from?._id}`;
    const status = pinStatus(pins, subject, senderKey);
    note(`"${share.safe?.name}" from ${senderLabel(share)}`);
    note(
      `  key fingerprint ${fingerprint}${status === 'match' ? '  (known on this machine)' : ''}`
    );
    if (status === 'changed') {
      note(
        `  WARNING: this machine knew ANOTHER key for ${senderLabel(share)} ` +
          `(${fingerprintOf(pins[subject])}). It changes only if they reset their keyring.`
      );
    } else if (status === 'new') {
      note('  First time this machine sees this key: compare it with them.');
    }
    const verdict = senderVerdict(status, fingerprint, {
      expected: values.fingerprint,
      acceptKeyChange: values['accept-key-change'],
      yes: values.yes,
    });
    if (verdict === 'refuse') {
      note('  That is not the --fingerprint you gave.');
      return false;
    }
    if (
      verdict === 'ask' &&
      !(await confirm(
        status === 'changed'
          ? 'Accept their NEW key? Confirm it with them first. [y/N] '
          : 'Accept this share? [y/N] ',
        status === 'changed'
          ? 'pass --fingerprint <fingerprint>, checked with them'
          : 'pass --yes, or --fingerprint <fingerprint> checked with them'
      ))
    ) {
      return false;
    }
    if (opened.teamKeyVouched === false && !(await confirmTeamKey(pins, opened, values))) {
      return false;
    }
    store.writePins(pinKey(pins, subject, senderKey));
    return true;
  };
}

async function cmdAccept({ values, positionals: [ref] }) {
  const { client, privateKey } = await unlock();
  const safeId = await resolvePendingShare(client, ref, values.team);
  const confirm = confirmShare(values);
  const log = { store };
  const result = values.team
    ? await acceptTeamShare(client, privateKey, values.team, safeId, { confirm, log })
    : await acceptShare(client, privateKey, safeId, { confirm, log });
  note(result.accepted ? 'Accepted.' : 'Left pending.');
}

async function cmdDecline({ values, positionals: [ref] }) {
  const client = connect();
  const safeId = await resolvePendingShare(client, ref, values.team);
  if (values.team) await declineTeamShare(client, values.team, safeId);
  else await declineShare(client, safeId);
  note('Declined.');
}

// Derived from YOUR private key, never the server's copy: the value a teammate checks a
// key against must not be one the server chose.
async function cmdFingerprint() {
  const { privateKey } = await unlock();
  say(fingerprintOf(publicKeyOf(privateKey)));
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

const COMMANDS = {
  login: {
    usage: 'login [--api <url>] [--identifier <email or username>]',
    summary: 'Sign in (keeps the session cookies only)',
    details:
      'Asks for what is missing. Without a terminal, nothing is asked: give --identifier\n' +
      '(or SHAREDENV_IDENTIFIER), SHAREDENV_PASSWORD, and SHAREDENV_OTP if the account\n' +
      'has a second factor.',
    options: { api: { type: 'string' }, identifier: { type: 'string' } },
    positionals: 0,
    run: cmdLogin,
  },
  pull: {
    usage: 'pull <vault> [--out <file>] [--format dotenv|json]',
    summary: 'Print or write the decrypted secrets',
    details:
      '<vault> is a vault name or id. --out writes the file readable by you only. A dotenv\n' +
      'file is safe to source in a shell: values are quoted so that none is expanded.',
    options: { out: { type: 'string' }, format: { type: 'string', default: 'dotenv' } },
    positionals: 1,
    run: cmdPull,
  },
  run: {
    usage: 'run <vault> [--allow-unsafe-env] [--override-env] -- <command> [args...]',
    summary: 'Run a command with the secrets in its environment',
    details:
      'The secrets reach the command in memory, never on disk. Held back unless asked:\n' +
      'variables that make the command run code or redirect its traffic (LD_*, PATH,\n' +
      'NODE_OPTIONS, *_PROXY...: --allow-unsafe-env), and variables your environment\n' +
      "already sets (--override-env). The exit code is the command's.",
    options: { 'allow-unsafe-env': { type: 'boolean' }, 'override-env': { type: 'boolean' } },
    positionals: 1,
    takesCommand: true,
    run: cmdRun,
  },
  list: {
    usage: 'list',
    summary: 'Your vaults, then the shares waiting for your answer',
    options: {},
    positionals: 0,
    run: cmdList,
  },
  accept: {
    usage:
      'accept <vault> [--team <id>] [--yes] [--fingerprint <fp>] [--accept-key-change]\n' +
      '                 [--team-fingerprint <fp>]',
    summary: 'Accept a share after checking who sealed it',
    details:
      "Shows the sender and their key's fingerprint, and asks. --yes: no question for a key\n" +
      'that is new or already known here. --fingerprint: accept only if the key is this\n' +
      'one. --accept-key-change: take a key that differs from the one known here. --team:\n' +
      'a share to a team you lead; if its key must be confirmed, only a human or\n' +
      '--team-fingerprint can.',
    options: {
      team: { type: 'string' },
      yes: { type: 'boolean', short: 'y' },
      fingerprint: { type: 'string' },
      'accept-key-change': { type: 'boolean' },
      'team-fingerprint': { type: 'string' },
    },
    positionals: 1,
    run: cmdAccept,
  },
  decline: {
    usage: 'decline <vault> [--team <id>]',
    summary: 'Decline a share',
    options: { team: { type: 'string' } },
    positionals: 1,
    run: cmdDecline,
  },
  fingerprint: {
    usage: 'fingerprint',
    summary: 'Your public-key fingerprint, to read to a teammate',
    options: {},
    positionals: 0,
    run: cmdFingerprint,
  },
  logout: {
    usage: 'logout',
    summary: 'Close the session, on the server and here',
    options: {},
    positionals: 0,
    run: cmdLogout,
  },
};

const HELP = `sharedenv ${VERSION} — zero-knowledge secrets, decrypted locally

Usage: sharedenv <command> [options]

Commands:
${Object.entries(COMMANDS)
  .map(([name, c]) => `  ${name.padEnd(12)} ${c.summary}`)
  .join('\n')}

Run \`sharedenv help <command>\` for its options.

Environment:
  SHAREDENV_API         API URL (default ${DEFAULT_API})
  SHAREDENV_IDENTIFIER  email or username, for a login without questions
  SHAREDENV_PASSWORD    master password, for commands without questions
  SHAREDENV_OTP         second-factor code, for a login without questions
  SHAREDENV_HOME        where the session and the pinned keys live (default ~/.sharedenv)`;

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
  if (name === 'version' || name === '--version' || name === '-v') return say(VERSION);

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
  if (
    parsed.positionals.length !== command.positionals ||
    (command.takesCommand && (sep < 0 || shell.length === 0))
  ) {
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
