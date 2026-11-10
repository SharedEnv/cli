// What the CLI keeps on disk, under ~/.sharedenv (or $SHAREDENV_HOME): the session cookies,
// and for each server then each account its memory (lib/crypto/trust/memory.js: the versions
// seen, who sealed them, the people vouched for, how far the public key log was checked). Never
// the password, never a private key, never a secret.

import { createHash, randomBytes } from 'crypto';
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from 'fs';
import { homedir } from 'os';
import { basename, dirname, join } from 'path';
import { claimOwnKey, mergeMemory, readMemory, readOwnKeys } from './crypto.js';

// Writes `data` to `file`, readable by its owner only. Through a fresh temporary file
// then a rename: the target is never readable by others, not even for an instant (an
// existing .env is often 0644), a symlink planted at its path is replaced rather than
// followed, and a crash never leaves half a file.
export function writePrivate(file, data, mode = 0o600) {
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx', mode);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, file);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

function readText(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function readJson(file) {
  try {
    return JSON.parse(readText(file));
  } catch {
    return null;
  }
}

const saveJson = (dir, file, value) => {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writePrivate(file, `${JSON.stringify(value, null, 2)}\n`);
};

// The account id names a folder, and it comes from the server.
const ACCOUNT = /^[0-9a-f]{24}$/;
const serverOf = (baseUrl) => createHash('sha256').update(baseUrl).digest('hex').slice(0, 16);

export function createStore(dir = process.env.SHAREDENV_HOME || join(homedir(), '.sharedenv')) {
  const sessionFile = join(dir, 'session.json');

  return {
    dir,
    // → { baseUrl, cookies, userId? } | null
    readSession: () => readJson(sessionFile),
    writeSession: (session) => saveJson(dir, sessionFile, session),
    clearSession: () => rmSync(sessionFile, { force: true }),
    // Before an account's memory is opened on the server's word: the account this machine knows
    // for the key it derived, apart from any account's folder. → whether this account may go on.
    claimOwnKey(baseUrl, publicKey, userId) {
      if (userId && !ACCOUNT.test(String(userId))) {
        throw new Error('the server named an unusable account');
      }
      const folder = join(dir, 'servers', serverOf(baseUrl));
      const file = join(folder, 'own-keys.json');
      const owners = readOwnKeys(readText(file));
      const kept = claimOwnKey(owners, publicKey, userId);
      if (!kept) return false;
      if (kept !== owners) saveJson(folder, file, kept);
      return true;
    },
    // What this machine knows, for one account on one server: nothing crosses over.
    forAccount(baseUrl, userId) {
      if (!ACCOUNT.test(String(userId))) throw new Error('the server named an unusable account');
      const folder = join(dir, 'servers', serverOf(baseUrl), String(userId));
      const file = join(folder, 'memory.json');
      const read = () => readMemory(readText(file), String(userId));
      const write = (memory) => saveJson(folder, file, memory);
      return {
        file,
        readMemory: read,
        // Another process may have written since: both are kept (the memory only grows). The
        // log is not merged: the record on disk is the one syncLog last wrote.
        commit(inHand) {
          const onDisk = read();
          const merged = mergeMemory({ ...inHand, log: onDisk.log }, onDisk);
          write(merged);
          return merged;
        },
        // → { seq, hash, latest, alerts, ... } | null: the public key log, as far as it was checked
        readLogView: () => read().log,
        writeLogView: (view) => write({ ...read(), log: view }),
      };
    },
  };
}
