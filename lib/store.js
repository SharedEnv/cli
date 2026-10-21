// What the CLI keeps on disk, under ~/.sharedenv (or $SHAREDENV_HOME): the session
// cookies, and the public keys this machine has vouched for (trust.js). Never the
// password, never a private key, never a secret.

import { randomBytes } from 'crypto';
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

// Writes `data` to `file`, readable by its owner only. Through a fresh temporary file
// then a rename: the target is never readable by others, not even for an instant (an
// existing .env is often 0644), a symlink planted at its path is replaced rather than
// followed, and a crash never leaves half a file.
export function writePrivate(file, data) {
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx', 0o600);
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

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

export function createStore(dir = process.env.SHAREDENV_HOME || join(homedir(), '.sharedenv')) {
  const sessionFile = join(dir, 'session.json');
  const pinsFile = join(dir, 'pins.json');
  const save = (file, value) => {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writePrivate(file, `${JSON.stringify(value, null, 2)}\n`);
  };

  return {
    dir,
    // → { baseUrl, cookies } | null
    readSession: () => readJson(sessionFile),
    writeSession: (session) => save(sessionFile, session),
    clearSession: () => rmSync(sessionFile, { force: true }),
    // → { [subject]: publicKey }
    readPins: () => readJson(pinsFile) || {},
    writePins: (pins) => save(pinsFile, pins),
  };
}
