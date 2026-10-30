// The vault a project uses: `.sharedenv.json`, written by `sharedenv link` in the
// project's directory and found from there or any directory below it (like .nvmrc). It
// holds the vault's id and nothing else - no secret - so it can be committed, and the
// whole team works on the same vault. An id grants nothing: the server still decides
// who opens the vault, and every command says which vault it used.

import { readFileSync, writeFileSync } from 'fs';
import path from 'path';

export const LINK_FILE = '.sharedenv.json';
const VAULT_ID = /^[a-f0-9]{24}$/i;

// → { file, vault } — the nearest link from `dir` up, or null when there is none.
export function findLink(dir = process.cwd()) {
  for (let current = path.resolve(dir); ; current = path.dirname(current)) {
    const file = path.join(current, LINK_FILE);
    let text = null;
    try {
      text = readFileSync(file, 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') throw new Error(`cannot read ${file} (${err.code})`);
    }
    if (text !== null) return { file, vault: vaultOf(file, text) };
    if (path.dirname(current) === current) return null;
  }
}

function vaultOf(file, text) {
  let vault;
  try {
    vault = JSON.parse(text)?.vault;
  } catch {
    vault = undefined;
  }
  if (typeof vault !== 'string' || !VAULT_ID.test(vault)) {
    throw new Error(`${file} does not name a vault: run \`sharedenv link\` again`);
  }
  return vault.toLowerCase();
}

// → the file written.
export function writeLink(dir, vault) {
  const file = path.join(dir, LINK_FILE);
  writeFileSync(file, `${JSON.stringify({ vault: String(vault) }, null, 2)}\n`);
  return file;
}
