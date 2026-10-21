// What `sharedenv pull` writes. Keys are sorted, so two pulls of the same safe give the
// same file.
//
// A .env is read by dotenv-style parsers AND sourced by shells (`set -a; . ./.env`).
// Each value is written in the first form both read literally — nothing expanded,
// nothing executed: a value is chosen by any WRITER on the safe, and `$(…)` in double
// quotes would run on the machine that sources the file.
//
//   bare     only characters with no meaning to either
//   '…'      anything without a single quote (newlines included)
//   "…"      a single quote, but none of " $ ` \ (which a shell or dotenv would interpret)
//
// A value that fits none (or holds a carriage return, which dotenv rewrites) is refused
// with its name: `--format json` or `sharedenv run` carry it as is.

const BARE = /^[A-Za-z0-9_\-.,:/@+%]+$/;

const sorted = (map) => Object.entries(map).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

function dotenvValue(name, value) {
  if (BARE.test(value)) return value;
  if (!value.includes('\r')) {
    if (!value.includes("'")) return `'${value}'`;
    if (!/["$`\\]/.test(value)) return `"${value}"`;
  }
  throw new Error(
    `"${name}" cannot be written as a .env line that is safe to source (it holds a ' with ` +
      'one of " $ ` \\, or a carriage return): use --format json, or sharedenv run'
  );
}

export function toDotenv(map) {
  return sorted(map)
    .map(([name, value]) => `${name}=${dotenvValue(name, value)}`)
    .join('\n');
}

export function toJson(map) {
  return JSON.stringify(Object.fromEntries(sorted(map)), null, 2);
}

export const FORMATS = { dotenv: toDotenv, json: toJson };
