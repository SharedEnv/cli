# sharedenv CLI

Pull and run with your [sharedenv](https://sharedenv.com) secrets, decrypted on your machine.

sharedenv is a zero-knowledge secrets vault. Secrets are encrypted before they leave your
browser or your terminal, and decrypted only on the devices of the people they are shared
with. The server stores sealed blobs and public keys: it never sees a secret, your master
password or your private key. This CLI is one of those devices.

## Install

```bash
npm install -g @sharedenv/cli     # Node.js 20.19 or later
```

## Quick start

```bash
sharedenv login                      # once per machine
sharedenv list                       # your safes, and the shares waiting for you
sharedenv run prod -- npm start      # run a command with the secrets in its environment
sharedenv pull prod --out .env       # or write them to a file only you can read
```

`prod` is the name (or id) of a safe. Create safes and share them from the web app; the CLI
reads them.

## Commands

| Command                                                         | What it does                                                  |
| --------------------------------------------------------------- | ------------------------------------------------------------- |
| `login [--api <url>] [--identifier <id>]`                       | Sign in. Keeps the session cookies, nothing else.             |
| `list`                                                          | Your safes, then the shares waiting for your answer.          |
| `pull <safe> [--out <file>] [--format dotenv\|json]`            | Print or write the decrypted secrets.                         |
| `run <safe> [--allow-unsafe-env] [--override-env] -- <command>` | Run a command with the secrets in its environment, in memory. |
| `accept <safe> [--team <id>] [--yes] [--fingerprint <fp>]`      | Accept a share after checking who sealed it.                  |
| `decline <safe> [--team <id>]`                                  | Decline a share.                                              |
| `fingerprint`                                                   | Your public-key fingerprint, to read to a teammate.           |
| `logout`                                                        | Close the session on the server, and forget it here.          |

`sharedenv help <command>` gives every option of a command.

## In CI and scripts

Nothing is asked when there is no terminal: give the CLI what it would ask for.

```bash
export SHAREDENV_IDENTIFIER=ci@example.com
export SHAREDENV_PASSWORD=...        # from your CI's secret store
sharedenv login
sharedenv run prod -- ./deploy.sh
```

- **Use an account dedicated to the job.** The master password opens every safe of its
  account: share with that account only the safes the job needs, read-only.
- **Log in at the start of each job.** Runners are disposable; so is the session.
- **A second factor needs `SHAREDENV_OTP`**, a code a job cannot produce on its own. The
  setup this version supports is a CI account without one, limited as above.
- `run` exits with the command's own exit code, so the job fails when the command does.

## Security model

What the CLI does so that the server — or anyone who controls it — learns nothing and
changes nothing unnoticed:

- **Your password never leaves the process.** The login sends a verifier derived from it
  (scrypt, then HMAC, kept separate from the key that unlocks the vault). The private key is
  unwrapped in memory and never written anywhere. Key-derivation parameters sent by the
  server are refused below a fixed floor: a server cannot make your password cheap to guess.
- **Keys are checked, not believed.** Your public key is derived from your private key, and
  a server that names another one is refused. A share opens only if it was sealed by its
  sender's key; `accept` shows that key's fingerprint, and remembers it on this machine
  (`~/.sharedenv/pins.json`): a different key later is never taken without your explicit yes.
  Compare fingerprints with people over another channel (`sharedenv fingerprint`), or give
  the expected one with `--fingerprint` in scripts.
- **A value cannot be moved.** Each secret is bound to its safe and its name: a server that
  serves one secret's value under another name, or from another safe, is refused.
- **`run` does not let a safe take over the machine.** Anyone who can write to a safe
  chooses its values. Variables that make a program run code or reroute its traffic
  (`LD_*`, `PATH`, `NODE_OPTIONS`, `*_PROXY`, `NODE_EXTRA_CA_CERTS`…) are held back unless
  you pass `--allow-unsafe-env`; a variable your environment already sets is not replaced
  unless you pass `--override-env`. The command never receives `SHAREDENV_*` variables —
  the master password stays with the CLI.
- **`pull` writes files that are safe to source.** Values are quoted so that a shell expands
  and executes nothing (`set -a; . ./.env` is fine); a value no safe quoting can carry is
  refused by name (use `--format json` or `run`). `--out` writes the file readable by you
  only, replacing it atomically.
- **Transport.** HTTPS only (plain HTTP to `localhost` only), no redirects followed.

What it does not protect against, said plainly:

- **First contact.** The first key the CLI sees for someone is the one the server serves.
  Pinning protects every later contact; comparing fingerprints protects the first.
- **After acceptance**, the sender of a share is not checked again: a server that replaced an
  already accepted envelope would not be noticed.
- **Replay.** A server could serve an older value of the same secret, sealed under the same
  key.
- **Your own account on your own machine.** The session file is a bearer credential (mode
  0600; `logout` revokes it). A program running as you can read it, and the CLI's memory.

## Files and environment

|                             |                                                      |
| --------------------------- | ---------------------------------------------------- |
| `~/.sharedenv/session.json` | The session cookies of your last login (0600).       |
| `~/.sharedenv/pins.json`    | The public keys this machine has vouched for (0600). |
| `SHAREDENV_API`             | API URL (default `https://api.sharedenv.com`).       |
| `SHAREDENV_IDENTIFIER`      | Email or username, for a login without questions.    |
| `SHAREDENV_PASSWORD`        | Master password, for commands without questions.     |
| `SHAREDENV_OTP`             | Second-factor code, for a login without questions.   |
| `SHAREDENV_HOME`            | Where the two files live (default `~/.sharedenv`).   |

## Exit codes

`0` success · `1` error · `2` wrong usage · `130` cancelled. With `run`: the command's own
code, `128 + n` when signal `n` ended it, `127` when the command does not exist.

## The code

The CLI is small and has one dependency, [`@noble/curves`](https://github.com/paulmillr/noble-curves)
(secp256k1). Its cryptography is in `lib/crypto/`, as readable files — the ones the
sharedenv server runs, byte-compatible with the web app's: `wallet.js` and `keypass.js`
(sealing to a public key), `kdf.js` (password stretching and the KDF floor), `secretBlob.js`
(secrets bound to their place), `aes.js`, `fingerprint.js`.

## Security and license

Found a vulnerability? Report it privately — see [SECURITY.md](SECURITY.md).

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
