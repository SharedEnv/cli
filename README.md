# sharedenv CLI

**The zero-knowledge secrets vault for teams, in your terminal.**

[![npm](https://img.shields.io/npm/v/@sharedenv/cli)](https://www.npmjs.com/package/@sharedenv/cli)
[![license](https://img.shields.io/github/license/SharedEnv/cli)](LICENSE)

Your `.env` files have no business in Slack, in an email or in a git repo. With
[sharedenv](https://sharedenv.com), your team keeps its environment variables, API keys and
certificates in shared vaults. The CLI brings them to your commands, decrypted on your
machine: sharedenv itself never sees a single secret.

```bash
npm install -g @sharedenv/cli
sharedenv login
sharedenv link                # once per project: pick its vault
sharedenv run -- npm start    # your app, with the vault's secrets
```

## Why teams use it

- **One source of truth for every environment.** One vault per project or environment
  (dev, staging, prod), shared with exactly the people who need it. No more "can you send me
  the new key?".
- **Nothing on disk.** `sharedenv run` starts your app with its secrets in memory. No stale
  `.env` lying around on laptops, no file to leak.
- **The same secrets in CI.** Your pipeline fetches what it needs at run time, instead of a
  copy of every secret in every tool.
- **Zero-knowledge, for real.** Secrets are encrypted before they leave your device and
  decrypted only on the devices of the people you share them with. A breach of our servers
  would expose encrypted values, never a secret.

## Get started in two minutes

1. **Create your account** on [sharedenv.com](https://sharedenv.com). It is free to start,
   no credit card.
2. **Install the CLI** (Node.js 20.19 or later):
   ```bash
   npm install -g @sharedenv/cli
   ```
3. **Sign in** with your email (or username) and your master password, plus your
   two-factor code if your account has one:
   ```bash
   sharedenv login
   ```
4. **Link your project to a vault**, from the project's directory:
   ```bash
   sharedenv create my-app-dev   # a new vault, or pick one you already have:
   sharedenv link                # lists your vaults, you choose
   ```
5. **Use it:**
   ```bash
   sharedenv set DATABASE_URL=postgres://localhost/app
   sharedenv run -- npm start
   ```

## Which vault a command works on

You may have many vaults: your own, the ones people shared with you, the ones your teams
reach. A command never guesses which one you mean.

- **In a project**, `sharedenv link` writes `.sharedenv.json` in its directory. It holds the
  vault's id and nothing else, no secret: commit it, and your whole team works on the same
  vault. Every command run in that directory, or below it, uses that vault.
- **Anywhere**, `-v <name or id>` names the vault: `sharedenv get API_KEY -v staging`.
- **A name two of your vaults share is refused**, with both listed (id, owner, teams): give
  the id instead. `sharedenv create` refuses a name you already have.
- **Every command says which vault it used**, on stderr: a link in a repository you cloned
  might not name the vault you expect.

```bash
sharedenv vaults                       # every vault you can open: id, your access, owner, teams
sharedenv show                         # this vault: members, teams, names of its keys
```

`vaults` and `show` never ask for your master password: vault and key names are stored in
clear, only values are encrypted.

## Everyday use

### Keys

```bash
sharedenv set API_KEY=sk_test_1 DEBUG=1   # add or replace
sharedenv set TLS_KEY < key.pem            # value from stdin
sharedenv set STRIPE_KEY                   # value asked, not echoed
sharedenv get API_KEY                      # one value, on stdout
sharedenv unset DEBUG                      # remove
```

A key given without a value has its value asked without echo, or read from stdin: it lands
neither in your shell history nor in the process list. `get` prints the value as is, with
nothing added when the output is a pipe or a file (`export API_KEY=$(sharedenv get API_KEY)`).

### Run anything with its secrets

```bash
sharedenv run -- npm start
sharedenv run -v staging -- docker compose up
sharedenv run -v prod -- python manage.py migrate
```

The secrets reach the command as environment variables, in memory. The command's exit code
is passed through, so scripts and CI behave exactly as without sharedenv.

A variable your shell already sets wins over the vault, so a local `DATABASE_URL` is never
replaced behind your back: add `--override-env` when you want the vault's value.

### Get your secrets as a file, or as JSON

```bash
sharedenv pull                         # dotenv, on stdout
sharedenv pull --out .env              # the same, in a file only you can read
sharedenv pull --format json           # JSON, for scripts and programs
```

stdout carries the secrets and nothing else (questions and messages go to stderr), so
pipes and redirections get clean data. From a script or a program there is no terminal to
ask for your master password: set `SHAREDENV_PASSWORD`.

#### dotenv (the default)

For a vault holding five secrets, `sharedenv pull` prints:

```dotenv
APP_NAME='Acme billing'
DATABASE_URL=postgres://app:s3cret@db.internal:5432/app
JWT_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----'
SMTP_PASSWORD="it's a pass"
STRIPE_KEY=sk_test_example
```

- One `NAME=value` per secret, sorted by name, so two pulls of the same vault give the
  same file.
- A value is written as is when it holds only plain characters, between single quotes
  otherwise (multi-line values such as a PEM key included), and between double quotes when
  it contains a single quote.
- Nothing is ever expanded or executed when the file is read. A value that no quoting can
  carry safely (a single quote together with `"`, `$`, a backtick or `\`) is refused with
  its name: use `--format json` for that vault.

Every common reader loads it as is:

```bash
set -a; . ./.env; set +a                 # a shell (bash, zsh, sh)
node --env-file=.env server.js           # Node.js 20.12 or later
```

```js
import 'dotenv/config'; // Node.js, with the dotenv package
```

```python
from dotenv import load_dotenv  # Python, with python-dotenv
load_dotenv()
```

One exception: `docker run --env-file` reads values literally (it would keep the quotes)
and refuses multi-line values. Hand the variables to Docker through `run` instead:

```bash
sharedenv run -- docker run -e DATABASE_URL -e STRIPE_KEY my-app
```

#### JSON

`sharedenv pull --format json` prints one object, names sorted, every value a string:

```json
{
  "APP_NAME": "Acme billing",
  "DATABASE_URL": "postgres://app:s3cret@db.internal:5432/app",
  "JWT_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
  "SMTP_PASSWORD": "it's a pass",
  "STRIPE_KEY": "sk_test_example"
}
```

From a program:

```js
// Node.js
import { execFileSync } from 'node:child_process';

const secrets = JSON.parse(
  execFileSync('sharedenv', ['pull', '-v', 'prod', '--format', 'json'], { encoding: 'utf8' })
);
console.log(secrets.DATABASE_URL);
```

```python
# Python
import json
import subprocess

secrets = json.loads(
    subprocess.run(
        ["sharedenv", "pull", "-v", "prod", "--format", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
)
print(secrets["DATABASE_URL"])
```

If the command fails (wrong password, unknown vault, no network), it exits with a non-zero
code and says why on stderr: `execFileSync` throws, and `check=True` raises.

### Share a vault

```bash
sharedenv share alice@example.com            # read access
sharedenv share alice@example.com --write    # or --admin
sharedenv share --team backend               # a team you are a member of
sharedenv teams                              # your organizations and their teams
```

Sharing with a person shows the fingerprint of their key, six words to read aloud and the
hexadecimal: compare it with them over another channel (a call, a chat) before you say yes,
they read theirs with `sharedenv fingerprint`. The key of a team reads the same way:
`sharedenv fingerprint --team backend`. The share then waits for their answer. Removing
someone's access means changing the vault's key and re-encrypting every secret: that is done
in the web app, as is managing teams and organizations.

In a script, a key this machine has never seen needs its fingerprint: `--yes` is not enough,
it only answers for a key already known here and for the other questions.

```bash
sharedenv share alice@example.com --fingerprint "$ALICE_FINGERPRINT"
```

The fingerprint is given in either form: the six words read aloud, with or without the `·`,
or the hexadecimal.

### Accept what your team shares with you

When a teammate shares a vault with you, it waits for your answer:

```bash
sharedenv vaults              # the shares waiting for you, with who sent them
sharedenv accept staging      # shows the sender's key fingerprint, then asks
sharedenv decline staging
```

Before you accept, compare the fingerprint with the sender over another channel. It proves
the share really comes from them.

### Sign out

```bash
sharedenv logout              # closes the session on our side too
```

## In CI/CD

The CLI asks nothing when there is no terminal: give it what it would ask for, from your
CI's secret store. Name the vault by its id (`sharedenv vaults` shows it), or commit the
project's `.sharedenv.json`.

**GitHub Actions**

```yaml
- run: npm install -g @sharedenv/cli
- run: sharedenv login
  env:
    SHAREDENV_IDENTIFIER: ${{ secrets.SHAREDENV_IDENTIFIER }}
    SHAREDENV_PASSWORD: ${{ secrets.SHAREDENV_PASSWORD }}
- run: sharedenv run -v 6721f0c2a8e4b1d3c5f70912 -- ./deploy.sh
  env:
    SHAREDENV_PASSWORD: ${{ secrets.SHAREDENV_PASSWORD }}
```

**GitLab CI**

```yaml
deploy:
  script:
    - npm install -g @sharedenv/cli
    - sharedenv login
    - sharedenv run -v "$SHAREDENV_VAULT" -- ./deploy.sh
  # SHAREDENV_IDENTIFIER, SHAREDENV_PASSWORD and SHAREDENV_VAULT: masked CI/CD variables
```

**Docker** (the secrets are fetched when the container starts, never baked into the image)

```dockerfile
RUN npm install -g @sharedenv/cli
CMD ["sh", "-c", "sharedenv login && exec sharedenv run -v \"$SHAREDENV_VAULT\" -- node server.js"]
```

```bash
docker run -e SHAREDENV_IDENTIFIER -e SHAREDENV_PASSWORD -e SHAREDENV_VAULT my-app
```

Good practice for pipelines:

- **Use a dedicated account** for CI, and share with it only the vaults the job needs,
  read-only. Its master password opens every vault of that account.
- **Prefer `run` to `pull`**, and never print a `pull` to the job log.
- **A second factor needs a code at login** (`SHAREDENV_OTP`), which a pipeline cannot
  produce on its own: keep the CI account without one, and limited as above.
- **List who may seal the vault's key.** A pipeline cannot answer a question, and its
  machine usually knows no key: a vault shared with the CI account is refused until
  `SHAREDENV_TRUSTED_SEALERS` lists the fingerprint of whoever sealed it, as they read it
  with `sharedenv fingerprint` (several: separated by commas). When another admin changes
  the vault's key, the job stops until their fingerprint is added.
- **A share or an accept names the fingerprint.** On a key this machine has never seen, a job
  passes `--fingerprint "$THEIR_FINGERPRINT"`, checked once by a person and kept in a CI
  variable: the first trust comes from someone, as with SSH's `known_hosts`. Without it the
  job stops, with the message and the fingerprint, and nothing is sealed.
- **Client version.** Each request names the CLI's version: below the version the server
  accepts, a command stops and says how to update.

## How your secrets stay yours

- **Encrypted on your device.** AES-256-GCM for the secrets, sharing through signed ECDH
  (secp256k1), your password stretched with scrypt. Standard primitives, nothing home-made.
- **Your password and your private key never leave your machine.** Signing in sends a
  verifier derived from your password, never the password. Your private key is unlocked in
  memory for the command, and never written anywhere.
- **You know who shares with you, and whom you share with.** A share opens only if it was
  sealed by its sender, and the CLI remembers the keys it has seen: if someone's key ever
  changes, it stops and asks.
- **A vault is sealed to a team's real key.** `share --team` uses the key you hold for the
  team, once it is the last one the public log holds for it, and sealed by you, known on
  this machine, or confirmed by its fingerprint (`--team-fingerprint`, for a script). If
  someone who left the team still holds that key, `share --team` says so and asks (`--yes`
  for a script): the vault key stays theirs to read even after the team key is replaced.
- **A vault key sealed by a stranger is not used.** Any key can seal a vault key of its
  choosing to yours. Before using a vault's key, the CLI checks who sealed it: you, or
  someone you accepted for this vault. A yes holds for that vault only, even for someone
  known elsewhere. A new key must be the last one the public log holds for that person, and
  is shown with its fingerprint: you say yes once, or nothing is read or written.
- **A vault key cannot go back.** What is sealed names its vault and its version, and this
  machine remembers the version it saw: an older one, or another key at that version, is
  refused.
- **A key cannot be swapped in our database without a trace.** Every public key the server
  hands out is first written to a log that only grows, each entry chained to the previous
  one by its hash. The CLI seals to a key, or starts trusting its seal, only if it is the last
  one logged for its owner; it warns you when a key that is not yours is logged under your
  name, or under the name of a team whose key you hold, and refuses a log that rewrites
  what it already checked. A warning is repeated at every unlock until you acknowledge it
  with `sharedenv log --ack`.
- **A vault cannot take over your machine.** Anyone who can edit a vault chooses its
  values, so `run` holds back variables that would make a program run code or reroute its
  traffic (`LD_*`, `PATH`, `NODE_OPTIONS`, proxies, custom certificates...) unless you pass
  `--allow-unsafe-env`. Your master password is never passed to the command.
- **Open source.** The CLI and its cryptography (`lib/crypto/`) are here for anyone to
  read. Found something? See [SECURITY.md](SECURITY.md).

What it does not protect against, said plainly:

- **Names.** Vault names and secret names (like `DATABASE_URL`) are stored in clear, so
  that they can be listed and organized; values are encrypted. Never put a secret in a name.
- **A swap is caught, not prevented.** Someone who can write to our database could still
  log a key of their own: the log keeps the trace, and its owner is warned the next time
  they unlock. Someone who controls our servers themselves could show you a different log.
  Comparing fingerprints once with someone settles it for good.
- **A yes without comparing.** The CLI shows a new sealer's fingerprint, comparing it is up
  to you. Until you do, someone who can write to our database and logs a key of their own
  under a new account is only a name you do not know.
- **Replays, on a machine that never saw the vault.** With no memory of it, an older vault
  key sealed by someone you accept, or an older value of the same secret, could be served
  back to you. `set` and `share` refuse a key rotation that did not finish, and a key that
  does not open the vault's secrets; a value marked as set aside by a rotation does not count.
- **A new machine knows nothing.** Until it has seen a vault, the CLI cannot tell a key put back in our database from the real one, and a swap in the log of a team it never saw raises no alarm. Where a key looks unsafe and only an admin can renew it, the CLI never asks: it says so and sends you to the web app.
- **Someone who writes to our database can block you**, by putting a vault ahead of its key or marking its lines unreadable, without reading anything. The CLI then refuses to write and says why.
- **A key replaced by its owner** stays good only for the vaults and versions this machine
  already saw from it, so that they keep opening. If they replaced it because it leaked, ask
  an admin to change the key of those vaults.
- **Renewing a key is done in the web app.** The CLI never changes a vault's key: where only
  that would help, it says so and sends you there.
- **Your own account on your own machine.** The session file (`~/.sharedenv/session.json`,
  readable by you only) lets a program running as you act as you: sign out on machines you
  do not trust.

## Reference

| Command                                                 | What it does                                                |
| ------------------------------------------------------- | ----------------------------------------------------------- |
| `sharedenv login [--api <url>] [--identifier <id>]`     | Sign in. Keeps the session, nothing else.                   |
| `sharedenv logout`                                      | Close the session, on our side and on this machine.         |
| `sharedenv vaults`                                      | Your vaults, then the shares waiting for your answer.       |
| `sharedenv create <name>`                               | Create a vault (prints its id).                             |
| `sharedenv link [<vault>]`                              | Link this directory to a vault (`.sharedenv.json`).         |
| `sharedenv show`                                        | The vault: owner, members, teams, names of its keys.        |
| `sharedenv get <KEY>`                                   | Print one value.                                            |
| `sharedenv set <KEY>=<value>... [<KEY>]`                | Add or replace keys.                                        |
| `sharedenv unset <KEY>...`                              | Remove keys.                                                |
| `sharedenv run -- <command>`                            | Run a command with the vault's secrets in its environment.  |
| `sharedenv pull [--out <file>] [--format dotenv\|json]` | Print or write every secret.                                |
| `sharedenv share <email> [--write\|--admin]`            | Share the vault with a person.                              |
| `sharedenv share --team <team> [--write\|--admin]`      | Share the vault with one of your teams.                     |
| `sharedenv accept <vault> [--team <team>]`              | Accept a share after checking who sealed it.                |
| `sharedenv decline <vault> [--team <team>]`             | Decline a share.                                            |
| `sharedenv teams`                                       | Your organizations and their teams.                         |
| `sharedenv fingerprint [--team <team>]`                 | Your key fingerprint, or a team's, to read to a teammate.   |
| `sharedenv log [--ack]`                                 | The public key log warnings kept here, or acknowledge them. |

Commands that work on a vault take `-v <name or id>`, or use the vault the current
directory is linked to. `sharedenv help <command>` lists every option.

| Environment variable        | Use                                                                 |
| --------------------------- | ------------------------------------------------------------------- |
| `SHAREDENV_IDENTIFIER`      | Email or username, for a login without questions.                   |
| `SHAREDENV_PASSWORD`        | Master password, for commands without questions.                    |
| `SHAREDENV_OTP`             | Two-factor code, for a login without questions.                     |
| `SHAREDENV_TRUSTED_SEALERS` | Fingerprints allowed to have sealed a vault's key, comma separated. A team key they sealed also counts as vouched for when the public key log is watched. |
| `SHAREDENV_API`             | API URL (default `https://api.sharedenv.com`).                      |
| `SHAREDENV_HOME`            | Where the CLI keeps its files (default `~/.sharedenv`).             |

The CLI keeps there, all readable by you only: `session.json` (your session), and one
`servers/<server>/<account>/memory.json` per server and account (the keys this machine has
checked, which vaults and versions it saw, how far it checked the public key log, the warnings
not acknowledged yet). Never a secret, never your password, never your private key.

Exit codes: `0` success, `1` error, `2` wrong usage (an ambiguous vault name included),
`130` cancelled. With `run`: the command's own code, `128 + n` when signal `n` ended it,
`127` when the command does not exist.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Made by
[SharedEnv](https://sharedenv.com).
