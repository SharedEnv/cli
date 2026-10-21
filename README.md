# sharedenv CLI

**The zero-knowledge secrets vault for teams, in your terminal.**

[![npm](https://img.shields.io/npm/v/@sharedenv/cli)](https://www.npmjs.com/package/@sharedenv/cli)
[![license](https://img.shields.io/npm/l/@sharedenv/cli)](LICENSE)

Your `.env` files have no business in Slack, in an email or in a git repo. With
[sharedenv](https://sharedenv.com), your team keeps its environment variables, API keys and
certificates in shared vaults. The CLI brings them to your commands, decrypted on your
machine: sharedenv itself never sees a single secret.

```bash
npm install -g @sharedenv/cli
sharedenv login
sharedenv run prod -- npm start
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

1. **Create your account** on [sharedenv.com](https://sharedenv.com) and your first vault.
   It is free to start, no credit card.
2. **Install the CLI** (Node.js 20.19 or later):
   ```bash
   npm install -g @sharedenv/cli
   ```
3. **Sign in** with your email (or username) and your master password, plus your
   two-factor code if your account has one:
   ```bash
   sharedenv login
   ```
4. **Use your vaults:**
   ```bash
   sharedenv list                      # your vaults
   sharedenv run prod -- npm start     # your app, with the prod secrets
   ```

## Everyday use

### Run anything with its secrets

```bash
sharedenv run prod -- npm start
sharedenv run staging -- docker compose up
sharedenv run prod -- python manage.py migrate
```

The secrets reach the command as environment variables, in memory. The command's exit code
is passed through, so scripts and CI behave exactly as without sharedenv.

A variable your shell already sets wins over the vault, so a local `DATABASE_URL` is never
replaced behind your back: add `--override-env` when you want the vault's value.

### Get your secrets as a file, or as JSON

```bash
sharedenv pull prod                    # dotenv, on stdout
sharedenv pull prod --out .env         # the same, in a file only you can read
sharedenv pull prod --format json      # JSON, for scripts and programs
```

stdout carries the secrets and nothing else (questions and messages go to stderr), so
pipes and redirections get clean data. From a script or a program there is no terminal to
ask for your master password: set `SHAREDENV_PASSWORD`.

#### dotenv (the default)

For a vault holding five secrets, `sharedenv pull prod` prints:

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
sharedenv run prod -- docker run -e DATABASE_URL -e STRIPE_KEY my-app
```

#### JSON

`sharedenv pull prod --format json` prints one object, names sorted, every value a string:

```json
{
  "APP_NAME": "Acme billing",
  "DATABASE_URL": "postgres://app:s3cret@db.internal:5432/app",
  "JWT_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
  "SMTP_PASSWORD": "it's a pass",
  "STRIPE_KEY": "sk_test_example"
}
```

One value, from a shell:

```bash
sharedenv pull prod --format json | jq -r .DATABASE_URL
```

From a program:

```js
// Node.js
import { execFileSync } from 'node:child_process';

const secrets = JSON.parse(
  execFileSync('sharedenv', ['pull', 'prod', '--format', 'json'], { encoding: 'utf8' })
);
console.log(secrets.DATABASE_URL);
```

```python
# Python
import json
import subprocess

secrets = json.loads(
    subprocess.run(
        ["sharedenv", "pull", "prod", "--format", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
)
print(secrets["DATABASE_URL"])
```

If the command fails (wrong password, unknown vault, no network), it exits with a non-zero
code and says why on stderr: `execFileSync` throws, and `check=True` raises.

### Accept what your team shares with you

When a teammate shares a vault with you, it waits for your answer:

```bash
sharedenv list                # the shares waiting for you, with who sent them
sharedenv accept staging      # shows the sender's key fingerprint, then asks
sharedenv decline staging
```

Before you accept, compare the fingerprint with the sender over another channel (a call,
a chat). It proves the share really comes from them. They can check yours the same way:
`sharedenv fingerprint`.

### Sign out

```bash
sharedenv logout              # closes the session on our side too
```

## In CI/CD

The CLI asks nothing when there is no terminal: give it what it would ask for, from your
CI's secret store.

**GitHub Actions**

```yaml
- run: npm install -g @sharedenv/cli
- run: sharedenv login
  env:
    SHAREDENV_IDENTIFIER: ${{ secrets.SHAREDENV_IDENTIFIER }}
    SHAREDENV_PASSWORD: ${{ secrets.SHAREDENV_PASSWORD }}
- run: sharedenv run prod -- ./deploy.sh
  env:
    SHAREDENV_PASSWORD: ${{ secrets.SHAREDENV_PASSWORD }}
```

**GitLab CI**

```yaml
deploy:
  script:
    - npm install -g @sharedenv/cli
    - sharedenv login
    - sharedenv run prod -- ./deploy.sh
  # SHAREDENV_IDENTIFIER and SHAREDENV_PASSWORD: masked CI/CD variables
```

**Docker** (the secrets are fetched when the container starts, never baked into the image)

```dockerfile
RUN npm install -g @sharedenv/cli
CMD ["sh", "-c", "sharedenv login && exec sharedenv run prod -- node server.js"]
```

```bash
docker run -e SHAREDENV_IDENTIFIER -e SHAREDENV_PASSWORD my-app
```

Good practice for pipelines:

- **Use a dedicated account** for CI, and share with it only the vaults the job needs,
  read-only. Its master password opens every vault of that account.
- **Prefer `run` to `pull`**, and never print a `pull` to the job log.
- **A second factor needs a code at login** (`SHAREDENV_OTP`), which a pipeline cannot
  produce on its own: keep the CI account without one, and limited as above.

## How your secrets stay yours

- **Encrypted on your device.** AES-256-GCM for the secrets, sharing through signed ECDH
  (secp256k1), your password stretched with scrypt. Standard primitives, nothing home-made.
- **Your password and your private key never leave your machine.** Signing in sends a
  verifier derived from your password, never the password. Your private key is unlocked in
  memory for the command, and never written anywhere.
- **You know who shares with you.** A share opens only if it was sealed by its sender, and
  the CLI remembers the keys it has seen: if someone's key ever changes, it stops and asks.
- **A vault cannot take over your machine.** Anyone who can edit a vault chooses its
  values, so `run` holds back variables that would make a program run code or reroute its
  traffic (`LD_*`, `PATH`, `NODE_OPTIONS`, proxies, custom certificates...) unless you pass
  `--allow-unsafe-env`. Your master password is never passed to the command.
- **Open source.** The CLI and its cryptography (`lib/crypto/`) are here for anyone to
  read. Found something? See [SECURITY.md](SECURITY.md).

What it does not protect against, said plainly:

- **Names.** Vault names and secret names (like `DATABASE_URL`) are stored in clear, so
  that they can be listed and organized; values, and the URL and username that go with
  them, are encrypted. Never put a secret in a name.
- **The first contact.** The first key the CLI sees for someone is the one our directory
  serves; comparing fingerprints once settles it for good.
- **After you accept a share**, its sender is not checked again; and an older value of the
  same secret could be served back to you.
- **Your own account on your own machine.** The session file (`~/.sharedenv/session.json`,
  readable by you only) lets a program running as you act as you: sign out on machines you
  do not trust.

## Reference

| Command                                                               | What it does                                               |
| --------------------------------------------------------------------- | ---------------------------------------------------------- |
| `sharedenv login [--api <url>] [--identifier <id>]`                   | Sign in. Keeps the session, nothing else.                  |
| `sharedenv list`                                                      | Your vaults, then the shares waiting for your answer.      |
| `sharedenv run <vault> -- <command>`                                  | Run a command with the vault's secrets in its environment. |
| `sharedenv pull <vault> [--out <file>] [--format dotenv\|json]`       | Print or write the secrets.                                |
| `sharedenv accept <vault> [--team <id>] [--yes] [--fingerprint <fp>]` | Accept a share after checking who sealed it.               |
| `sharedenv decline <vault> [--team <id>]`                             | Decline a share.                                           |
| `sharedenv fingerprint`                                               | Your key fingerprint, to read to a teammate.               |
| `sharedenv logout`                                                    | Close the session, on our side and on this machine.        |

`<vault>` is a vault's name or id. `sharedenv help <command>` lists every option.

| Environment variable   | Use                                                     |
| ---------------------- | ------------------------------------------------------- |
| `SHAREDENV_IDENTIFIER` | Email or username, for a login without questions.       |
| `SHAREDENV_PASSWORD`   | Master password, for commands without questions.        |
| `SHAREDENV_OTP`        | Two-factor code, for a login without questions.         |
| `SHAREDENV_API`        | API URL (default `https://api.sharedenv.com`).          |
| `SHAREDENV_HOME`       | Where the CLI keeps its files (default `~/.sharedenv`). |

The CLI keeps two files there, both readable by you only: `session.json` (your session)
and `pins.json` (the public keys this machine has checked). Never a secret, never your
password, never your private key.

Exit codes: `0` success, `1` error, `2` wrong usage, `130` cancelled. With `run`: the
command's own code, `128 + n` when signal `n` ended it, `127` when the command does not
exist.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Made by
[SharedEnv](https://sharedenv.com).
