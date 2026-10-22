// Signing in and unlocking the vault. The master password never leaves this process:
// the server receives a verifier derived from it, and the private key is unwrapped
// locally from the keyring the server stores sealed.

import { Wallet, assertKdfParams, deriveAuthVerifier, unwrapPrivateKey } from './crypto.js';
import { expectOk } from './api.js';

const wallet = new Wallet();

// `authKdf` comes from the server: the verifier is domain-separated from the wrap key,
// so a server that serves the keyring's `kdf` as `authKdf` still never receives the key
// that unwraps the vault.
//
// `otp` answers the second factor when the account has one: a code, or an async function
// returning one. Any code the API accepts works — authenticator, mail or recovery code.
export async function login(client, { identifier, password, otp }) {
  const pre = expectOk(
    await client.call('GET', `/auth/prelogin?identifier=${encodeURIComponent(identifier)}`),
    'cannot sign in'
  );
  if (!pre?.authKdf) throw new Error('cannot sign in: the server sent no login parameters');
  const authVerifier = await deriveAuthVerifier(password, pre.authKdf);
  const session = expectOk(
    await client.call('POST', '/auth/sign-in', { identifier, authVerifier }),
    'cannot sign in'
  );
  if (session?.use2fa) {
    const code = typeof otp === 'function' ? await otp() : otp;
    if (!code) throw new Error('this account requires a two-factor code');
    expectOk(
      await client.call('POST', '/auth/2fa/validate', { code: String(code).trim() }),
      'two-factor code refused'
    );
  }
  return session;
}

// Our public key, DERIVED from the private key we hold — never the server's copy.
export function publicKeyOf(privateKey) {
  return wallet.keypass.publicFromPrivate(privateKey);
}

// → the account's private key, in memory only.
export async function unlockPrivateKey(client, password) {
  return (await unlockAccount(client, password)).privateKey;
}

// → { privateKey, userId }: the key, and the name it is logged under (transparency.js).
export async function unlockAccount(client, password) {
  const keyring = expectOk(await client.call('GET', '/keyring/me'), 'cannot read your keyring');
  if (!keyring?.encPrivateKey) {
    throw new Error('this account has no keyring yet: open the web app once to create it');
  }
  // The KDF parameters come from the server. Below the floor, the password would be
  // stretched by almost nothing — an offline attack, not a typo: say so.
  try {
    assertKdfParams(keyring.kdf);
  } catch (err) {
    throw new Error(
      `refusing to unlock: the server sent key-derivation parameters below the accepted floor (${err.message})`
    );
  }
  let privateKey;
  try {
    privateKey = unwrapPrivateKey(keyring.encPrivateKey, password, keyring.kdf);
  } catch {
    throw new Error('wrong password — could not unlock the vault');
  }
  // The directory must name the key we hold: a row naming another public key would let
  // the server choose who receives what is sealed to "us".
  if (String(keyring.publicKey || '').toLowerCase() !== publicKeyOf(privateKey)) {
    throw new Error('the public key on file is not the one of your private key — refusing');
  }
  return { privateKey, userId: keyring.userId };
}
