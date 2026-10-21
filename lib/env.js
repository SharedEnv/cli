// The environment `sharedenv run` gives the child process.
//
// A safe is writable by every WRITER on it. Injected blindly, its values would make write
// access to a shared safe code execution — or eavesdropping — on the machine of whoever
// runs it next (a teammate's laptop, the CI runner). Two rules:
//
//   - names that make the dynamic loader, a shell, an interpreter or a tool the child
//     spawns run code of someone else's choosing, or route and trust its traffic
//     (UNSAFE_ENV), are held back unless `--allow-unsafe-env`;
//   - no such list is complete, so a name the caller's environment already sets is not
//     overridden either, unless `--override-env`.
//
// And the child never receives the CLI's own SHAREDENV_* variables: SHAREDENV_PASSWORD
// opens every safe of the account, not just the one being run.

const UNSAFE_ENV = [
  // dynamic loader, shells
  /^LD_/,
  /^DYLD_/,
  /^PATH$/,
  /^IFS$/,
  /^BASH_ENV$/,
  /^BASH_FUNC_/,
  /^ENV$/,
  /^SHELLOPTS$/,
  /^BASHOPTS$/,
  /^PS4$/,
  /^PROMPT_COMMAND$/,
  /^ZDOTDIR$/,
  // interpreters
  /^NODE_OPTIONS$/,
  /^NODE_PATH$/,
  /^NODE_REPL_EXTERNAL_MODULE$/,
  /^PYTHONSTARTUP$/,
  /^PYTHONPATH$/,
  /^PYTHONHOME$/,
  /^PYTHONINSPECT$/,
  /^PERL5OPT$/,
  /^PERL5LIB$/,
  /^PERLLIB$/,
  /^RUBYOPT$/,
  /^RUBYLIB$/,
  /^JAVA_TOOL_OPTIONS$/,
  /^_JAVA_OPTIONS$/,
  /^JDK_JAVA_OPTIONS$/,
  // tools the child may spawn
  /^GIT_/,
  /^NPM_CONFIG_/,
  /^YARN_/,
  /^COMPOSER_/,
  /^PAGER$/,
  /^MANPAGER$/,
  /^LESSOPEN$/,
  /^LESSCLOSE$/,
  /^EDITOR$/,
  /^VISUAL$/,
  /^BROWSER$/,
  /^SSH_ASKPASS$/,
  /^SUDO_ASKPASS$/,
  // where the child's traffic goes, and which certificates it trusts: together they let
  // a writer read the other secrets in flight
  /^(HTTPS?|ALL|FTP)_PROXY$/,
  /^NODE_EXTRA_CA_CERTS$/,
  /^NODE_TLS_REJECT_UNAUTHORIZED$/,
  /^SSL_CERT_(FILE|DIR)$/,
  /_CA_BUNDLE$/,
  // this CLI's own configuration (a nested `sharedenv` would talk to another server)
  /^SHAREDENV_/,
];

const OWN_ENV = /^SHAREDENV_/i;

// → { safe: {…}, blocked: [names], kept: [names] }. Matched case-insensitively.
//   blocked — UNSAFE_ENV names, unless `allowUnsafe`;
//   kept    — names `base` (the caller's environment) already sets: its value stays,
//             unless `override`.
export function splitUnsafeEnv(map, { base = {}, allowUnsafe = false, override = false } = {}) {
  const safe = {};
  const blocked = [];
  const kept = [];
  for (const [name, value] of Object.entries(map)) {
    if (!allowUnsafe && UNSAFE_ENV.some((re) => re.test(name.toUpperCase()))) blocked.push(name);
    else if (!override && Object.hasOwn(base, name)) kept.push(name);
    else safe[name] = value;
  }
  return { safe, blocked, kept };
}

// The child's environment: the caller's, minus SHAREDENV_*, plus the injected secrets.
export function childEnv(parentEnv, injected) {
  const env = {};
  for (const [name, value] of Object.entries(parentEnv)) {
    if (!OWN_ENV.test(name)) env[name] = value;
  }
  return { ...env, ...injected };
}
