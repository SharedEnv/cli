// Runs the child of `sharedenv run` and reports how it ended, the way a shell would: its
// exit code, or 128 + n when signal n ended it (a CI must not read an OOM kill as a
// success). The signals the CLI receives are passed on, so stopping the CLI (`docker
// stop`, Ctrl-C, a closed terminal) stops the child instead of orphaning it.

import { spawn } from 'child_process';
import { constants } from 'os';

const FORWARDED = ['SIGINT', 'SIGTERM', 'SIGHUP'];

// A command that could not start, with the exit code a shell gives it.
const UNSTARTABLE = {
  ENOENT: ['command not found', 127],
  EACCES: ['permission denied', 126],
};

function spawnError(command, err) {
  if (!UNSTARTABLE[err.code]) return err;
  const [what, exitCode] = UNSTARTABLE[err.code];
  return Object.assign(new Error(`${what}: ${command}`), { exitCode });
}

// → Promise<exit code>. Rejects (with `exitCode`) when the command cannot be started.
export function runChild(command, args, env, { stdio = 'inherit' } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio, env });
    const forward = (signal) => child.kill(signal);
    let settled = false;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      for (const signal of FORWARDED) process.off(signal, forward);
      fn(value);
    };
    for (const signal of FORWARDED) process.on(signal, forward);
    child.on('error', (err) => settle(reject, spawnError(command, err)));
    child.on('exit', (code, signal) =>
      settle(resolve, signal ? 128 + (constants.signals[signal] ?? 0) : code ?? 0)
    );
  });
}
