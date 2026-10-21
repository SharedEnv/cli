// HTTP client for the sharedenv API. Node's fetch keeps no cookies, so the session
// cookies are threaded by hand; the jar is a plain object the caller persists and
// restores. Only the session travels this way — the password and the keys never do.

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const TIMEOUT_MS = 60_000;
const PAGE_SIZE = 200; // the API's largest page

// → the canonical base URL, or throws. Plain http would carry the login verifier (enough
// to sign in) and the session cookies in clear: only a local server may use it.
export function apiBase(raw) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    throw new Error(`not a URL: "${raw}"`);
  }
  const local = url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !local) {
    throw new Error(`refusing ${url.origin}: the API must be https (plain http only on localhost)`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('the API URL must not carry credentials, a query or a fragment');
  }
  return url.href.replace(/\/+$/, '');
}

// A Set-Cookie that expires the cookie (sign-out, rotation) removes it from the jar.
function expired(attributes) {
  const maxAge = /;\s*max-age=(-?\d+)/i.exec(attributes);
  if (maxAge) return Number(maxAge[1]) <= 0;
  const expires = /;\s*expires=([^;]+)/i.exec(attributes);
  return expires ? Date.parse(expires[1]) <= Date.now() : false;
}

export function createClient({ baseUrl, cookies = {}, userAgent = 'sharedenv-cli' }) {
  const jar = { ...cookies };

  function absorb(res) {
    for (const line of res.headers.getSetCookie?.() ?? []) {
      const [pair] = line.split(';');
      const i = pair.indexOf('=');
      if (i <= 0) continue;
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      if (!value || expired(line)) delete jar[name];
      else jar[name] = value;
    }
  }

  // → { status, body }. Throws only when the server could not be reached.
  async function call(method, path, body) {
    const headers = { 'User-Agent': userAgent, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const cookie = Object.entries(jar)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookie) headers.Cookie = cookie;

    let res;
    try {
      res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        redirect: 'error', // the API never redirects: a redirect would carry the session elsewhere
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      if (err.name === 'TimeoutError') {
        throw new Error(`no answer from ${baseUrl} after ${TIMEOUT_MS / 1000} s`);
      }
      const reason = err.cause?.code || err.cause?.message || err.message;
      throw new Error(`cannot reach ${baseUrl} (${reason})`);
    }
    absorb(res);
    let json = null;
    try {
      json = await res.json();
    } catch {
      /* no JSON body */
    }
    return { status: res.status, body: json };
  }

  return { baseUrl, call, cookies: () => ({ ...jar }) };
}

// An error answer of the API. Its body is { key, message, requestId }: the message is
// what the user reads, the request id is what support needs.
export class ApiError extends Error {
  constructor(what, { status, body }) {
    const detail = body?.message || `HTTP ${status}`;
    const ref = body?.requestId ? ` (request ${body.requestId})` : '';
    super(`${what}: ${detail}${ref}`);
    this.status = status;
    this.key = body?.key;
    this.requestId = body?.requestId;
  }
}

// Answers that say what to do next rather than what failed.
const NEXT_STEP = {
  1013: 'this session has not answered the second factor — run `sharedenv login` again',
  1014: 'the second-factor confirmation is too old — run `sharedenv login` again',
};

// → the body of a 2xx answer; otherwise throws, with the API's own message.
export function expectOk(res, what) {
  if (res.status >= 200 && res.status < 300) return res.body;
  if (res.status === 401)
    throw new Error('not signed in, or the session expired — run `sharedenv login`');
  if (NEXT_STEP[res.body?.key]) throw new Error(NEXT_STEP[res.body.key]);
  throw new ApiError(what, res);
}

// Every row of a paginated list route. Reading one page and stopping would silently drop
// what lies beyond it — a process started with variables missing.
export async function listAll(client, path, what) {
  const rows = [];
  for (let page = 1; ; page += 1) {
    const sep = path.includes('?') ? '&' : '?';
    const body = expectOk(
      await client.call('GET', `${path}${sep}limit=${PAGE_SIZE}&page=${page}`),
      `cannot list ${what}`
    );
    rows.push(...(body?.data || []));
    if (page >= (body?.pagination?.pages ?? 1)) return rows;
  }
}
