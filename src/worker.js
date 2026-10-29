// IAM Demo: static site + JSON auth API on one Cloudflare Worker.
// Storage: D1 (users, sessions). Passwords: PBKDF2-SHA256. Sessions: random token in an HttpOnly cookie.

const ITER = 100000;                 // Workers' PBKDF2 maximum
const SESSION_SECONDS = 7 * 24 * 3600;
const MAX_FAILS = 5;
const LOCK_SECONDS = 600;
const PROTECTED = ['/dashboard', '/profile', '/admin'];
const enc = new TextEncoder();
const now = () => Math.floor(Date.now() / 1000);

/* ---------- schema (created automatically on first request) ---------- */
let schemaPromise;
function ensureSchema(env) {
  schemaPromise ??= env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      failed_count INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_login INTEGER
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
  ]).catch(err => { schemaPromise = undefined; throw err; });
  return schemaPromise;
}

/* ---------- crypto helpers ---------- */
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITER}$${toB64(salt)}$${toB64(await derive(password, salt, ITER))}`;
}
async function verifyPassword(password, stored) {
  const [scheme, iter, salt, hash] = stored.split('$');
  if (scheme !== 'pbkdf2') return false;
  const a = new Uint8Array(await derive(password, fromB64(salt), Math.min(Number(iter), ITER)));
  const b = fromB64(hash);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
let dummyHash;
async function burnTime(password) {           // equalise timing when the account doesn't exist
  dummyHash ??= await hashPassword('not-a-real-password');
  await verifyPassword(password, dummyHash);
}
async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

/* ---------- http helpers ---------- */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
};
function withHeaders(res, extra = {}) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...SECURITY_HEADERS, ...extra })) out.headers.set(k, v);
  return out;
}
function json(data, status = 200, headers = {}) {
  return withHeaders(
    new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }),
    { 'Cache-Control': 'no-store', ...headers }
  );
}
function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}
const sessionCookie = (token, maxAge) =>
  `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
async function readJson(request) {
  try { return await request.json(); } catch { return {}; }
}

/* ---------- users & sessions ---------- */
const publicUser = u => ({
  id: u.id, username: u.username, email: u.email, role: u.role,
  status: u.status, created_at: u.created_at, last_login: u.last_login
});

async function createSession(env, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const t = now();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t).run();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256Hex(token), userId, t, t + SESSION_SECONDS).run();
  return sessionCookie(token, SESSION_SECONDS);
}
async function currentUser(request, env) {
  const token = getCookie(request, 'session');
  if (!token) return null;
  return env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'`
  ).bind(await sha256Hex(token), now()).first();
}

/* ---------- API handlers ---------- */
function validate({ username, email, password }) {
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) return ['username', 'Username must be 3 to 24 letters, numbers or underscores.'];
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return ['email', 'Enter a valid email address.'];
  if (password.length < 10) return ['password', 'Password must be at least 10 characters.'];
  if (password.length > 128) return ['password', 'Password must be 128 characters or fewer.'];
  return null;
}

async function register(request, env) {
  const body = await readJson(request);
  const input = {
    username: String(body.username ?? '').trim(),
    email: String(body.email ?? '').trim().toLowerCase(),
    password: String(body.password ?? '')
  };
  const problem = validate(input);
  if (problem) return json({ error: problem[1], field: problem[0] }, 400);

  const count = await env.DB.prepare('SELECT COUNT(*) AS c FROM users').first('c');
  if (count > 0 && env.ALLOW_REGISTRATION === 'false') return json({ error: 'Registration is closed.' }, 403);
  const role = count === 0 ? 'admin' : 'user';   // first account becomes the administrator

  let id;
  try {
    const res = await env.DB.prepare(
      'INSERT INTO users (username, email, password_hash, role, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(input.username, input.email, await hashPassword(input.password), role, now(), now()).run();
    id = res.meta.last_row_id;
  } catch (err) {
    if (String(err).includes('UNIQUE')) return json({ error: 'That username or email is already registered.' }, 409);
    throw err;
  }
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  return json({ user: publicUser(user) }, 201, { 'Set-Cookie': await createSession(env, id) });
}

async function login(request, env) {
  const body = await readJson(request);
  const identifier = String(body.identifier ?? '').trim();
  const password = String(body.password ?? '');
  const generic = () => json({ error: 'Incorrect email, username or password.' }, 401);
  if (!identifier || !password || password.length > 128) return generic();

  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? OR username = ?')
    .bind(identifier, identifier).first();
  if (!user) { await burnTime(password); return generic(); }
  if (user.locked_until > now()) return json({ error: 'Too many failed attempts. Try again in a few minutes.' }, 429);

  if (!(await verifyPassword(password, user.password_hash))) {
    const fails = user.failed_count + 1;
    if (fails >= MAX_FAILS) {
      await env.DB.prepare('UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?').bind(now() + LOCK_SECONDS, user.id).run();
    } else {
      await env.DB.prepare('UPDATE users SET failed_count = ? WHERE id = ?').bind(fails, user.id).run();
    }
    return generic();
  }
  if (user.status !== 'active') return json({ error: 'This account is suspended. Contact an administrator.' }, 403);

  await env.DB.prepare('UPDATE users SET failed_count = 0, locked_until = 0, last_login = ? WHERE id = ?').bind(now(), user.id).run();
  return json({ user: publicUser(user) }, 200, { 'Set-Cookie': await createSession(env, user.id) });
}

async function logout(request, env) {
  const token = getCookie(request, 'session');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
}

async function changePassword(request, env, user) {
  const body = await readJson(request);
  const current = String(body.current ?? '');
  const next = String(body.next ?? '');
  if (!(await verifyPassword(current, user.password_hash))) return json({ error: 'Current password is incorrect.', field: 'current' }, 400);
  if (next.length < 10 || next.length > 128) return json({ error: 'New password must be 10 to 128 characters.', field: 'next' }, 400);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await hashPassword(next), user.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();   // sign out everywhere
  return json({ ok: true }, 200, { 'Set-Cookie': await createSession(env, user.id) });
}

async function adminUsers(request, env, url, admin) {
  if (url.pathname === '/api/admin/users' && request.method === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT id, username, email, role, status, created_at, last_login FROM users ORDER BY id'
    ).all();
    return json({ users: results });
  }
  const m = url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
  if (!m) return json({ error: 'Not found' }, 404);
  const id = Number(m[1]);
  if (id === admin.id) return json({ error: 'You cannot change your own account here.' }, 400);
  const target = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
  if (!target) return json({ error: 'User not found.' }, 404);

  if (request.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }
  if (request.method === 'PATCH') {
    const body = await readJson(request);
    if (body.role !== undefined) {
      if (!['user', 'admin'].includes(body.role)) return json({ error: 'Invalid role.' }, 400);
      await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(body.role, id).run();
    }
    if (body.status !== undefined) {
      if (!['active', 'suspended'].includes(body.status)) return json({ error: 'Invalid status.' }, 400);
      await env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(body.status, id).run();
      if (body.status === 'suspended') await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
    }
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

async function api(request, env, url) {
  const { pathname } = url;
  const method = request.method;

  if (method !== 'GET' && method !== 'HEAD') {           // basic CSRF defence on top of SameSite=Lax
    const origin = request.headers.get('Origin');
    if (origin) {
      let host;
      try { host = new URL(origin).host; } catch { host = null; }
      if (host !== url.host) return json({ error: 'Cross-site request blocked.' }, 403);
    }
  }

  if (pathname === '/api/register' && method === 'POST') return register(request, env);
  if (pathname === '/api/login' && method === 'POST') return login(request, env);
  if (pathname === '/api/logout' && method === 'POST') return logout(request, env);

  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Not signed in.' }, 401);

  if (pathname === '/api/me' && method === 'GET') return json({ user: publicUser(user) });
  if (pathname === '/api/change-password' && method === 'POST') return changePassword(request, env, user);
  if (pathname.startsWith('/api/admin/')) {
    if (user.role !== 'admin') return json({ error: 'Administrators only.' }, 403);
    return adminUsers(request, env, url, user);
  }
  return json({ error: 'Not found' }, 404);
}

/* ---------- pages: gate private pages, serve everything else as static assets ---------- */
async function pages(request, env, url) {
  const path = url.pathname.replace(/\.html$/, '').replace(/\/+$/, '');
  if (PROTECTED.includes(path)) {
    const user = await currentUser(request, env);
    if (!user) return withHeaders(Response.redirect(new URL('/login', url).toString(), 302), { 'Cache-Control': 'no-store' });
    if (path === '/admin' && user.role !== 'admin') {
      const denied = await env.ASSETS.fetch(new Request(new URL('/access-denied', url)));
      return withHeaders(new Response(denied.body, { status: 403, headers: denied.headers }), { 'Cache-Control': 'no-store' });
    }
    return withHeaders(await env.ASSETS.fetch(request), { 'Cache-Control': 'no-store' });
  }
  return withHeaders(await env.ASSETS.fetch(request));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      await ensureSchema(env);
      return url.pathname.startsWith('/api/') ? await api(request, env, url) : await pages(request, env, url);
    } catch (err) {
      console.error(err);
      return json({ error: 'Server error.' }, 500);
    }
  }
};
