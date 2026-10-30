// MySite API: accounts, email verification, sessions. Runs only for /api/*
const enc = new TextEncoder();
const SESSION_TTL = 30 * 24 * 3600;          // seconds
const CODE_TTL = 10 * 60 * 1000;             // ms
const RESEND_COOLDOWN = 60 * 1000;           // ms
const MAX_CODE_ATTEMPTS = 5;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });
const fail = (error, status = 400) => json({ error }, status);

/* ---------- crypto helpers ---------- */
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64url = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sha256 = async t => b64(await crypto.subtle.digest('SHA-256', enc.encode(t)));

async function hashPassword(pw, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  // 100,000 is the maximum PBKDF2 iteration count Workers allows
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256));
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const newCode = () => String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
const codeHash = (code, email) => sha256(code + ':' + email);

/* ---------- cookies & sessions ---------- */
const sessionCookie = (v, maxAge) => `session=${v}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? m[1] : null;
}
async function startSession(env, userId) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires < ?').bind(Date.now()),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)')
      .bind(await sha256(token), userId, Date.now() + SESSION_TTL * 1000),
  ]);
  return sessionCookie(token, SESSION_TTL);
}
async function currentUser(request, env) {
  const token = getCookie(request, 'session');
  if (!token) return null;
  return env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.pass_hash, u.pass_salt, s.token_hash
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires > ?`
  ).bind(await sha256(token), Date.now()).first();
}

/* ---------- Turnstile & email ---------- */
async function verifyTurnstile(env, request, token) {
  if (!token) return false;
  const f = new FormData();
  f.append('secret', env.TURNSTILE_SECRET);
  f.append('response', token);
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) f.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: f });
  return !!(await r.json()).success;
}
async function sendCode(env, email, code) {
  if (!env.RESEND_API_KEY) throw new Error('EMAIL_NOT_CONFIGURED');
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to: [email],
      subject: 'Your MySite verification code',
      text: `Your verification code is ${code}. It expires in 10 minutes.\n\nIf you did not sign up, you can ignore this email.`,
    }),
  });
  if (!r.ok) { console.error('Resend error', r.status, await r.text()); throw new Error('EMAIL_FAILED'); }
}

/* ---------- handlers ---------- */
const normEmail = e => String(e || '').trim().toLowerCase();

async function signup(b, request, env) {
  const name = String(b.name || '').trim().slice(0, 80);
  const email = normEmail(b.email);
  const pw = String(b.password || '');
  if (!name) return fail('Please enter your name.');
  if (!EMAIL_RE.test(email)) return fail('Please enter a valid email.');
  if (pw.length < 8 || pw.length > 200) return fail('Password must be 8 to 200 characters.');
  if (!(await verifyTurnstile(env, request, b.turnstile))) return fail('Cloudflare check failed. Please try again.');
  if (await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first())
    return fail('That email is already registered.', 409);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(pw, salt);
  const code = newCode();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO pending (email, name, pass_hash, pass_salt, code_hash, expires, attempts, last_sent)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?)
     ON CONFLICT(email) DO UPDATE SET name = excluded.name, pass_hash = excluded.pass_hash,
       pass_salt = excluded.pass_salt, code_hash = excluded.code_hash, expires = excluded.expires,
       attempts = 0, last_sent = excluded.last_sent`
  ).bind(email, name, hash, b64(salt), await codeHash(code, email), now + CODE_TTL, now).run();
  await sendCode(env, email, code);
  return json({ ok: true });
}

async function resend(b, request, env) {
  const email = normEmail(b.email);
  const p = await env.DB.prepare('SELECT last_sent FROM pending WHERE email = ?').bind(email).first();
  if (!p) return fail('Please sign up again.', 404);
  if (Date.now() - p.last_sent < RESEND_COOLDOWN) return fail('Please wait a minute before requesting another code.', 429);
  const code = newCode();
  const now = Date.now();
  await env.DB.prepare('UPDATE pending SET code_hash = ?, expires = ?, attempts = 0, last_sent = ? WHERE email = ?')
    .bind(await codeHash(code, email), now + CODE_TTL, now, email).run();
  await sendCode(env, email, code);
  return json({ ok: true });
}

async function verify(b, request, env) {
  const email = normEmail(b.email);
  const code = String(b.code || '').trim();
  const p = await env.DB.prepare('SELECT * FROM pending WHERE email = ?').bind(email).first();
  if (!p || Date.now() > p.expires) return fail('Code expired. Please resend.');
  if (p.attempts >= MAX_CODE_ATTEMPTS) {
    await env.DB.prepare('DELETE FROM pending WHERE email = ?').bind(email).run();
    return fail('Too many attempts. Please sign up again.', 429);
  }
  if (!safeEqual(await codeHash(code, email), p.code_hash)) {
    await env.DB.prepare('UPDATE pending SET attempts = attempts + 1 WHERE email = ?').bind(email).run();
    return fail('Incorrect code.');
  }
  await env.DB.prepare('INSERT OR IGNORE INTO users (email, name, pass_hash, pass_salt, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(email, p.name, p.pass_hash, p.pass_salt, Date.now()).run();
  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  await env.DB.prepare('DELETE FROM pending WHERE email = ?').bind(email).run();
  return json({ ok: true }, 200, { 'Set-Cookie': await startSession(env, user.id) });
}

async function login(b, request, env) {
  const email = normEmail(b.email);
  const pw = String(b.password || '');
  if (!(await verifyTurnstile(env, request, b.turnstile))) return fail('Cloudflare check failed. Please try again.');
  const u = await env.DB.prepare('SELECT id, pass_hash, pass_salt FROM users WHERE email = ?').bind(email).first();
  // Always hash, so unknown emails take as long as real ones
  const hash = await hashPassword(pw.slice(0, 200), u ? unb64(u.pass_salt) : new Uint8Array(16));
  if (!u || !safeEqual(hash, u.pass_hash)) return fail('Invalid email or password.', 401);
  return json({ ok: true }, 200, { 'Set-Cookie': await startSession(env, u.id) });
}

async function logout(b, request, env) {
  const token = getCookie(request, 'session');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
}

async function changePassword(b, request, env) {
  const me = await currentUser(request, env);
  if (!me) return fail('Please log in.', 401);
  const next = String(b.next || '');
  if (next.length < 8 || next.length > 200) return fail('New password must be 8 to 200 characters.');
  const cur = await hashPassword(String(b.current || '').slice(0, 200), unb64(me.pass_salt));
  if (!safeEqual(cur, me.pass_hash)) return fail('Current password is wrong.', 403);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?').bind(await hashPassword(next, salt), b64(salt), me.id),
    // sign out every other device
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(me.id, me.token_hash),
  ]);
  return json({ ok: true });
}

async function deleteAccount(b, request, env) {
  const me = await currentUser(request, env);
  if (!me) return fail('Please log in.', 401);
  const cur = await hashPassword(String(b.password || '').slice(0, 200), unb64(me.pass_salt));
  if (!safeEqual(cur, me.pass_hash)) return fail('Password is wrong.', 403);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(me.id),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(me.id),
  ]);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
}

const POST_ROUTES = { signup, resend, verify, login, logout, password: changePassword, delete: deleteAccount };

/* ---------- router ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    const route = url.pathname.slice(5).replace(/\/$/, '');
    try {
      if (request.method === 'GET' && route === 'me') {
        const me = await currentUser(request, env);
        return json({ user: me ? { name: me.name, email: me.email } : null });
      }
      const handler = request.method === 'POST' && Object.hasOwn(POST_ROUTES, route) ? POST_ROUTES[route] : null;
      if (!handler) return fail('Not found', 404);
      const origin = request.headers.get('Origin');
      if (origin && origin !== url.origin) return fail('Bad origin', 403);
      let body;
      try { body = await request.json(); } catch { return fail('Invalid request'); }
      return await handler(body || {}, request, env);
    } catch (e) {
      if (e.message === 'EMAIL_NOT_CONFIGURED') return fail('Email sending is not set up yet.', 503);
      if (e.message === 'EMAIL_FAILED') return fail('Could not send the email. Please try again.', 502);
      console.error(e);
      return fail('Server error', 500);
    }
  },
};
