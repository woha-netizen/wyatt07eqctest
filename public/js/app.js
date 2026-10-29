const $ = id => document.getElementById(id);
const norm = p => p.replace(/\.html$/, '').replace(/\/+$/, '');
const fmt = ts => (ts ? new Date(ts * 1000).toLocaleString() : 'Never');

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

function show(el, text, kind) {
  el.textContent = text;
  el.className = `msg ${kind}`;
  el.classList.remove('hidden');
}

async function currentUser() {
  const r = await api('/api/me');
  return r.ok ? r.data.user : null;
}

function applyNav(user) {
  document.querySelectorAll('[data-auth="in"]').forEach(e => e.classList.toggle('hidden', !user));
  document.querySelectorAll('[data-auth="out"]').forEach(e => e.classList.toggle('hidden', !!user));
  document.querySelectorAll('[data-auth="admin"]').forEach(e => e.classList.toggle('hidden', !(user && user.role === 'admin')));
  const chip = $('user-chip');
  if (chip) chip.textContent = user ? `Signed in as ${user.username}` : '';
  document.querySelectorAll('nav a[href]').forEach(a => {
    if (norm(new URL(a.href).pathname) === norm(location.pathname)) a.classList.add('active');
  });
  const logout = $('logout');
  if (logout) logout.addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' });
    location.href = '/login';
  });
}

/* ---------- pages ---------- */
function setupAuthForm(kind) {
  const form = $('auth-form');
  const msg = $('msg');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    msg.classList.add('hidden');
    const data = Object.fromEntries(new FormData(form));
    if (kind === 'register' && data.password !== data.confirm) {
      return show(msg, 'Passwords do not match.', 'error');
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    const r = kind === 'login'
      ? await api('/api/login', { method: 'POST', body: { identifier: data.identifier, password: data.password } })
      : await api('/api/register', { method: 'POST', body: { username: data.username, email: data.email, password: data.password } });
    if (r.ok) { location.href = '/dashboard'; return; }
    button.disabled = false;
    show(msg, r.data.error || 'Something went wrong. Try again.', 'error');
  });
}

function setupDashboard(user) {
  $('welcome').textContent = `Welcome, ${user.username}`;
  $('d-role').textContent = user.role === 'admin' ? 'Administrator' : 'Standard user';
  $('d-since').textContent = new Date(user.created_at * 1000).toLocaleDateString();
  $('d-last').textContent = fmt(user.last_login);
  $('d-time').textContent = new Date().toLocaleString();
}

function setupProfile(user) {
  $('p-username').textContent = user.username;
  $('p-email').textContent = user.email;
  $('p-role').textContent = user.role === 'admin' ? 'Administrator' : 'Standard user';
  $('p-status').textContent = user.status;
  $('p-since').textContent = fmt(user.created_at);
  $('p-last').textContent = fmt(user.last_login);

  const form = $('pw-form');
  const msg = $('msg');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    msg.classList.add('hidden');
    const d = Object.fromEntries(new FormData(form));
    if (d.next !== d.confirm) return show(msg, 'New passwords do not match.', 'error');
    const r = await api('/api/change-password', { method: 'POST', body: { current: d.current, next: d.next } });
    if (r.ok) { form.reset(); show(msg, 'Password changed. Other devices have been signed out.', 'success'); }
    else show(msg, r.data.error || 'Could not change password.', 'error');
  });
}

function cell(text) { const td = document.createElement('td'); td.textContent = text; return td; }
function badge(text, cls) { const s = document.createElement('span'); s.className = `badge ${cls || ''}`; s.textContent = text; return s; }
function actionButton(label, cls, onClick) {
  const b = document.createElement('button');
  b.className = `btn small ${cls}`; b.textContent = label; b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

async function setupAdmin(me) {
  const body = $('users-body');
  const msg = $('msg');

  async function patch(id, change) {
    const r = await api(`/api/admin/users/${id}`, { method: 'PATCH', body: change });
    if (!r.ok) show(msg, r.data.error || 'Update failed.', 'error'); else msg.classList.add('hidden');
    load();
  }
  async function remove(user) {
    if (!confirm(`Delete ${user.username}? This cannot be undone.`)) return;
    const r = await api(`/api/admin/users/${user.id}`, { method: 'DELETE' });
    if (!r.ok) show(msg, r.data.error || 'Delete failed.', 'error'); else msg.classList.add('hidden');
    load();
  }

  async function load() {
    const r = await api('/api/admin/users');
    if (!r.ok) return show(msg, r.data.error || 'Could not load users.', 'error');
    body.replaceChildren();
    for (const u of r.data.users) {
      const tr = document.createElement('tr');
      tr.append(cell(u.username), cell(u.email));
      const role = document.createElement('td'); role.append(badge(u.role, u.role === 'admin' ? 'warn' : '')); tr.append(role);
      const st = document.createElement('td'); st.append(badge(u.status, u.status === 'active' ? '' : 'bad')); tr.append(st);
      tr.append(cell(fmt(u.last_login)));
      const act = document.createElement('td');
      if (u.id === me.id) { act.textContent = 'You'; }
      else {
        const wrap = document.createElement('div'); wrap.className = 'actions';
        wrap.append(
          actionButton(u.role === 'admin' ? 'Make user' : 'Make admin', 'secondary', () => patch(u.id, { role: u.role === 'admin' ? 'user' : 'admin' })),
          actionButton(u.status === 'active' ? 'Suspend' : 'Reactivate', 'secondary', () => patch(u.id, { status: u.status === 'active' ? 'suspended' : 'active' })),
          actionButton('Delete', 'danger', () => remove(u))
        );
        act.append(wrap);
      }
      tr.append(act);
      body.append(tr);
    }
  }
  load();
}

document.addEventListener('DOMContentLoaded', async () => {
  const page = document.body.dataset.page;
  const user = await currentUser();
  applyNav(user);

  if (page === 'login' || page === 'register') {
    if (user) { location.href = '/dashboard'; return; }
    setupAuthForm(page);
    return;
  }
  if (['dashboard', 'profile', 'admin'].includes(page)) {
    if (!user) { location.href = '/login'; return; }
    if (page === 'dashboard') setupDashboard(user);
    if (page === 'profile') setupProfile(user);
    if (page === 'admin') setupAdmin(user);
  }
});
