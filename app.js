// Shared client-side logic for the IAM demo.
// Behind Cloudflare Access, /cdn-cgi/access/get-identity returns the signed-in user.
// Outside Access (e.g. local preview) it fails, so we fall back to a demo identity.

const DEMO_IDENTITY = {
  name: 'Demo User',
  email: 'demo.user@example.com',
  idp: { type: 'demo' },
  groups: [{ name: 'employees' }],
  geo: { country: 'AU' },
  demo: true
};

async function getIdentity() {
  try {
    const res = await fetch('/cdn-cgi/access/get-identity', { credentials: 'same-origin' });
    if (!res.ok) throw new Error('Not behind Access');
    return await res.json();
  } catch {
    return DEMO_IDENTITY;
  }
}

function isAdmin(identity) {
  const groups = (identity.groups || []).map(g => (g.name || g).toLowerCase());
  return groups.includes('admins');
}

const $ = id => document.getElementById(id);
const setText = (id, value) => { const el = $(id); if (el) el.textContent = value ?? '—'; };

function markActiveNav() {
  const here = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('nav a[href]').forEach(a => {
    if (a.getAttribute('href') === here) a.classList.add('active');
  });
}

async function initPage() {
  markActiveNav();
  const identity = await getIdentity();
  const admin = isAdmin(identity);

  setText('user-chip', identity.email ? `Signed in as ${identity.email}` : 'Not signed in');
  document.querySelectorAll('[data-admin-only]').forEach(el => el.classList.toggle('hidden', !admin));

  const logout = $('logout');
  if (logout) logout.href = identity.demo ? '#' : '/cdn-cgi/access/logout';

  // Page-specific hooks
  if ($('profile-name')) renderProfile(identity, admin);
  if ($('admin-gate')) renderAdminGate(admin, identity);
  if ($('session-time')) setText('session-time', new Date().toLocaleString());
  return identity;
}

function renderProfile(identity, admin) {
  setText('profile-name', identity.name);
  setText('profile-email', identity.email);
  setText('profile-idp', identity.idp && identity.idp.type);
  setText('profile-country', identity.geo && identity.geo.country);
  setText('profile-groups', (identity.groups || []).map(g => g.name || g).join(', ') || 'none');
  setText('profile-role', admin ? 'Administrator' : 'Standard user');
  setText('profile-mode', identity.demo ? 'Demo (not behind Access)' : 'Cloudflare Access');
  setText('profile-json', JSON.stringify(identity, null, 2));
}

// NOTE: this only hides the UI. Real enforcement must be an Access policy on /admin*.
function renderAdminGate(admin, identity) {
  $('admin-gate').classList.toggle('hidden', admin);
  $('admin-content').classList.toggle('hidden', !admin);
  if (identity.demo) $('demo-toggle').classList.remove('hidden');
}

function toggleDemoAdmin() {
  DEMO_IDENTITY.groups = isAdmin(DEMO_IDENTITY) ? [{ name: 'employees' }] : [{ name: 'admins' }];
  initPage();
}

document.addEventListener('DOMContentLoaded', initPage);
