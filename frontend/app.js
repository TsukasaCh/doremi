'use strict';

const $ = (s) => document.querySelector(s);
const api = async (path, opts = {}) => {
  const res = await fetch('/api' + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
};

function toast(msg, kind = 'ok') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast ${kind}`;
  setTimeout(() => t.classList.add('hidden'), 4000);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z');
  return d.toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' });
}
function daysLeft(iso) {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  return Math.ceil(ms / 86400000);
}

// ---------- Auth ----------
async function checkAuth() {
  try {
    const me = await api('/auth/me');
    $('#whoami').textContent = '👤 ' + me.user;
    showApp();
  } catch {
    showLogin();
  }
}
function showLogin() { $('#login-view').classList.remove('hidden'); $('#app-view').classList.add('hidden'); }
function showApp() { $('#login-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); refreshAll(); }

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ user: $('#login-user').value, password: $('#login-pass').value }),
    });
    checkAuth();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});
$('#logout-btn').addEventListener('click', async () => {
  await api('/auth/logout', { method: 'POST' });
  showLogin();
});

// ---------- Data ----------
let USERS = [];
async function loadUsers() {
  USERS = await api('/users');
  renderUsers();
}
async function loadAgentStatus() {
  const el = $('#agent-status');
  el.innerHTML = '';
  try {
    const s = await api('/agents/status');
    for (const [name, info] of Object.entries(s)) {
      const pill = document.createElement('div');
      pill.className = 'agent-pill';
      pill.title = info.online ? (info.host || '') : info.error;
      pill.innerHTML = `<span class="dot ${info.online ? 'on' : 'off'}"></span>${name}`;
      el.appendChild(pill);
    }
  } catch { /* not logged in yet */ }
}
function refreshAll() { loadUsers().catch((e) => toast(e.message, 'err')); loadAgentStatus(); }

// ---------- Render users ----------
function renderUsers() {
  const body = $('#users-body');
  body.innerHTML = '';
  $('#users-empty').classList.toggle('hidden', USERS.length > 0);

  for (const u of USERS) {
    const tr = document.createElement('tr');
    const dl = daysLeft(u.expires_at);
    const expiryTxt = u.expires_at
      ? `${fmtDate(u.expires_at)}${dl !== null ? ` <span class="muted">(${dl > 0 ? dl + 'h lagi' : 'lewat'})</span>` : ''}`
      : '<span class="muted">Tidak ada</span>';

    tr.innerHTML = `
      <td><strong>${esc(u.name)}</strong></td>
      <td><code>${u.static_ip || '—'}</code></td>
      <td><span class="badge ${u.status}">${u.status}</span></td>
      <td>${fmtDate(u.created_at)}</td>
      <td>${expiryTxt}</td>
      <td>${u.acl.length} rule${u.acl.length !== 1 ? 's' : ''}</td>
      <td class="actions"></td>`;
    const actions = tr.querySelector('.actions');

    const aclBtn = mkBtn('ACL', 'small', () => openAclModal(u));
    const renewBtn = mkBtn('Perpanjang', 'small ghost', () => openRenewModal(u));
    const delBtn = mkBtn('Hapus', 'small danger', () => deleteUser(u));
    actions.append(aclBtn, renewBtn, delBtn);
    body.appendChild(tr);
  }
}
function mkBtn(text, cls, onclick) {
  const b = document.createElement('button');
  b.className = cls;
  b.textContent = text;
  b.addEventListener('click', onclick);
  return b;
}
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

// ---------- Modal helper ----------
function openModal(html) {
  $('#modal').innerHTML = html;
  $('#modal-backdrop').classList.remove('hidden');
}
function closeModal() { $('#modal-backdrop').classList.add('hidden'); }
$('#modal-backdrop').addEventListener('click', (e) => { if (e.target.id === 'modal-backdrop') closeModal(); });

// ---------- Create user ----------
$('#new-user-btn').addEventListener('click', () => {
  openModal(`
    <h2>Buat User VPN Baru</h2>
    <label>Nama user<input id="nu-name" placeholder="mis. budi.santoso" /></label>
    <div class="row">
      <label>Masa aktif (hari)<input id="nu-days" type="number" min="1" placeholder="mis. 30 (kosong = permanen)" /></label>
    </div>
    <label>Catatan (opsional)<input id="nu-note" placeholder="mis. Divisi Marketing" /></label>
    <div class="modal-actions">
      <button class="ghost" id="nu-cancel">Batal</button>
      <button class="primary" id="nu-create">Buat</button>
    </div>`);
  $('#nu-cancel').addEventListener('click', closeModal);
  $('#nu-create').addEventListener('click', createUser);
  $('#nu-name').focus();
});

async function createUser() {
  const name = $('#nu-name').value.trim();
  const days = $('#nu-days').value.trim();
  const note = $('#nu-note').value.trim();
  const btn = $('#nu-create');
  btn.disabled = true; btn.textContent = 'Membuat...';
  try {
    const r = await api('/users', {
      method: 'POST',
      body: JSON.stringify({ name, expiryDays: days || null, note }),
    });
    toast(`User "${name}" dibuat (IP ${r.user.static_ip})`);
    showOvpnModal(name, r.ovpn);
    loadUsers();
  } catch (err) {
    toast(err.message, 'err');
    btn.disabled = false; btn.textContent = 'Buat';
  }
}

function showOvpnModal(name, ovpn) {
  openModal(`
    <h2>Config untuk ${esc(name)}</h2>
    <p class="muted">File .ovpn ini hanya ditampilkan sekali. Unduh dan serahkan ke user.</p>
    <pre class="ovpn">${esc(ovpn)}</pre>
    <div class="modal-actions">
      <button class="ghost" id="ov-close">Tutup</button>
      <button class="primary" id="ov-dl">⬇ Unduh ${esc(name)}.ovpn</button>
    </div>`);
  $('#ov-close').addEventListener('click', closeModal);
  $('#ov-dl').addEventListener('click', () => {
    const blob = new Blob([ovpn], { type: 'application/x-openvpn-profile' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${name}.ovpn`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

// ---------- Renew ----------
function openRenewModal(u) {
  openModal(`
    <h2>Perpanjang: ${esc(u.name)}</h2>
    <p class="muted">Expiry saat ini: ${u.expires_at ? fmtDate(u.expires_at) : 'permanen'}</p>
    <label>Aktif untuk (hari, dihitung dari sekarang)
      <input id="rn-days" type="number" min="1" placeholder="mis. 30. Kosong = permanen" /></label>
    <div class="modal-actions">
      <button class="ghost" id="rn-cancel">Batal</button>
      <button class="primary" id="rn-save">Simpan</button>
    </div>`);
  $('#rn-cancel').addEventListener('click', closeModal);
  $('#rn-save').addEventListener('click', async () => {
    const days = $('#rn-days').value.trim();
    try {
      await api(`/users/${u.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ expiryDays: days === '' ? null : parseInt(days, 10) }),
      });
      toast('Expiry diperbarui');
      closeModal(); loadUsers();
    } catch (err) { toast(err.message, 'err'); }
  });
}

// ---------- Delete ----------
async function deleteUser(u) {
  if (!confirm(`Hapus & revoke user "${u.name}"? Sertifikat dicabut dan ACL iptables dihapus.`)) return;
  try {
    const r = await api(`/users/${u.id}`, { method: 'DELETE' });
    if (r.warning) toast(r.warning + ': ' + (r.errors || []).join('; '), 'err');
    else toast(`User "${u.name}" dihapus`);
    loadUsers();
  } catch (err) { toast(err.message, 'err'); }
}

// ---------- ACL ----------
function openAclModal(u) {
  const render = (rules) => `
    <h2>ACL: ${esc(u.name)} <span class="muted" style="font-weight:400">(${u.static_ip})</span></h2>
    <p class="muted">Aturan diterapkan otomatis ke iptables di Proxmox host.</p>
    <div class="acl-list" id="acl-list">
      ${rules.length === 0 ? '<div class="muted">Belum ada rule. Default policy VPN berlaku.</div>' : ''}
      ${rules.map((r) => `
        <div class="acl-row">
          <span class="act-${r.action}">${r.action.toUpperCase()}</span>
          <span>→ <code>${esc(r.dst)}</code></span>
          <span class="muted">${r.proto}${r.port ? ':' + r.port : ''}</span>
          <span class="spacer" style="flex:1"></span>
          <button class="small danger" data-rule="${r.id}">✕</button>
        </div>`).join('')}
    </div>
    <div class="acl-add">
      <div><label>Aksi</label><select id="acl-action"><option value="allow">allow</option><option value="deny">deny</option></select></div>
      <div style="flex:1.4"><label>Tujuan (IP/CIDR)</label><input id="acl-dst" placeholder="10.10.10.0/24" /></div>
      <div><label>Proto</label><select id="acl-proto"><option>all</option><option>tcp</option><option>udp</option><option>icmp</option></select></div>
      <div><label>Port</label><input id="acl-port" placeholder="mis. 443 / 80:90" style="width:90px" /></div>
      <button class="primary" id="acl-add-btn">Tambah</button>
    </div>
    <div class="modal-actions"><button class="ghost" id="acl-close">Tutup</button></div>`;

  const draw = (rules) => {
    openModal(render(rules));
    $('#acl-close').addEventListener('click', () => { closeModal(); loadUsers(); });
    $('#acl-add-btn').addEventListener('click', () => addRule(u, draw));
    $('#acl-list').querySelectorAll('[data-rule]').forEach((b) =>
      b.addEventListener('click', () => delRule(u, b.dataset.rule, draw)));
  };
  draw(u.acl);
}

async function addRule(u, draw) {
  const body = {
    action: $('#acl-action').value,
    dst: $('#acl-dst').value.trim(),
    proto: $('#acl-proto').value,
    port: $('#acl-port').value.trim() || null,
  };
  try {
    const r = await api(`/users/${u.id}/acl`, { method: 'POST', body: JSON.stringify(body) });
    u.acl = r.acl;
    toast('Rule ditambahkan & diterapkan');
    draw(u.acl);
  } catch (err) { toast(err.message, 'err'); }
}
async function delRule(u, ruleId, draw) {
  try {
    await api(`/users/${u.id}/acl/${ruleId}`, { method: 'DELETE' });
    u.acl = u.acl.filter((r) => String(r.id) !== String(ruleId));
    toast('Rule dihapus');
    draw(u.acl);
  } catch (err) { toast(err.message, 'err'); }
}

// ---------- iptables & audit views ----------
$('#iptables-btn').addEventListener('click', async () => {
  try {
    const r = await api('/agents/iptables');
    openModal(`
      <h2>iptables ACL (Proxmox host)</h2>
      <pre class="ovpn">${esc(r.raw || JSON.stringify(r, null, 2))}</pre>
      <div class="modal-actions"><button class="ghost" onclick="document.getElementById('modal-backdrop').classList.add('hidden')">Tutup</button></div>`);
  } catch (err) { toast(err.message, 'err'); }
});

$('#audit-btn').addEventListener('click', async () => {
  try {
    const rows = await api('/audit');
    openModal(`
      <h2>Audit Log</h2>
      <div style="max-height:400px;overflow:auto">
      <table><thead><tr><th>Waktu</th><th>Aktor</th><th>Aksi</th><th>Target</th><th>Detail</th></tr></thead>
      <tbody>${rows.map((r) => `<tr>
        <td>${fmtDate(r.ts)}</td><td>${esc(r.actor)}</td>
        <td>${r.ok ? '' : '⚠️ '}${esc(r.action)}</td><td>${esc(r.target || '')}</td>
        <td class="muted">${esc(r.detail || '')}</td></tr>`).join('')}</tbody></table></div>
      <div class="modal-actions"><button class="ghost" onclick="document.getElementById('modal-backdrop').classList.add('hidden')">Tutup</button></div>`);
  } catch (err) { toast(err.message, 'err'); }
});

$('#refresh-btn').addEventListener('click', refreshAll);

// ---------- Boot ----------
checkAuth();
setInterval(loadAgentStatus, 30000);
