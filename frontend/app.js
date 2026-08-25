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
let GROUPS = [];
async function loadUsers() {
  USERS = await api('/users');
  renderUsers();
}
async function loadGroups() {
  GROUPS = await api('/groups');
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
function refreshAll() {
  loadUsers().catch((e) => toast(e.message, 'err'));
  loadGroups().catch(() => {});
  loadAgentStatus();
}

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
      <td>${u.acl.length} rule${u.acl.length !== 1 ? 's' : ''}${(u.groups && u.groups.length) ? ` <span class="muted">+${u.groups.length} grp</span>` : ''}</td>
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

// ---------- ACL (per-user: manual rules + groups) ----------
async function refetchUser(u) {
  const fresh = await api(`/users/${u.id}`);
  Object.assign(u, fresh);
}

function ruleRowHtml(r, removable) {
  return `<div class="acl-row">
    <span class="act-${r.action}">${r.action.toUpperCase()}</span>
    <span>→ <code>${esc(r.dst)}</code></span>
    <span class="muted">${r.proto}${r.port ? ':' + r.port : ''}</span>
    <span style="flex:1"></span>
    ${removable ? `<button class="small danger" data-rule="${r.id}">✕</button>` : ''}
  </div>`;
}

function openAclModal(u) {
  const draw = () => {
    const assigned = u.groups || [];
    const assignedIds = new Set(assigned.map((g) => g.id));
    const available = GROUPS.filter((g) => !assignedIds.has(g.id));

    openModal(`
      <h2>ACL: ${esc(u.name)} <span class="muted" style="font-weight:400">(${u.static_ip})</span></h2>
      <p class="muted">Aturan (manual + group) diterapkan otomatis ke iptables di Proxmox host.</p>

      <h3 style="margin:14px 0 6px;font-size:14px">Group terpasang</h3>
      <div id="grp-chips" class="chips">
        ${assigned.length === 0 ? '<span class="muted">Belum ada group.</span>' : ''}
        ${assigned.map((g) => `<span class="chip">${esc(g.name)}<button class="chip-x" data-grp="${g.id}">✕</button></span>`).join('')}
      </div>
      <div class="acl-add" style="margin-top:10px">
        <div style="flex:1"><label>Pilih group</label>
          <select id="grp-select">
            <option value="">— pilih group —</option>
            ${available.map((g) => `<option value="${g.id}">${esc(g.name)} (${g.rules.length} rule)</option>`).join('')}
          </select>
        </div>
        <button class="primary" id="grp-apply">Terapkan</button>
      </div>

      <h3 style="margin:20px 0 6px;font-size:14px">Rule manual</h3>
      <div class="acl-list" id="acl-list">
        ${(u.acl || []).length === 0 ? '<div class="muted">Belum ada rule manual.</div>' : ''}
        ${(u.acl || []).map((r) => ruleRowHtml(r, true)).join('')}
      </div>
      <div class="acl-add">
        <div><label>Aksi</label><select id="acl-action"><option value="allow">allow</option><option value="deny">deny</option></select></div>
        <div style="flex:1.4"><label>Tujuan (IP/CIDR)</label><input id="acl-dst" placeholder="10.10.10.0/24" /></div>
        <div><label>Proto</label><select id="acl-proto"><option>all</option><option>tcp</option><option>udp</option><option>icmp</option></select></div>
        <div><label>Port</label><input id="acl-port" placeholder="443 / 80:90" style="width:90px" /></div>
        <button class="primary" id="acl-add-btn">Tambah</button>
      </div>
      <div class="modal-actions"><button class="ghost" id="acl-close">Tutup</button></div>`);

    $('#acl-close').addEventListener('click', () => { closeModal(); loadUsers(); });
    $('#acl-add-btn').addEventListener('click', () => addRule(u, draw));
    $('#grp-apply').addEventListener('click', () => applyGroup(u, draw));
    $('#acl-list').querySelectorAll('[data-rule]').forEach((b) =>
      b.addEventListener('click', () => delRule(u, b.dataset.rule, draw)));
    $('#grp-chips').querySelectorAll('[data-grp]').forEach((b) =>
      b.addEventListener('click', () => removeGroup(u, b.dataset.grp, draw)));
  };
  draw();
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
    toast('Rule manual ditambahkan & diterapkan');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function delRule(u, ruleId, draw) {
  try {
    await api(`/users/${u.id}/acl/${ruleId}`, { method: 'DELETE' });
    u.acl = u.acl.filter((r) => String(r.id) !== String(ruleId));
    toast('Rule dihapus');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function applyGroup(u, draw) {
  const groupId = $('#grp-select').value;
  if (!groupId) return;
  try {
    await api(`/users/${u.id}/groups`, { method: 'POST', body: JSON.stringify({ groupId: parseInt(groupId, 10) }) });
    await refetchUser(u);
    toast('Group diterapkan ke user');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function removeGroup(u, groupId, draw) {
  try {
    await api(`/users/${u.id}/groups/${groupId}`, { method: 'DELETE' });
    await refetchUser(u);
    toast('Group dilepas dari user');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}

// ---------- Group manager ----------
function openGroupsModal() {
  const draw = () => {
    openModal(`
      <h2>Kelola ACL Group</h2>
      <p class="muted">Group = kumpulan rule yang bisa dipakai ulang. Edit rule group → semua user yang pakai otomatis ke-update.</p>
      <div class="acl-add" style="margin:10px 0 16px">
        <div style="flex:1"><label>Nama group baru</label><input id="ng-name" placeholder="mis. Web Only" /></div>
        <div style="flex:1.4"><label>Deskripsi (opsional)</label><input id="ng-desc" placeholder="mis. HTTP/HTTPS saja" /></div>
        <button class="primary" id="ng-create">Buat Group</button>
      </div>
      <div id="groups-list">
        ${GROUPS.length === 0 ? '<div class="muted">Belum ada group.</div>' : ''}
        ${GROUPS.map((g) => `
          <div class="card" style="margin-bottom:12px;padding:14px">
            <div style="display:flex;align-items:center;gap:10px">
              <strong>${esc(g.name)}</strong>
              <span class="muted" style="font-size:12px">${esc(g.description || '')}</span>
              <span style="flex:1"></span>
              <span class="muted" style="font-size:12px">${g.members} user</span>
              <button class="small danger" data-delgrp="${g.id}">Hapus group</button>
            </div>
            <div class="acl-list" style="margin-top:8px">
              ${g.rules.length === 0 ? '<div class="muted">Belum ada rule.</div>' : ''}
              ${g.rules.map((r) => `<div class="acl-row">
                <span class="act-${r.action}">${r.action.toUpperCase()}</span>
                <span>→ <code>${esc(r.dst)}</code></span>
                <span class="muted">${r.proto}${r.port ? ':' + r.port : ''}</span>
                <span style="flex:1"></span>
                <button class="small danger" data-grp="${g.id}" data-rule="${r.id}">✕</button>
              </div>`).join('')}
            </div>
            <div class="acl-add" style="margin-top:8px">
              <div><label>Aksi</label><select data-f="action" data-g="${g.id}"><option value="allow">allow</option><option value="deny">deny</option></select></div>
              <div style="flex:1.4"><label>Tujuan (IP/CIDR)</label><input data-f="dst" data-g="${g.id}" placeholder="10.10.10.0/24" /></div>
              <div><label>Proto</label><select data-f="proto" data-g="${g.id}"><option>all</option><option>tcp</option><option>udp</option><option>icmp</option></select></div>
              <div><label>Port</label><input data-f="port" data-g="${g.id}" placeholder="443" style="width:80px" /></div>
              <button class="primary small" data-addrule="${g.id}">+ Rule</button>
            </div>
          </div>`).join('')}
      </div>
      <div class="modal-actions"><button class="ghost" id="grp-mgr-close">Tutup</button></div>`);

    $('#grp-mgr-close').addEventListener('click', () => { closeModal(); loadUsers(); });
    $('#ng-create').addEventListener('click', () => createGroup(draw));
    $('#groups-list').querySelectorAll('[data-delgrp]').forEach((b) =>
      b.addEventListener('click', () => deleteGroup(b.dataset.delgrp, draw)));
    $('#groups-list').querySelectorAll('[data-addrule]').forEach((b) =>
      b.addEventListener('click', () => addGroupRule(b.dataset.addrule, draw)));
    $('#groups-list').querySelectorAll('[data-grp][data-rule]').forEach((b) =>
      b.addEventListener('click', () => delGroupRule(b.dataset.grp, b.dataset.rule, draw)));
  };
  draw();
}

async function createGroup(draw) {
  const name = $('#ng-name').value.trim();
  const description = $('#ng-desc').value.trim();
  try {
    await api('/groups', { method: 'POST', body: JSON.stringify({ name, description }) });
    await loadGroups();
    toast('Group dibuat');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function deleteGroup(id, draw) {
  if (!confirm('Hapus group ini? Rule-nya dilepas dari semua user yang memakainya.')) return;
  try {
    await api(`/groups/${id}`, { method: 'DELETE' });
    await loadGroups();
    toast('Group dihapus');
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function addGroupRule(gid, draw) {
  const q = (f) => document.querySelector(`[data-f="${f}"][data-g="${gid}"]`);
  const body = {
    action: q('action').value,
    dst: q('dst').value.trim(),
    proto: q('proto').value,
    port: q('port').value.trim() || null,
  };
  try {
    const r = await api(`/groups/${gid}/rules`, { method: 'POST', body: JSON.stringify(body) });
    if (r.warning) toast('Rule ditambah, tapi sebagian user gagal update: ' + r.warning.join('; '), 'err');
    else toast('Rule group ditambahkan (semua user ke-update)');
    await loadGroups();
    draw();
  } catch (err) { toast(err.message, 'err'); }
}
async function delGroupRule(gid, ruleId, draw) {
  try {
    await api(`/groups/${gid}/rules/${ruleId}`, { method: 'DELETE' });
    toast('Rule group dihapus (semua user ke-update)');
    await loadGroups();
    draw();
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

$('#groups-btn').addEventListener('click', () => {
  loadGroups().then(openGroupsModal).catch((e) => toast(e.message, 'err'));
});

$('#refresh-btn').addEventListener('click', refreshAll);

// ---------- Boot ----------
checkAuth();
setInterval(loadAgentStatus, 30000);
