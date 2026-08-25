# OpenVPN Manager

Web dashboard untuk mengelola user OpenVPN: **buat user**, **hapus/revoke**, **expiry otomatis**, dan **manajemen ACL** — dengan **auto-konfigurasi iptables** di Proxmox host lewat sebuah *agent*.

```
┌────────────────────┐      HTTPS/JSON       ┌───────────────────────────┐
│   Browser (admin)  │  ───────────────────► │   Dashboard backend       │
│   frontend (SPA)   │                        │   Node.js + Express        │
└────────────────────┘                        │   SQLite + scheduler       │
                                               └───────────┬───────────────┘
                                    POST /rpc (Bearer token)│
                          ┌──────────────────────────────────┼────────────────────────────┐
                          ▼                                                                 ▼
             ┌───────────────────────────┐                            ┌────────────────────────────┐
             │  Agent @ OpenVPN server    │                            │  Agent @ Proxmox host        │
             │  10.10.10.101  ROLE=openvpn│                            │  10.10.10.1   ROLE=proxmox   │
             │  • easy-rsa build/revoke   │                            │  • iptables per-user ACL     │
             │  • client-config-dir (IP)  │                            │    chains (VPN_ACL)          │
             └───────────────────────────┘                            └────────────────────────────┘
```

Satu file agent yang sama dijalankan di kedua host; variabel `ROLE` menentukan
kemampuan mana yang aktif.

---

## Komponen

| Folder | Isi |
|--------|-----|
| `backend/` | API dashboard (Node.js/Express), DB SQLite, scheduler expiry |
| `frontend/` | Dashboard single-page (HTML/CSS/JS, tanpa build) |
| `agent/` | Agent host (Python 3, stdlib saja) untuk kedua host |
| `deploy/` | systemd unit + skrip instalasi |

---

## 1. Menjalankan backend (dashboard)

Butuh Node.js 18+.

```bash
cd backend
cp .env.example .env
#   ↳ WAJIB edit: ADMIN_PASSWORD, SESSION_SECRET, dan token agent
npm install
npm start
```

Buka `http://localhost:8080`, login dengan `ADMIN_USER` / `ADMIN_PASSWORD`.

Backend menyimpan state (user, ACL, audit) di `backend/data/openvpn-manager.db`.
Cert & key **tidak** disimpan di dashboard — hanya ada di OpenVPN host. File `.ovpn`
ditampilkan **sekali** saat pembuatan agar bisa diunduh dan diserahkan ke user.

## 2. Memasang agent di kedua host

Salin folder repo ke tiap host, lalu:

```bash
sudo ./deploy/install-agent.sh
sudo nano /etc/openvpn-agent.env     # set AGENT_TOKEN, ROLE, path
sudo systemctl enable --now openvpn-agent
```

**OpenVPN server (10.10.10.101):** `ROLE=openvpn`, isi `EASYRSA_DIR`, `TA_KEY`,
`VPN_REMOTE`, dst. **Proxmox host (10.10.10.1):** `ROLE=proxmox`, isi `VPN_IFACE`.

Token di `/etc/openvpn-agent.env` tiap host harus **sama persis** dengan
`OPENVPN_AGENT_TOKEN` / `PROXMOX_AGENT_TOKEN` di `backend/.env`.

## 3. Prasyarat OpenVPN server

Agent memakai Easy-RSA 3 yang sudah ter-init (`easyrsa init-pki`, `build-ca`).
`server.conf` OpenVPN harus mengaktifkan:

```
client-config-dir /etc/openvpn/ccd      # untuk IP statik per user
crl-verify /etc/openvpn/crl.pem         # agar revoke langsung berlaku
tls-crypt /etc/openvpn/ta.key           # (atau tls-auth) — samakan TLS_MODE
```

---

## Cara kerja fitur

- **Buat user** → agent OpenVPN jalankan `easyrsa --days=N build-client-full <nama> nopass`,
  dashboard alokasikan IP statik dari pool VPN dan tulis file CCD (`ifconfig-push`),
  lalu kembalikan `.ovpn` inline untuk diunduh.
- **Expiry otomatis** → scheduler backend (tiap `EXPIRY_CHECK_INTERVAL_MIN` menit)
  mencari user yang `expires_at`-nya lewat, lalu revoke cert + hapus CCD + hapus ACL
  iptables. Status jadi `expired`. Bisa di-*Perpanjang* untuk aktif lagi.
- **Hapus/revoke** → `easyrsa revoke` + `gen-crl`, publish CRL, hapus CCD & ACL.
- **ACL** → tiap user punya chain iptables sendiri (`VACL_<ip>`) di dalam chain
  induk `VPN_ACL` yang di-hook ke `FORWARD` berdasar source IP user. Rule
  `allow/deny` diterjemahkan ke `ACCEPT/DROP` dengan match `-d dst -p proto --dport port`.
  Setiap perubahan langsung di-push ke Proxmox host dan dipersist (`iptables-save`).

---

## Keamanan

- Ganti `ADMIN_PASSWORD` dan `SESSION_SECRET`. Login pakai cookie ber-HMAC (8 jam).
- Agent hanya menerima request ber-`Bearer` token; **batasi** port `9000` agar
  hanya bisa diakses dari host backend (firewall / bind ke IP internal).
- Sangat disarankan menaruh backend di belakang reverse proxy TLS (nginx/caddy),
  dan menjalankan trafik backend↔agent lewat jaringan tepercaya/VPN.
- Agent butuh root (easy-rsa & iptables). Input nama/IP/CIDR/port divalidasi
  ketat sebelum masuk ke perintah shell (dijalankan tanpa shell, argumen list).

## API ringkas (semua butuh sesi login)

| Method | Endpoint | Fungsi |
|--------|----------|--------|
| GET | `/api/users` | daftar user + ACL |
| POST | `/api/users` | buat user `{name, expiryDays?, note?}` → `.ovpn` |
| PATCH | `/api/users/:id` | perpanjang/ubah expiry |
| DELETE | `/api/users/:id` | revoke + hapus |
| POST | `/api/users/:id/acl` | tambah rule `{action,dst,proto?,port?}` |
| DELETE | `/api/users/:id/acl/:ruleId` | hapus rule |
| GET | `/api/agents/status` | health kedua agent |
| GET | `/api/agents/iptables` | dump iptables ACL dari Proxmox |
| GET | `/api/audit` | audit log |
```
