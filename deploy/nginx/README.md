# Reverse proxy: vvpn.redlimit.id → OpenVPN Manager

nginx VM `10.10.10.105` terminates TLS for `vvpn.redlimit.id` and proxies to the
dashboard/API container on `10.10.10.110:8080`.

```
browser / CTF backend ──HTTPS──► 10.10.10.105 (nginx)
                                      │ proxy_pass
                                      ▼
                              10.10.10.110:8080 (dashboard + /api/v1)
```

## 1. DNS
Point `vvpn.redlimit.id` to the nginx VM `10.10.10.105`. Since everything is
internal, use internal DNS, or a Cloudflare A record in **DNS-only (grey cloud)**
mode. (For the DNS‑01 cert below, the A record's value is irrelevant — validation
is a TXT record — so the cert issues even for a private IP.)

## 2. TLS certificate (pick one)

### A) Let's Encrypt via Cloudflare DNS‑01 — recommended (trusted, box stays internal)
```bash
sudo apt install -y certbot python3-certbot-dns-cloudflare
sudo tee /root/.cloudflare.ini >/dev/null <<'EOF'
dns_cloudflare_api_token = <CLOUDFLARE_API_TOKEN_with_DNS_edit>
EOF
sudo chmod 600 /root/.cloudflare.ini
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /root/.cloudflare.ini \
  -d vvpn.redlimit.id
```
Auto-renew is handled by the certbot systemd timer.

### B) Cloudflare Origin Certificate (if you proxy the subdomain through Cloudflare)
Create an Origin cert in the Cloudflare dashboard, save cert+key on the VM, and
point `ssl_certificate` / `ssl_certificate_key` in the conf at them.

### C) Self-signed (quick, but browser warns unless the CA is trusted)
```bash
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/ssl/private/vvpn.key -out /etc/ssl/certs/vvpn.crt \
  -subj "/CN=vvpn.redlimit.id"
```
Then set the two `ssl_certificate*` paths in the conf accordingly.

## 3. Install the site
```bash
sudo cp vvpn.redlimit.id.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/vvpn.redlimit.id.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 4. Lock the backend to the proxy (optional, recommended)
On the OpenVPN Manager VM `10.10.10.110`, only allow port 8080 from the nginx VM:
```bash
sudo ufw allow from 10.10.10.105 to any port 8080 proto tcp
sudo ufw deny 8080
```
(Or an equivalent iptables rule.) After this, the dashboard is reachable only
through `https://vvpn.redlimit.id`.

## 5. Enable secure cookies (after HTTPS works)
In the dashboard's `backend/.env` set `COOKIE_SECURE=true` and rebuild. The app
trusts `X-Forwarded-Proto` from the proxy, so session cookies get the `Secure`
flag. (Leave it `false` while you still test over plain `http://10.10.10.110:8080`.)

## 6. Integration URL for the CTF platform
Point the CTF backend at the HTTPS endpoint:
```
OVPN_MANAGER_URL=https://vvpn.redlimit.id
OVPN_MANAGER_KEY=<API key from IAM → API Keys>
```
With a trusted cert (option A/B) no TLS bypass is needed.
