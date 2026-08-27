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
Point `vvpn.redlimit.id` at the nginx VM (in the Cloudflare dashboard, an A
record). For the HTTP‑01 cert below, the record must be reachable from the
internet on port 80 during issuance — if it's proxied (orange cloud), set it to
**DNS‑only (grey cloud)** while issuing, then switch back to Full(strict) after.

## 2. Install the site (HTTP first)
```bash
sudo cp vvpn.redlimit.id.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/vvpn.redlimit.id.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 3. TLS with certbot (HTTP‑01 — no Cloudflare token needed)
```bash
sudo certbot --nginx -d vvpn.redlimit.id
```
certbot proves control by answering on port 80, then **rewrites the conf in
place**: it adds the `listen 443 ssl` server with the cert paths and turns the
port‑80 block into an HTTP→HTTPS redirect. Auto‑renew runs via the certbot timer.

> Only if this VM is NOT reachable from the internet on port 80: use DNS‑01
> manually — `sudo certbot certonly --manual --preferred-challenges dns -d
> vvpn.redlimit.id` — certbot prints a TXT record you add in the Cloudflare
> dashboard by hand (renewals are manual too). No API token required.

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
