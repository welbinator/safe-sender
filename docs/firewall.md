# Production Firewall Plan (Hetzner Cloud Firewall)

## Why Hetzner Cloud Firewall, not ufw

Docker publishes container ports straight into iptables and **bypasses ufw**.
A Hetzner Cloud Firewall is enforced at the network edge before traffic ever
reaches the VM, so it works correctly even with Docker port publishing.

## Rules for app server (5.78.219.242)

| Port  | Protocol | Source              | Purpose                                   |
| ----- | -------- | ------------------- | ----------------------------------------- |
| 22    | TCP      | YOUR_HOME_IP/32     | SSH (lock to your home/office IP)         |
| 80    | TCP      | 0.0.0.0/0, ::/0     | HTTP (LE renewal + redirect)              |
| 443   | TCP      | 0.0.0.0/0, ::/0     | HTTPS (API + admin)                       |
| 25    | TCP      | Google MTA CIDRs    | Inbound MX from Google Workspace only     |
| 587   | TCP      | 0.0.0.0/0, ::/0     | Submission (auth required at app layer)   |

Everything else: deny by default.

### Google MTA source CIDRs (port 25)

Pull live from Google's published SPF:

```bash
dig +short txt _spf.google.com
dig +short txt _netblocks.google.com
dig +short txt _netblocks2.google.com
dig +short txt _netblocks3.google.com
```

Starter set (verify before applying — Google updates these):

```
35.190.247.0/24
64.233.160.0/19
66.102.0.0/20
66.249.80.0/20
72.14.192.0/18
74.125.0.0/16
108.177.8.0/21
173.194.0.0/16
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
```

The SMTP container *also* enforces this allowlist at the app layer
(`PORT25_ALLOWED_CIDRS` env), so the firewall is defense-in-depth, not the only
gate.

## Apply via Hetzner Cloud Console (no CLI needed)

1. Log in: https://console.hetzner.cloud
2. Project → **Firewalls** → **Create Firewall**.
3. Name: `safe-sender-app`.
4. Add the inbound rules from the table above.
5. **Apply to resource** → select the app server (5.78.219.242).
6. After applying, from a *different* network confirm:
   - `nc -zv 5.78.219.242 443` → succeeds
   - `nc -zv 5.78.219.242 22`  → fails unless from your allowed IP
   - `nc -zv 5.78.219.242 8000` → fails (backend no longer reachable from outside)

## Apply via hcloud CLI (optional)

```bash
# Install
curl -L https://github.com/hetznercloud/cli/releases/latest/download/hcloud-linux-amd64.tar.gz \
  | tar xz -C /usr/local/bin hcloud

# Login
hcloud context create safe-sender   # paste API token

# Create
hcloud firewall create --name safe-sender-app
FW=$(hcloud firewall list -o noheader -o columns=id,name | awk '/safe-sender-app/{print $1}')

# Rules (replace YOUR_HOME_IP)
hcloud firewall add-rule "$FW" --direction in --protocol tcp --port 22 \
  --source-ips YOUR_HOME_IP/32
hcloud firewall add-rule "$FW" --direction in --protocol tcp --port 80 \
  --source-ips 0.0.0.0/0 --source-ips ::/0
hcloud firewall add-rule "$FW" --direction in --protocol tcp --port 443 \
  --source-ips 0.0.0.0/0 --source-ips ::/0
hcloud firewall add-rule "$FW" --direction in --protocol tcp --port 587 \
  --source-ips 0.0.0.0/0 --source-ips ::/0
# Port 25 — add each Google CIDR with --source-ips, repeated.
# Apply to server
hcloud firewall apply-to-resource "$FW" --type server --server safe-sender-app
```
