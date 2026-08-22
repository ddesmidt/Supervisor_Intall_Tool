# Installation Guide

This guide walks through deploying the **vSphere Supervisor Readiness Check + Installation** tool on a Linux VM inside your VCF environment.

---

## VM Requirements

| Resource | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS or Ubuntu 24.04 LTS |
| CPU | 1 vCPU |
| RAM | 2 GB |
| Disk | 5 GB |
| Network | Access to vCenter and NSX Manager APIs (port 443) |

> The VM should be placed in the **workload domain** so it can reach both the management vCenter (`vc-mgmt-a`) and the WLD vCenter (`vc-wld01-a`) as well as NSX Manager.

---

## Step 1 — Clone the Repository

```bash
apt-get update && apt-get install -y git
git clone https://github.com/ddesmidt/Supervisor_Intall_Tool.git
cd Supervisor_Intall_Tool
```

---

## Step 2 — Install Python Dependencies

The app uses only packages available via `apt` (no PyPI access required):

```bash
apt-get install -y python3-flask python3-requests
```

Alternatively, if PyPI is accessible:

```bash
pip3 install -r app/requirements.txt
```

**Dependencies:**

| Package | Version | Purpose |
|---|---|---|
| `flask` | ≥ 3.0 | Web framework |
| `requests` | ≥ 2.31 | HTTP client for vCenter/NSX APIs |
| `urllib3` | ≥ 2.0 | TLS handling (self-signed cert support) |

---

## Step 3 — Deploy the App

```bash
# Copy app files to the standard location
mkdir -p /opt/supervisor-check
cp -r app/* /opt/supervisor-check/

# Verify structure
ls /opt/supervisor-check/
# app.py  requirements.txt  supervisor-check.service  templates/
```

---

## Step 4 — Configure and Start the systemd Service

```bash
# Install the service unit
cp /opt/supervisor-check/supervisor-check.service /etc/systemd/system/

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable supervisor-check
systemctl start supervisor-check

# Verify it is running
systemctl status supervisor-check
```

Expected output:
```
● supervisor-check.service - vSphere Supervisor Readiness Check
     Loaded: loaded (/etc/systemd/system/supervisor-check.service; enabled)
     Active: active (running) since ...
```

The app listens on **port 80** and starts automatically on boot.

---

## Step 5 — Verify

Open a browser and navigate to:

```
http://<VM-IP>/
```

You should see the **vSphere Supervisor Readiness Check + Installation** interface.

---

## Network Configuration Script

A utility script `net-config` is installed at `/usr/local/bin/net-config` on the VM. Run it as root to:

- View the current IP configuration (DHCP or Static)
- Switch to DHCP
- Set a static IP (prompts for IP, subnet prefix, gateway, DNS)

```bash
net-config
```

This uses `netplan` under the hood and applies changes immediately.

---

## Managing the Service

| Task | Command |
|---|---|
| Start | `systemctl start supervisor-check` |
| Stop | `systemctl stop supervisor-check` |
| Restart | `systemctl restart supervisor-check` |
| View logs | `journalctl -u supervisor-check -f` |
| Disable autostart | `systemctl disable supervisor-check` |

---

## Updating the App

After pulling new changes from the repo:

```bash
cd Supervisor_Intall_Tool
git pull

cp app/app.py /opt/supervisor-check/app.py
cp app/templates/index.html /opt/supervisor-check/templates/index.html

systemctl restart supervisor-check
```

> Flask caches Jinja2 templates in memory — always restart the service after updating `index.html`.

---

## Troubleshooting

**App not reachable on port 80**

Check if another process is listening on port 80:
```bash
ss -tlnp | grep :80
```

If Apache or nginx is running, stop it:
```bash
systemctl stop apache2 && systemctl disable apache2
systemctl stop nginx && systemctl disable nginx
systemctl restart supervisor-check
```

**"Connection refused" when checking vCenter/NSX**

The VM must be able to reach the target hosts on port 443:
```bash
curl -k https://<vcenter-fqdn>/api/session -v
```

**SSL certificate errors**

All vCenter and NSX API calls disable SSL verification by default (`urllib3.disable_warnings` + `verify=False`). This is intentional for lab environments with self-signed certificates.

**Service crashes on startup**

Check the logs:
```bash
journalctl -u supervisor-check --no-pager -n 50
```

Common causes: missing Python packages, wrong working directory, port 80 already in use.
