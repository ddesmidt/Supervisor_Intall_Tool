# Usage Guide

This guide explains how to use the **vSphere Supervisor Readiness Check + Installation** tool step by step.

---

## Interface Overview

The web interface uses the **[Clarity Design System](https://clarity.design)** (Broadcom's official design language) and has three main sections, accessed top to bottom:

1. **Connection Details** — enter vCenter and NSX credentials
2. **Check if Supervisor is Installed** — query the current state
3. **Check Supervisor Requirements** — 3-column readiness matrix with fix wizards
4. **Deploy Supervisor** — guided deployment wizard (available once requirements pass)

---

## Step 1 — Enter Connection Details

At the top of the page, fill in the two connection sections:

### vCenter

| Field | Example | Notes |
|---|---|---|
| vCenter IP / FQDN | `vc-wld01-a.site-a.vcf.lab` | Do not include `https://` |
| Username | `administrator@vsphere.local` | Pre-filled |
| Password | `VMware123!VMware123!` | |

> **VCF 9.1 note**: The WLD vCenter uses an internal SSO domain (`wld.sso`). The app auto-detects the correct authentication domain — just enter your usual credentials and it will find the right domain automatically.

### NSX

| Field | Example | Notes |
|---|---|---|
| NSX IP / FQDN | `nsx-wld01-a.site-a.vcf.lab` | Do not include `https://` |
| NSX Username | `admin` | Pre-filled |
| Password | `VMware123!VMware123!` | |

---

## Step 2 — Check if Supervisor is Already Installed

Click **"Check if Supervisor is Installed"**.

**Possible results:**

- **Supervisor [name] is INSTALLED** (green banner) — Supervisor is running on this vCenter. The cluster name, config status, k8s status, control plane VIP, and **network mode** (`NSX-VPC Distributed`, `NSX-VPC Centralized`, or `VDS / FLB`) are shown. The network mode is auto-detected by querying the NSX Transit Gateway attachment type via the NSX API.
- **Supervisor is NOT installed** (blue banner) — The "Check Supervisor Requirements" button appears below.

---

## Step 3 — Check Supervisor Requirements

Click **"Check Supervisor Requirements"**.

The tool queries vCenter and NSX and displays a **3-column matrix**, one column per deployment mode:

| Column | Mode |
|---|---|
| 1 | **NSX-VPC Distributed** ⭐ (Recommended) |
| 2 | **NSX-VPC Centralized** |
| 3 | **VDS / FLB** |

Each column shows:

- A **Pros / Cons / Requirements** summary at the top
- **8 requirement steps** (S1–S8), each with a status badge:
  - ✅ **Green** — requirement met
  - ⚠️ **Amber** — warning (not blocking, but worth noting)
  - ❌ **Red** — requirement not met
- A **Deploy** button at the bottom (enabled only when all steps are green)

### Expanding a Step

Click any step row to expand it and see details — e.g. which VNA cluster was found, which IP blocks exist, what is missing.

### Fix Buttons

Steps that the tool can remediate show a **"Fix"** button. Clicking it opens a guided wizard that collects the necessary input and calls the NSX API to create the missing resource.

Steps the tool cannot automate (e.g. Edge Cluster + Tier-0 for Centralized mode) show an **info popup** with a link to the relevant VMware blog post.

---

## Step 4 — Fixing Prerequisites

The following steps have automated Fix wizards:

| Step | Mode | What the fix does |
|---|---|---|
| S3 — VNA Cluster | Distributed | Deploys a 2-node VNA cluster on the WLD vCenter cluster |
| S4 — Distributed External Connection | Distributed | Creates a Distributed VLAN Connection in NSX |
| S4 — Centralized External Connection | Centralized | Creates a Gateway Connection (Tier-0 + BGP required first) |
| S5 — Distributed Transit Gateway | Distributed | Attaches the Default TGW to a DVLAN connection, or creates a new Distributed TGW |
| S5 — Centralized Transit Gateway | Centralized | Attaches the Default TGW to a Gateway Connection, or creates a new Centralized TGW |
| S6 — External IP Block | Distributed + Centralized | Creates an NSX External IP Block |
| S7 — VPC Connectivity Profile | Distributed + Centralized | Creates or updates the VPC Connectivity Profile in the NSX Default Project |

### VNA Cluster Deployment (S3 Distributed)

When you click **Fix** on S3 Distributed, a 3-step wizard opens:

1. **Node IPs** — Select the port group, enter the two management IPs (one per VNA node). The vSphere cluster and datastore are auto-selected.
2. **Network settings** — If the IPs are in the same subnet as the vCenter management network, no extra input is needed. Otherwise, enter the subnet prefix, gateway, and DNS.
3. **Confirm** — Review the settings and click **"Deploy VNA Cluster"**.

After clicking Deploy, the wizard shows live progress (polled every 30 seconds). Deployment typically takes 15–20 minutes.

### VPC Connectivity Profile (S7 Distributed)

The S7 fix wizard auto-populates fields from data already discovered during the requirements check:

- **NSX Project** — defaults to "Default"; refreshes the profile list if changed
- **Distributed Transit Gateway** — auto-selected if only one exists
- **External IP Block** — auto-selected if it uniquely matches the TGW's DVLAN subnet
- **VNA Cluster** — auto-selected if only one exists
- **Private TGW IP Block** — auto-selected if only one PRIVATE block exists

---

## Step 5 — Deploy Supervisor

Once all steps in a column are green, click **"Deploy Supervisor"** in that column.

A 4-step wizard opens:

### Wizard Step 1 — Cluster
Select the vSphere cluster to enable Supervisor on. If only one cluster exists it is pre-selected.

### Wizard Step 2 — Network
| Field | Description |
|---|---|
| NSX Project | Auto-populated from the valid VPC Connectivity Profile found in Step 7 |
| VPC Connectivity Profile | Auto-populated; can be changed if multiple valid profiles exist |
| First Control Plane IP | Enter the first of 5 consecutive IPs (e.g. `10.1.1.85` reserves `.85`–`.89`) |
| Content Library | Select a vSphere Content Library for Supervisor VM images |

### Wizard Step 3 — Storage
Select the storage policy for Supervisor control plane VMs. The list is filtered to policies compatible with the selected cluster's datastore type (VVol, PMem, and ESA policies are excluded unless the cluster supports them).

### Wizard Step 4 — Config
| Field | Description |
|---|---|
| Supervisor Name | A name for the Supervisor (e.g. `supervisor-wld01-a`) |
| Management Network | The port group for the control plane management network |

### Deployment Progress

After clicking **"Deploy"**, the wizard switches to a status view that polls every 30 seconds:

- **Config Status: CONFIGURING** — deployment in progress (K8s status hidden)
- **Config Status: RUNNING** — deployment complete; K8s status and Control Plane VIP are shown

---

## Tips

- **Hard refresh** (`Cmd+Shift+R` on Mac, `Ctrl+Shift+R` on Windows) if the UI looks stale after a change — Flask serves templates from disk but browsers cache aggressively.
- **Re-check Requirements** after each Fix to confirm the step turned green before moving to the next one.
- The **VDS/FLB** column Deploy button is always disabled — the tool does not automate VDS/FLB Supervisor deployment.
- Credentials are **not stored** — if you refresh the page you will need to re-enter them.
