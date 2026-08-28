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

The tool queries vCenter and NSX and displays a **3-column summary** (one card per deployment mode), then a **full-width step panel** for whichever mode you select.

### The three column cards

| Column | Mode | Status chip |
|---|---|---|
| 1 | **NSX-VPC Distributed** ⭐ (Recommended) | Ready / Warnings / Issues |
| 2 | **NSX-VPC Centralized** | Ready / Warnings / Issues |
| 3 | **VDS / FLB** | To Validate |

Each card shows:
- An architecture **thumbnail** (Distributed column) — click it to open a draggable full-size diagram overlay
- **Pros / Cons / Requirements** text
- A **status chip** summarising the overall result
- A **"View steps"** radio button in the footer — click it to expand the full-width steps panel for that mode
- A **Deploy** button (enabled only when all steps are green)

### The full-width steps panel

Clicking **"View steps"** on a card shows all requirement steps for that mode in a full-width panel below the cards. Only one mode's steps are visible at a time. Each step shows:
- A status icon: ✅ green / ⚠️ amber / ❌ red / ℹ️ info
- The step name and a one-line summary message
- Action buttons where applicable (Fix, Check MTU, Check VLAN, Open in vCenter)
- An expandable detail section (click the row) with full check output

### Expanding a Step

Click any step row in the panel to expand it and see details — e.g. which VNA cluster was found, which IP blocks exist, what is missing.

### Fix Buttons

Steps that the tool can remediate show a **"Fix"** button. Clicking it opens a guided wizard that collects the necessary input and calls the NSX API to create the missing resource.

Steps the tool cannot automate (e.g. Edge Cluster + Tier-0 for Centralized mode) show an **info popup** with a link to the relevant VMware blog post.

### Open in vCenter Links

Most steps show a small **"Open in vCenter"** link button below the step title. Clicking it computes the exact vSphere Client deep link for the relevant page and opens it in a new browser tab — so you can jump directly to the right screen without navigating through the vCenter UI.

| Step | What opens |
|---|---|
| S2 — vSphere HA / DRS | Cluster > Configure > DRS (and a second link for HA) for each cluster |
| S3 — NSX Host Preparation | Cluster > Configure > Networking > Network Configuration for each cluster |
| S4 Distributed | NSX VNA Clusters page |
| S4 Centralized | NSX Edge Clusters page |
| S5-1 | External Connections page |
| S5-2 | Transit Gateway detail page (jumps to the specific TGW found by the check) |
| S5-3 | VPC > Configure > IP Blocks |
| S5-4 | VPC > Configure > Connectivity Profile |

### Check MTU Button

S3 (NSX Host Preparation) shows a **"Check MTU"** button in the NSX columns. NSX overlay networking requires MTU ≥ 1700 on the physical fabric — use this to verify before deploying.

Clicking it opens a wizard that:
1. Shows all available ESX hosts (with health indicator); user selects the source host
2. Prompts for the **ESX root password**
3. **Temporarily enables SSH** on that host via vCenter SOAP (if not already enabled)
4. Runs large ICMP pings to each TEP tunnel peer to test the path
5. Shows per-tunnel **pass / fail** results; the button turns green or red
6. **Restores SSH** to its original state automatically

If any tunnel shows as failed, the physical switch ports or vDS uplinks MTU needs to be raised to at least 1700 bytes before proceeding.

### Check VLAN Button

Once **S5-1 through S5-4 are all green**, a **"Check VLAN"** button appears on S5-1 in the Distributed steps panel. Use it to verify that the DVLAN VLAN ID is correctly configured end-to-end on every ESX host before deploying Supervisor.

Clicking it opens a wizard that:
1. Shows all ESX hosts; prompts for the root password (entering the first password copies it to all hosts)
2. Creates a **temporary DVPortGroup** on the VDS with the connection's VLAN ID
3. Adds a **temporary VMkernel NIC** to host 0 only; then scans all IPs in the External IP Block (see below) before adding the remaining hosts
4. Adds VMkernel NICs to all remaining hosts (using re-picked IPs if conflicts were found)
5. Pings the **VLAN gateway** from each VMkernel NIC
6. Shows a per-host **pass / fail** result; conflicts shown in a yellow box with two fix options:
   - **Fix Automatically** — adds the conflicting IPs to the IP Block's Excluded Ranges via the NSX API immediately
   - **Fix Manually** — opens vCenter → VPC → Configure → IP Blocks in a new tab
7. Removes all temporary VMkernel NICs and the temporary DVPortGroup automatically

The button turns green only when all hosts pass the gateway ping **and** no IP conflicts were detected.

---

## Step 4 — Fixing Prerequisites

The following steps have automated Fix wizards:

| Step | Mode | What the fix does |
|---|---|---|
| S2 — vSphere HA / DRS | All | Enables HA and sets DRS to Fully Automated on the cluster via vCenter SOAP |
| S4 — VNA Cluster | Distributed | Deploys a 2-node VNA cluster on the WLD vCenter cluster |
| S5-1 — Distributed External Connection | Distributed | Creates a Distributed VLAN Connection in NSX |
| S5-1 — Centralized External Connection | Centralized | Creates a Gateway Connection (Tier-0 + BGP required first) |
| S5-2 — Distributed Transit Gateway | Distributed | Attaches the Default TGW to a DVLAN connection, or creates a new Distributed TGW |
| S5-2 — Centralized Transit Gateway | Centralized | Attaches the Default TGW to a Gateway Connection, or creates a new Centralized TGW |
| S5-3 — External IP Block | Distributed + Centralized | Creates an NSX External IP Block |
| S5-4 — VPC Connectivity Profile | Distributed + Centralized | Creates or updates the VPC Connectivity Profile in the NSX Default Project |

### VNA Cluster Deployment (S4 Distributed)

When you click **Fix** on S4 Distributed, a 3-step wizard opens:

1. **Node IPs** — Select the port group, enter the two management IPs (one per VNA node). The vSphere cluster and datastore are auto-selected.
2. **Network settings** — If the IPs are in the same subnet as the vCenter management network, no extra input is needed. Otherwise, enter the subnet prefix, gateway, and DNS.
3. **Confirm** — Review the settings and click **"Deploy VNA Cluster"**.

After clicking Deploy, the wizard shows live progress (polled every 30 seconds). Deployment typically takes 15–20 minutes.

### Cascade Fix (S5-1 Distributed)

The S5-1 Distributed External Connection fix wizard includes an optional **"Also auto-fix S5-2, S5-3, S5-4"** checkbox. When enabled, after creating the DVLAN connection the tool automatically:
1. Attaches the Transit Gateway to the new connection (S5-2)
2. Creates an External IP Block using the connection's subnet (S5-3)
3. Configures the VPC Connectivity Profile (S5-4)

Each sub-step is shown with its own progress row. Steps that cannot complete (e.g. S5-4 is skipped if no VNA Cluster exists yet) are marked as skipped with a warning message.

### VPC Connectivity Profile (S5-4 Distributed)

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
