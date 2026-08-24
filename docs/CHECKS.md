# Requirement Checks Reference

This document explains each of the 8 requirement steps checked by the tool, what the tool looks for, and what the Fix wizard does when a step fails.

---

## Overview

The tool runs the same set of checks against three deployment modes in parallel. Some steps are specific to a mode (NSX-related steps are skipped or differ for VDS/FLB). Each step can result in:

| Status | Meaning |
|---|---|
| ✅ Green | Requirement fully met |
| ⚠️ Amber (Warning) | Partially met or not yet configured — not a hard blocker in all cases |
| ❌ Red | Requirement not met — must be fixed before deploying |

---

## Auth — vCenter Authentication

**What it checks:** Can the tool authenticate to the vCenter API using the provided credentials?

**How it works:**
The tool sends a `POST /api/session` to vCenter. In VCF 9.1 environments, the WLD vCenter uses an internal SSO domain (e.g. `wld.sso`) rather than the federation domain (`vcf.lab`). The tool auto-detects the correct domain by reading the `WWW-Authenticate` header and trying a fallback sequence:
1. Try the username as entered
2. Extract the SSO domain from the `sts=` field in `WWW-Authenticate`
3. Try `<username-part>@<detected-domain>`
4. Try `administrator@<detected-domain>` as last resort

**Fix:** Not automated — verify credentials and NSX/vCenter connectivity.

---

## S1 — Supervisor Capability (vSphere)

**What it checks:** Is the vSphere cluster capable of running Supervisor?

**API:** `GET /api/vcenter/namespace-management/cluster-compatibility`

**What is required:** The cluster must appear in the compatibility list with `compatible: true`.

**Common failure reasons:**
- Cluster does not meet minimum hardware requirements
- vSphere license does not include Supervisor capability

**Fix:** Not automated — check vSphere licensing and hardware requirements.

---

## S2 — NSX Host Preparation

**What it checks:** Are the ESXi hosts in the cluster prepared for NSX (i.e. NSX agents installed and Transport Node configuration applied)?

**APIs used:**
- NSX Policy: `GET /policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections` — lists Transport Node Collections (TNCs, one per vSphere cluster)
- NSX Policy: `GET /policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes` — lists prepared hosts
- NSX Policy: `GET /…/host-transport-nodes/{id}/state` — per-host deployment state
- NSX Manager: `GET /api/v1/fabric/compute-collections` — resolves TNC UUIDs to human-readable cluster names

**What is displayed when green:**
```
· esx-01: SUCCESS
· esx-02: SUCCESS
· esx-03: SUCCESS
· esx-04: SUCCESS
```

If any host has issues the step shows ⚠️ Amber with a summary such as `3/4 hosts healthy — 1 host(s) with issues`, and the expanded detail shows the state and failure message for the affected host(s).

**Fix:** Not automated — NSX host preparation is done via SDDC Manager or NSX Manager UI.

**Check MTU button:**
A **"Check MTU"** button appears on S2 for NSX columns. Clicking it opens a wizard that:
1. Prompts for the ESX root password
2. Picks one ESX host from the cluster
3. Temporarily enables SSH on that host via vCenter SOAP (if not already enabled)
4. Runs large ICMP pings (`ping -s 1672`) to each TEP tunnel peer to verify the physical fabric supports MTU ≥ 1700 (required for NSX overlay)
5. Displays per-tunnel pass/fail results
6. Restores SSH to its original state (disabled if it was disabled before)

> NSX overlay requires MTU ≥ 1700 on the physical network. If any tunnel ping fails, the physical switch ports or vDS uplinks need their MTU raised.

---

## S3 — VNA Cluster / Edge Cluster

This step differs significantly between modes.

### S3 — Distributed: VNA Cluster

**What it checks:** Is there at least one Virtual Network Appliance (VNA) cluster in NSX in a `SUCCESS` deployment state?

**API:** `GET /policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters`

**Status mapping:**

| NSX state | Tool status |
|---|---|
| `SUCCESS` | ✅ Green |
| `IN_PROGRESS` / `PENDING` / `DEPLOYING` | ⚠️ Amber — "VNA Cluster deploying" |
| Not found | ❌ Red |

**Fix wizard (automated):**
1. Fetches available port groups from vCenter (distributed port groups only)
2. Auto-discovers the Overlay Transport Zone from the NSX TNC → TNP chain
3. You enter: port group, Node 1 IP, Node 2 IP
4. Tool calls `PUT /…/virtual-network-appliance-clusters/vna-cluster-1` then `PUT /…/virtual-network-appliances/vna-node-{1,2}`
5. Shows live deployment progress (polled every 30s)

### S3 — Centralized: Edge Cluster + Tier-0

**What it checks:** Are there Edge Clusters and Tier-0 gateways present in NSX (required for centralized routing)?

**Fix:** **Not automated** — Edge Cluster + Tier-0 + BGP deployment is complex. An info popup links to the [VMware blog post with recorded installation demo](https://blogs.vmware.com/cloud-foundation/2025/06/25/vpc-centralized-network-connectivity-with-guided-edge-deployment/).

---

## S4 — Distributed / Centralized External Connection

This step differs between modes.

### S4 — Distributed: Distributed External Connection

**What it checks:** Is there at least one **Distributed VLAN Connection** in NSX?

**API:** `GET /policy/api/v1/infra/distributed-vlan-connections`

**Expanded detail shows:**
```
· dvlan-connection-1
  VLAN ID: 22
  Gateway: 10.1.7.129/25
```

**Fix wizard (automated):** Creates a new Distributed VLAN Connection — prompts for name, VLAN ID, and gateway CIDR.

### S4 — Centralized: Centralized External Connection

**What it checks:** Is there at least one **Gateway Connection** (Tier-0 backed) in NSX?

**API:** `GET /policy/api/v1/infra/gateway-connections`

**Expanded detail shows:**
```
· cent-ext1
  Tier-0: T0
```

**Fix wizard (automated):** Creates a new Gateway Connection — prompts for name and Tier-0 selection.

---

## S5 — Distributed / Centralized Transit Gateway

### S5 — Distributed: Distributed Transit Gateway

**What it checks:** Is there at least one Transit Gateway (TGW) that has an attachment pointing to a Distributed VLAN Connection?

**APIs:**
- `GET /policy/api/v1/orgs/default/projects/default/transit-gateways`
- `GET /…/transit-gateways/{id}/attachments`

**Expanded detail shows:**
```
· Default Transit Gateway
  Attached to: dvlan-connection-1
```

**Fix wizard — two cases:**

| Case | Condition | Action |
|---|---|---|
| Case 1 | Default TGW has no attachment | Attach Default TGW to a selected DVLAN connection |
| Case 2 | Default TGW has a Centralized attachment | Create a new `dist-tgw1` TGW and attach it to a selected DVLAN connection |

### S5 — Centralized: Centralized Transit Gateway

**What it checks:** Is there at least one TGW with an attachment pointing to a Gateway Connection?

**Expanded detail shows:**
```
· cent-tgw1
  Attached to: cent-ext1
  Edge Cluster: EdgeCluster1
```

The Edge Cluster is read from `GET /…/transit-gateways/{id}/centralized-configs` (auto-populated by NSX when the attachment is created).

**Fix wizard — same Case 1/2 logic as Distributed**, but uses Gateway Connections instead.

---

## S6 — External IP Block

**What it checks:** Is there at least one NSX IP Block with `visibility = EXTERNAL`?

**API:** `GET /policy/api/v1/infra/ip-blocks`

**Why `visibility = EXTERNAL` and not CIDR-based filtering?**
Earlier versions of this check rejected RFC-1918 ranges (private IPs), but in lab environments, VPC NAT means the IP block can be a private range that is "externally visible" to the VPC. NSX's own `visibility` field is the authoritative classification.

**Mode-specific filtering:**
- **Centralized**: additionally excludes blocks whose CIDR overlaps with any Distributed VLAN connection's gateway subnet (those belong to the Distributed mode)

**Expanded detail shows:**
```
· ext-ip-block-1
  CIDR: 10.1.7.128/25
  Excluded ranges: 10.1.7.254
· ext-ip-block-2
  CIDR: 10.1.9.128/25
```

**Fix wizard (automated):**
- Name is pre-filled (`dist-ext-ip-block-1` or `cent-ext-ip-block-1`)
- CIDR is pre-filled from the TGW's DVLAN connection gateway subnet (read-only)
- Optional: enter comma-separated excluded IP ranges
- Creates `PUT /policy/api/v1/infra/ip-blocks/{name}` with `visibility: EXTERNAL`

---

## S7 — Distributed / Centralized VPC Connectivity Profile

**What it checks:** Does the NSX Default Project have a VPC Connectivity Profile that satisfies all of the following?

| Field | Requirement |
|---|---|
| `transit_gateway_path` | Points to a TGW with a Distributed (or Centralized) attachment |
| `external_ip_blocks` | At least one entry |
| `service_gateway.enable` | `true` |
| `service_gateway.edge_cluster_paths` | At least one VNA cluster path (Distributed) or Edge Cluster (Centralized) |
| `service_gateway.nat_config.enable_default_snat` | `true` |

**APIs:**
- `GET /policy/api/v1/orgs/default/projects` — lists all NSX projects
- `GET /…/projects/{id}/vpc-connectivity-profiles` — lists profiles per project
- `GET /…/transit-gateways/{id}/attachments` — validates TGW attachment type

The check scans **all projects** (not just Default) and shows all valid profiles.

**Expanded detail (when green):**
```
· vpc-dist-prof1  (Project: default)
  TGW: Default Transit Gateway
  External IP Block: ext-ip-block-1
  VNA Cluster: vna-cluster-1
  N/S Services: enabled   Outbound NAT: enabled
```

**Fix wizard (automated):**

Fully reactive form:

| Field | Behavior |
|---|---|
| NSX Project | Dropdown of all NSX projects; defaults to "Default" |
| Distributed TGW | Dropdown refreshes per project; auto-selected if only one |
| VPC Profile name | Read-only; shows `Default VPC Connectivity Profile` for Default TGW, or `vpc-dist-prof1` for a custom TGW |
| External IP Block | Filtered to EXTERNAL blocks matching the TGW's subnet; auto-selected if only one |
| VNA Cluster | Dropdown; auto-selected if only one |
| Private TGW IP Block | Optional — dropdown of PRIVATE blocks |

**Profile creation/update logic:**
- If the profile does not exist → `PUT` (create)
- If the profile exists with the same TGW → `PATCH` (update fields only, no TGW change — NSX restriction)
- If the profile exists with a different TGW → creates a new profile with a different ID (NSX does not allow changing `transit_gateway_path` on an existing profile)

---

## S8 — (Additional checks)

Additional checks may be added here in future versions.

---

## NSX API Reference

Key NSX Policy API paths used by this tool:

| Resource | API Path |
|---|---|
| Transport Node Collections | `/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections` |
| Host Transport Nodes | `/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes` |
| VNA Clusters | `/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters` |
| Distributed VLAN Connections | `/policy/api/v1/infra/distributed-vlan-connections` |
| Gateway Connections | `/policy/api/v1/infra/gateway-connections` |
| Transit Gateways | `/policy/api/v1/orgs/default/projects/default/transit-gateways` |
| TGW Attachments | `/policy/api/v1/orgs/default/projects/default/transit-gateways/{id}/attachments` |
| TGW Centralized Config | `/policy/api/v1/orgs/default/projects/default/transit-gateways/{id}/centralized-configs` |
| IP Blocks | `/policy/api/v1/infra/ip-blocks` |
| VPC Connectivity Profiles | `/policy/api/v1/orgs/default/projects/{id}/vpc-connectivity-profiles` |
| Overlay Transport Zones | `/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones` |
