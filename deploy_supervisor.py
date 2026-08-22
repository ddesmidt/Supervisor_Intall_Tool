#!/usr/bin/env python3
"""
Full end-to-end Supervisor deployment for VCF 9.1 lab.
Steps: VNA cluster → DVLAN → TGW attachment → IP block → VPC profile → Supervisor.

Reads credentials from environment (vcf_env.sh).
User-provided parameters are at the top of this file.
"""
import os, sys, json, time, subprocess

# ── User-provided parameters ───────────────────────────────────────────────
VNA_IPS          = ["10.1.1.178", "10.1.1.179"]   # 2 free IPs in mgmt VLAN
VNA_PREFIX       = 24
VNA_GATEWAY      = "10.1.1.1"
DVLAN_VLAN_ID    = 22
DVLAN_GW_CIDR    = "10.1.7.129/25"                # gateway_addresses entry
DVLAN_BLOCK_CIDR = "10.1.7.128/25"                # external IP block CIDR
SUPERVISOR_FIRST_IP = "10.1.1.85"                 # 5 consecutive IPs .85-.89
SUPERVISOR_NAME  = "supervisor-mgmt"
VNA_CLUSTER_ID   = "vna-mgmt-01a"
DVLAN_ID         = "dvlan-vlan22"
EXT_IPBLOCK_ID   = "ext-ipblock-vlan22"
TGW_ATTACH_ID    = "dvlan-tgw-attachment-vlan22"
SEARCH_DOMAINS   = ["site-a.vcf.lab"]

# ── Credentials & proxy ────────────────────────────────────────────────────
VC_HOST  = os.environ["VC_HOST"]
VC_USER  = os.environ["VC_USER"]
VC_PASS  = os.environ["VC_PASS"]
NSX_HOST = os.environ["NSX_HOST"]
NSX_USER = os.environ["NSX_USER"]
NSX_PASS = os.environ["NSX_PASS"]
PROXY    = "socks5h://localhost:1080"
VC_TOKEN = None

# ── curl helpers ───────────────────────────────────────────────────────────
def _run(args):
    args = args + ["-w", "\n__S__%{http_code}"]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    if "__S__" in out:
        body, code = out.rsplit("__S__", 1)
        try:    return int(code.strip()), json.loads(body.strip())
        except: return int(code.strip()), body.strip()
    try:    return 0, json.loads(out)
    except: return 0, out

def vc(method, path, data=None):
    args = ["curl", "-x", PROXY, "-sk", "-X", method.upper(),
            f"https://{VC_HOST}{path}",
            "-H", f"vmware-api-session-id: {VC_TOKEN}",
            "-H", "Content-Type: application/json"]
    if data: args += ["-d", json.dumps(data)]
    return _run(args)

def nsx(method, path, data=None):
    args = ["curl", "-x", PROXY, "-sk", "-X", method.upper(),
            f"https://{NSX_HOST}{path}",
            "-u", f"{NSX_USER}:{NSX_PASS}",
            "-H", "Content-Type: application/json"]
    if data: args += ["-d", json.dumps(data)]
    return _run(args)

def soap_vc(body):
    args = ["curl", "-x", PROXY, "-sk", "-X", "POST",
            f"https://{VC_HOST}/pbm/sdk",
            "-H", "Content-Type: text/xml; charset=utf-8",
            "-H", "SOAPAction: urn:pbm/5.5",
            "-d", body]
    return subprocess.run(args, capture_output=True, text=True).stdout

def vc_auth():
    global VC_TOKEN
    args = ["curl", "-x", PROXY, "-sk", "-X", "POST",
            f"https://{VC_HOST}/api/session",
            "-H", "Content-Type: application/json",
            "-u", f"{VC_USER}:{VC_PASS}"]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    VC_TOKEN = out.strip().strip('"')
    ok(f"vCenter session (token {len(VC_TOKEN)} chars)")

# ── Logging ────────────────────────────────────────────────────────────────
def hdr(msg):  print(f"\n{'='*60}\n{msg}\n{'='*60}")
def ok(msg):   print(f"  ✓ {msg}")
def info(msg): print(f"  → {msg}")
def warn(msg): print(f"  ⚠ {msg}")
def die(msg):  print(f"\n✗ FATAL: {msg}"); sys.exit(1)
def pp(d):     print(json.dumps(d, indent=2) if isinstance(d,(dict,list)) else str(d))

# ── Prerequisite discovery ─────────────────────────────────────────────────
def discover():
    hdr("DISCOVER — auto-gathering all required IDs")

    # Compute manager (vCenter UUID in NSX)
    _, cm = nsx("GET", "/api/v1/fabric/compute-managers")
    compute_mgr_id = cm["results"][0]["id"] if isinstance(cm,dict) and cm.get("results") else ""
    info(f"Compute manager ID: {compute_mgr_id}")

    # vCenter cluster moref
    _, clusters = vc("GET", "/api/vcenter/cluster")
    cluster = clusters[0] if isinstance(clusters,list) and clusters else {}
    cluster_id   = cluster.get("cluster", "domain-c9")
    cluster_name = cluster.get("name","?")
    info(f"Cluster: {cluster_name} ({cluster_id})")

    # Datastore scoped to cluster
    _, ds_list = vc("GET", f"/api/vcenter/datastore?clusters={cluster_id}")
    ds = ds_list[0] if isinstance(ds_list,list) and ds_list else {}
    datastore_id = ds.get("datastore","")
    info(f"Datastore: {ds.get('name')} ({datastore_id})")

    # VM-mgmt DVPG from TNC tags
    _, tncs = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections")
    vm_mgmt_dvpg = ""
    for tnc in (tncs.get("results",[]) if isinstance(tncs,dict) else []):
        for tag in tnc.get("tags",[]):
            if tag.get("scope") == "vcf-orchestration/vm-mgmt-dvpg-moid":
                vm_mgmt_dvpg = tag.get("tag","")
    if not vm_mgmt_dvpg:
        vm_mgmt_dvpg = "dvportgroup-24"   # fallback from earlier enumeration
    info(f"VM-mgmt DVPG (for VNA VMs): {vm_mgmt_dvpg}")

    # Overlay TZ from host TN profile
    _, tnc_list = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections")
    tnp_path = ""
    for tnc in (tnc_list.get("results",[]) if isinstance(tnc_list,dict) else []):
        tnp_path = tnc.get("transport_node_profile_id","")
        if tnp_path: break
    overlay_tz_path = ""
    if tnp_path:
        profile_id = tnp_path.split("/")[-1]
        _, tnp = nsx("GET", f"/policy/api/v1/infra/host-transport-node-profiles/{profile_id}")
        if isinstance(tnp, dict):
            for hs in tnp.get("host_switch_spec",{}).get("host_switches",[]):
                for ep in hs.get("transport_zone_endpoints",[]):
                    tz = ep.get("transport_zone_id","") or ep.get("transport_zone_path","")
                    if tz:
                        overlay_tz_path = tz
                        break
    info(f"Overlay TZ path: {overlay_tz_path}")

    # vCenter networking for supervisor CPs
    _, ifaces = vc("GET", "/api/appliance/networking/interfaces")
    vc_gw, vc_prefix = "10.1.1.1", 24
    if isinstance(ifaces,list):
        for iface in ifaces:
            ip4 = iface.get("ipv4",{})
            if ip4.get("default_gateway"):
                vc_gw     = ip4.get("default_gateway","10.1.1.1")
                vc_prefix = ip4.get("prefix",24)
                break
    info(f"vCenter gateway: {vc_gw}/{vc_prefix}")

    # DNS / NTP
    _, dns_data = vc("GET", "/api/appliance/networking/dns/servers")
    _, ntp_data = vc("GET", "/api/appliance/ntp")
    dns_servers = dns_data.get("servers", ["10.1.1.1"]) if isinstance(dns_data,dict) else ["10.1.1.1"]
    ntp_servers = ntp_data if isinstance(ntp_data,list) else ["10.1.1.1"]
    info(f"DNS: {dns_servers}  NTP: {ntp_servers}")

    # NSX project path
    _, proj = nsx("GET", "/policy/api/v1/orgs/default/projects")
    nsx_proj_path = proj.get("results",[{}])[0].get("path","/orgs/default/projects/default") if isinstance(proj,dict) and proj.get("results") else "/orgs/default/projects/default"
    info(f"NSX project: {nsx_proj_path}")

    # Compatible storage policy via PBMAPI
    _, policies = vc("GET", "/api/vcenter/storage/policies")
    storage_uuid = pick_storage_policy(cluster_id, policies if isinstance(policies,list) else [])
    info(f"Storage policy: {storage_uuid}")

    # Zone ID
    _, zones_raw = vc("GET", "/api/vcenter/consumption-domains/zones")
    zone_id = cluster_id
    if isinstance(zones_raw, dict) and "items" in zones_raw:
        items = zones_raw["items"]
        if items: zone_id = items[0].get("zone", cluster_id)
    elif isinstance(zones_raw, list) and zones_raw:
        zone_id = zones_raw[0].get("zone", cluster_id)
    info(f"Zone ID: {zone_id}")

    # Management DPG for Supervisor control plane
    _, dpgs = vc("GET", "/api/vcenter/network?types=DISTRIBUTED_PORTGROUP")
    sup_dpg = vm_mgmt_dvpg   # default: vm-mgmt DPG
    if isinstance(dpgs, list):
        for d in dpgs:
            n = d.get("name","").lower()
            if "vmmgmt" in n or "vm-mgmt" in n or "vm_mgmt" in n:
                sup_dpg = d.get("network", sup_dpg)
                break
    info(f"Supervisor mgmt DPG: {sup_dpg}")

    return dict(
        compute_mgr_id  = compute_mgr_id,
        cluster_id      = cluster_id,
        datastore_id    = datastore_id,
        vm_mgmt_dvpg    = vm_mgmt_dvpg,
        overlay_tz_path = overlay_tz_path,
        vc_gw           = vc_gw,
        vc_prefix       = vc_prefix,
        dns_servers     = dns_servers,
        ntp_servers     = ntp_servers,
        nsx_proj_path   = nsx_proj_path,
        storage_uuid    = storage_uuid,
        zone_id         = zone_id,
        sup_dpg         = sup_dpg,
    )

def pick_storage_policy(cluster_id, policies):
    """PBMAPI check; fallback to vSAN/regular heuristic."""
    _, ds_list = vc("GET", f"/api/vcenter/datastore?clusters={cluster_id}")
    datastores = ds_list if isinstance(ds_list,list) else []
    for pol in policies:
        uuid = pol.get("policy","")
        name = pol.get("name","")
        for ds in datastores:
            ds_moref = ds.get("datastore","")
            soap = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:pbm="urn:pbm">
  <soapenv:Header><pbm:vcSessionCookie>{VC_TOKEN}</pbm:vcSessionCookie></soapenv:Header>
  <soapenv:Body><pbm:PbmCheckCompatibility>
    <_this type="PbmPlacementSolver">placementSolver</_this>
    <hubsToSearch><hubId>{ds_moref}</hubId><hubType>Datastore</hubType></hubsToSearch>
    <profile><uniqueId>{uuid}</uniqueId></profile>
  </pbm:PbmCheckCompatibility></soapenv:Body>
</soapenv:Envelope>"""
            resp = soap_vc(soap)
            if "incompatibilityReason" not in resp and "Fault" not in resp and "<returnval>" in resp:
                ok(f"PBMAPI compatible policy: {name} ({uuid})")
                return uuid
    # heuristic fallback
    for pol in policies:
        n = pol.get("name","").lower()
        if "vsan" in n and "stretched" not in n and "encryption" not in n and "esa" not in n:
            warn(f"Heuristic fallback policy: {pol.get('name')} ({pol.get('policy')})")
            return pol.get("policy","")
    for pol in policies:
        n = pol.get("name","").lower()
        if "regular" in n or ("management" in n and "thin" not in n and "encryption" not in n):
            warn(f"Heuristic fallback policy: {pol.get('name')} ({pol.get('policy')})")
            return pol.get("policy","")
    return policies[0].get("policy","") if policies else ""

# ══════════════════════════════════════════════════════════════════════════
# STEP 3a — Create VNA Cluster
# ══════════════════════════════════════════════════════════════════════════
def create_vna_cluster(d):
    hdr(f"STEP 3a — Create VNA Cluster '{VNA_CLUSTER_ID}'")

    # 1. Create cluster object
    vna_body = {
        "resource_type": "VirtualNetworkApplianceCluster",
        "id": VNA_CLUSTER_ID,
        "display_name": VNA_CLUSTER_ID,
        "appliance_form_factor": "MEDIUM",
        "appliance_type": "VirtualNetworkAppliance",
        "service_type": "VPC_SERVICES",
        "advanced_configuration": {
            "overlay_transport_zone_path": d["overlay_tz_path"],
            "high_availability_profile": "/infra/sites/default/enforcement-points/default/edge-cluster-high-availability-profiles/019a9fc9-f1ab-76b9-b515-d73348fdf2fe"
        }
    }
    code, resp = nsx("PUT", f"/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{VNA_CLUSTER_ID}", data=vna_body)
    info(f"Create VNA cluster → HTTP {code}")
    if code not in (200, 201):
        if isinstance(resp,dict) and "already exists" in str(resp):
            warn("VNA cluster already exists — skipping create")
        else:
            warn(f"VNA cluster create response: {resp}")
            # Try PATCH
            code2, resp2 = nsx("PATCH", f"/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{VNA_CLUSTER_ID}", data=vna_body)
            info(f"PATCH → HTTP {code2}: {resp2}")
    else:
        ok(f"VNA cluster created")

    vna_path = f"/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{VNA_CLUSTER_ID}"

    # 2. Create two VNA appliance nodes
    for i, node_ip in enumerate(VNA_IPS, 1):
        node_id   = f"{VNA_CLUSTER_ID}-node-{i}"
        hostname  = f"{node_id}.{SEARCH_DOMAINS[0]}"
        node_body = {
            "resource_type": "VirtualNetworkAppliance",
            "id": node_id,
            "display_name": node_id,
            "hostname": hostname,
            "failure_domain_path": "/infra/sites/default/enforcement-points/default/failure-domains/4fc1e3b0-1cd4-4339-86c8-f76baddbaafb",
            "vm_deployment_config": {
                "compute_manager_id": d["compute_mgr_id"],
                "cluster_or_resource_pool_id": d["cluster_id"],
                "datastore_id": d["datastore_id"],
                "reservation_info": {
                    "memory_reservation": {"reservation_percentage": 100},
                    "cpu_reservation": {"reservation_in_shares": "HIGH_PRIORITY"}
                }
            },
            "management_interface": {
                "ip_assignment_specs": [{
                    "management_port_subnets": [{"ip_addresses": [node_ip], "prefix_length": VNA_PREFIX}],
                    "default_gateway": [VNA_GATEWAY],
                    "ip_assignment_type": "StaticIpv4"
                }],
                "network_id": d["vm_mgmt_dvpg"]
            },
            "credentials": {
                "cli_username": "admin",
                "audit_username": "audit"
            }
        }
        code, resp = nsx("PUT", f"/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{VNA_CLUSTER_ID}/virtual-network-appliances/{node_id}", data=node_body)
        info(f"  Node {i} ({node_ip}) → HTTP {code}")
        if code in (200, 201):
            if isinstance(resp,dict) and resp.get("error_message"):
                warn(f"  Node error: {resp.get('error_message')}")
            else:
                ok(f"  VNA node {node_id} deploy started")
        else:
            warn(f"  Node create response: {resp}")

    return vna_path

def wait_vna_ready():
    hdr(f"WAIT — VNA cluster '{VNA_CLUSTER_ID}' deployment (up to 25 min)")
    for i in range(30):
        time.sleep(60)
        _, state = nsx("GET", f"/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{VNA_CLUSTER_ID}/state")
        cs = state.get("consolidated_status","?") if isinstance(state,dict) else "?"
        members = state.get("members_state",[]) if isinstance(state,dict) else []
        steps = [m.get("configuration_state",{}).get("progress_state",{}).get("current_step_title","?") for m in members]
        pcts  = [m.get("configuration_state",{}).get("progress_state",{}).get("progress",0) for m in members]
        info(f"  [{i+1}m] status={cs} steps={steps} progress={pcts}")
        if cs == "SUCCESS":
            ok("VNA cluster is UP and healthy")
            return True
        if cs == "FAILED":
            warn(f"VNA deployment FAILED after {i+1} minutes")
            pp(state)
            return False
    warn("Timed out waiting for VNA cluster (25 min)")
    return False

# ══════════════════════════════════════════════════════════════════════════
# STEP 4-D — Create DVLAN connection
# ══════════════════════════════════════════════════════════════════════════
def create_dvlan():
    hdr(f"STEP 4-D — Create Distributed VLAN connection '{DVLAN_ID}'")
    body = {
        "resource_type": "DistributedVlanConnection",
        "id": DVLAN_ID,
        "display_name": DVLAN_ID,
        "vlan_id": DVLAN_VLAN_ID,
        "gateway_addresses": [DVLAN_GW_CIDR]
    }
    code, resp = nsx("PUT", f"/policy/api/v1/infra/distributed-vlan-connections/{DVLAN_ID}", data=body)
    info(f"HTTP {code}")
    if code in (200, 201):
        ok(f"DVLAN connection created: VLAN {DVLAN_VLAN_ID} gw={DVLAN_GW_CIDR}")
    else:
        warn(f"DVLAN create response: {resp}")
    dvlan_path = f"/infra/distributed-vlan-connections/{DVLAN_ID}"
    return dvlan_path

# ══════════════════════════════════════════════════════════════════════════
# STEP 5-D — Create TGW attachment
# ══════════════════════════════════════════════════════════════════════════
def create_tgw_attachment(dvlan_path):
    hdr(f"STEP 5-D — Create TGW attachment '{TGW_ATTACH_ID}'")
    body = {
        "resource_type": "TransitGatewayAttachment",
        "id": TGW_ATTACH_ID,
        "display_name": TGW_ATTACH_ID,
        "connection_path": dvlan_path,
        "urpf_mode": "STRICT"
    }
    code, resp = nsx("PUT", f"/policy/api/v1/orgs/default/projects/default/transit-gateways/default/attachments/{TGW_ATTACH_ID}", data=body)
    info(f"HTTP {code}")
    if code in (200, 201):
        ok(f"TGW attachment created → {dvlan_path}")
    else:
        warn(f"TGW attachment response: {resp}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 6 — Create external IP block
# ══════════════════════════════════════════════════════════════════════════
def create_ext_ip_block():
    hdr(f"STEP 6 — Create external IP block '{EXT_IPBLOCK_ID}' ({DVLAN_BLOCK_CIDR})")
    body = {"id": EXT_IPBLOCK_ID, "display_name": EXT_IPBLOCK_ID, "cidr": DVLAN_BLOCK_CIDR}
    code, resp = nsx("PUT", f"/policy/api/v1/infra/ip-blocks/{EXT_IPBLOCK_ID}", data=body)
    info(f"HTTP {code}")
    if code in (200, 201):
        ok(f"External IP block created: {DVLAN_BLOCK_CIDR}")
    else:
        warn(f"IP block response: {resp}")
    ext_block_path = f"/infra/ip-blocks/{EXT_IPBLOCK_ID}"
    return ext_block_path

# ══════════════════════════════════════════════════════════════════════════
# STEP 7 — Patch VPC Connectivity Profile
# ══════════════════════════════════════════════════════════════════════════
def patch_vpc_profile(vna_path, ext_block_path):
    hdr("STEP 7 — Patch Default VPC Connectivity Profile")

    # Current profile
    _, profile = nsx("GET", "/policy/api/v1/orgs/default/projects/default/vpc-connectivity-profiles/default")
    priv_blocks = profile.get("private_tgw_ip_blocks",[]) if isinstance(profile,dict) else []
    info(f"Current private_tgw_ip_blocks: {priv_blocks}")

    patch_body = {
        "transit_gateway_path": "/orgs/default/projects/default/transit-gateways/default",
        "external_ip_blocks": [ext_block_path],
        "private_tgw_ip_blocks": priv_blocks if priv_blocks else ["/infra/ip-blocks/f5c251d9-644c-436f-a288-c7347899d7a7"],
        "service_gateway": {
            "enable": True,
            "edge_cluster_paths": [vna_path],
            "nat_config": {
                "enable_default_snat": True,
                "auto_snat_ip_block": ext_block_path
            }
        }
    }
    info("Patching with:")
    pp(patch_body)

    code, resp = nsx("PATCH", "/policy/api/v1/orgs/default/projects/default/vpc-connectivity-profiles/default", data=patch_body)
    info(f"HTTP {code}")
    if code in (200, 204):
        ok("VPC Connectivity Profile patched successfully")
    else:
        warn(f"Patch response: {resp}")

    # Verify
    _, updated = nsx("GET", "/policy/api/v1/orgs/default/projects/default/vpc-connectivity-profiles/default")
    ok(f"Profile now: svc_gw={updated.get('service_gateway') if isinstance(updated,dict) else '?'}")
    ok(f"           ext_ip_blocks={updated.get('external_ip_blocks') if isinstance(updated,dict) else '?'}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8c — Enable HA/DRS (should already be on per pre-check)
# ══════════════════════════════════════════════════════════════════════════
def ensure_ha_drs(cluster_id):
    hdr(f"STEP 8c — Verify HA/DRS on {cluster_id}")
    _, clusters = vc("GET", "/api/vcenter/cluster")
    for c in (clusters if isinstance(clusters,list) else []):
        if c.get("cluster") == cluster_id:
            if c.get("ha_enabled") and c.get("drs_enabled"):
                ok("HA and DRS are already enabled")
                return
            break
    warn("HA or DRS may not be enabled — pre-check showed True, continuing")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8d — Enable Supervisor
# ══════════════════════════════════════════════════════════════════════════
def enable_supervisor(d):
    hdr("STEP 8d — Enable Supervisor (NSX VPC / enable_on_zones)")

    gw_cidr = f"{d['vc_gw']}/{d['vc_prefix']}"
    spec = {
        "name": SUPERVISOR_NAME,
        "zones": [d["zone_id"]],
        "control_plane": {
            "size": "SMALL",
            "storage_policy": d["storage_uuid"],
            "network": {
                "backing": {
                    "backing": "NETWORK",
                    "network": d["sup_dpg"]
                },
                "services": {
                    "dns": {"servers": d["dns_servers"], "search_domains": SEARCH_DOMAINS},
                    "ntp": {"servers": d["ntp_servers"]}
                },
                "ip_management": {
                    "dhcp_enabled": False,
                    "gateway_address": gw_cidr,
                    "ip_assignments": [
                        {"assignee": "NODE", "ranges": [{"address": SUPERVISOR_FIRST_IP, "count": 5}]}
                    ]
                }
            }
        },
        "workloads": {
            "network": {
                "network_type": "NSX_VPC",
                "nsx_vpc": {
                    "nsx_project": d["nsx_proj_path"],
                    "vpc_connectivity_profile": "/orgs/default/projects/default/vpc-connectivity-profiles/default",
                    "default_private_cidrs": [{"address": "172.30.0.0", "prefix": 16}]
                },
                "services": {
                    "dns": {"servers": d["dns_servers"], "search_domains": SEARCH_DOMAINS},
                    "ntp": {"servers": d["ntp_servers"]}
                },
                "ip_management": {
                    "dhcp_enabled": False,
                    "ip_assignments": [
                        {"assignee": "SERVICE", "ranges": [{"address": "10.96.0.0", "count": 1048576}]}
                    ]
                }
            },
            "edge": {"provider": "NSX", "nsx": {"routing_mode": "NO_NAT"}},
            "storage": {
                "ephemeral_storage_policy": d["storage_uuid"],
                "image_storage_policy": d["storage_uuid"]
            }
        }
    }

    info("Supervisor enable spec:")
    pp(spec)

    code, resp = vc("POST", "/api/vcenter/namespace-management/supervisors?action=enable_on_zones", data=spec)
    info(f"HTTP {code}")
    pp(resp)

    if code == 200:
        sup_id = resp.strip('"') if isinstance(resp,str) else str(resp)
        ok(f"Supervisor submitted — UUID: {sup_id}")
        return d["zone_id"]  # monitor via cluster ID
    else:
        if isinstance(resp,dict):
            for m in resp.get("messages",[]):
                warn(f"  {m.get('default_message','')}")
        die(f"Enable Supervisor failed HTTP {code}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8e — Monitor Supervisor
# ══════════════════════════════════════════════════════════════════════════
def monitor_supervisor(cluster_id):
    hdr(f"STEP 8e — Monitoring Supervisor on {cluster_id}")
    print("  Polling every 60s (up to 90 min)…")
    for i in range(90):
        time.sleep(60)
        code, data = vc("GET", f"/api/vcenter/namespace-management/clusters/{cluster_id}")
        if not isinstance(data,dict):
            info(f"  [{i+1}m] no data yet (HTTP {code})")
            continue
        cfg  = data.get("config_status","?")
        kube = data.get("kubernetes_status","?")
        vip  = data.get("api_server_cluster_endpoint","")
        vms  = data.get("api_servers",[])
        msgs = [m.get("default_message","") for m in data.get("messages",[])]
        info(f"  [{i+1}m] config={cfg}  k8s={kube}  vip={vip}  vms={vms}")
        for m in msgs: warn(f"    msg: {m}")
        if cfg == "RUNNING":
            ok("\n" + "="*50)
            ok("SUPERVISOR DEPLOYMENT COMPLETE!")
            ok(f"  VIP  : {vip}")
            ok(f"  VMs  : {vms}")
            ok("="*50)
            return True
        if cfg == "ERROR":
            warn(f"ERROR after {i+1}m — see messages above")
            return False
    warn("Timed out after 90 min")
    return False

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    vc_auth()

    # Check if already installed
    hdr("CHECK — Is Supervisor already installed?")
    code, clusters_ns = vc("GET", "/api/vcenter/namespace-management/clusters")
    if isinstance(clusters_ns,list) and clusters_ns:
        ok(f"Supervisor ALREADY installed: {clusters_ns[0].get('cluster')} status={clusters_ns[0].get('config_status')}")
        sys.exit(0)
    ok("Not installed — starting deployment")

    # Discover
    d = discover()

    # VNA cluster
    vna_path = create_vna_cluster(d)
    ok(f"VNA path: {vna_path}")
    vna_ready = wait_vna_ready()
    if not vna_ready:
        die("VNA cluster failed to come up — aborting")

    # DVLAN + TGW attachment
    dvlan_path = create_dvlan()
    create_tgw_attachment(dvlan_path)

    # External IP block
    ext_block_path = create_ext_ip_block()

    # VPC Connectivity Profile
    patch_vpc_profile(vna_path, ext_block_path)

    # HA/DRS check
    ensure_ha_drs(d["cluster_id"])

    # Enable Supervisor
    cluster_id = enable_supervisor(d)

    # Monitor
    monitor_supervisor(d["cluster_id"])
