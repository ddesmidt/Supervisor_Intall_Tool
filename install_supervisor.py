#!/usr/bin/env python3
"""
VCF Supervisor installer — follows vsphere-supervisor-deployment.md
Uses curl via subprocess (no PySocks dependency needed).
Reads credentials from environment variables set in vcf_env.sh.
"""
import os, sys, json, time, subprocess, textwrap

# ── Credentials & endpoints ────────────────────────────────────────────────
VC_HOST  = os.environ["VC_HOST"]
VC_USER  = os.environ["VC_USER"]
VC_PASS  = os.environ["VC_PASS"]
NSX_HOST = os.environ["NSX_HOST"]
NSX_USER = os.environ["NSX_USER"]
NSX_PASS = os.environ["NSX_PASS"]
PROXY    = "socks5h://localhost:1080"

VC_TOKEN = None

# ── curl wrappers ──────────────────────────────────────────────────────────
def _curl(args):
    """Run curl and return (status_code, body_str)."""
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout

def _curl_code(args):
    """Run curl with -w %{http_code} and return (http_code, body)."""
    args = args + ["-w", "\n__STATUS__%{http_code}"]
    out = _curl(args)
    if "__STATUS__" in out:
        body, code = out.rsplit("__STATUS__", 1)
        return int(code.strip()), body.strip()
    return 0, out

def vc_auth():
    global VC_TOKEN
    base = ["curl", "-x", PROXY, "-sk", "-X", "POST",
            f"https://{VC_HOST}/api/session",
            "-H", "Content-Type: application/json",
            "-u", f"{VC_USER}:{VC_PASS}"]
    body = _curl(base)
    VC_TOKEN = body.strip().strip('"')
    ok(f"vCenter session established (token len={len(VC_TOKEN)})")

def vc(method, path, data=None):
    args = ["curl", "-x", PROXY, "-sk", "-X", method.upper(),
            f"https://{VC_HOST}{path}",
            "-H", f"vmware-api-session-id: {VC_TOKEN}",
            "-H", "Content-Type: application/json"]
    if data:
        args += ["-d", json.dumps(data)]
    code, body = _curl_code(args)
    try:    return code, json.loads(body)
    except: return code, body

def nsx(method, path, data=None):
    args = ["curl", "-x", PROXY, "-sk", "-X", method.upper(),
            f"https://{NSX_HOST}{path}",
            "-u", f"{NSX_USER}:{NSX_PASS}",
            "-H", "Content-Type: application/json"]
    if data:
        args += ["-d", json.dumps(data)]
    code, body = _curl_code(args)
    try:    return code, json.loads(body)
    except: return code, body

# ── Logging ────────────────────────────────────────────────────────────────
def log(msg):  print(f"\n{'='*60}\n{msg}\n{'='*60}")
def ok(msg):   print(f"  ✓ {msg}")
def info(msg): print(f"  → {msg}")
def warn(msg): print(f"  ⚠ {msg}")
def die(msg):  print(f"\n✗ FATAL: {msg}"); sys.exit(1)

def pp(data):
    print(json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data))

# ══════════════════════════════════════════════════════════════════════════
# STEP 1 — Is Supervisor already installed?
# ══════════════════════════════════════════════════════════════════════════
def step1_check_supervisor():
    log("STEP 1 — Check if Supervisor is already installed")
    code, clusters = vc("GET", "/api/vcenter/namespace-management/clusters")
    info(f"HTTP {code}")
    if isinstance(clusters, list) and len(clusters) > 0:
        for c in clusters:
            ok(f"Supervisor ALREADY installed: cluster={c.get('cluster')} "
               f"status={c.get('config_status')} network={c.get('network_provider')}")
        return True, clusters
    else:
        info("No Supervisor found → proceeding")

    code2, cap = vc("GET", "/api/vcenter/namespace-management/capability")
    info(f"Capability: namespaces_supported={cap.get('namespaces_supported')} "
         f"namespaces_licensed={cap.get('namespaces_licensed')}")
    return False, []

# ══════════════════════════════════════════════════════════════════════════
# STEP 2 — NSX host transport nodes
# ══════════════════════════════════════════════════════════════════════════
def step2_check_host_prep():
    log("STEP 2 — Check ESXi host NSX prep (transport nodes)")

    _, tnc = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections")
    cols = tnc.get("results", []) if isinstance(tnc, dict) else []
    info(f"Transport node collections: {len(cols)}")
    for c in cols:
        info(f"  {c.get('display_name','?')} state={c.get('state','?')} tnp_id={c.get('transport_node_profile_id','?')}")

    _, htn = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes")
    hosts = [n for n in (htn.get("results", []) if isinstance(htn, dict) else [])
             if n.get("node_deployment_info", {}).get("resource_type") == "HostNode"]
    info(f"HostNode transport nodes: {len(hosts)}")
    for h in hosts:
        info(f"  {h.get('display_name','?')} deploy_state={h.get('deploy_state','?')}")

    if not cols and not hosts:
        die("No ESXi hosts are prepared with NSX TEP — cannot deploy Supervisor via API.")
    ok("NSX host prep confirmed")
    return cols

# ══════════════════════════════════════════════════════════════════════════
# STEP 3 — VNA cluster or Edge cluster + T0
# ══════════════════════════════════════════════════════════════════════════
def step3_check_networking(tnc_collections):
    log("STEP 3 — Check VNA cluster or Edge Cluster + Tier-0")

    _, vna_data = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters")
    vna_results = vna_data.get("results", []) if isinstance(vna_data, dict) else []
    info(f"VNA clusters: {len(vna_results)}")

    healthy_vna = None
    for vna in vna_results:
        vna_id   = vna.get("id")
        vna_path = vna.get("path")
        info(f"  VNA: {vna.get('display_name','?')} id={vna_id} path={vna_path}")
        _, nodes_data = nsx("GET", f"/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters/{vna_id}/virtual-network-appliances")
        nodes = nodes_data.get("results", []) if isinstance(nodes_data, dict) else []
        all_up = True
        for node in nodes:
            node_id = node.get("id")
            _, st = nsx("GET", f"/api/v1/transport-nodes/{node_id}/status")
            up   = st.get("pnic_status", {}).get("num_uplinks_up", 0) if isinstance(st, dict) else 0
            down = st.get("pnic_status", {}).get("num_uplinks_down", 0) if isinstance(st, dict) else 0
            info(f"    node {node_id}: uplinks_up={up} uplinks_down={down}")
            if up == 0 or down > 0:
                all_up = False
        if all_up and nodes:
            healthy_vna = {"id": vna_id, "path": vna_path}
            ok(f"VNA cluster {vna_id} is healthy")
        elif not nodes:
            # No node-level health data — trust state from cluster
            healthy_vna = {"id": vna_id, "path": vna_path}
            warn(f"VNA cluster {vna_id} exists but no node status available — assuming healthy")

    if healthy_vna:
        return "distributed", healthy_vna

    _, ec_data = nsx("GET", "/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters")
    edge_clusters = ec_data.get("results", []) if isinstance(ec_data, dict) else []
    _, t0_data = nsx("GET", "/policy/api/v1/infra/tier-0s")
    tier0s = t0_data.get("results", []) if isinstance(t0_data, dict) else []
    info(f"Edge clusters: {len(edge_clusters)}  Tier-0s: {len(tier0s)}")
    for e in edge_clusters:
        info(f"  Edge: {e.get('display_name')} id={e.get('id')}")
    for t in tier0s:
        info(f"  T0: {t.get('display_name')} id={t.get('id')}")

    if edge_clusters and tier0s:
        ok("Edge Cluster + Tier-0 found → Centralized TGW path")
        return "centralized", {"edge_cluster": edge_clusters[0], "tier0": tier0s[0]}

    return "none", {}

# ══════════════════════════════════════════════════════════════════════════
# STEP 4-Distributed — Distributed VLAN connection
# ══════════════════════════════════════════════════════════════════════════
def step4_distributed_vlan():
    log("STEP 4-Distributed — Check Distributed VLAN External Connection")
    _, data = nsx("GET", "/policy/api/v1/infra/distributed-vlan-connections")
    results = data.get("results", []) if isinstance(data, dict) else []
    dvlan_results = [x for x in results if x.get("resource_type") == "DistributedVlanConnection"]
    info(f"DistributedVlanConnection objects: {len(dvlan_results)}")
    for d in dvlan_results:
        info(f"  id={d.get('id')} vlan={d.get('vlan_id')} gw={d.get('gateway_addresses')} path={d.get('path')}")
    if dvlan_results:
        ok(f"DVLAN connection: {dvlan_results[0].get('id')}")
        return dvlan_results[0]
    return None

# ══════════════════════════════════════════════════════════════════════════
# STEP 5-Distributed — TGW attachment
# ══════════════════════════════════════════════════════════════════════════
def step5_tgw_attachment(dvlan):
    log("STEP 5-Distributed — Check Transit Gateway attachment")
    _, data = nsx("GET", "/policy/api/v1/orgs/default/projects/default/transit-gateways/default/attachments")
    results = data.get("results", []) if isinstance(data, dict) else []
    dvlan_path = dvlan.get("path") if dvlan else None
    info(f"TGW attachments found: {len(results)}")
    for a in results:
        info(f"  id={a.get('id')} connection_path={a.get('connection_path')}")
        if a.get("connection_path") == dvlan_path:
            ok(f"TGW attachment correctly points to DVLAN {dvlan_path}")
            return a
    if results:
        # Any attachment is better than none
        ok(f"TGW has attachment: {results[0].get('id')}")
        return results[0]
    warn("No TGW attachment found")
    return None

# ══════════════════════════════════════════════════════════════════════════
# STEP 6 — External IP blocks
# ══════════════════════════════════════════════════════════════════════════
def step6_ip_blocks():
    log("STEP 6 — Check External IP Blocks")
    _, infra_data = nsx("GET", "/policy/api/v1/infra/ip-blocks")
    infra_blocks = infra_data.get("results", []) if isinstance(infra_data, dict) else []
    _, proj_data = nsx("GET", "/policy/api/v1/orgs/default/projects/default/infra/ip-blocks")
    proj_blocks = proj_data.get("results", []) if isinstance(proj_data, dict) else []

    info(f"Infra IP blocks: {len(infra_blocks)}")
    for b in infra_blocks:
        info(f"  {b.get('display_name','?')} cidr={b.get('cidr')} path={b.get('path')}")
    info(f"Project IP blocks (private TGW): {len(proj_blocks)}")
    for b in proj_blocks:
        info(f"  {b.get('display_name','?')} cidr={b.get('cidr')} path={b.get('path')}")

    if infra_blocks:
        ok(f"External IP block: {infra_blocks[0].get('path')}")
    return infra_blocks, proj_blocks

# ══════════════════════════════════════════════════════════════════════════
# STEP 7 — VPC Connectivity Profile
# ══════════════════════════════════════════════════════════════════════════
def step7_vpc_profile():
    log("STEP 7 — Check VPC Connectivity Profile")
    _, profile = nsx("GET", "/policy/api/v1/orgs/default/projects/default/vpc-connectivity-profiles/default")
    pp(profile)
    return profile

# ══════════════════════════════════════════════════════════════════════════
# STEP 8a — Gather vCenter info
# ══════════════════════════════════════════════════════════════════════════
def step8a_gather_vcenter():
    log("STEP 8a — Gather vCenter deployment info")

    _, clusters   = vc("GET", "/api/vcenter/cluster")
    _, dpgs       = vc("GET", "/api/vcenter/network?types=DISTRIBUTED_PORTGROUP")
    _, policies   = vc("GET", "/api/vcenter/storage/policies")
    _, dns        = vc("GET", "/api/appliance/networking/dns/servers")
    _, ntp        = vc("GET", "/api/appliance/ntp")
    _, zones      = vc("GET", "/api/vcenter/consumption-domains/zones")
    _, net_ifaces = vc("GET", "/api/appliance/networking/interfaces")

    info(f"Clusters ({len(clusters) if isinstance(clusters,list) else '?'}):")
    if isinstance(clusters, list):
        for c in clusters:
            info(f"  {c.get('name')} moref={c.get('cluster')} ha={c.get('ha_enabled')} drs={c.get('drs_enabled')}")

    info(f"DPGs ({len(dpgs) if isinstance(dpgs,list) else '?'}):")
    if isinstance(dpgs, list):
        for d in dpgs:
            info(f"  {d.get('name')} id={d.get('network')}")

    info(f"Storage policies ({len(policies) if isinstance(policies,list) else '?'}):")
    if isinstance(policies, list):
        for p in policies:
            info(f"  {p.get('name')} uuid={p.get('policy')}")

    info(f"DNS: {dns}")
    info(f"NTP: {ntp}")

    if isinstance(zones, list):
        info(f"Zones ({len(zones)}):")
        for z in zones:
            info(f"  {z.get('name')} id={z.get('zone')} cluster={z.get('clusters')}")
    else:
        info(f"Zones: {zones}")

    # vc-specific network: get mgmt port group
    if isinstance(net_ifaces, list):
        for iface in net_ifaces:
            ip4 = iface.get("ipv4", {})
            info(f"  vCenter NIC: addr={ip4.get('address')} prefix={ip4.get('prefix')} gw={ip4.get('default_gateway')}")

    # DVS compatibility
    if isinstance(clusters, list) and clusters:
        cluster_id = clusters[0].get("cluster")
        _, dvs = vc("GET", f"/api/vcenter/namespace-management/distributed-switch-compatibility?cluster={cluster_id}&compatible=true")
        info(f"DVS compatibility for {cluster_id}: {dvs}")

    return {
        "clusters": clusters if isinstance(clusters, list) else [],
        "dpgs":     dpgs     if isinstance(dpgs, list) else [],
        "policies": policies if isinstance(policies, list) else [],
        "dns":      dns,
        "ntp":      ntp,
        "zones":    zones    if isinstance(zones, list) else [],
        "net_ifaces": net_ifaces,
    }

# ══════════════════════════════════════════════════════════════════════════
# STEP 8b — Storage policy PBMAPI compatibility check
# ══════════════════════════════════════════════════════════════════════════
def step8b_compatible_policies(cluster_id, policies):
    log("STEP 8b — Check storage policy compatibility via PBMAPI")

    # Get datastores scoped to the cluster
    _, ds_list = vc("GET", f"/api/vcenter/datastore?clusters={cluster_id}")
    datastores = ds_list if isinstance(ds_list, list) else []
    info(f"Datastores in cluster {cluster_id}: {len(datastores)}")
    for d in datastores:
        info(f"  {d.get('name')} moref={d.get('datastore')} type={d.get('type')} free={d.get('free_space')}")

    compatible = []
    for pol in policies:
        pol_uuid = pol.get("policy")
        pol_name = pol.get("name","?")
        any_compat = False
        for ds in datastores:
            ds_moref = ds.get("datastore","")
            soap_body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:pbm="urn:pbm">
  <soapenv:Header><pbm:vcSessionCookie>{VC_TOKEN}</pbm:vcSessionCookie></soapenv:Header>
  <soapenv:Body>
    <pbm:PbmCheckCompatibility>
      <_this type="PbmPlacementSolver">placementSolver</_this>
      <hubsToSearch><hubId>{ds_moref}</hubId><hubType>Datastore</hubType></hubsToSearch>
      <profile><uniqueId>{pol_uuid}</uniqueId></profile>
    </pbm:PbmCheckCompatibility>
  </soapenv:Body>
</soapenv:Envelope>"""
            args = ["curl", "-x", PROXY, "-sk", "-X", "POST",
                    f"https://{VC_HOST}/pbm/sdk",
                    "-H", "Content-Type: text/xml; charset=utf-8",
                    "-H", "SOAPAction: urn:pbm/5.5",
                    "-d", soap_body]
            resp = _curl(args)
            if "incompatibilityReason" not in resp and "Fault" not in resp and "<returnval>" in resp:
                any_compat = True
                break
        if any_compat:
            compatible.append(pol)
            ok(f"  Compatible: {pol_name} ({pol_uuid})")
        else:
            info(f"  Incompatible/skipped: {pol_name}")

    if not compatible:
        # Fall back to name heuristic
        warn("PBMAPI checks found no compatible policies — falling back to name heuristic")
        ds_types = {d.get("type","") for d in datastores}
        for pol in policies:
            name = pol.get("name","").lower()
            if ds_types & {"NFS","NFS41","VMFS"} and not any(x in name for x in ["vsan","stretched","vvol","pmem","encryption"]):
                compatible.append(pol)
                ok(f"  Heuristic compatible: {pol.get('name')} ({pol.get('policy')})")
            elif "VSAN" in ds_types and not any(x in name for x in ["vvol","pmem"]):
                compatible.append(pol)
                ok(f"  Heuristic compatible: {pol.get('name')} ({pol.get('policy')})")

    return compatible, datastores

# ══════════════════════════════════════════════════════════════════════════
# STEP 8c — Auto-fix HA/DRS
# ══════════════════════════════════════════════════════════════════════════
def step8c_enable_ha_drs(cluster_moref):
    log(f"STEP 8c — Verify/enable HA and DRS on cluster {cluster_moref}")

    # Check via SOAP
    soap_check = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:vim25="urn:vim25">
  <soapenv:Body>
    <vim25:RetrievePropertiesEx>
      <_this type="PropertyCollector">propertyCollector</_this>
      <specSet>
        <propSpec><type>ClusterComputeResource</type>
          <pathSet>configurationEx.drsConfig.enabled</pathSet>
          <pathSet>configurationEx.dasConfig.enabled</pathSet>
        </propSpec>
        <objectSet>
          <obj type="ClusterComputeResource">{cluster_moref}</obj>
        </objectSet>
      </specSet>
      <options/>
    </vim25:RetrievePropertiesEx>
  </soapenv:Body>
</soapenv:Envelope>"""
    args = ["curl", "-x", PROXY, "-sk", "-X", "POST",
            f"https://{VC_HOST}/sdk",
            "-H", "Content-Type: text/xml; charset=utf-8",
            "-H", "SOAPAction: urn:vim25/8.0",
            "-H", f"Cookie: vmware_soap_session={VC_TOKEN}",
            "-d", soap_check]
    resp = _curl(args)
    info(f"SOAP HA/DRS check: {'dasConfig' in resp and 'drsConfig' in resp}")

    ha_enabled  = "<val xsi:type=\"xsd:boolean\">true</val>" in resp and "dasConfig.enabled" in resp
    drs_enabled = "<val xsi:type=\"xsd:boolean\">true</val>" in resp and "drsConfig.enabled" in resp

    # Best-effort parse — look for the values
    ha_on  = "dasConfig.enabled" in resp and resp.split("dasConfig.enabled")[1][:200].find("true") >= 0
    drs_on = "drsConfig.enabled" in resp and resp.split("drsConfig.enabled")[1][:200].find("true") >= 0

    info(f"  HA detected: {ha_on}  DRS detected: {drs_on}")

    def reconfig(spec_xml, desc):
        soap = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:vim25="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <vim25:ReconfigureComputeResource_Task>
      <_this type="ClusterComputeResource">{cluster_moref}</_this>
      {spec_xml}
      <modify>true</modify>
    </vim25:ReconfigureComputeResource_Task>
  </soapenv:Body>
</soapenv:Envelope>"""
        args = ["curl", "-x", PROXY, "-sk", "-X", "POST",
                f"https://{VC_HOST}/sdk",
                "-H", "Content-Type: text/xml; charset=utf-8",
                "-H", "SOAPAction: urn:vim25/8.0",
                "-H", f"Cookie: vmware_soap_session={VC_TOKEN}",
                "-d", soap]
        r = _curl(args)
        if "task-" in r:
            ok(f"  {desc} task submitted")
            time.sleep(5)
        else:
            warn(f"  {desc} SOAP response: {r[:300]}")

    if not ha_on:
        info("Enabling HA on cluster...")
        reconfig("""<spec xsi:type="ClusterConfigSpecEx">
          <dasConfig><enabled>true</enabled><vmMonitoring>vmMonitoringDisabled</vmMonitoring>
          <hostMonitoring>enabled</hostMonitoring><failoverLevel>1</failoverLevel></dasConfig>
        </spec>""", "Enable HA")
        ok("HA enable requested")

    if not drs_on:
        info("Enabling DRS on cluster...")
        reconfig("""<spec xsi:type="ClusterConfigSpecEx">
          <drsConfig><enabled>true</enabled>
          <defaultVmBehavior>fullyAutomated</defaultVmBehavior>
          <vmotionRate>3</vmotionRate></drsConfig>
        </spec>""", "Enable DRS")
        ok("DRS enable requested")

    if ha_on and drs_on:
        ok("HA and DRS already enabled")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8d — Enable Supervisor (NSX VPC / enable_on_zones)
# ══════════════════════════════════════════════════════════════════════════
def step8d_enable_supervisor(zone_id, storage_uuid, dpg_id,
                              gateway_cidr, dns_servers, search_domains,
                              ntp_servers, first_ip, nsx_project_path, vcp_path):
    log("STEP 8d — Enable Supervisor (NSX VPC mode)")

    spec = {
        "name": "supervisor-mgmt",
        "zones": [zone_id],
        "control_plane": {
            "size": "SMALL",
            "storage_policy": storage_uuid,
            "network": {
                "backing": {
                    "backing": "NETWORK",
                    "network": dpg_id
                },
                "services": {
                    "dns": {"servers": dns_servers, "search_domains": search_domains},
                    "ntp": {"servers": ntp_servers}
                },
                "ip_management": {
                    "dhcp_enabled": False,
                    "gateway_address": gateway_cidr,
                    "ip_assignments": [
                        {"assignee": "NODE", "ranges": [{"address": first_ip, "count": 5}]}
                    ]
                }
            }
        },
        "workloads": {
            "network": {
                "network_type": "NSX_VPC",
                "nsx_vpc": {
                    "nsx_project": nsx_project_path,
                    "vpc_connectivity_profile": vcp_path,
                    "default_private_cidrs": [{"address": "172.30.0.0", "prefix": 16}]
                },
                "services": {
                    "dns": {"servers": dns_servers, "search_domains": search_domains},
                    "ntp": {"servers": ntp_servers}
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
                "ephemeral_storage_policy": storage_uuid,
                "image_storage_policy": storage_uuid
            }
        }
    }

    info("Submitting enable_on_zones spec:")
    pp(spec)

    code, resp = vc("POST", "/api/vcenter/namespace-management/supervisors?action=enable_on_zones", data=spec)
    info(f"HTTP {code}")
    pp(resp)

    if code == 200:
        supervisor_id = resp if isinstance(resp, str) else str(resp)
        ok(f"Supervisor creation accepted — UUID: {supervisor_id}")
        return supervisor_id.strip('"')
    else:
        warn(f"Enable failed: HTTP {code}")
        if isinstance(resp, dict):
            for m in resp.get("messages", []):
                warn(f"  {m.get('default_message','')}")
        return None

# ══════════════════════════════════════════════════════════════════════════
# STEP 8e — Monitor deployment
# ══════════════════════════════════════════════════════════════════════════
def step8e_monitor(cluster_moref):
    log(f"STEP 8e — Monitoring Supervisor deployment on {cluster_moref}")
    print("  Polling every 60s — Ctrl+C to stop monitoring (deployment continues in background)")
    prev_status = ""
    for i in range(90):   # up to 90 minutes
        time.sleep(60)
        code, data = vc("GET", f"/api/vcenter/namespace-management/clusters/{cluster_moref}")
        if code != 200 or not isinstance(data, dict):
            info(f"  [{i+1}m] No data yet (HTTP {code})")
            continue
        cfg   = data.get("config_status","?")
        kube  = data.get("kubernetes_status","?")
        msgs  = [m.get("default_message","") for m in data.get("messages",[])]
        vms   = data.get("api_servers",[])
        vip   = data.get("api_server_cluster_endpoint","")
        status_line = f"[{i+1}m] config={cfg} k8s={kube} vip={vip} vms={vms}"
        if status_line != prev_status:
            info(status_line)
            if msgs:
                for m in msgs: warn(f"    msg: {m}")
            prev_status = status_line
        if cfg == "RUNNING":
            ok(f"\nSupervisor is RUNNING!")
            ok(f"  VIP: {vip}")
            ok(f"  Control plane VMs: {vms}")
            return True
        if cfg == "ERROR":
            warn(f"Deployment ERROR after {i+1} minutes")
            pp(data)
            return False
    warn("Timed out waiting for RUNNING state — check vCenter UI")
    return False

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    vc_auth()

    # Step 1 — already installed?
    installed, existing = step1_check_supervisor()
    if installed:
        print("\n✓ Supervisor is already installed. Nothing to do.")
        sys.exit(0)

    # Step 2 — host prep
    tnc_cols = step2_check_host_prep()

    # Step 3 — network mode
    network_mode, net_info = step3_check_networking(tnc_cols)
    info(f"Network mode: {network_mode}")
    if network_mode == "none":
        die("No VNA cluster or Edge Cluster found — cannot deploy Supervisor automatically.")

    # Steps 4-7 (distributed VLAN path)
    dvlan      = None
    tgw_att    = None
    vna_path   = None
    if network_mode == "distributed":
        dvlan      = step4_distributed_vlan()
        tgw_att    = step5_tgw_attachment(dvlan)
        vna_path   = net_info.get("path")
    infra_blocks, proj_blocks = step6_ip_blocks()
    vpc_profile = step7_vpc_profile()

    # Step 8a — gather vCenter info
    vc_info = step8a_gather_vcenter()

    # NSX project / VCP paths
    _, proj_data = nsx("GET", "/policy/api/v1/orgs/default/projects")
    projects = proj_data.get("results",[]) if isinstance(proj_data,dict) else []
    nsx_project_path = projects[0].get("path","/orgs/default/projects/default") if projects else "/orgs/default/projects/default"

    _, vcp_data = nsx("GET", "/policy/api/v1/orgs/default/projects/default/vpc-connectivity-profiles")
    vcps = vcp_data.get("results",[]) if isinstance(vcp_data,dict) else []
    vcp_path = vcps[0].get("path","/orgs/default/projects/default/vpc-connectivity-profiles/default") if vcps else "/orgs/default/projects/default/vpc-connectivity-profiles/default"

    # Summarise what we found
    log("ENVIRONMENT SUMMARY")
    clusters  = vc_info["clusters"]
    dpgs      = vc_info["dpgs"]
    policies  = vc_info["policies"]
    zones     = vc_info["zones"]
    dns_raw   = vc_info["dns"]
    ntp_raw   = vc_info["ntp"]

    if not clusters: die("No vSphere clusters found in vCenter")

    cluster     = clusters[0]
    cluster_id  = cluster.get("cluster")   # e.g. domain-c9
    cluster_name= cluster.get("name")

    # Zone ID: match cluster moref
    zone_id = cluster_id   # by default
    if isinstance(zones, list):
        for z in zones:
            zc = z.get("clusters",[])
            if cluster_id in str(zc):
                zone_id = z.get("zone", cluster_id)
                break

    info(f"Using cluster: {cluster_name} ({cluster_id})  zone_id={zone_id}")

    # Storage — PBMAPI check
    compatible_policies, datastores = step8b_compatible_policies(cluster_id, policies)
    if not compatible_policies:
        die("No compatible storage policies found for the target cluster.")
    storage_policy = compatible_policies[0]
    storage_uuid   = storage_policy.get("policy")
    info(f"Using storage policy: {storage_policy.get('name')} ({storage_uuid})")

    # Management DPG — prefer "mgmt" or "management" in name
    mgmt_dpg = dpgs[0] if dpgs else None
    for d in dpgs:
        if any(x in d.get("name","").lower() for x in ["mgmt","management","vm-mgmt","vm_mgmt"]):
            mgmt_dpg = d
            break
    if not mgmt_dpg:
        die("No Distributed Port Groups found")
    dpg_id   = mgmt_dpg.get("network")
    dpg_name = mgmt_dpg.get("name")
    info(f"Using DPG: {dpg_name} ({dpg_id})")

    # DNS / NTP from vCenter appliance
    dns_servers    = dns_raw.get("servers", []) if isinstance(dns_raw, dict) else []
    if not dns_servers and isinstance(dns_raw, list): dns_servers = dns_raw
    ntp_servers    = ntp_raw if isinstance(ntp_raw, list) else []
    search_domains = ["site-a.vcf.lab"]

    # vCenter gateway CIDR from appliance networking
    gateway_ip    = ""
    gateway_cidr  = ""
    net_ifaces    = vc_info.get("net_ifaces", [])
    if isinstance(net_ifaces, list):
        for iface in net_ifaces:
            ip4 = iface.get("ipv4", {})
            addr = ip4.get("address","")
            pfx  = ip4.get("prefix",24)
            gw   = ip4.get("default_gateway","")
            if addr and gw:
                gateway_ip   = gw
                gateway_cidr = f"{gw}/{pfx}"
                break

    info(f"vCenter gateway: {gateway_cidr}")
    info(f"DNS servers: {dns_servers}")
    info(f"NTP servers: {ntp_servers}")
    info(f"NSX project: {nsx_project_path}")
    info(f"VCP path:    {vcp_path}")

    # ── Ask user for the 5 control plane IPs ──────────────────────────────
    log("INPUT REQUIRED — 5 consecutive static IPs for Supervisor control plane")
    print(f"""
  Please provide 5 consecutive static IPs in the management network.
  - Network: same subnet as vCenter appliance ({gateway_cidr})
  - These will be used for 3 control plane VMs + 1 VIP + 1 spare
  - Example: if vCenter is 10.1.1.10/24 and gateway is 10.1.1.1,
    provide the first of 5 consecutive free IPs (e.g. 10.1.1.85)

  Enter the FIRST IP address (the other 4 must be consecutive and free):
""")
    first_ip = input("  First IP: ").strip()
    if not first_ip:
        die("No IP provided — aborting")

    # ── Step 8c — enable HA/DRS ───────────────────────────────────────────
    step8c_enable_ha_drs(cluster_id)

    # ── Step 8d — enable Supervisor ───────────────────────────────────────
    supervisor_id = step8d_enable_supervisor(
        zone_id        = zone_id,
        storage_uuid   = storage_uuid,
        dpg_id         = dpg_id,
        gateway_cidr   = gateway_cidr,
        dns_servers    = dns_servers,
        search_domains = search_domains,
        ntp_servers    = ntp_servers,
        first_ip       = first_ip,
        nsx_project_path = nsx_project_path,
        vcp_path       = vcp_path,
    )

    if not supervisor_id:
        print("\nEnable API call failed — review errors above.")
        sys.exit(1)

    # ── Step 8e — monitor ─────────────────────────────────────────────────
    step8e_monitor(cluster_id)
