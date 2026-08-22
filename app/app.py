import ipaddress
import re
import traceback
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, jsonify, render_template, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

SESS = requests.Session()
SESS.verify = False


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_external_ip_block(cidr: str) -> bool:
    """True only if cidr is publicly routable (not private / link-local / reserved)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return not (net.is_private or net.is_link_local or net.is_reserved or net.is_loopback)
    except ValueError:
        return False


def _block_cidr(b: dict, nsx_url: str = "", user: str = "", pwd: str = "") -> str:
    """Extract CIDR from an NSX IP block object.

    NSX returns the subnet in 'cidr' (singular) OR 'cidrs' (array) — never reliably both.
    Fall back to subnets[].network, then to an individual GET if still empty.
    """
    cidr = (b.get("cidr") or "").strip()
    if not cidr:
        # NSX sometimes uses a 'cidrs' array instead of 'cidr'
        cidrs_list = b.get("cidrs") or []
        if cidrs_list:
            cidr = str(cidrs_list[0]).strip()
    if not cidr:
        # Some NSX versions embed CIDR inside a 'subnets' array
        for s in (b.get("subnets") or []):
            net = (s.get("network") or s.get("cidr") or "").strip()
            if net:
                cidr = net
                break
    if not cidr and nsx_url and b.get("path"):
        # Last resort: individual GET for the full block object
        try:
            full = nsx_get(nsx_url, user, pwd,
                           f"/policy/api/v1{b['path']}")
            if full:
                cidr = (full.get("cidr") or "").strip()
                if not cidr:
                    cidrs_list = full.get("cidrs") or []
                    if cidrs_list:
                        cidr = str(cidrs_list[0]).strip()
                if not cidr:
                    for s in (full.get("subnets") or []):
                        net = (s.get("network") or s.get("cidr") or "").strip()
                        if net:
                            cidr = net
                            break
        except Exception:
            pass
    return cidr


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    # strip trailing path components like /ui
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def guess_nsx_url(vc_url: str) -> str | None:
    """Derive NSX URL from vCenter URL by swapping 'vc' prefix → 'nsx'."""
    p = urlparse(vc_url)
    host = p.hostname or ""
    if host.startswith("vc-"):
        return f"https://nsx-{host[3:]}"
    if host.startswith("vc"):
        return f"https://nsx{host[2:]}"
    return None


def _detect_sso_domain(www_auth_header: str) -> str | None:
    """Extract SSO domain from WWW-Authenticate STS URL.
    e.g. sts="https://host/sts/STSService/wld.sso" → "wld.sso"
    """
    m = re.search(r'sts="[^"]+/STSService/([^"]+)"', www_auth_header)
    return m.group(1) if m else None


def vc_auth(vc_url: str, username: str, password: str) -> tuple[str, str]:
    """Authenticate to vCenter REST API.

    Returns (token, effective_username).
    On 401, auto-detects the vCenter's local SSO domain from the
    WWW-Authenticate header and retries with administrator@<domain>.
    Uses fresh requests.post() calls to avoid session cookie interference.
    """
    url = f"{vc_url}/api/session"
    kw = dict(verify=False, headers={"Content-Type": "application/json"}, timeout=15)

    resp = requests.post(url, auth=(username, password), **kw)

    if resp.status_code == 401:
        www_auth = resp.headers.get("WWW-Authenticate", "")
        sso_domain = _detect_sso_domain(www_auth)
        if sso_domain:
            local = username.split("@")[0] if "@" in username else username
            candidates = [
                f"{local}@{sso_domain}",
                f"administrator@{sso_domain}",
            ]
            for candidate in candidates:
                if candidate == username:
                    continue
                r2 = requests.post(url, auth=(candidate, password), **kw)
                if r2.ok:
                    return r2.json(), candidate
        resp.raise_for_status()

    resp.raise_for_status()
    return resp.json(), username


def vc_get(vc_url: str, token: str, path: str, params: dict = None):
    resp = SESS.get(
        f"{vc_url}{path}",
        headers={"vmware-api-session-id": token},
        params=params,
        timeout=15,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def nsx_get(nsx_url: str, user: str, pwd: str, path: str):
    resp = SESS.get(
        f"{nsx_url}{path}",
        auth=(user, pwd),
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if resp.status_code in (404, 405):
        return None
    resp.raise_for_status()
    return resp.json()


# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check-installed", methods=["POST"])
def check_installed():
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")

    result = {"success": False, "installed": False, "clusters": [], "capability": {},
              "error": None, "auth_user": None}

    try:
        token, effective_user = vc_auth(vc_url, username, password)

        clusters = vc_get(vc_url, token, "/api/vcenter/namespace-management/clusters") or []
        capability = vc_get(vc_url, token, "/api/vcenter/namespace-management/capability") or {}

        # Enrich each cluster with detail data (api_server_cluster_endpoint, etc.)
        # The list endpoint omits these fields; the individual GET includes them.
        enriched = []
        for c in clusters:
            cid = c.get("cluster")
            if cid:
                try:
                    detail = vc_get(vc_url, token,
                                    f"/api/vcenter/namespace-management/clusters/{cid}")
                    if detail:
                        c = {**c, **detail}
                except Exception:
                    pass
            enriched.append(c)

        result.update(success=True, installed=bool(enriched), clusters=enriched,
                      capability=capability, auth_user=effective_user)

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


@app.route("/api/check-requirements", methods=["POST"])
def check_requirements():
    body = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    # ── Phase 1: collect all raw data (single API pass) ──────────────────────
    d: dict = {}

    try:
        d["token"], d["effective_user"] = vc_auth(vc_url, username, password)
        d["vc_auth_ok"] = True
    except Exception as e:
        d["vc_auth_ok"] = False
        d["vc_auth_error"] = str(e)

    if d.get("vc_auth_ok"):
        try:
            d["cap"] = vc_get(vc_url, d["token"],
                              "/api/vcenter/namespace-management/capability") or {}
        except Exception as e:
            d["cap"] = {}; d["cap_error"] = str(e)

        try:
            d["vc_clusters"] = vc_get(vc_url, d["token"], "/api/vcenter/cluster") or []
        except Exception as e:
            d["vc_clusters"] = []; d["clusters_error"] = str(e)

    if nsx_url:
        try:
            tnc = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections")
            d["tnc"] = (tnc or {}).get("results", [])
            htn = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes")
            d["htn"] = (htn or {}).get("results", [])
        except Exception as e:
            d["tnc"] = []; d["htn"] = []; d["tep_error"] = str(e)

        # Resolve TNC UUID → cluster name via Manager API
        # compute_collection_id uses external_id format: "{cm_id}:{cluster_moref}"
        try:
            cc_resp  = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/fabric/compute-collections")
            cc_list  = (cc_resp or {}).get("results", [])
            # Key by external_id (matches TNC compute_collection_id exactly)
            cc_names = {c.get("external_id", c.get("id", "")): c.get("display_name", "")
                        for c in cc_list if c.get("origin_type") == "VC_Cluster"}

            tnc_v1_resp = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/transport-node-collections")
            tnc_v1_list = (tnc_v1_resp or {}).get("results", [])

            tnc_cluster_map: dict = {}
            for t in tnc_v1_list:
                tid   = t.get("id", "")
                cc_id = t.get("compute_collection_id", "")
                cname = cc_names.get(cc_id, "")
                if cname:
                    tnc_cluster_map[tid] = cname

            d["tnc_cluster_map"] = tnc_cluster_map
        except Exception:
            d["tnc_cluster_map"] = {}

        try:
            vna = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters")
            d["vna"] = (vna or {}).get("results", [])
            # Fetch deployment state for each VNA cluster
            d["vna_states"] = {}
            for v in d["vna"]:
                cid = v.get("id", "")
                if cid:
                    try:
                        st = nsx_get(nsx_url, nsx_user, nsx_pass,
                            f"/policy/api/v1/infra/sites/default/enforcement-points/default"
                            f"/virtual-network-appliance-clusters/{cid}/state")
                        d["vna_states"][cid] = (st or {}).get("consolidated_status", "UNKNOWN")
                    except Exception:
                        d["vna_states"][cid] = "UNKNOWN"
            ec = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters")
            d["ec"] = (ec or {}).get("results", [])
            t0 = nsx_get(nsx_url, nsx_user, nsx_pass, "/policy/api/v1/infra/tier-0s")
            d["t0"] = (t0 or {}).get("results", [])
        except Exception as e:
            d["vna"] = []; d["ec"] = []; d["t0"] = []; d["topo_error"] = str(e)

        try:
            dv = nsx_get(nsx_url, nsx_user, nsx_pass,
                         "/policy/api/v1/infra/distributed-vlan-connections")
            d["dvlan"] = (dv or {}).get("results", [])
            gw = nsx_get(nsx_url, nsx_user, nsx_pass,
                         "/policy/api/v1/infra/gateway-connections")
            d["gw_conn"] = (gw or {}).get("results", [])
        except Exception as e:
            d["dvlan"] = []; d["gw_conn"] = []; d["extconn_error"] = str(e)

        try:
            # Fetch ALL TGWs, then all their attachments
            tgw_list_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/orgs/default/projects/default/transit-gateways")
            all_tgws = (tgw_list_resp or {}).get("results", [])
            d["tgw"] = next((t for t in all_tgws if t.get("id") == "default"), None)
            d["tgw_all_att"] = []
            for _tgw in all_tgws:
                _tid = _tgw.get("id", "")
                _ta  = nsx_get(nsx_url, nsx_user, nsx_pass,
                    f"/policy/api/v1/orgs/default/projects/default"
                    f"/transit-gateways/{_tid}/attachments")
                for _a in (_ta or {}).get("results", []):
                    _a["_tgw_id"]   = _tid
                    _a["_tgw_name"] = _tgw.get("display_name", _tid)
                    d["tgw_all_att"].append(_a)
            # Backward compat: tgw_att = Default TGW attachments only
            d["tgw_att"] = [a for a in d["tgw_all_att"] if a.get("_tgw_id") == "default"]
        except Exception as e:
            d["tgw_all_att"] = []; d["tgw_att"] = []; d["tgw"] = None; d["tgw_error"] = str(e)

        try:
            bl = nsx_get(nsx_url, nsx_user, nsx_pass, "/policy/api/v1/infra/ip-blocks")
            all_blocks = (bl or {}).get("results", [])
            # Enrich each block with resolved CIDR (handles list-API omissions)
            for b in all_blocks:
                if not b.get("cidr"):
                    resolved = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                    if resolved:
                        b["cidr"] = resolved
            # Use NSX's own visibility field ("EXTERNAL") as the authoritative filter.
            # Fall back to CIDR-based heuristic only for blocks with no visibility set.
            def _block_is_external(b):
                vis = (b.get("visibility") or "").upper()
                if vis == "EXTERNAL":
                    return True
                if vis in ("PRIVATE", "PROJECT"):
                    return False
                # No visibility set — fall back to CIDR heuristic
                return _is_external_ip_block(b.get("cidr", ""))
            d["ext_blocks"] = [b for b in all_blocks if _block_is_external(b)]
            d["int_blocks"] = [b for b in all_blocks if not _block_is_external(b)]
        except Exception as e:
            d["ext_blocks"] = []; d["int_blocks"] = []; d["blocks_error"] = str(e)

        try:
            # Fetch VPC Connectivity Profiles from ALL projects
            _proj_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/orgs/default/projects")
            _all_projs = (_proj_resp or {}).get("results", [{"id": "default", "display_name": "default"}])
            all_vcps: list = []
            for _proj in _all_projs:
                _pid = _proj.get("id", "")
                _vr  = nsx_get(nsx_url, nsx_user, nsx_pass,
                    f"/policy/api/v1/orgs/default/projects/{_pid}/vpc-connectivity-profiles")
                for _vcp in (_vr or {}).get("results", []):
                    _vcp["_proj_id"]   = _pid
                    _vcp["_proj_name"] = _proj.get("display_name", _pid)
                    all_vcps.append(_vcp)
            d["all_vcps"] = all_vcps
            # Backward compat: keep d["vcp"] = default project default profile
            d["vcp"] = next((v for v in all_vcps
                             if v.get("_proj_id") == "default" and v.get("id") == "default"), None)
        except Exception as e:
            d["all_vcps"] = []; d["vcp"] = None; d["vcp_error"] = str(e)

    # ── Phase 2: build per-mode check lists ──────────────────────────────────

    def build_checks(mode: str) -> list:
        checks: list = []

        def add(step, name, status, message, details="", can_fix=False, link=None, **extra):
            entry = {"step": step, "name": name, "status": status,
                     "message": message, "details": details,
                     "can_fix": can_fix, "link": link}
            entry.update(extra)
            checks.append(entry)

        # ── Auth (all modes) ────────────────────────────────────────────────
        if not d.get("vc_auth_ok"):
            add("Auth", "vCenter Authentication", "error", f"Failed: {d.get('vc_auth_error')}")
            return checks
        note = (f" (auto-detected: {d['effective_user']})"
                if d["effective_user"] != username else "")
        add("Auth", "vCenter Authentication", "ok",
            f"Authenticated to {vc_url}{note}", f"User: {d['effective_user']}")

        # ── Step 1: Supervisor capability (all modes) ────────────────────────
        if "cap_error" in d:
            add("1", "Supervisor Capability", "warning", f"Could not check: {d['cap_error']}")
        else:
            cap = d.get("cap", {})
            supported = cap.get("namespaces_supported", False)
            licensed  = cap.get("namespaces_licensed",  False)
            msg = "Supervisor supported" if supported else "Supervisor NOT supported on this vCenter"
            if supported and not licensed:
                msg += " (unlicensed — still OK in VCF 9.1)"
            add("1", "Supervisor Capability", "ok" if supported else "error", msg,
                f"namespaces_supported={supported}\nnamespaces_licensed={licensed}")

        # ── Steps 2-7: NSX checks ────────────────────────────────────────────
        nsx_na = "Not required for this deployment mode."

        if mode == "vds_flb":
            add("2", "NSX Host Preparation", "info", "Not required for VDS/FLB mode", nsx_na)
            add("3", "NSX Networking",        "info", "Not required for VDS/FLB mode", nsx_na)
            add("4", "External Connection",   "info", "Not required for VDS/FLB mode", nsx_na)
            add("5", "TGW Attachment",         "info", "Not required for VDS/FLB mode", nsx_na)
            add("6", "External IP Block",     "info", "Not required for VDS/FLB mode", nsx_na)
            add("7", "VPC Profile",           "info", "Not required for VDS/FLB mode", nsx_na)
        elif not nsx_url:
            ext_conn_name = ("Distributed External Connection" if mode == "distributed"
                             else "Centralized External Connection" if mode == "centralized"
                             else "External Connection")
            for sn, nm in [
                ("2", "NSX Host Preparation"), ("3", "NSX Networking"),
                ("4", ext_conn_name),           ("5", "TGW Attachment"),
                ("6", "External IP Block"),    ("7", "VPC Profile"),
            ]:
                add(sn, nm, "warning", "NSX URL not provided — enter it in the NSX section above.")
        else:
            # Step 2: TEPs (same for both NSX modes)
            if "tep_error" in d:
                add("2", "NSX Host Preparation", "warning", f"Could not check: {d['tep_error']}")
            elif d.get("tnc") or d.get("htn"):
                tncs            = d.get("tnc", [])
                htns            = d.get("htn", [])
                tnc_cluster_map = d.get("tnc_cluster_map", {})
                total_hosts     = len(htns)

                cluster_names = []
                detail_lines  = []
                for t in tncs:
                    tid   = t.get("id", "")
                    cname = tnc_cluster_map.get(tid) or t.get("display_name") or tid
                    # TNC state is unreliable in NSX 4.x — use total HTN count
                    # (split evenly if multiple TNCs, exact if only one)
                    count = total_hosts if len(tncs) == 1 else total_hosts // len(tncs)
                    cluster_names.append(cname)
                    detail_lines.append(f"· {cname}: SUCCESS")

                if not cluster_names:
                    cluster_names = ["(unknown)"]
                    detail_lines  = ["· (unknown): SUCCESS"]

                add("2", "NSX Host Preparation", "ok",
                    f"vCenter Clusters hosts prepared — {', '.join(cluster_names)}",
                    "\n".join(detail_lines))
            else:
                add("2", "NSX Host Preparation", "error",
                    "No ESXi hosts prepared with NSX.",
                    "Without NSX host prep, Supervisor cannot use NSX-VPC networking.")

            # Step 3: networking topology (mode-specific)
            if mode == "distributed":
                if "topo_error" in d:
                    add("3", "VNA Cluster", "warning", f"Could not check: {d['topo_error']}")
                elif d.get("vna"):
                    vna_states = d.get("vna_states") or {}
                    detail_lines = []
                    all_ok = True
                    any_deploying = False
                    any_failed = False
                    names = []
                    for vna in d["vna"]:
                        cid     = vna.get("id", "?")
                        cname   = vna.get("display_name", cid)
                        cstatus = vna_states.get(cid, "UNKNOWN")
                        names.append(cname)
                        detail_lines.append(f"· {cname}: {cstatus}")
                        if cstatus != "SUCCESS":
                            all_ok = False
                        if cstatus in ("IN_PROGRESS", "PENDING", "DEPLOYING"):
                            any_deploying = True
                        if cstatus in ("FAILED", "ERROR", "PARTIAL_SUCCESS"):
                            any_failed = True
                    detail = "\n".join(detail_lines)
                    names_str = ", ".join(names)
                    if all_ok:
                        add("3", "VNA Cluster", "ok",
                            f"VNA Cluster found: {names_str}", detail)
                    elif any_failed:
                        add("3", "VNA Cluster", "error",
                            f"VNA Cluster deployment failed", detail, can_fix=True)
                    elif any_deploying:
                        add("3", "VNA Cluster", "warning",
                            f"VNA Cluster deploying: {names_str}", detail)
                    else:
                        add("3", "VNA Cluster", "warning",
                            f"VNA Cluster status unknown: {names_str}", detail)
                else:
                    add("3", "VNA Cluster", "error",
                        "No VNA Cluster found.",
                        "A VNA Cluster is required for Distributed NSX-VPC mode.\n"
                        "This tool will guide you through the installation.\n\n"
                        "VNA requirements:\n"
                        "  · 2 management IPs for the VNA nodes (on the mgmt VLAN)",
                        can_fix=True)
            else:  # centralized
                if "topo_error" in d:
                    add("3", "Edge Cluster + Tier-0", "warning", f"Could not check: {d['topo_error']}")
                elif d.get("ec") and d.get("t0"):
                    ec_lines = "\n".join(f"  - {e.get('display_name','?')}" for e in d["ec"])
                    t0_lines = "\n".join(f"  - {t.get('display_name','?')}" for t in d["t0"])
                    detail   = f"· Edge cluster(s):\n{ec_lines}\n· Tier-0(s):\n{t0_lines}"
                    add("3", "Edge Cluster + Tier-0", "ok",
                        "Edge Cluster + Tier-0 found", detail)
                elif d.get("ec"):
                    add("3", "Edge Cluster + Tier-0", "error",
                        "Edge Cluster found but no Tier-0.",
                        f"Edge clusters: {[e.get('display_name','?') for e in d['ec']]}\n"
                        "A Tier-0 with BGP is required for Centralized NSX-VPC mode.",
                        can_fix=True)
                else:
                    add("3", "Edge Cluster + Tier-0", "error",
                        "No Edge Cluster found.",
                        "An Edge Cluster with Tier-0 + BGP is required for Centralized NSX-VPC.\n"
                        "This tool does not automate Edge Cluster + Tier-0 deployment.\n"
                        "A blog with a recorded installation demo is available.",
                        can_fix=True,
                        link={"text": "blog with recorded installation demo here",
                              "url": "https://blogs.vmware.com/cloud-foundation/2025/06/25/vpc-centralized-network-connectivity-with-guided-edge-deployment/"})

            # Step 4: external connection (mode-specific)
            if mode == "distributed":
                if "extconn_error" in d:
                    add("4", "Distributed External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("dvlan"):
                    names = [dc.get("display_name", dc.get("id", "?")) for dc in d["dvlan"]]
                    detail_lines = []
                    for dc in d["dvlan"]:
                        name = dc.get("display_name", dc.get("id", "?"))
                        vlan = dc.get("vlan_id", "?")
                        gws  = ", ".join(dc.get("gateway_addresses") or []) or "?"
                        detail_lines.append(f"· {name}\n  VLAN ID: {vlan}\n  Gateway: {gws}")
                    add("4", "Distributed External Connection", "ok",
                        f"{len(d['dvlan'])} Distributed External Connection(s): {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("4", "Distributed External Connection", "error",
                        "No Distributed External Connection found.",
                        "The Distributed External Connection is the connection to the physical fabric.\n"
                        "In the Distributed option, that's a VLAN / physical gateway.\n"
                        "This tool will guide you through its creation.\n"
                        "Requires: 1 VLAN/subnet reachable from all ESXi hosts.",
                        can_fix=True)
            else:  # centralized
                if "extconn_error" in d:
                    add("4", "Centralized External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("gw_conn"):
                    detail_lines = []
                    for gc in d["gw_conn"]:
                        name  = gc.get("display_name", gc.get("id", "?"))
                        t0    = (gc.get("tier0_path") or "?").rstrip("/").split("/")[-1]
                        detail_lines.append(f"· {name}\n  Tier-0: {t0}")
                    names = [gc.get("display_name", gc.get("id","?")) for gc in d["gw_conn"]]
                    add("4", "Centralized External Connection", "ok",
                        f"Gateway Connection: {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("4", "Centralized External Connection", "error",
                        "No Centralized External Connection found.",
                        "The Centralized External Connection is the connection to the physical fabric.\n"
                        "In the Centralized option, that's an NSX Tier-0.\n"
                        "This tool will guide you through its creation.",
                        can_fix=True)

            # Step 5: TGW attachment — mode-specific connection type check
            if "tgw_error" in d:
                add("5", "Distributed Transit Gateway" if mode == "distributed" else "TGW Attachment",
                    "warning", f"Could not check: {d['tgw_error']}")
            else:
                all_att_global = d.get("tgw_all_att", d.get("tgw_att", []))
                if mode == "distributed":
                    # Distributed: any TGW must have an attachment to /distributed-vlan-connections/
                    dist_att = [a for a in all_att_global
                                if "/distributed-vlan-connections/" in (a.get("connection_path") or "")]
                    # Check Default TGW for centralized (to decide fix Case 1 vs Case 2)
                    default_att = d.get("tgw_att", [])
                    centralized_att = [a for a in default_att
                                       if "/gateway-connections/" in (a.get("connection_path") or "")]
                    if dist_att:
                        # Group by TGW for display
                        tgw_groups: dict = {}
                        for a in dist_att:
                            tname = a.get("_tgw_name", a.get("_tgw_id", "Transit Gateway"))
                            tgw_groups.setdefault(tname, []).append(a.get("connection_path", "?"))
                        lines = []
                        for tname, cps in tgw_groups.items():
                            lines.append(f"· {tname}")
                            for cp in cps:
                                conn_name = cp.rstrip("/").split("/")[-1]
                                lines.append(f"  Attached to: {conn_name}")
                        add("5", "Distributed Transit Gateway", "ok",
                            f"{len(dist_att)} Distributed Transit Gateway attachment(s)",
                            "\n".join(lines))
                    elif d.get("tgw"):
                        if centralized_att:
                            # Case 2: Default TGW is already Centralized → must create a new TGW
                            add("5", "Distributed Transit Gateway", "error",
                                "No Distributed Transit Gateway",
                                "The Default Transit Gateway is already configured as Centralized.\n"
                                "A new Distributed Transit Gateway must be created and attached\n"
                                "to a Distributed External Connection.\n"
                                "This tool will guide you through creating it.",
                                can_fix=True)
                        else:
                            # Case 1: Default TGW has no connection → attach it
                            add("5", "Distributed Transit Gateway", "error",
                                "No existing Distributed Transit Gateway.",
                                "This tool will guide you through attaching it to a Distributed External Connection.",
                                can_fix=True)
                    else:
                        add("5", "Distributed Transit Gateway", "error",
                            "Default Transit Gateway not found.",
                            "The Transit Gateway is required for NSX-VPC networking.\n"
                            "This tool will guide you through the configuration.",
                            can_fix=True)
                else:  # centralized
                    # Centralized: any TGW must have an attachment to /gateway-connections/
                    cent_att = [a for a in all_att_global
                                if "/gateway-connections/" in (a.get("connection_path") or "")]
                    if cent_att:
                        # Build edge-cluster path → name lookup
                        ec_names = {ec.get("path", ""): ec.get("display_name", ec.get("id", "?"))
                                    for ec in d.get("ec", [])}
                        # Group by TGW id for display; keep full attachment object
                        tgw_id_groups: dict = {}
                        for a in cent_att:
                            tid   = a.get("_tgw_id", "default")
                            tname = a.get("_tgw_name", tid)
                            tgw_id_groups.setdefault(tid, {"name": tname, "atts": []})["atts"].append(a)
                        tgw_names = [v["name"] for v in tgw_id_groups.values()]
                        subtitle = (f"1 Centralized Transit Gateway: {tgw_names[0]}"
                                    if len(tgw_names) == 1
                                    else f"{len(tgw_names)} Centralized Transit Gateways")
                        lines = []
                        for tid, info in tgw_id_groups.items():
                            lines.append(f"· {info['name']}")
                            for a in info["atts"]:
                                conn_name = (a.get("connection_path") or "?").rstrip("/").split("/")[-1]
                                lines.append(f"  Attached to: {conn_name}")
                            # Fetch CentralizedConfig to get the TGW Edge Cluster
                            try:
                                cc_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                                    f"/policy/api/v1/orgs/default/projects/default"
                                    f"/transit-gateways/{tid}/centralized-configs")
                                cc_list = (cc_resp or {}).get("results", [])
                                ec_paths = []
                                for cc in cc_list:
                                    ec_paths.extend(cc.get("edge_cluster_paths") or [])
                                for ecp in ec_paths:
                                    ec_name = ec_names.get(ecp, ecp.rstrip("/").split("/")[-1])
                                    lines.append(f"  Edge Cluster: {ec_name}")
                            except Exception:
                                pass
                        add("5", "Centralized Transit Gateway", "ok",
                            subtitle, "\n".join(lines))
                    elif d.get("tgw"):
                        add("5", "Centralized Transit Gateway", "error",
                            "No existing Centralized Transit Gateway.",
                            "This tool will guide you through attaching it to a Centralized External Connection.",
                            can_fix=True)
                    else:
                        add("5", "Centralized Transit Gateway", "error",
                            "Default Transit Gateway not found.",
                            "The Transit Gateway is required for NSX-VPC networking.\n"
                            "This tool will guide you through the configuration.",
                            can_fix=True)

            # Step 6: external IP blocks — mode-specific validity check
            if "blocks_error" in d:
                add("6", "External IP Block", "warning", f"Could not check: {d['blocks_error']}")
            else:
                all_ext = d.get("ext_blocks", [])

                if mode == "distributed":
                    # Distributed: any external IP block is valid
                    valid_blocks = all_ext
                else:
                    # Centralized: the block must NOT overlap with a DVLAN gateway subnet
                    # (those subnets belong to the Distributed physical fabric)
                    dvlan_nets = []
                    for dv in d.get("dvlan", []):
                        for gw in (dv.get("gateway_addresses") or []):
                            try:
                                dvlan_nets.append(ipaddress.ip_network(gw, strict=False))
                            except ValueError:
                                pass

                    def _overlaps_dvlan(cidr):
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                            return any(net.overlaps(dv) for dv in dvlan_nets)
                        except ValueError:
                            return False

                    valid_blocks = [b for b in all_ext
                                    if not _overlaps_dvlan(b.get("cidr", ""))]

                if valid_blocks:
                    block_info = [f"{b.get('display_name','?')} ({b.get('cidr','?')})"
                                  for b in valid_blocks]
                    # Build details lines, including excluded ranges from description if present
                    detail_lines = []
                    for b in valid_blocks:
                        line = f"· {b.get('display_name', b.get('id','?'))}\n  CIDR: {b.get('cidr','?')}"
                        desc = (b.get("description") or "").strip()
                        if desc:
                            line += f"\n  {desc}"
                        detail_lines.append(line)
                    add("6", "External IP Block", "ok",
                        f"{len(valid_blocks)} External IP block(s): {', '.join(block_info)}",
                        "\n".join(detail_lines))
                else:
                    if mode == "distributed":
                        ext_detail = (
                            "An External IP Block is required for future Supervisor VIP and NAT allocation.\n"
                            "In the Distributed option, that's the subnet defined in Step 4.\n"
                            "This tool will guide you through the creation of an External IP Block."
                        )
                    else:
                        overlap_note = ""
                        if all_ext:
                            names = [b.get("display_name", "?") for b in all_ext]
                            overlap_note = (f"\nNote: {len(all_ext)} external block(s) found ({', '.join(names)})"
                                            " but they overlap with the Distributed VLAN subnet — not usable for Centralized mode.")
                        ext_detail = (
                            "An External IP Block is required for future Supervisor VIP and NAT allocation.\n"
                            "In the Centralized option, that's a new subnet (not on the physical fabric)\n"
                            "which the physical fabric will learn from the T0-BGP." + overlap_note + "\n"
                            "This tool will guide you through the creation of an External IP Block."
                        )
                    add("6", "External IP Block", "error",
                        "No External IP Block found.",
                        ext_detail,
                        can_fix=True)

            # Step 7: VPC connectivity profile
            title_7 = ("Distributed VPC Connectivity Profile"
                       if mode == "distributed"
                       else "Centralized VPC Connectivity Profile")
            if "vcp_error" in d:
                add("7", title_7, "warning", f"Could not check: {d['vcp_error']}")
            else:
                all_vcps      = d.get("all_vcps", [v for v in [d.get("vcp")] if v])
                cluster_label = "VNA Cluster" if mode == "distributed" else "Edge Cluster"

                def _vcp_is_valid_dist(vcp):
                    """Return True if a VCP satisfies the Distributed requirements."""
                    sg  = (vcp.get("service_gateway") or {})
                    nat = (sg.get("nat_config") or {})
                    tgw_path = vcp.get("transit_gateway_path", "")
                    if not tgw_path:
                        return False
                    tgw_id = tgw_path.rstrip("/").split("/")[-1]
                    has_dist = any(
                        a.get("_tgw_id") == tgw_id and
                        "/distributed-vlan-connections/" in (a.get("connection_path") or "")
                        for a in d.get("tgw_all_att", [])
                    )
                    return (has_dist and
                            bool(vcp.get("external_ip_blocks")) and
                            bool(sg.get("edge_cluster_paths")) and
                            bool(sg.get("enable")) and
                            bool(nat.get("enable_default_snat")))

                def _vcp_is_valid_cent(vcp):
                    """Return True if a VCP satisfies the Centralized requirements.
                    The TGW must have a Gateway Connection (centralized) attachment.
                    """
                    sg  = (vcp.get("service_gateway") or {})
                    nat = (sg.get("nat_config") or {})
                    tgw_path = vcp.get("transit_gateway_path", "")
                    if not tgw_path:
                        return False
                    tgw_id = tgw_path.rstrip("/").split("/")[-1]
                    has_cent = any(
                        a.get("_tgw_id") == tgw_id and
                        "/gateway-connections/" in (a.get("connection_path") or "")
                        for a in d.get("tgw_all_att", [])
                    )
                    return (has_cent and
                            bool(vcp.get("external_ip_blocks")) and
                            bool(sg.get("edge_cluster_paths")) and
                            bool(sg.get("enable")) and
                            bool(nat.get("enable_default_snat")))

                is_valid = _vcp_is_valid_dist if mode == "distributed" else _vcp_is_valid_cent
                valid_vcps = [v for v in all_vcps if is_valid(v)]

                if valid_vcps:
                    lines = []
                    for v in valid_vcps:
                        sg  = (v.get("service_gateway") or {})
                        nat = (sg.get("nat_config") or {})
                        proj  = v.get("_proj_name", v.get("_proj_id", "?"))
                        name  = v.get("display_name", v.get("id", "?"))
                        tgw   = v.get("transit_gateway_path", "?").rstrip("/").split("/")[-1]
                        ext_b = ", ".join(b.rstrip("/").split("/")[-1]
                                          for b in (v.get("external_ip_blocks") or []))
                        clu   = ", ".join(p.rstrip("/").split("/")[-1]
                                          for p in (sg.get("edge_cluster_paths") or []))
                        lines.append(f"· {name}  (Project: {proj})")
                        lines.append(f"  TGW: {tgw}")
                        lines.append(f"  External IP Block: {ext_b}")
                        lines.append(f"  {cluster_label}: {clu}")
                        lines.append(f"  N/S Services: enabled   Outbound NAT: enabled")
                    subtitle = (f"1 valid VPC Connectivity Profile: {valid_vcps[0].get('display_name', valid_vcps[0].get('id','?'))}"
                                if len(valid_vcps) == 1
                                else f"{len(valid_vcps)} valid VPC Connectivity Profile(s)")
                    # Build structured deploy data (grouped by project) for the Deploy wizard
                    from collections import OrderedDict as _OD
                    _proj_map: dict = _OD()
                    for _v in valid_vcps:
                        _pid   = _v.get("_proj_id",   "default")
                        _pname = _v.get("_proj_name",  _pid)
                        _ppath = _v.get("path", "").rsplit("/vpc-connectivity-profiles/", 1)[0]
                        if not _ppath:
                            _ppath = f"/orgs/default/projects/{_pid}"
                        key = (_pid, _pname, _ppath)
                        if key not in _proj_map:
                            _proj_map[key] = []
                        _prof_path = _v.get("path", "")
                        _prof_name = _v.get("display_name", _v.get("id", ""))
                        _proj_map[key].append({"id": _v.get("id",""), "display_name": _prof_name, "path": _prof_path})
                    _deploy_projects = [
                        {"id": pid, "display_name": pname, "path": ppath,
                         "valid_vpc_profiles": profs}
                        for (pid, pname, ppath), profs in _proj_map.items()
                    ]
                    add("7", title_7, "ok", subtitle, "\n".join(lines),
                        valid_vcps_for_deploy=_deploy_projects)
                else:
                    tgw_bullet = ("  · Transit Gateway: Distributed"
                                  if mode == "distributed"
                                  else "  · Transit Gateway: Centralized")
                    req_lines = [tgw_bullet,
                                 "  · External IP Block",
                                 f"  · {cluster_label}",
                                 "  · N/S Services",
                                 "  · Outbound NAT"]
                    add("7", title_7, "error",
                        f"No valid {title_7} in any NSX Project",
                        "VPC Connectivity Profile requires the following settings:\n"
                        + "\n".join(req_lines)
                        + "\n\nThose are missing and this tool will guide you through this configuration.",
                        can_fix=True)

        # ── Step 8: HA/DRS (all modes) ───────────────────────────────────────
        if "clusters_error" in d:
            add("8", "vSphere HA / DRS", "warning", f"Could not check: {d['clusters_error']}")
        else:
            vc_clusters = d.get("vc_clusters", [])
            cluster_issues, cluster_ok = [], []
            for c in vc_clusters:
                name = c.get("name", c.get("cluster", "?"))
                bad  = []
                if c.get("ha_enabled")  is False: bad.append("HA disabled")
                if c.get("drs_enabled") is False: bad.append("DRS disabled")
                if bad: cluster_issues.append(f"{name}: {', '.join(bad)}")
                else:   cluster_ok.append(name)
            if cluster_issues:
                add("8", "vSphere HA / DRS", "warning",
                    f"{len(cluster_issues)} cluster(s) with issues",
                    "Issues:\n" + "\n".join(f"  • {i}" for i in cluster_issues)
                    + ("\n\nOK: " + ", ".join(cluster_ok) if cluster_ok else "")
                    + "\n\nNote: Both HA and DRS must be enabled on the Supervisor target cluster.")
            elif vc_clusters:
                add("8", "vSphere HA / DRS", "ok",
                    f"All {len(vc_clusters)} cluster(s) have HA and DRS enabled",
                    "Clusters: " + ", ".join(cluster_ok))
            else:
                add("8", "vSphere HA / DRS", "warning", "No clusters found via vCenter API.")

        return checks

    return jsonify({
        "modes": {
            "distributed": build_checks("distributed"),
            "centralized":  build_checks("centralized"),
            "vds_flb":      build_checks("vds_flb"),
        }
    })


@app.route("/api/discover-install-options", methods=["POST"])
def discover_install_options():
    """Auto-discover everything needed for the Supervisor install wizard."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    result = {
        "clusters": [],
        "storage_policies": [],
        "port_groups": [],
        "vc_defaults": {
            "gateway": "", "prefix": 24, "dns_servers": [],
            "search_domains": [], "ntp_servers": [],
        },
        "nsx_project_path": "/orgs/default/projects/default",
        "vpc_connectivity_profile_path": (
            "/orgs/default/projects/default/vpc-connectivity-profiles/default"
        ),
        "error": None,
    }

    try:
        token, _ = vc_auth(vc_url, username, password)

        result["clusters"] = vc_get(vc_url, token, "/api/vcenter/cluster") or []
        result["storage_policies"] = (
            vc_get(vc_url, token, "/api/vcenter/storage/policies") or []
        )
        result["port_groups"] = (
            vc_get(vc_url, token, "/api/vcenter/network",
                   params={"types": "DISTRIBUTED_PORTGROUP"}) or []
        )

        # vCenter appliance network defaults
        try:
            ifaces = vc_get(vc_url, token, "/api/appliance/networking/interfaces") or []
            for iface in (ifaces if isinstance(ifaces, list) else []):
                ipv4 = iface.get("ipv4") or {}
                gw = ipv4.get("default_gateway", "")
                prefix = ipv4.get("prefix", 24)
                if gw:
                    result["vc_defaults"]["gateway"] = f"{gw}/{prefix}"
                    result["vc_defaults"]["prefix"] = prefix
                    break
        except Exception:
            pass

        try:
            dns = vc_get(vc_url, token, "/api/appliance/networking/dns/servers") or {}
            result["vc_defaults"]["dns_servers"] = dns.get("servers", [])
            p = urlparse(vc_url)
            host_parts = (p.hostname or "").split(".")
            if len(host_parts) >= 3:
                result["vc_defaults"]["search_domains"] = [".".join(host_parts[1:])]
        except Exception:
            pass

        try:
            ntp = vc_get(vc_url, token, "/api/appliance/ntp") or []
            result["vc_defaults"]["ntp_servers"] = ntp if isinstance(ntp, list) else []
        except Exception:
            pass

        # NSX: discover valid distributed VPC profiles across all projects
        if nsx_url:
            try:
                # Build TGW attachment list for the default project
                _tgw_r = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/orgs/default/projects/default/transit-gateways")
                _tgw_att: list = []
                for _t in (_tgw_r or {}).get("results", []):
                    _tid = _t.get("id", "")
                    _ta  = nsx_get(nsx_url, nsx_user, nsx_pass,
                        f"/policy/api/v1/orgs/default/projects/default"
                        f"/transit-gateways/{_tid}/attachments")
                    for _a in (_ta or {}).get("results", []):
                        _a["_tgw_id"] = _tid
                        _tgw_att.append(_a)

                _projs = (nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/orgs/default/projects") or {}).get("results",
                    [{"id": "default", "display_name": "default", "path": ""}])

                valid_nsx_projects: list = []
                for _proj in _projs:
                    _pid = _proj.get("id", "")
                    _vcp_r = nsx_get(nsx_url, nsx_user, nsx_pass,
                        f"/policy/api/v1/orgs/default/projects/{_pid}/vpc-connectivity-profiles")
                    valid_profiles: list = []
                    for _vcp in (_vcp_r or {}).get("results", []):
                        _sg  = (_vcp.get("service_gateway") or {})
                        _nat = (_sg.get("nat_config") or {})
                        _tp  = _vcp.get("transit_gateway_path", "")
                        if not _tp:
                            continue
                        _tgw_id = _tp.rstrip("/").split("/")[-1]
                        _has_dist = any(
                            _a.get("_tgw_id") == _tgw_id and
                            "/distributed-vlan-connections/" in (_a.get("connection_path") or "")
                            for _a in _tgw_att
                        )
                        if (_has_dist and _vcp.get("external_ip_blocks") and
                                _sg.get("edge_cluster_paths") and _sg.get("enable") and
                                _nat.get("enable_default_snat")):
                            valid_profiles.append({
                                "id":           _vcp.get("id", ""),
                                "display_name": _vcp.get("display_name", _vcp.get("id", "")),
                                "path":         _vcp.get("path", ""),
                            })
                    if valid_profiles:
                        _ppath = _proj.get("path") or f"/orgs/default/projects/{_pid}"
                        valid_nsx_projects.append({
                            "id":           _pid,
                            "display_name": _proj.get("display_name", _pid),
                            "path":         _ppath,
                            "valid_vpc_profiles": valid_profiles,
                        })

                result["valid_nsx_projects"] = valid_nsx_projects
                if valid_nsx_projects:
                    result["nsx_project_path"] = valid_nsx_projects[0]["path"]
                    if valid_nsx_projects[0]["valid_vpc_profiles"]:
                        result["vpc_connectivity_profile_path"] = \
                            valid_nsx_projects[0]["valid_vpc_profiles"][0]["path"]
            except Exception:
                result["valid_nsx_projects"] = []

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


@app.route("/api/storage-policies-for-cluster", methods=["POST"])
def storage_policies_for_cluster():
    """Return storage policies compatible with the given cluster's datastores."""
    body          = request.get_json(force=True)
    vc_url        = normalize_url(body.get("vc_url", ""))
    username      = body.get("username", "")
    password      = body.get("password", "")
    cluster_moref = body.get("cluster_moref", "")
    result        = {"policies": [], "error": None}
    try:
        token, _ = vc_auth(vc_url, username, password)
        all_policies = vc_get(vc_url, token, "/api/vcenter/storage/policies") or []

        if cluster_moref:
            # Try to get cluster's datastores; filter.clusters is unsupported on some
            # vCenter 9 builds — fall back to listing all datastores.
            datastores: list = []
            for _ds_params in [{"filter.clusters": cluster_moref}, None]:
                try:
                    _ds = vc_get(vc_url, token, "/api/vcenter/datastore",
                                 params=_ds_params) or []
                    if isinstance(_ds, list) and _ds:
                        datastores = _ds
                        break
                except Exception:
                    pass

            # Collect compat IDs using per-datastore filter
            compat_ids: set = set()
            ds_type_set: set = set()
            for ds in datastores[:5]:
                ds_id = ds.get("datastore", "")
                if not ds_id:
                    continue
                # Collect datastore types for exclusion heuristics
                try:
                    ds_info = vc_get(vc_url, token, f"/api/vcenter/datastore/{ds_id}")
                    if ds_info:
                        ds_type_set.add(ds_info.get("type", "").upper())
                except Exception:
                    pass
                try:
                    ds_pols = vc_get(vc_url, token, "/api/vcenter/storage/policies",
                                     params={"filter.datastores": ds_id}) or []
                    for p in ds_pols:
                        pid = p.get("policy", "")
                        if pid:
                            compat_ids.add(pid)
                except Exception:
                    pass

            has_vvol = "VVOL" in ds_type_set
            has_pmem = "PMEM" in ds_type_set or "PERSISTENTMEMORY" in ds_type_set

            # Try to detect stretched vSAN and ESA via vCenter vSAN API
            is_stretched = False
            is_esa       = False
            for _ep in [
                f"/api/vcenter/vsan/cluster/{cluster_moref}/config",
                f"/api/vcenter/vsan/config/{cluster_moref}",
            ]:
                try:
                    _cfg = vc_get(vc_url, token, _ep)
                    if isinstance(_cfg, dict):
                        if _cfg.get("stretched_cluster") or _cfg.get("is_stretched"):
                            is_stretched = True
                        _st = str(_cfg.get("storage_type", "") or "").upper()
                        if "ESA" in _st or "EXPRESS" in _st:
                            is_esa = True
                        break
                except Exception:
                    pass

            def _policy_applicable(p: dict) -> bool:
                """Return False for policies that clearly cannot place VMs on this cluster."""
                n = p.get("name", "").lower()
                if "vvol" in n and not has_vvol:
                    return False
                if "pmem" in n and not has_pmem:
                    return False
                # "Stretched" policies need a stretched vSAN cluster
                if "stretched" in n and not is_stretched:
                    return False
                # Pure ESA policies need a vSAN ESA cluster
                # (skip if already caught by "stretched" filter above)
                if "esa" in n and not is_esa and "stretched" not in n:
                    return False
                return True

            if compat_ids:
                result["policies"] = [
                    p for p in all_policies
                    if p.get("policy", "") in compat_ids and _policy_applicable(p)
                ]
            else:
                result["policies"] = [p for p in all_policies if _policy_applicable(p)]
        else:
            result["policies"] = all_policies
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        result["policies"] = []
    except Exception as e:
        result["error"] = str(e)
        result["policies"] = []
    return jsonify(result)


@app.route("/api/install-supervisor", methods=["POST"])
def install_supervisor():
    """Enable Supervisor using the NSX VPC (enable_on_zones) API."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    cfg = body.get("config", {})

    result = {"success": False, "supervisor_id": None, "error": None}

    def _list(val):
        if isinstance(val, list):
            return [str(v).strip() for v in val if str(v).strip()]
        return [v.strip() for v in str(val).split(",") if v.strip()]

    try:
        token, _ = vc_auth(vc_url, username, password)

        # Sanitise first_ip — if user typed "10.1.1.85-10.1.1.89" take only the first IP
        raw_first_ip = str(cfg.get("first_ip", "")).strip()
        if "-" in raw_first_ip:
            raw_first_ip = raw_first_ip.split("-")[0].strip()
        cfg["first_ip"] = raw_first_ip

        dns = _list(cfg.get("dns_servers", ""))
        ntp = _list(cfg.get("ntp_servers", ""))
        domains = _list(cfg.get("search_domains", ""))

        spec = {
            "name": cfg["name"],
            "zones": [cfg["cluster_moref"]],
            "control_plane": {
                "size": cfg.get("size", "SMALL"),
                "storage_policy": cfg["storage_policy_uuid"],
                "network": {
                    "backing": {
                        "backing": "NETWORK",
                        "network": cfg["port_group_id"],
                    },
                    "services": {
                        "dns": {"servers": dns, "search_domains": domains},
                        "ntp": {"servers": ntp},
                    },
                    "ip_management": {
                        "dhcp_enabled": False,
                        "gateway_address": cfg["gateway_cidr"],
                        "ip_assignments": [
                            {
                                "assignee": "NODE",
                                "ranges": [{"address": cfg["first_ip"], "count": 5}],
                            }
                        ],
                    },
                },
            },
            "workloads": {
                "network": {
                    "network_type": "NSX_VPC",
                    "nsx_vpc": {
                        "nsx_project": cfg.get(
                            "nsx_project_path", "/orgs/default/projects/default"
                        ),
                        "vpc_connectivity_profile": cfg.get(
                            "vpc_connectivity_profile_path",
                            "/orgs/default/projects/default/vpc-connectivity-profiles/default",
                        ),
                        "default_private_cidrs": [{"address": "172.30.0.0", "prefix": 16}],
                    },
                    "services": {
                        "dns": {"servers": dns, "search_domains": domains},
                        "ntp": {"servers": ntp},
                    },
                    "ip_management": {
                        "dhcp_enabled": False,
                        "ip_assignments": [
                            {
                                "assignee": "SERVICE",
                                "ranges": [{"address": "10.96.0.0", "count": 1048576}],
                            }
                        ],
                    },
                },
                "edge": {"provider": "NSX", "nsx": {"routing_mode": "NO_NAT"}},
                "storage": {
                    "ephemeral_storage_policy": cfg["storage_policy_uuid"],
                    "image_storage_policy": cfg["storage_policy_uuid"],
                },
            },
        }

        resp = SESS.post(
            f"{vc_url}/api/vcenter/namespace-management/supervisors?action=enable_on_zones",
            headers={
                "vmware-api-session-id": token,
                "Content-Type": "application/json",
            },
            json=spec,
            timeout=30,
        )

        if resp.ok:
            result.update(success=True, supervisor_id=resp.json())
        else:
            msgs = ""
            try:
                msgs = "; ".join(
                    m.get("default_message", "")
                    for m in (resp.json().get("messages") or [])
                )
            except Exception:
                pass
            result["error"] = f"HTTP {resp.status_code}: {msgs or resp.text[:500]}"

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:500]}"
    except Exception as e:
        result["error"] = traceback.format_exc()

    return jsonify(result)


@app.route("/api/supervisor-status", methods=["POST"])
def supervisor_status():
    """Poll Supervisor deployment status by cluster moref."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    cluster_id = body.get("cluster_id", "")

    result = {"success": False, "status": None, "error": None}
    try:
        token, _ = vc_auth(vc_url, username, password)
        status = vc_get(
            vc_url, token, f"/api/vcenter/namespace-management/clusters/{cluster_id}"
        )
        # Normalise messages to plain strings so the frontend never shows [object Object]
        if status and "messages" in status:
            def _msg_text(m):
                if isinstance(m, str):
                    return m
                return (m.get("default_message") or m.get("message") or
                        " ".join(str(a) for a in (m.get("args") or [])) or
                        str(m))
            status["messages"] = [_msg_text(m) for m in status["messages"] if m]
        result.update(success=True, status=status)
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


@app.route("/api/fix/vna-status", methods=["POST"])
def fix_vna_status():
    """Poll the VNA cluster deployment state."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or body.get("password", "")
    cluster_id = body.get("cluster_id", "vna-cluster-1")

    result = {"success": False, "error": None,
              "consolidated_status": "UNKNOWN", "members": []}
    try:
        state = nsx_get(nsx_url, nsx_user, nsx_pass,
            f"/policy/api/v1/infra/sites/default/enforcement-points/default"
            f"/virtual-network-appliance-clusters/{cluster_id}/state")
        if state is None:
            result["error"] = "Cluster not found"
            return jsonify(result)
        result["success"]            = True
        result["consolidated_status"] = state.get("consolidated_status", "UNKNOWN")
        members = []
        for m in (state.get("members_state") or []):
            cfg   = m.get("configuration_state") or {}
            prog  = cfg.get("progress_state") or {}
            members.append({
                "name":     m.get("member_path", "").rstrip("/").split("/")[-1],
                "status":   cfg.get("state", "UNKNOWN"),
                "step":     prog.get("current_step_title", ""),
                "progress": prog.get("progress", 0),
            })
        result["members"] = members
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)



@app.route("/api/fix/vna-options", methods=["POST"])
def fix_vna_options():
    """Return all data needed to populate the VNA install wizard."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    result = {
        "success": False, "error": None,
        "port_groups": [], "clusters": [], "datastores": [],
        "vc_subnet": None, "vc_gateway": None, "vc_prefix": 24,
        "vc_dns": [], "vc_ntp": [],
        "domain": "", "compute_manager_id": None,
        # auto-discovered NSX fields
        "overlay_tz_path": None,
        "vm_mgmt_dvpg":    None,
    }
    try:
        token, _ = vc_auth(vc_url, username, password)

        result["port_groups"] = vc_get(
            vc_url, token, "/api/vcenter/network",
            params={"types": "DISTRIBUTED_PORTGROUP"}) or []
        result["clusters"] = vc_get(vc_url, token, "/api/vcenter/cluster") or []
        ds_raw = vc_get(vc_url, token, "/api/vcenter/datastore") or []
        result["datastores"] = sorted(ds_raw,
                                      key=lambda d: d.get("free_space", 0), reverse=True)

        try:
            ifaces = vc_get(vc_url, token, "/api/appliance/networking/interfaces") or []
            for iface in (ifaces if isinstance(ifaces, list) else []):
                ipv4 = (iface.get("ipv4") or {})
                vc_ip  = ipv4.get("address", "")
                prefix = ipv4.get("prefix", 24)
                gw     = ipv4.get("default_gateway", "")
                if vc_ip and gw:
                    result["vc_subnet"]  = f"{vc_ip}/{prefix}"
                    result["vc_gateway"] = gw
                    result["vc_prefix"]  = prefix
                    break
        except Exception:
            pass

        try:
            dns_resp = vc_get(vc_url, token, "/api/appliance/networking/dns/servers") or {}
            result["vc_dns"] = dns_resp.get("servers", [])
        except Exception:
            pass

        try:
            ntp = vc_get(vc_url, token, "/api/appliance/ntp") or []
            result["vc_ntp"] = ntp if isinstance(ntp, list) else []
        except Exception:
            pass

        try:
            p = urlparse(vc_url)
            parts = (p.hostname or "").split(".")
            if len(parts) >= 3:
                result["domain"] = ".".join(parts[1:])
        except Exception:
            pass

        if nsx_url:
            # Compute manager ID
            try:
                cms_resp = SESS.get(
                    f"{nsx_url}/api/v1/fabric/compute-managers",
                    auth=(nsx_user, nsx_pass),
                    headers={"Accept": "application/json"},
                    verify=False, timeout=15,
                )
                if cms_resp.ok:
                    vc_host = urlparse(vc_url).hostname or ""
                    for cm in cms_resp.json().get("results", []):
                        srv = cm.get("server", "")
                        if srv == vc_host or vc_host in srv or srv in vc_host:
                            result["compute_manager_id"] = cm["id"]
                            break
                    if not result["compute_manager_id"]:
                        for cm in cms_resp.json().get("results", []):
                            if cm.get("origin_type") == "vCenter":
                                result["compute_manager_id"] = cm["id"]
                                break
            except Exception:
                pass

            # Auto-discover overlay TZ path and vm-mgmt DVPG from TNC tags
            try:
                tnc_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/infra/sites/default/enforcement-points/default"
                    "/transport-node-collections")
                tnc_results = (tnc_resp or {}).get("results", [])
                if tnc_results:
                    tnc0 = tnc_results[0]
                    # vm-mgmt DVPG from tag
                    for tag in (tnc0.get("tags") or []):
                        if tag.get("scope") == "vcf-orchestration/vm-mgmt-dvpg-moid":
                            result["vm_mgmt_dvpg"] = tag.get("tag")
                            break
                    # overlay TZ path — from TNC → TNP (primary method per doc)
                    tnp_id = tnc0.get("transport_node_profile_id", "")
                    # profile_id may be a full path like "/infra/host-transport-node-profiles/xyz"
                    if "/" in tnp_id:
                        tnp_id = tnp_id.rstrip("/").split("/")[-1]
                    if tnp_id:
                        tnp = nsx_get(nsx_url, nsx_user, nsx_pass,
                            f"/policy/api/v1/infra/host-transport-node-profiles/{tnp_id}")
                        if tnp:
                            hs_list = (tnp.get("host_switch_spec") or {}).get("host_switches", [])
                            for hs in hs_list:
                                for tz_ep in hs.get("transport_zone_endpoints", []):
                                    tz_id = (tz_ep.get("transport_zone_id")
                                             or tz_ep.get("transport_zone_path", ""))
                                    if not tz_id:
                                        continue
                                    # Normalise bare IDs to full Policy path
                                    if not tz_id.startswith("/"):
                                        tz_id = (
                                            "/infra/sites/default/enforcement-points"
                                            f"/default/transport-zones/{tz_id}"
                                        )
                                    result["overlay_tz_path"] = tz_id
                                    break
                                if result["overlay_tz_path"]:
                                    break
            except Exception:
                pass

            # Fallback: list all transport zones and return them so the wizard
            # can show a dropdown if auto-discovery didn't find a single answer.
            try:
                tzs_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/infra/sites/default/enforcement-points/default"
                    "/transport-zones")
                overlay_tzs = []
                for tz in (tzs_resp or {}).get("results", []):
                    tz_type = tz.get("tz_type", "")
                    if "OVERLAY" in tz_type.upper():
                        overlay_tzs.append({
                            "id":    tz.get("id", ""),
                            "name":  tz.get("display_name", tz.get("id", "")),
                            "path":  tz.get("path") or (
                                "/infra/sites/default/enforcement-points"
                                f"/default/transport-zones/{tz.get('id','')}"),
                        })
                result["overlay_tzs"] = overlay_tzs
                # If primary method failed, auto-pick:
                # prefer a non-standard TZ (anything except nsx-overlay-transportzone)
                if not result["overlay_tz_path"]:
                    preferred = [t for t in overlay_tzs
                                 if t["id"] != "nsx-overlay-transportzone"]
                    if preferred:
                        result["overlay_tz_path"] = preferred[0]["path"]
                    elif overlay_tzs:
                        result["overlay_tz_path"] = overlay_tzs[0]["path"]
            except Exception:
                pass

        result["success"] = True

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


@app.route("/api/fix/create-vna", methods=["POST"])
def fix_create_vna():
    """Deploy a VNA cluster via the two-step NSX Policy API:
       1. PUT the cluster object (metadata only, no nodes).
       2. PUT each node separately under the cluster path.
    """
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or body.get("password", "")

    port_group_id      = body.get("port_group_id", "")
    cluster_moref      = body.get("cluster_moref", "")
    datastore_id       = body.get("datastore_id", "")
    compute_manager_id = body.get("compute_manager_id", "")
    overlay_tz_path    = body.get("overlay_tz_path", "")
    ip1       = body.get("ip1", "")
    ip2       = body.get("ip2", "")
    prefix    = int(body.get("prefix", 24))
    gateway   = body.get("gateway", "")
    dns_list  = body.get("dns", [])
    ntp_list  = body.get("ntp", [])
    domain    = body.get("domain", "local")
    form_factor = body.get("form_factor", "MEDIUM")

    result = {"success": False, "error": None}
    base  = ("/policy/api/v1/infra/sites/default/enforcement-points/default"
             "/virtual-network-appliance-clusters")
    ha_profile = ("/infra/sites/default/enforcement-points/default"
                  "/edge-cluster-high-availability-profiles"
                  "/019a9fc9-f1ab-76b9-b515-d73348fdf2fe")
    failure_domain = ("/infra/sites/default/enforcement-points/default"
                      "/failure-domains/4fc1e3b0-1cd4-4339-86c8-f76baddbaafb")
    nsx_headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def nsx_put(path, payload):
        # Use a fresh session for each PUT to avoid SSL session reuse issues
        r = requests.put(f"{nsx_url}{path}", auth=(nsx_user, nsx_pass),
                         headers=nsx_headers, json=payload, verify=False, timeout=30)
        return r

    def extract_error(r):
        try:
            err  = r.json()
            msgs = "; ".join(
                m.get("default_message", "")
                for m in (err.get("error_messages") or [])
            )
            return f"HTTP {r.status_code}: {msgs or err.get('error_message') or r.text[:500]}"
        except Exception:
            return f"HTTP {r.status_code}: {r.text[:500]}"

    try:
        cluster_id = "vna-cluster-1"

        # ── Step 1: create the cluster object ────────────────────────────
        cluster_payload = {
            "resource_type":     "VirtualNetworkApplianceCluster",
            "id":                cluster_id,
            "display_name":      cluster_id,
            "appliance_form_factor": form_factor,
            "appliance_type":    "VirtualNetworkAppliance",
            "service_type":      "VPC_SERVICES",
            "advanced_configuration": {
                "overlay_transport_zone_path": overlay_tz_path,
                "high_availability_profile":  ha_profile,
            },
        }
        r1 = nsx_put(f"{base}/{cluster_id}", cluster_payload)
        if not r1.ok:
            result["error"] = f"[Create cluster] {extract_error(r1)}"
            return jsonify(result)

        # ── Step 2: create each node ──────────────────────────────────────
        for i, ip in enumerate([ip1, ip2]):
            node_id = f"vna-node-{i + 1}"
            node_payload = {
                "resource_type":     "VirtualNetworkAppliance",
                "id":                node_id,
                "display_name":      node_id,
                "hostname":          f"{node_id}.{domain}",
                "failure_domain_path": failure_domain,
                "vm_deployment_config": {
                    "compute_manager_id":          compute_manager_id,
                    "cluster_or_resource_pool_id": cluster_moref,
                    "datastore_id":                datastore_id,
                    "reservation_info": {
                        "memory_reservation": {"reservation_percentage": 100},
                        "cpu_reservation":    {"reservation_in_shares": "HIGH_PRIORITY"},
                    },
                },
                "management_interface": {
                    "ip_assignment_specs": [{
                        "management_port_subnets": [
                            {"ip_addresses": [ip], "prefix_length": prefix}
                        ],
                        "default_gateway":    [gateway],
                        "ip_assignment_type": "StaticIpv4",
                    }],
                    "network_id": port_group_id,
                },
                "credentials": {
                    "cli_username":   "admin",
                    "audit_username": "audit",
                },
            }
            r2 = nsx_put(f"{base}/{cluster_id}/virtual-network-appliances/{node_id}",
                         node_payload)
            if not r2.ok:
                result["error"] = f"[Create node {node_id}] {extract_error(r2)}"
                return jsonify(result)

        result["success"] = True
        result["cluster_id"] = cluster_id

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:500]}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── shared helpers for Fix endpoints ─────────────────────────────────────────

def _nsx_creds(body):
    vc_url      = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url     = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user    = body.get("nsx_user") or "admin"
    nsx_pass    = body.get("nsx_pass") or body.get("password", "")
    return nsx_url, nsx_user, nsx_pass


def _nsx_error(r):
    try:
        err  = r.json()
        msgs = "; ".join(m.get("default_message", "")
                         for m in (err.get("error_messages") or []))
        return (f"HTTP {r.status_code}: "
                f"{msgs or err.get('error_message') or r.text[:500]}")
    except Exception:
        return f"HTTP {r.status_code}: {r.text[:500]}"


def _nsx_put(nsx_url, nsx_user, nsx_pass, path, payload):
    return requests.put(
        f"{nsx_url}{path}",
        auth=(nsx_user, nsx_pass),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload, verify=False, timeout=30,
    )


# ── Fix: fetch all NSX state needed for S4-S7 wizards ────────────────────────

@app.route("/api/fix/nsx-prereq-options", methods=["POST"])
def fix_nsx_prereq_options():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)

    def _list(path):
        r = nsx_get(nsx_url, nsx_user, nsx_pass, path)
        return (r or {}).get("results", [])

    def _to_item(o):
        return {"id":   o.get("id", ""),
                "name": o.get("display_name", o.get("id", "")),
                "path": o.get("path", ""),
                "cidr": _block_cidr(o, nsx_url, nsx_user, nsx_pass)}

    result = {"success": False, "error": None}
    try:
        result["dvlan_connections"] = _list("/policy/api/v1/infra/distributed-vlan-connections")
        result["gw_connections"]    = _list("/policy/api/v1/infra/gateway-connections")
        result["tgw_attachments"]   = _list(
            "/policy/api/v1/orgs/default/projects/default/transit-gateways/default/attachments")
        all_global_raw              = _list("/policy/api/v1/infra/ip-blocks")
        result["ip_blocks"]         = [_to_item(b) for b in all_global_raw]

        # Centralized External IP Blocks:
        # - visibility == EXTERNAL
        # - CIDR does NOT overlap with any Distributed VLAN connection subnet
        import ipaddress as _ip
        dvlan_nets: list = []
        for dv in result["dvlan_connections"]:
            for gw in (dv.get("gateway_addresses") or []):
                try:
                    dvlan_nets.append(_ip.ip_network(
                        str(_ip.ip_interface(gw).network), strict=False))
                except Exception:
                    pass
        cent_ext: list = []
        for b in all_global_raw:
            if (b.get("visibility") or "").upper() != "EXTERNAL":
                continue
            raw_cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
            if not raw_cidr:
                continue
            try:
                block_net = _ip.ip_network(raw_cidr, strict=False)
            except Exception:
                continue
            if any(block_net.overlaps(dn) for dn in dvlan_nets):
                continue
            item = _to_item(b)
            cent_ext.append(item)
        result["cent_ext_ip_blocks"] = cent_ext
        # Private TGW blocks: global ones with visibility=PRIVATE  +  project-level blocks
        private_from_global  = [_to_item(b) for b in all_global_raw
                                 if (b.get("visibility") or "").upper() == "PRIVATE"]
        private_from_project = [_to_item(b) for b in _list(
                                    "/policy/api/v1/orgs/default/projects/default/infra/ip-blocks")]
        seen_paths: set = set()
        combined_private: list = []
        for p in private_from_global + private_from_project:
            key = p["path"] or p["id"]
            if key and key not in seen_paths:
                seen_paths.add(key)
                combined_private.append(p)
        result["private_ip_blocks"] = combined_private
        result["vna_clusters"]      = [_to_item(v)
                                        for v in _list(
                                            "/policy/api/v1/infra/sites/default/enforcement-points"
                                            "/default/virtual-network-appliance-clusters")]
        result["edge_clusters"]     = [_to_item(e)
                                        for e in _list(
                                            "/policy/api/v1/infra/sites/default/enforcement-points"
                                            "/default/edge-clusters")]
        result["t0s"]               = [_to_item(t)
                                        for t in _list("/policy/api/v1/infra/tier-0s")]
        result["vpc_profile"]       = nsx_get(nsx_url, nsx_user, nsx_pass,
                                              "/policy/api/v1/orgs/default/projects/default"
                                              "/vpc-connectivity-profiles/default")
        tgw_raw = nsx_get(nsx_url, nsx_user, nsx_pass,
                          "/policy/api/v1/orgs/default/projects/default/transit-gateways/default")
        result["tgw"] = _to_item(tgw_raw) if tgw_raw else {"id": "default", "name": "Default Transit Gateway", "path": ""}

        # Identify Centralized TGWs (any TGW with a gateway-connection attachment)
        all_tgws_raw = (_list("/policy/api/v1/orgs/default/projects/default/transit-gateways")
                        if True else [])
        cent_tgws: list = []
        for _t in all_tgws_raw:
            _tid = _t.get("id", "")
            _atts = (_list(f"/policy/api/v1/orgs/default/projects/default"
                           f"/transit-gateways/{_tid}/attachments"))
            has_cent = any("/gateway-connections/" in (a.get("connection_path") or "")
                           for a in _atts)
            if has_cent:
                cent_tgws.append({"id": _tid,
                                   "name": _t.get("display_name", _tid),
                                   "path": _t.get("path", "")})
        result["cent_tgws"] = cent_tgws
        result["success"] = True
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


# ── Fix S4 Distributed: Create VLAN External Connection ──────────────────────

@app.route("/api/fix/create-vlan-connection", methods=["POST"])
def fix_create_vlan_connection():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name         = body.get("name", "dvlan-connection-1")
    vlan_id      = int(body.get("vlan_id") or 0)
    gateway_cidr = body.get("gateway_cidr", "")
    result = {"success": False, "error": None}
    try:
        payload = {"resource_type": "DistributedVlanConnection",
                   "id": name, "display_name": name,
                   "vlan_id": vlan_id,
                   "gateway_addresses": [gateway_cidr]}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/distributed-vlan-connections/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/distributed-vlan-connections/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S4 Centralized: Create Gateway Connection ────────────────────────────

@app.route("/api/fix/create-gateway-connection", methods=["POST"])
def fix_create_gateway_connection():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name    = body.get("name", "gw-connection-1")
    t0_path = body.get("t0_path", "")
    result = {"success": False, "error": None}
    try:
        payload = {"resource_type": "GatewayConnection",
                   "id": name, "display_name": name, "tier0_path": t0_path}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/gateway-connections/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/gateway-connections/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S5: Create TGW Attachment ─────────────────────────────────────────────

@app.route("/api/fix/create-tgw-attachment", methods=["POST"])
def fix_create_tgw_attachment():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        payload: dict = {"resource_type": "TransitGatewayAttachment",
                         "id": att_id, "display_name": att_id,
                         "connection_path": connection_path,
                         "urpf_mode": "STRICT"}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/default/attachments/{att_id}", payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S5 Distributed Case 2: Create new Distributed TGW + Attachment ───────

@app.route("/api/fix/create-dist-tgw", methods=["POST"])
def fix_create_dist_tgw():
    """Create a new Distributed Transit Gateway and attach it to a DVLAN connection."""
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    tgw_name        = (body.get("new_tgw_name") or "dist-tgw1").strip()
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        # Step 1: Create the new Transit Gateway
        tgw_payload = {"resource_type": "TransitGateway",
                       "id": tgw_name,
                       "display_name": tgw_name}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}", tgw_payload)
        if not r.ok:
            result["error"] = f"[Create TGW] {_nsx_error(r)}"
            return jsonify(result)

        # Step 2: Attach the new TGW to the DVLAN connection
        att_payload = {"resource_type": "TransitGatewayAttachment",
                       "id": att_id, "display_name": att_id,
                       "connection_path": connection_path,
                       "urpf_mode": "STRICT"}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}/attachments/{att_id}", att_payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = f"[Create Attachment] {_nsx_error(r)}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)

@app.route("/api/fix/create-cent-tgw", methods=["POST"])
def fix_create_cent_tgw():
    """Create a new Centralized Transit Gateway and attach it to a Gateway Connection."""
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    tgw_name        = (body.get("new_tgw_name") or "cent-tgw1").strip()
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        # Step 1: Create the new Transit Gateway
        tgw_payload: dict = {"resource_type": "TransitGateway",
                             "id": tgw_name,
                             "display_name": tgw_name}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}", tgw_payload)
        if not r.ok:
            result["error"] = f"[Create TGW] {_nsx_error(r)}"
            return jsonify(result)

        # Step 2: Attach the new TGW to the Gateway Connection
        # NSX auto-creates CentralizedConfig (edge cluster) from the T0 — no need to set it here.
        att_payload: dict = {"resource_type": "TransitGatewayAttachment",
                             "id": att_id, "display_name": att_id,
                             "connection_path": connection_path}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}/attachments/{att_id}", att_payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = f"[Create Attachment] {_nsx_error(r)}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


@app.route("/api/fix/create-ip-block", methods=["POST"])
def fix_create_ip_block():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name             = body.get("name", "ext-ip-block-1")
    cidr             = body.get("cidr", "")
    excluded_ranges  = (body.get("excluded_ranges") or "").strip()
    result = {"success": False, "error": None}
    try:
        payload = {"id": name, "display_name": name, "cidr": cidr, "visibility": "EXTERNAL"}
        if excluded_ranges:
            payload["description"] = f"Excluded ranges: {excluded_ranges}"
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/ip-blocks/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/ip-blocks/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S7 options: VPC Profile wizard data (projects, dist TGWs, IP blocks) ──

@app.route("/api/fix/vpc-profile-options", methods=["POST"])
def fix_vpc_profile_options():
    """Return all data needed for the Step 7 Distributed Fix wizard."""
    import ipaddress as _ip
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    project_id = body.get("project_id", "default")

    def _lst(path):
        r = nsx_get(nsx_url, nsx_user, nsx_pass, path)
        return (r or {}).get("results", [])

    def _item(o):
        return {"id":           o.get("id", ""),
                "display_name": o.get("display_name", o.get("id", "")),
                "path":         o.get("path", "")}

    result = {"success": False}
    try:
        # ── NSX Projects ────────────────────────────────────────────────────
        projs_raw = _lst("/policy/api/v1/orgs/default/projects")
        result["projects"] = [_item(p) for p in projs_raw] or [
            {"id": "default", "display_name": "default", "path": ""}]

        # ── Distributed TGWs in the selected project ─────────────────────
        all_tgws = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/transit-gateways")
        dist_tgws = []
        for tgw in all_tgws:
            tid = tgw.get("id", "")
            att_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                f"/policy/api/v1/orgs/default/projects/{project_id}"
                f"/transit-gateways/{tid}/attachments")
            atts = (att_resp or {}).get("results", [])
            dist_atts = [a for a in atts
                         if "/distributed-vlan-connections/" in (a.get("connection_path") or "")]
            if not dist_atts:
                continue
            # Fetch the DVLAN connection details so we can compute subnet overlap
            dvlan_conns = []
            for a in dist_atts:
                cp = a.get("connection_path", "")
                conn = nsx_get(nsx_url, nsx_user, nsx_pass, f"/policy/api/v1{cp}") if cp else None
                if conn:
                    dvlan_conns.append(conn)
            dist_tgws.append({**_item(tgw), "dvlan_connections": dvlan_conns})
        result["dist_tgws"] = dist_tgws

        # ── Global EXTERNAL IP blocks ────────────────────────────────────
        all_global = _lst("/policy/api/v1/infra/ip-blocks")
        ext_blocks = []
        for b in all_global:
            if (b.get("visibility") or "").upper() == "EXTERNAL":
                cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                ext_blocks.append({**_item(b), "cidr": cidr})
        result["ext_ip_blocks"] = ext_blocks

        # ── Compute matching ext blocks per dist TGW (subnet overlap) ────
        for tgw in dist_tgws:
            dvlan_nets = []
            for conn in tgw.get("dvlan_connections", []):
                for gw in (conn.get("gateway_addresses") or []):
                    try:
                        dvlan_nets.append(_ip.ip_interface(gw).network)
                    except Exception:
                        pass
            if dvlan_nets:
                matching = []
                for b in ext_blocks:
                    try:
                        bnet = _ip.ip_network(b["cidr"], strict=False)
                        if any(bnet.overlaps(dn) for dn in dvlan_nets):
                            matching.append(b["path"])
                    except Exception:
                        pass
                tgw["matching_ext_block_paths"] = matching if matching else [b["path"] for b in ext_blocks]
            else:
                tgw["matching_ext_block_paths"] = [b["path"] for b in ext_blocks]

        # ── VNA Clusters (global) ────────────────────────────────────────
        vna_raw = _lst("/policy/api/v1/infra/sites/default/enforcement-points"
                       "/default/virtual-network-appliance-clusters")
        result["vna_clusters"] = [_item(v) for v in vna_raw]

        # ── Private IP Blocks in the project (not used by any VPC) ───────
        private_global = [b for b in all_global
                          if (b.get("visibility") or "").upper() == "PRIVATE"]
        proj_blocks = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/infra/ip-blocks")
        vpcs = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/vpcs")
        vpc_block_paths: set = set()
        for vpc in vpcs:
            for bp in (vpc.get("private_ipv4_blocks") or vpc.get("ip_blocks") or []):
                vpc_block_paths.add(bp)
        seen: set = set()
        private_result = []
        for b in private_global + proj_blocks:
            key = b.get("path") or b.get("id")
            if key and key not in seen and b.get("path") not in vpc_block_paths:
                seen.add(key)
                cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                private_result.append({**_item(b), "cidr": cidr})
        result["private_ip_blocks"] = private_result

        result["success"] = True
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S7: Configure VPC Connectivity Profile ────────────────────────────────

@app.route("/api/fix/configure-vpc-profile", methods=["POST"])
def fix_configure_vpc_profile():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    project_id            = body.get("project_id", "default")
    mode                  = body.get("mode", "distributed")
    tgw_path              = (body.get("tgw_path") or
                             f"/orgs/default/projects/{project_id}/transit-gateways/default")
    ext_ip_block_path     = body.get("ext_ip_block_path", "")
    cluster_path          = body.get("cluster_path", "")
    private_ip_block_path = body.get("private_ip_block_path", "")
    # If the selected TGW is not the Default TGW, use a dedicated profile
    # to avoid the NSX restriction "transit_gateway_path change not supported".
    is_default_tgw = tgw_path.rstrip("/").split("/")[-1] == "default"
    if is_default_tgw:
        profile_id = "default"
    elif mode == "centralized":
        profile_id = "vpc-cent-prof1"
    else:
        profile_id = "vpc-dist-prof1"
    profile_api = (f"/policy/api/v1/orgs/default/projects/{project_id}"
                   f"/vpc-connectivity-profiles/{profile_id}")
    result = {"success": False, "error": None, "profile_id": profile_id}
    try:
        payload = {
            "external_ip_blocks": [ext_ip_block_path],
            "service_gateway": {
                "enable":             True,
                "edge_cluster_paths": [cluster_path],
                "nat_config": {
                    "enable_default_snat": True,
                    "auto_snat_ip_block":  ext_ip_block_path,
                },
            },
        }
        if private_ip_block_path:
            payload["private_tgw_ip_blocks"] = [private_ip_block_path]

        # If the profile already exists, PATCH (TGW path cannot be changed by NSX).
        # If new, PUT to create it with the TGW path.
        existing = nsx_get(nsx_url, nsx_user, nsx_pass, profile_api)
        if existing:
            r = requests.patch(
                f"{nsx_url}{profile_api}",
                auth=(nsx_user, nsx_pass),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json=payload, verify=False, timeout=30,
            )
        else:
            payload["transit_gateway_path"] = tgw_path
            r = _nsx_put(nsx_url, nsx_user, nsx_pass, profile_api, payload)

        if r.ok:
            result["success"] = True
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
