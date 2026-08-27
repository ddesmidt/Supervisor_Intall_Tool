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
    return render_template("index_clarity.html")


@app.route("/api/check-installed", methods=["POST"])
def check_installed():
    body = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    # Fall back to auto-discovery from vCenter if NSX URL not supplied (e.g. browser autofill race)
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

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

        # Determine human-readable network mode for each cluster.
        # For NSX_VPC: vCenter cluster detail → VPC profile → NSX TGW → check attachment type.
        for c in enriched:
            np = c.get("network_provider", "")
            if np == "VSPHERE_NETWORK":
                c["network_mode"] = "VDS / FLB"
            elif np == "NSX_T":
                c["network_mode"] = "NSX-T (Legacy)"
            elif np == "NSX_VPC":
                c["network_mode"] = "NSX-VPC"  # default; refined below
                c["network_mode_warning"] = None

                def _detect_nsx_vpc_mode(nsx, user, pw, prof_path):
                    """Return 'NSX-VPC Distributed', 'NSX-VPC Centralized', or None."""
                    vcp      = nsx_get(nsx, user, pw, f"/policy/api/v1{prof_path}")
                    tgw_path = (vcp or {}).get("transit_gateway_path", "")
                    if not tgw_path:
                        return None
                    parts   = tgw_path.rstrip("/").split("/")
                    tgw_id  = parts[-1]
                    try:
                        tgw_proj = parts[parts.index("projects") + 1]
                    except (ValueError, IndexError):
                        tgw_proj = "default"
                    ta   = nsx_get(nsx, user, pw,
                                   f"/policy/api/v1/orgs/default/projects/{tgw_proj}"
                                   f"/transit-gateways/{tgw_id}/attachments")
                    atts = (ta or {}).get("results", [])
                    if any("/distributed-vlan-connections/" in (a.get("connection_path") or "") for a in atts):
                        return "NSX-VPC Distributed"
                    if any("/gateway-connections/" in (a.get("connection_path") or "") for a in atts):
                        return "NSX-VPC Centralized"
                    return None

                if nsx_url:
                    # Build the VPC profile path from vCenter cluster detail
                    vpc_net       = c.get("vpc_network") or {}
                    vpc_prof_path = vpc_net.get("vpc_connectivity_profile", "")
                    nsx_proj_path = vpc_net.get("nsx_project", "/orgs/default/projects/default")
                    parts_proj    = nsx_proj_path.rstrip("/").split("/")
                    nsx_proj_id   = (parts_proj[parts_proj.index("projects") + 1]
                                     if "projects" in parts_proj else "default")
                    if not vpc_prof_path:
                        vpc_prof_path = f"/orgs/default/projects/{nsx_proj_id}/vpc-connectivity-profiles/default"
                    if "/" not in vpc_prof_path:
                        vpc_prof_path = f"/orgs/default/projects/{nsx_proj_id}/vpc-connectivity-profiles/{vpc_prof_path}"

                    # First attempt with supplied NSX URL
                    detected = None
                    try:
                        detected = _detect_nsx_vpc_mode(nsx_url, nsx_user, nsx_pass, vpc_prof_path)
                    except Exception:
                        pass

                    # Second attempt: auto-discovered URL (handles truncated/wrong FQDNs)
                    if detected is None:
                        _fallback = guess_nsx_url(vc_url)
                        if _fallback and _fallback != nsx_url:
                            try:
                                detected = _detect_nsx_vpc_mode(_fallback, nsx_user, nsx_pass, vpc_prof_path)
                            except Exception:
                                pass

                    if detected:
                        c["network_mode"]         = detected
                        c["network_mode_warning"] = None
                    else:
                        c["network_mode_warning"] = (
                            "Cannot reach NSX to determine if Distributed or Centralized. "
                            "Check NSX FQDN / credentials."
                        )
            else:
                c["network_mode"] = np or "Unknown"
                c["network_mode_warning"] = None

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
            # REST API ha_enabled/drs_enabled can be stale — overlay with accurate SOAP values
            _morefs = [c.get("cluster") for c in d["vc_clusters"] if c.get("cluster")]
            _soap_ha_drs = _soap_get_cluster_ha_drs(vc_url, username, password, _morefs)
            for _c in d["vc_clusters"]:
                _m = _c.get("cluster")
                if _m and _m in _soap_ha_drs:
                    _s = _soap_ha_drs[_m]
                    if _s.get("ha_enabled")  is not None: _c["ha_enabled"]   = _s["ha_enabled"]
                    if _s.get("drs_enabled") is not None: _c["drs_enabled"]  = _s["drs_enabled"]
                    _c["drs_behavior"] = _s.get("drs_behavior")
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
            # Fetch per-host /state to detect disconnected/failed hosts
            _htn_ep = ("/policy/api/v1/infra/sites/default/enforcement-points"
                       "/default/host-transport-nodes")
            htn_states: dict = {}
            for _h in d["htn"][:50]:
                _hid = _h.get("id", "")
                if _hid:
                    try:
                        _st = nsx_get(nsx_url, nsx_user, nsx_pass,
                                      f"{_htn_ep}/{_hid}/state")
                        htn_states[_hid] = _st or {}
                    except Exception:
                        pass
            d["htn_states"] = htn_states
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

        # ── Step 2: HA/DRS (all modes) ───────────────────────────────────────
        if "clusters_error" in d:
            add("2", "vSphere HA / DRS", "warning", f"Could not check: {d['clusters_error']}")
        else:
            vc_clusters = d.get("vc_clusters", [])
            cluster_issues, cluster_ok, clusters_to_fix = [], [], []
            cluster_details = []
            for c in vc_clusters:
                name  = c.get("name", c.get("cluster", "?"))
                moref = c.get("cluster", "")
                bad   = []
                if not c.get("ha_enabled"):
                    bad.append("HA disabled")
                if not c.get("drs_enabled"):
                    bad.append("DRS disabled")
                elif c.get("drs_behavior") and c["drs_behavior"] != "fullyAutomated":
                    beh = c["drs_behavior"]
                    bad.append(f"DRS not Fully Automated (mode: {beh})")
                if bad:
                    cluster_issues.append(f"{name}: {', '.join(bad)}")
                    cluster_details.append(f"  · {name}: {', '.join(bad)}")
                    clusters_to_fix.append({"moref": moref, "name": name, "issues": bad})
                else:
                    beh = c.get("drs_behavior") or "fullyAutomated"
                    cluster_ok.append(name)
                    cluster_details.append(f"  · {name}: HA ✓  DRS ✓ ({beh})")
            if cluster_issues:
                add("2", "vSphere HA / DRS", "error",
                    f"{len(cluster_issues)} cluster(s) missing HA or DRS",
                    "\n".join(cluster_details)
                    + "\n\nBoth HA and DRS (Fully Automated) are required for Supervisor.",
                    can_fix=True, fix_clusters=clusters_to_fix)
            elif vc_clusters:
                add("2", "vSphere HA / DRS", "ok",
                    f"All {len(vc_clusters)} cluster(s) have HA and DRS enabled",
                    "\n".join(cluster_details))
            else:
                add("2", "vSphere HA / DRS", "warning", "No clusters found via vCenter API.")

        # ── Steps 3-8: NSX checks ────────────────────────────────────────────
        nsx_na = "Not required for this deployment mode."

        if mode == "vds_flb":
            add("3", "NSX Host Preparation", "info", "Not required for VDS/FLB mode", nsx_na)
            add("4", "NSX Networking",        "info", "Not required for VDS/FLB mode", nsx_na)
            add("5-1", "External Connection",   "info", "Not required for VDS/FLB mode", nsx_na)
            add("5-2", "TGW Attachment",         "info", "Not required for VDS/FLB mode", nsx_na)
            add("5-3", "External IP Block",     "info", "Not required for VDS/FLB mode", nsx_na)
            add("5-4", "VPC Profile",           "info", "Not required for VDS/FLB mode", nsx_na)
        elif not nsx_url:
            ext_conn_name = ("Distributed External Connection" if mode == "distributed"
                             else "Centralized External Connection" if mode == "centralized"
                             else "External Connection")
            for sn, nm in [
                ("3", "NSX Host Preparation"), ("4", "NSX Networking"),
                ("5-1", ext_conn_name),           ("5-2", "TGW Attachment"),
                ("5-3", "External IP Block"),    ("5-4", "VPC Profile"),
            ]:
                add(sn, nm, "warning", "NSX URL not provided — enter it in the NSX section above.")
        else:
            # Step 2: TEPs (same for both NSX modes)
            if "tep_error" in d:
                add("3", "NSX Host Preparation", "warning", f"Could not check: {d['tep_error']}")
            elif d.get("tnc") or d.get("htn"):
                tncs            = d.get("tnc", [])
                htns            = d.get("htn", [])
                htn_states      = d.get("htn_states", {})
                tnc_cluster_map = d.get("tnc_cluster_map", {})

                cluster_names = []
                for t in tncs:
                    tid   = t.get("id", "")
                    cname = tnc_cluster_map.get(tid) or t.get("display_name") or tid
                    cluster_names.append(cname)
                if not cluster_names:
                    cluster_names = ["(unknown)"]

                # Per-host state lines
                detail_lines = []
                fail_count   = 0
                for h in htns:
                    hid   = h.get("id", "")
                    hname = h.get("display_name", hid)
                    short = hname.split(".")[0] if "." in hname else hname
                    st    = htn_states.get(hid, {})
                    if st:
                        dstate  = (st.get("node_deployment_state") or {}).get("state", "unknown")
                        overall = st.get("state", dstate)
                        if overall == "success":
                            detail_lines.append(f"· {short}: SUCCESS")
                        else:
                            state_label = dstate.upper()
                            fail_msg    = (st.get("failure_message") or "").split(".")[0]
                            if fail_msg:
                                detail_lines.append(f"· {short}: {state_label} — {fail_msg}")
                            else:
                                detail_lines.append(f"· {short}: {state_label}")
                            fail_count += 1
                    else:
                        # No state data (e.g. state fetch failed) — assume ok
                        detail_lines.append(f"· {short}: SUCCESS")

                total = len(htns)
                if fail_count == 0:
                    step_status = "ok"
                    subtitle    = f"vCenter Clusters hosts prepared — {', '.join(cluster_names)}"
                else:
                    step_status = "warning"
                    ok_count    = total - fail_count
                    subtitle    = (f"{ok_count}/{total} hosts healthy in "
                                   f"{', '.join(cluster_names)} — "
                                   f"{fail_count} host(s) with issues")

                add("3", "NSX Host Preparation", step_status, subtitle,
                    "\n".join(detail_lines))
            else:
                add("3", "NSX Host Preparation", "error",
                    "No ESXi hosts prepared with NSX.",
                    "Without NSX host prep, Supervisor cannot use NSX-VPC networking.")

            # Step 3: networking topology (mode-specific)
            if mode == "distributed":
                if "topo_error" in d:
                    add("4", "VNA Cluster", "warning", f"Could not check: {d['topo_error']}")
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
                        add("4", "VNA Cluster", "ok",
                            f"VNA Cluster found: {names_str}", detail)
                    elif any_failed:
                        add("4", "VNA Cluster", "error",
                            f"VNA Cluster deployment failed", detail, can_fix=True)
                    elif any_deploying:
                        add("4", "VNA Cluster", "warning",
                            f"VNA Cluster deploying: {names_str}", detail)
                    else:
                        add("4", "VNA Cluster", "warning",
                            f"VNA Cluster status unknown: {names_str}", detail)
                else:
                    add("4", "VNA Cluster", "error",
                        "No VNA Cluster found.",
                        "A VNA Cluster is required for Distributed NSX-VPC mode.\n"
                        "This tool will guide you through the installation.\n\n"
                        "VNA requirements:\n"
                        "  · 2 management IPs for the VNA nodes (on the mgmt VLAN)",
                        can_fix=True)
            else:  # centralized
                if "topo_error" in d:
                    add("4", "Edge Cluster + Tier-0", "warning", f"Could not check: {d['topo_error']}")
                elif d.get("ec") and d.get("t0"):
                    ec_lines = "\n".join(f"  - {e.get('display_name','?')}" for e in d["ec"])
                    t0_lines = "\n".join(f"  - {t.get('display_name','?')}" for t in d["t0"])
                    detail   = f"· Edge cluster(s):\n{ec_lines}\n· Tier-0(s):\n{t0_lines}"
                    add("4", "Edge Cluster + Tier-0", "ok",
                        "Edge Cluster + Tier-0 found", detail)
                elif d.get("ec"):
                    add("4", "Edge Cluster + Tier-0", "error",
                        "Edge Cluster found but no Tier-0.",
                        f"Edge clusters: {[e.get('display_name','?') for e in d['ec']]}\n"
                        "A Tier-0 with BGP is required for Centralized NSX-VPC mode.",
                        can_fix=True)
                else:
                    add("4", "Edge Cluster + Tier-0", "error",
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
                    add("5-1", "Distributed External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("dvlan"):
                    names = [dc.get("display_name", dc.get("id", "?")) for dc in d["dvlan"]]
                    detail_lines = []
                    for dc in d["dvlan"]:
                        name = dc.get("display_name", dc.get("id", "?"))
                        vlan = dc.get("vlan_id", "?")
                        gws  = ", ".join(dc.get("gateway_addresses") or []) or "?"
                        detail_lines.append(f"· {name}\n  VLAN ID: {vlan}\n  Gateway: {gws}")
                    add("5-1", "Distributed External Connection", "ok",
                        f"{len(d['dvlan'])} Distributed External Connection(s): {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("5-1", "Distributed External Connection", "error",
                        "No Distributed External Connection found.",
                        "The Distributed External Connection is the connection to the physical fabric.\n"
                        "In the Distributed option, that's a VLAN / physical gateway.\n"
                        "This tool will guide you through its creation.\n"
                        "Requires: 1 VLAN/subnet reachable from all ESXi hosts.",
                        can_fix=True)
            else:  # centralized
                if "extconn_error" in d:
                    add("5-1", "Centralized External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("gw_conn"):
                    detail_lines = []
                    for gc in d["gw_conn"]:
                        name  = gc.get("display_name", gc.get("id", "?"))
                        t0    = (gc.get("tier0_path") or "?").rstrip("/").split("/")[-1]
                        detail_lines.append(f"· {name}\n  Tier-0: {t0}")
                    names = [gc.get("display_name", gc.get("id","?")) for gc in d["gw_conn"]]
                    add("5-1", "Centralized External Connection", "ok",
                        f"Gateway Connection: {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("5-1", "Centralized External Connection", "error",
                        "No Centralized External Connection found.",
                        "The Centralized External Connection is the connection to the physical fabric.\n"
                        "In the Centralized option, that's an NSX Tier-0.\n"
                        "This tool will guide you through its creation.",
                        can_fix=True)

            # Step 5: TGW attachment — mode-specific connection type check
            if "tgw_error" in d:
                add("5-2", "Distributed Transit Gateway" if mode == "distributed" else "TGW Attachment",
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
                        add("5-2", "Distributed Transit Gateway", "ok",
                            f"{len(dist_att)} Distributed Transit Gateway attachment(s)",
                            "\n".join(lines))
                    elif d.get("tgw"):
                        if centralized_att:
                            # Case 2: Default TGW is already Centralized → must create a new TGW
                            add("5-2", "Distributed Transit Gateway", "error",
                                "No Distributed Transit Gateway",
                                "The Default Transit Gateway is already configured as Centralized.\n"
                                "A new Distributed Transit Gateway must be created and attached\n"
                                "to a Distributed External Connection.\n"
                                "This tool will guide you through creating it.",
                                can_fix=True)
                        else:
                            # Case 1: Default TGW has no connection → attach it
                            add("5-2", "Distributed Transit Gateway", "error",
                                "No existing Distributed Transit Gateway.",
                                "This tool will guide you through attaching it to a Distributed External Connection.",
                                can_fix=True)
                    else:
                        add("5-2", "Distributed Transit Gateway", "error",
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
                        add("5-2", "Centralized Transit Gateway", "ok",
                            subtitle, "\n".join(lines))
                    elif d.get("tgw"):
                        add("5-2", "Centralized Transit Gateway", "error",
                            "No existing Centralized Transit Gateway.",
                            "This tool will guide you through attaching it to a Centralized External Connection.",
                            can_fix=True)
                    else:
                        add("5-2", "Centralized Transit Gateway", "error",
                            "Default Transit Gateway not found.",
                            "The Transit Gateway is required for NSX-VPC networking.\n"
                            "This tool will guide you through the configuration.",
                            can_fix=True)

            # Step 6: external IP blocks — mode-specific validity check
            if "blocks_error" in d:
                add("5-3", "External IP Block", "warning", f"Could not check: {d['blocks_error']}")
            else:
                all_ext = d.get("ext_blocks", [])

                # Build the set of DVLAN gateway subnets once (used by both modes)
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

                if mode == "distributed":
                    # Distributed: the block MUST overlap a DVLAN connection's gateway subnet.
                    # If there are no DVLAN connections there can be no valid block.
                    valid_blocks = [b for b in all_ext
                                    if dvlan_nets and _overlaps_dvlan(b.get("cidr", ""))]
                else:
                    # Centralized: the block must NOT overlap with a DVLAN gateway subnet
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
                    add("5-3", "External IP Block", "ok",
                        f"{len(valid_blocks)} External IP block(s): {', '.join(block_info)}",
                        "\n".join(detail_lines))
                else:
                    if mode == "distributed":
                        if not dvlan_nets:
                            ext_detail = (
                                "No Distributed External Connection found (Step S5-1).\n"
                                "An External IP Block for Distributed mode requires a Distributed External Connection first —\n"
                                "its CIDR must match that connection's gateway subnet."
                            )
                        else:
                            rejected = [b for b in all_ext if not _overlaps_dvlan(b.get("cidr", ""))]
                            overlap_note = ""
                            if rejected:
                                names = [b.get("display_name", "?") for b in rejected]
                                overlap_note = (f"\nNote: {len(rejected)} block(s) found ({', '.join(names)})"
                                                " but their CIDR does not match any Distributed External Connection subnet.")
                            ext_detail = (
                                "An External IP Block is required for future Supervisor VIP and NAT allocation.\n"
                                "In the Distributed option, the CIDR must match the subnet from Step S5-1 "
                                "(Distributed External Connection)." + overlap_note + "\n"
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
                    add("5-3", "External IP Block", "error",
                        "No External IP Block found.",
                        ext_detail,
                        can_fix=True)

            # Step 7: VPC connectivity profile
            title_7 = ("Distributed VPC Connectivity Profile"
                       if mode == "distributed"
                       else "Centralized VPC Connectivity Profile")
            if "vcp_error" in d:
                add("5-4", title_7, "warning", f"Could not check: {d['vcp_error']}")
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
                        lines.append(f"  N/S Services: enabled")
                        lines.append(f"  Outbound NAT: enabled")
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
                    add("5-4", title_7, "ok", subtitle, "\n".join(lines),
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
                    add("5-4", title_7, "error",
                        f"No valid {title_7} in any NSX Project",
                        "VPC Connectivity Profile requires the following settings:\n"
                        + "\n".join(req_lines)
                        + "\n\nThose are missing and this tool will guide you through this configuration.",
                        can_fix=True)

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
        r = requests.put(f"{nsx_url}{path}", auth=(nsx_user, nsx_pass),
                         headers=nsx_headers, json=payload, verify=False, timeout=30)
        return r

    def nsx_get_raw(path):
        return requests.get(f"{nsx_url}{path}", auth=(nsx_user, nsx_pass),
                            headers=nsx_headers, verify=False, timeout=15)

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
        # Find a free cluster ID — skip any objects still marked for deletion
        cluster_id = "vna-cluster-1"
        for _suffix in range(1, 20):
            _cid  = f"vna-cluster-{_suffix}"
            _rc   = nsx_get_raw(f"{base}/{_cid}")
            if _rc.status_code == 404:
                cluster_id = _cid
                break
            if _rc.ok and _rc.json().get("marked_for_delete"):
                continue  # still being purged — try next suffix
            cluster_id = _cid  # exists and healthy, or unknown error; just use it
            break

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
            if r1.status_code == 400 and "marked for deletion" in r1.text:
                result["error"] = (
                    f"NSX object '{cluster_id}' was recently deleted and is still "
                    f"being purged (up to 5 minutes). Please wait a few minutes "
                    f"and try again."
                )
            else:
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
        # Build edge-cluster path → T0 name mapping via T0 locale-services
        _ec_to_t0: dict = {}
        _t0_raw = _list("/policy/api/v1/infra/tier-0s")
        for _t0 in _t0_raw:
            _t0_id   = _t0.get("id", "")
            _t0_name = _t0.get("display_name", _t0_id)
            try:
                _ls = nsx_get(nsx_url, nsx_user, nsx_pass,
                              f"/policy/api/v1/infra/tier-0s/{_t0_id}/locale-services")
                for _s in (_ls or {}).get("results", []):
                    _ec_path = _s.get("edge_cluster_path", "")
                    if _ec_path:
                        _ec_to_t0[_ec_path] = _t0_name
            except Exception:
                pass
        _ec_items = []
        for _e in _list("/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters"):
            _item = _to_item(_e)
            _item["t0_name"] = _ec_to_t0.get(_e.get("path", ""), "")
            _ec_items.append(_item)
        result["edge_clusters"] = _ec_items
        result["t0s"]           = [_to_item(t) for t in _t0_raw]
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

        # If the profile already exists, PATCH (TGW path cannot be changed by NSX,
        # but must still be present in every request as it is a required field).
        # If new, PUT to create it with the desired TGW path.
        existing = nsx_get(nsx_url, nsx_user, nsx_pass, profile_api)
        if existing:
            # Carry the existing transit_gateway_path unchanged (NSX forbids changing it
            # but also rejects requests where the field is absent).
            payload["transit_gateway_path"] = (existing.get("transit_gateway_path") or tgw_path)
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


# ── vCenter SOAP helpers for SSH service management ──────────────────────────

def _soap_get_cluster_ha_drs(vc_url, vc_user, vc_pass, cluster_morefs):
    """
    Fetch accurate HA and DRS settings for vSphere clusters via SOAP.
    The REST API /api/vcenter/cluster returns stale ha_enabled / drs_enabled values;
    SOAP ClusterComputeResource.configuration is the authoritative source.

    Returns dict: {moref: {"ha_enabled": bool, "drs_enabled": bool, "drs_behavior": str}}
    where drs_behavior is "fullyAutomated" | "partiallyAutomated" | "manual" | None.
    """
    import re as _re
    if not cluster_morefs:
        return {}
    result = {}
    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)
        for moref in cluster_morefs:
            r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ClusterComputeResource</type><all>false</all>'
                '<pathSet>configuration</pathSet>'
                '</propSet>'
                f'<objectSet><obj type="ClusterComputeResource">{moref}</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
            if r.status_code != 200 or 'Fault' in r.text:
                continue
            t = r.text
            m_ha  = _re.search(r'<dasConfig>.*?<enabled>(.*?)</enabled>', t, _re.S)
            m_den = _re.search(r'<drsConfig>.*?<enabled>(.*?)</enabled>', t, _re.S)
            m_dbh = _re.search(r'<drsConfig>.*?<defaultVmBehavior>(.*?)</defaultVmBehavior>', t, _re.S)
            result[moref] = {
                "ha_enabled":   m_ha.group(1).strip().lower()  == 'true' if m_ha  else None,
                "drs_enabled":  m_den.group(1).strip().lower() == 'true' if m_den else None,
                "drs_behavior": m_dbh.group(1).strip()                   if m_dbh else None,
            }
    except Exception:
        pass
    return result


def _soap_session(vc_url, vc_user, vc_pass):
    """Open a vCenter SOAP session. Returns (requests.Session, endpoint, headers)."""
    ep  = f"{vc_url}/sdk"
    hdr = {"Content-Type": "text/xml; charset=UTF-8"}
    s   = requests.Session()
    r   = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><Login xmlns="urn:vim25">'
        '<_this type="SessionManager">SessionManager</_this>'
        f'<userName>{vc_user}</userName><password>{vc_pass}</password>'
        '</Login></Body></Envelope>'))
    if not r.ok or "Fault" in r.text:
        raise RuntimeError(f"SOAP login failed ({r.status_code})")
    return s, ep, hdr


def _soap_find_host(s, ep, hdr, fqdn):
    """Return HostSystem MoRef for the given FQDN, or None."""
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><FindByDnsName xmlns="urn:vim25">'
        '<_this type="SearchIndex">SearchIndex</_this>'
        f'<dnsName>{fqdn}</dnsName><vmSearch>false</vmSearch>'
        '</FindByDnsName></Body></Envelope>'))
    import re as _re
    m = _re.search(r'type="HostSystem"[^>]*>([^<]+)<', r.text)
    return m.group(1).strip() if m else None


def _soap_get_service_system(s, ep, hdr, host_moref):
    """Return HostServiceSystem MoRef for a host.

    Uses RetrieveProperties (not Ex) with propSet — the Ex variant and the
    old propSpec element name both cause vCenter to return HTTP 500.
    """
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet>'
        '<propSet><type>HostSystem</type><all>false</all>'
        '<pathSet>configManager.serviceSystem</pathSet></propSet>'
        f'<objectSet><obj type="HostSystem">{host_moref}</obj></objectSet>'
        '</specSet>'
        '</RetrieveProperties></Body></Envelope>'))
    import re as _re
    m = _re.search(r'type="HostServiceSystem"[^>]*>([^<]+)<', r.text)
    return m.group(1).strip() if m else None


def _soap_get_ssh_state(s, ep, hdr, svc_moref):
    """Return True if SSH (TSM-SSH) is currently running on the host."""
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet>'
        '<propSet><type>HostServiceSystem</type><all>false</all>'
        '<pathSet>serviceInfo</pathSet></propSet>'
        f'<objectSet><obj type="HostServiceSystem">{svc_moref}</obj></objectSet>'
        '</specSet>'
        '</RetrieveProperties></Body></Envelope>'))
    import re as _re
    m = _re.search(r'<key>TSM-SSH</key>.*?<running>(.*?)</running>', r.text, _re.S)
    return m.group(1).strip().lower() == 'true' if m else False


def _soap_set_ssh(s, ep, hdr, svc_moref, enable):
    """Start or stop SSH (TSM-SSH) on an ESX host. Returns ok (bool)."""
    action = "StartService" if enable else "StopService"
    r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        f'<Body><{action} xmlns="urn:vim25">'
        f'<_this type="HostServiceSystem">{svc_moref}</_this>'
        f'<id>TSM-SSH</id>'
        f'</{action}></Body></Envelope>'))
    return "Fault" not in r.text


def _vc_manage_ssh(vc_url, vc_user, vc_pass, host_fqdn, enable):
    """
    Enable or disable SSH on an ESX host via vCenter SOAP.
    Returns (success, was_already_in_desired_state).
    """
    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)
        moref = _soap_find_host(s, ep, hdr, host_fqdn)
        if not moref:
            return False, False
        svc = _soap_get_service_system(s, ep, hdr, moref)
        if not svc:
            return False, False
        # Check current state first to avoid unnecessary calls
        currently_running = _soap_get_ssh_state(s, ep, hdr, svc)
        if currently_running == enable:
            return True, True   # already in desired state
        ok = _soap_set_ssh(s, ep, hdr, svc, enable)
        # Logout (best-effort)
        try:
            s.post(ep, verify=False, timeout=10, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><Logout xmlns="urn:vim25">'
                '<_this type="SessionManager">SessionManager</_this>'
                '</Logout></Body></Envelope>'))
        except Exception:
            pass
        return ok, False
    except Exception:
        return False, False


def _collect_mtu_hosts(nsx_url, nsx_user, nsx_pass):
    """Return list of dicts {id, name, short, healthy} from NSX HTNs."""
    ep = "/policy/api/v1/infra/sites/default/enforcement-points/default"
    htn_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/host-transport-nodes")
    htns     = (htn_resp or {}).get("results", [])
    hosts = []
    for h in htns:
        hid  = h.get("id", "")
        name = h.get("display_name", hid)
        healthy = False
        has_vmks = False
        try:
            st = nsx_get(nsx_url, nsx_user, nsx_pass,
                         f"{ep}/host-transport-nodes/{hid}/state")
            if (st or {}).get("state") == "success":
                healthy = True
            for hs in (st or {}).get("host_switch_states", []):
                for ep2 in hs.get("endpoints", []):
                    if ep2.get("ip") and "overlay" in ep2.get("net_stack_instance_key", "").lower():
                        has_vmks = True
        except Exception:
            pass
        hosts.append({
            "id":      hid,
            "name":    name,
            "short":   name.split(".")[0] if "." in name else name,
            "healthy": healthy,
            "has_vmks": has_vmks,
        })
    return hosts


@app.route("/api/fix-ha-drs", methods=["POST"])
def fix_ha_drs():
    """Enable HA and DRS (Fully Automated) on a vSphere cluster via SOAP."""
    import re as _re, time as _time
    body          = request.get_json(force=True)
    vc_url        = normalize_url(body.get("vc_url", ""))
    vc_user       = body.get("username", "")
    vc_pass       = body.get("password", "")
    cluster_moref = (body.get("cluster_moref") or "").strip()

    result = {"success": False, "error": None}
    if not cluster_moref:
        result["error"] = "No cluster moref provided."
        return jsonify(result)

    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)

        # ReconfigureComputeResource_Task — enable HA + DRS Fully Automated
        r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
            '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" '
            '          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<Body><ReconfigureComputeResource_Task xmlns="urn:vim25">'
            f'<_this type="ClusterComputeResource">{cluster_moref}</_this>'
            '<spec xsi:type="ClusterConfigSpecEx">'
            '<dasConfig><enabled>true</enabled></dasConfig>'
            '<drsConfig>'
            '<enabled>true</enabled>'
            '<defaultVmBehavior>fullyAutomated</defaultVmBehavior>'
            '</drsConfig>'
            '</spec>'
            '<modify>true</modify>'
            '</ReconfigureComputeResource_Task></Body></Envelope>'))

        if r.status_code != 200 or 'Fault' in r.text:
            m = _re.search(r'<faultstring>(.*?)</faultstring>', r.text, _re.S)
            result["error"] = (m.group(1).strip() if m else
                               f"HTTP {r.status_code}: {r.text[:200]}")
            return jsonify(result)

        m = _re.search(r'type="Task"[^>]*>([^<]+)<', r.text)
        if not m:
            result["error"] = "Could not parse task ID from vCenter response."
            return jsonify(result)
        task_moref = m.group(1).strip()

        # Poll task (up to 60 s)
        for _ in range(30):
            _time.sleep(2)
            rp = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>Task</type><all>false</all>'
                '<pathSet>info.state</pathSet>'
                '<pathSet>info.error</pathSet></propSet>'
                f'<objectSet><obj type="Task">{task_moref}</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
            m_st = _re.search(
                r'<name>info\.state</name>\s*<val[^>]*>([^<]+)</val>', rp.text, _re.S)
            state = m_st.group(1).strip() if m_st else "running"
            if state == "success":
                result["success"] = True
                return jsonify(result)
            if state == "error":
                m_err = _re.search(
                    r'<localizedMessage>(.*?)</localizedMessage>', rp.text, _re.S)
                result["error"] = m_err.group(1).strip() if m_err else "Task failed."
                return jsonify(result)

        result["error"] = "Task timed out after 60 s."
        return jsonify(result)

    except Exception as e:
        result["error"] = str(e)
        return jsonify(result)


@app.route("/api/mtu-hosts", methods=["POST"])
def mtu_hosts():
    """Return the list of ESX hosts available for MTU testing."""
    body     = request.get_json(force=True)
    nsx_raw  = (body.get("nsx_url") or "").strip()
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url  = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or body.get("password") or ""
    try:
        hosts = _collect_mtu_hosts(nsx_url, nsx_user, nsx_pass)
        return jsonify({"hosts": hosts})
    except Exception as e:
        return jsonify({"hosts": [], "error": str(e)})


@app.route("/api/check-mtu", methods=["POST"])
def check_mtu():
    """SSH into one ESX host per cluster and vmkping every TEP at the given MTU."""
    import re as _re
    try:
        import paramiko as _paramiko
    except ImportError:
        return jsonify({"error": "paramiko not installed on server (apt install python3-paramiko)",
                        "tests": [], "summary": ""})

    import socket as _socket
    body        = request.get_json(force=True)
    vc_url      = normalize_url(body.get("vc_url", ""))
    vc_user     = body.get("username", "")
    vc_pass     = body.get("password", "")
    nsx_raw     = (body.get("nsx_url") or "").strip()
    nsx_url     = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user    = body.get("nsx_user") or "admin"
    nsx_pass    = body.get("nsx_pass") or vc_pass
    esx_pass    = body.get("esx_pass") or ""
    mtu_size    = int(body.get("mtu_size") or 1600)
    source_host = (body.get("source_host") or "").strip()   # optional: specific host name/id

    # Determine this VM's IP so we can mention it in error messages
    try:
        vm_ip = _socket.gethostbyname(_socket.gethostname())
    except Exception:
        vm_ip = "this VM"

    result = {"tests": [], "summary": "", "error": None}
    ep = "/policy/api/v1/infra/sites/default/enforcement-points/default"

    try:
        # ── collect HTNs ──────────────────────────────────────────────────────
        htn_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/host-transport-nodes")
        htns     = (htn_resp or {}).get("results", [])
        if not htns:
            result["error"] = "No Host Transport Nodes found via NSX API."
            return jsonify(result)

        # ── per-host: TEP vmk interfaces + overall health ─────────────────────
        class _H:
            def __init__(self, hid, name):
                self.id      = hid
                self.name    = name
                self.short   = name.split(".")[0] if "." in name else name
                self.vmks    = []   # [{"vmk": str, "ip": str}]
                self.healthy = False

        all_hosts: list = []
        all_teps:  list = []   # [{"ip": str, "host": str}]  ← all TEP IPs (ESX + Edge)

        for h in htns:
            hid  = h.get("id", "")
            obj  = _H(hid, h.get("display_name", hid))
            try:
                st = nsx_get(nsx_url, nsx_user, nsx_pass,
                             f"{ep}/host-transport-nodes/{hid}/state")
                if (st or {}).get("state") == "success":
                    obj.healthy = True
                for hs in (st or {}).get("host_switch_states", []):
                    for ep2 in hs.get("endpoints", []):
                        ip    = ep2.get("ip", "")
                        vmk   = ep2.get("device_name", "")
                        stack = ep2.get("net_stack_instance_key", "")
                        if ip and vmk and "overlay" in stack.lower():
                            obj.vmks.append({"vmk": vmk, "ip": ip})
                            all_teps.append({"ip": ip, "host": obj.short})
            except Exception:
                pass
            all_hosts.append(obj)

        # ── add Edge node TEPs as targets ─────────────────────────────────────
        try:
            edge_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/edge-transport-nodes")
            for e in (edge_resp or {}).get("results", []):
                eid  = e.get("id", "")
                ename = e.get("display_name", eid).split(".")[0]
                est   = nsx_get(nsx_url, nsx_user, nsx_pass,
                                f"{ep}/edge-transport-nodes/{eid}/state")
                for hs in (est or {}).get("host_switch_states", []):
                    for ep3 in hs.get("endpoints", []):
                        ip = ep3.get("ip", "")
                        if ip:
                            all_teps.append({"ip": ip, "host": ename})
        except Exception:
            pass

        if not all_teps:
            result["error"] = "No TEP IPs found. Check NSX credentials."
            return jsonify(result)

        # ── pick source host ──────────────────────────────────────────────────
        if source_host:
            # Use the host explicitly chosen by the user
            sources = [h for h in all_hosts
                       if h.name == source_host or h.short == source_host or h.id == source_host]
            if not sources:
                result["error"] = f"Host '{source_host}' not found in NSX Transport Nodes."
                return jsonify(result)
        else:
            healthy = [h for h in all_hosts if h.healthy and h.vmks]
            if not healthy:
                healthy = [h for h in all_hosts if h.vmks]
            sources = healthy[:1] if healthy else []

        if not sources:
            result["error"] = "No ESX host with NSX-overlay VMkernel interfaces found."
            return jsonify(result)

        # ── run vmkping from each source host ─────────────────────────────────
        tests      = []
        fail_count = 0
        import time as _time

        for src in sources:
            # ── 1. Enable SSH via vCenter SOAP (if vCenter creds provided) ────
            ssh_we_enabled = False
            ssh_note       = ""
            if vc_url and vc_user and vc_pass:
                ok, already = _vc_manage_ssh(vc_url, vc_user, vc_pass,
                                             src.name, enable=True)
                if ok and not already:
                    ssh_we_enabled = True
                    _time.sleep(3)   # initial wait for sshd to start
                elif already:
                    ssh_note = "SSH was already enabled"
                else:
                    ssh_note = "Could not enable SSH via vCenter — trying anyway"

            # ── 2. SSH + vmkping ───────────────────────────────────────────────
            ssh = _paramiko.SSHClient()
            ssh.set_missing_host_key_policy(_paramiko.AutoAddPolicy())

            # Retry loop: sshd can take up to ~10s to start after being enabled
            _max_attempts = 6   # × 2s = 12s max wait
            _last_err     = None
            for _attempt in range(_max_attempts):
                try:
                    ssh.connect(src.name, username="root", password=esx_pass,
                                timeout=10, banner_timeout=15,
                                allow_agent=False, look_for_keys=False)
                    _last_err = None
                    break   # connected successfully
                except _paramiko.AuthenticationException:
                    result["error"] = (f"SSH authentication failed for {src.name} — "
                                       f"check ESX root password.")
                    return jsonify(result)
                except Exception as _e:
                    _last_err = _e
                    _es = str(_e).lower()
                    # "Unable to connect" / "Errno None" → sshd not ready yet → retry
                    if ("unable to connect" in _es or "errno none" in _es
                            or "connection refused" in _es):
                        if _attempt < _max_attempts - 1:
                            _time.sleep(2)
                            continue
                    break   # other error — don't retry

            if _last_err:
                _es = str(_last_err).lower()
                if ("unable to connect" in _es or "errno none" in _es
                        or "connection refused" in _es or "timed out" in _es):
                    result["error"] = (
                        f"Cannot reach {src.short} via SSH from this VM ({vm_ip}). "
                        f"Port 22 may be blocked by a firewall between "
                        f"{vm_ip} and {src.name}.")
                else:
                    result["error"] = f"SSH to {src.name} failed: {_last_err}"
                return jsonify(result)

            for vmk_info in src.vmks:
                vmk    = vmk_info["vmk"]
                src_ip = vmk_info["ip"]
                for tgt in all_teps:
                    tgt_ip   = tgt["ip"]
                    tgt_host = tgt["host"]
                    if tgt_ip == src_ip:
                        continue
                    cmd = (f"vmkping -I {vmk} -S vxlan -d -s {mtu_size} "
                           f"-c 2 {tgt_ip} 2>&1")
                    try:
                        _, stdout, _ = ssh.exec_command(cmd, timeout=12)
                        out = stdout.read().decode("utf-8", errors="replace")
                        ok  = ("0% packet loss" in out or
                               "0.0% packet loss" in out)
                        lat = ""
                        for line in out.splitlines():
                            m = _re.search(r"time=(\S+)", line)
                            if m:
                                lat = m.group(1) + " ms"
                                break
                    except Exception as ex:
                        out = str(ex)
                        ok  = False
                        lat = ""
                    tests.append({
                        "from_host": src.short,
                        "from_vmk":  vmk,
                        "from_ip":   src_ip,
                        "to_host":   tgt_host,
                        "to_ip":     tgt_ip,
                        "success":   ok,
                        "latency":   lat,
                    })
                    if not ok:
                        fail_count += 1
            ssh.close()

            # ── 3. Disable SSH if we enabled it ───────────────────────────────
            if ssh_we_enabled and vc_url and vc_user and vc_pass:
                _vc_manage_ssh(vc_url, vc_user, vc_pass, src.name, enable=False)

        result["tests"] = tests
        if not tests:
            result["error"] = "No tests ran — nothing to ping."
        elif fail_count == 0:
            result["summary"] = f"All {len(tests)} MTU {mtu_size} tests PASSED"
        else:
            result["summary"] = f"{fail_count} of {len(tests)} MTU tests FAILED"

    except Exception:
        result["error"] = traceback.format_exc()

    return jsonify(result)


# ── Check VLAN helpers ──────────────────────────────────────────────────────

def _pick_temp_ips(cidr, gateway_cidr, excluded_str, count):
    """Pick up to `count` host IPs from cidr, excluding gateway and excluded ranges."""
    import ipaddress as _ip
    try:
        net = _ip.ip_network(cidr, strict=False)
    except Exception:
        return []
    gw_ip = None
    if gateway_cidr:
        try:
            gw_ip = _ip.ip_address(gateway_cidr.split("/")[0])
        except Exception:
            pass
    excluded: set = set()
    for tok in (excluded_str or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            try:
                a, b = tok.split("-", 1)
                for i in range(int(_ip.ip_address(a.strip())),
                               int(_ip.ip_address(b.strip())) + 1):
                    excluded.add(_ip.ip_address(i))
            except Exception:
                pass
        else:
            try:
                excluded.add(_ip.ip_address(tok))
            except Exception:
                pass
    result: list = []
    for ip in net.hosts():
        if ip == gw_ip or ip in excluded:
            continue
        result.append(str(ip))
        if len(result) >= count:
            break
    return result


def _vc_soap_login(vc_url, vc_user, vc_pass):
    """Create an authenticated vCenter SOAP session. Returns (session, endpoint, headers)."""
    s = requests.Session()
    ep  = f"https://{vc_url}/sdk"
    hdr = {"Content-Type": "text/xml", "SOAPAction": "urn:vim25/6.7"}
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><Login xmlns="urn:vim25">'
        '<_this type="SessionManager">SessionManager</_this>'
        f'<userName>{vc_user}</userName><password>{vc_pass}</password>'
        '</Login></Body></Envelope>'))
    if "LoginResponse" not in r.text:
        raise RuntimeError(f"vCenter login failed: {r.text[:200]}")
    return s, ep, hdr


def _vc_soap_find_host(s, ep, hdr, fqdn):
    """Find host MOR by FQDN using SearchIndex."""
    import re as _re
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><FindByDnsName xmlns="urn:vim25">'
        '<_this type="SearchIndex">SearchIndex</_this>'
        f'<dnsName>{fqdn}</dnsName><vmSearch>false</vmSearch>'
        '</FindByDnsName></Body></Envelope>'))
    m = _re.search(r'<returnval type="HostSystem">([^<]+)</returnval>', r.text)
    return m.group(1).strip() if m else None


def _vc_soap_get_netsys_and_dvs(s, ep, hdr, host_moref):
    """Return (netsys_moref, []) for a host.
    The DVS list is no longer derived from the host (networkInfo.proxySwitch is gone
    in vCenter 9); DVS lookup is done separately via _vc_soap_find_dvs_by_name."""
    import re as _re
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet><propSet><type>HostSystem</type><all>false</all>'
        '<pathSet>configManager.networkSystem</pathSet></propSet>'
        f'<objectSet><obj type="HostSystem">{host_moref}</obj></objectSet>'
        '</specSet></RetrieveProperties></Body></Envelope>'))
    # vCenter 9 returns <val xsi:type="ManagedObjectReference" type="HostNetworkSystem">
    ns_m = _re.search(r'<val[^>]*type="HostNetworkSystem"[^>]*>([^<]+)</val>', r.text)
    if not ns_m:
        return None, []
    return ns_m.group(1).strip(), []


def _vc_soap_find_dvs_by_name(s, ep, hdr, dvs_name):
    """Find a DVS MOR and UUID by display name.
    Returns (dvs_mor, dvs_uuid) or (None, None).
    Tries VmwareDistributedVirtualSwitch first (VCF/NSX uses this concrete type),
    then falls back to the generic DistributedVirtualSwitch."""
    import re as _re

    def _scan(dvs_type):
        r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
            '<Body><CreateContainerView xmlns="urn:vim25">'
            '<_this type="ViewManager">ViewManager</_this>'
            '<container type="Folder">group-d1</container>'
            f'<type>{dvs_type}</type>'
            '<recursive>true</recursive>'
            '</CreateContainerView></Body></Envelope>'))
        cv_m = _re.search(r'<returnval type="ContainerView">([^<]+)</returnval>', r.text)
        if not cv_m:
            return None, None
        cv = cv_m.group(1)
        # Retrieve both 'name' and 'uuid' for every DVS in one call
        r2 = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
            '<Body><RetrieveProperties xmlns="urn:vim25">'
            '<_this type="PropertyCollector">propertyCollector</_this>'
            f'<specSet>'
            f'<propSet><type>{dvs_type}</type><all>false</all><pathSet>name</pathSet></propSet>'
            f'<propSet><type>{dvs_type}</type><all>false</all><pathSet>uuid</pathSet></propSet>'
            f'<objectSet><obj type="ContainerView">{cv}</obj>'
            '<selectSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="TraversalSpec">'
            '<type>ContainerView</type><path>view</path></selectSet>'
            '</objectSet></specSet></RetrieveProperties></Body></Envelope>'))
        # Build a map: mor → {name, uuid}
        dvs_map: dict = {}
        pat_obj = rf'<obj type="{_re.escape(dvs_type)}">([^<]+)</obj>'
        pat_prop = r'<propSet><name>([^<]+)</name><val[^>]*>([^<]+)</val></propSet>'
        # Split returnval blocks
        for block in _re.finditer(
                rf'<returnval>(<obj type="{_re.escape(dvs_type)}">[^<]+</obj>.*?)</returnval>',
                r2.text, _re.DOTALL):
            chunk = block.group(1)
            m_obj = _re.search(pat_obj, chunk)
            if not m_obj:
                continue
            mor = m_obj.group(1).strip()
            dvs_map.setdefault(mor, {})
            for pm in _re.finditer(pat_prop, chunk):
                dvs_map[mor][pm.group(1)] = pm.group(2).strip()
        for mor, props in dvs_map.items():
            if props.get("name", "").lower() == dvs_name.lower():
                return mor, props.get("uuid", "")
        return None, None

    mor, uid = _scan("VmwareDistributedVirtualSwitch")
    if mor:
        return mor, uid
    return _scan("DistributedVirtualSwitch")


# Keep legacy name as alias (still called in a couple places)
def _vc_soap_find_dvs(s, ep, hdr, dvs_uuid_or_name):
    mor, _ = _vc_soap_find_dvs_by_name(s, ep, hdr, dvs_uuid_or_name)
    return mor


def _vc_soap_ensure_dvpg(s, ep, hdr, dvs_moref, pg_name, vlan_id):
    """Create (or find existing) DVPortGroup with given VLAN. Returns (dvpg_moref, created_by_us)."""
    import re as _re, time as _time
    create_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><AddDVPortgroup_Task xmlns="urn:vim25">'
        f'<_this type="DistributedVirtualSwitch">{dvs_moref}</_this>'
        '<spec>'
        f'<name>{pg_name}</name><type>earlyBinding</type><numPorts>16</numPorts>'
        '<defaultPortConfig>'
        '<vlan xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xsi:type="VmwareDistributedVirtualSwitchVlanIdSpec">'
        f'<inherited>false</inherited><vlanId>{vlan_id}</vlanId>'
        '</vlan></defaultPortConfig>'
        '</spec>'
        '</AddDVPortgroup_Task></Body></Envelope>')
    r = s.post(ep, verify=False, timeout=30, headers=hdr, data=create_body)
    task_m = _re.search(r'<returnval type="Task">([^<]+)</returnval>', r.text)
    if task_m:
        task = task_m.group(1)
        for _ in range(30):
            _time.sleep(1)
            rt = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet><propSet><type>Task</type><all>false</all>'
                '<pathSet>info.state</pathSet><pathSet>info.result</pathSet>'
                '<pathSet>info.error</pathSet></propSet>'
                f'<objectSet><obj type="Task">{task}</obj></objectSet>'
                '</specSet></RetrieveProperties></Body></Envelope>'))
            st = _re.search(r'<val>(\w+)</val>', rt.text)
            state = st.group(1) if st else 'unknown'
            if state == 'success':
                res_m = _re.search(
                    r'<val type="DistributedVirtualPortgroup">([^<]+)</val>', rt.text)
                if res_m:
                    return res_m.group(1).strip(), True
                break
            elif state == 'error':
                em = _re.search(r'<localizedMessage>([^<]+)</localizedMessage>', rt.text)
                raise RuntimeError(f"DVPortGroup creation failed: {em.group(1) if em else rt.text[:300]}")
    # If task missing or result not found: find existing portgroup by name
    r3 = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet><propSet><type>DistributedVirtualPortgroup</type><all>false</all>'
        '<pathSet>name</pathSet></propSet>'
        f'<objectSet><obj type="DistributedVirtualSwitch">{dvs_moref}</obj>'
        '<selectSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="TraversalSpec">'
        '<type>DistributedVirtualSwitch</type><path>portgroup</path></selectSet>'
        '</objectSet></specSet></RetrieveProperties></Body></Envelope>'))
    # <val> may carry xsi:type attribute → use [^>]* to match any attrs
    for m in _re.finditer(
            r'<obj type="DistributedVirtualPortgroup">([^<]+)</obj>.*?<val[^>]*>([^<]+)</val>',
            r3.text, _re.DOTALL):
        if m.group(2).strip() == pg_name:
            return m.group(1).strip(), False
    raise RuntimeError(f"Could not create or locate DVPortGroup '{pg_name}'")


def _vc_soap_get_dvpg_key(s, ep, hdr, dvpg_moref):
    """Get the DVPortGroup's portgroup key."""
    import re as _re
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet><propSet><type>DistributedVirtualPortgroup</type><all>false</all>'
        '<pathSet>key</pathSet></propSet>'
        f'<objectSet><obj type="DistributedVirtualPortgroup">{dvpg_moref}</obj></objectSet>'
        '</specSet></RetrieveProperties></Body></Envelope>'))
    # <val> may carry xsi:type attribute → use [^>]* to match any attrs
    m = _re.search(r'<val[^>]*>([^<]+)</val>', r.text)
    return m.group(1).strip() if m else None


def _vc_soap_add_vmk(s, ep, hdr, netsys_moref, dvs_uuid, dvpg_key, ip_str, prefix_len):
    """Add a VMkernel NIC on a DVPortGroup. Returns device name (e.g. 'vmk5')."""
    import re as _re, ipaddress as _ip
    mask = str(_ip.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
    r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><AddVirtualNic xmlns="urn:vim25">'
        f'<_this type="HostNetworkSystem">{netsys_moref}</_this>'
        '<portgroup></portgroup>'
        '<nic>'
        '<distributedVirtualPort>'
        f'<switchUuid>{dvs_uuid}</switchUuid>'
        f'<portgroupKey>{dvpg_key}</portgroupKey>'
        '</distributedVirtualPort>'
        '<ip><dhcp>false</dhcp>'
        f'<ipAddress>{ip_str}</ipAddress>'
        f'<subnetMask>{mask}</subnetMask>'
        '</ip>'
        '</nic>'
        '</AddVirtualNic></Body></Envelope>'))
    m = _re.search(r'<returnval>([^<]+)</returnval>', r.text)
    if m:
        return m.group(1).strip()
    fm = _re.search(r'<faultstring>([^<]+)</faultstring>', r.text)
    raise RuntimeError(fm.group(1) if fm else f"AddVirtualNic failed: {r.text[:300]}")


def _vc_soap_remove_vmk(s, ep, hdr, netsys_moref, device):
    """Remove a VMkernel NIC."""
    s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RemoveVirtualNic xmlns="urn:vim25">'
        f'<_this type="HostNetworkSystem">{netsys_moref}</_this>'
        f'<device>{device}</device>'
        '</RemoveVirtualNic></Body></Envelope>'))


def _vc_soap_destroy_dvpg(s, ep, hdr, dvpg_moref):
    """Destroy a DVPortGroup (best-effort)."""
    s.post(ep, verify=False, timeout=30, headers=hdr, data=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><Destroy_Task xmlns="urn:vim25">'
        f'<_this type="DistributedVirtualPortgroup">{dvpg_moref}</_this>'
        '</Destroy_Task></Body></Envelope>'))


def _pcli_setup_vlan_test(vc_url, vc_user, vc_pass, vds_name, pg_name, vlan_id, host_ips):
    """
    PowerCLI: creates DVPortGroup + one vmk per host via New-VMHostNetworkAdapter.
    host_ips: list of (fqdn, ip_str, mask_str) tuples.
    Returns (vmk_map, pg_created, error_str)
      vmk_map: {fqdn: vmk_name}
    """
    import subprocess, tempfile, os, textwrap
    vc_host = vc_url.replace("https://", "").replace("http://", "").rstrip("/")

    per_host_lines = []
    for fqdn, ip, mask in host_ips:
        per_host_lines.append(textwrap.dedent(f"""            try {{
                $vmhost = Get-VMHost -Name '{fqdn}'
                Get-VMHostNetworkAdapter -VMHost $vmhost -PortGroup $pg -ErrorAction SilentlyContinue | Remove-VMHostNetworkAdapter -Confirm:$false
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vds -PortGroup $pg -IP '{ip}' -SubnetMask '{mask}' -Confirm:$false
                Write-Host "VMK:{fqdn}:$($vmk.Name)"
            }} catch {{
                Write-Host "VMK_ERR:{fqdn}:$($_.Exception.Message)"
            }}"""))

    script = textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $vds = Get-VDSwitch -Name '{vds_name}'
        Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue | Remove-VDPortgroup -Confirm:$false
        $pg = New-VDPortgroup -VDSwitch $vds -Name '{pg_name}' -VlanId {vlan_id} -NumPorts 16
        Write-Host "PG:CREATED:{pg_name}"
        Start-Sleep -Seconds 3
        {chr(10).join(per_host_lines)}
        Disconnect-VIServer -Confirm:$false | Out-Null
        Write-Host "PCLI_SETUP_DONE"
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="vcf_setup_") as f:
        f.write(script); script_path = f.name
    try:
        r = subprocess.run(["pwsh", "-NonInteractive", "-File", script_path],
                           capture_output=True, text=True, timeout=150)
        out = r.stdout + r.stderr
        if "PCLI_SETUP_DONE" not in out:
            return {}, False, f"PowerCLI setup failed (no DONE marker):\n{out[:800]}"
        pg_created = "PG:CREATED:" in out
        vmk_map = {}
        for line in out.splitlines():
            if line.startswith("VMK:"):
                parts = line.split(":", 2)
                if len(parts) == 3:
                    vmk_map[parts[1]] = parts[2].strip()
        return vmk_map, pg_created, ""
    except FileNotFoundError:
        return {}, False, "PowerShell (pwsh) not found — install via: snap install powershell --classic"
    except subprocess.TimeoutExpired:
        return {}, False, "PowerCLI timed out during setup (>150s)"
    finally:
        try: os.unlink(script_path)
        except Exception: pass


def _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, pg_name, host_fqdns):
    """PowerCLI: removes vmks on all hosts + DVPortGroup (best-effort)."""
    import subprocess, tempfile, os, textwrap
    vc_host = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    host_array = ", ".join(f"\'{h}\'" for h in host_fqdns)
    script = textwrap.dedent(f"""\
        $ErrorActionPreference = 'SilentlyContinue'
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $pg = Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue
        if ($pg) {{
            foreach ($fqdn in @({host_array})) {{
                try {{
                    $vmhost = Get-VMHost -Name $fqdn
                    Get-VMHostNetworkAdapter -VMHost $vmhost -PortGroup $pg -ErrorAction SilentlyContinue | Remove-VMHostNetworkAdapter -Confirm:$false
                }} catch {{}}
            }}
            $pg | Remove-VDPortgroup -Confirm:$false
        }}
        Disconnect-VIServer -Confirm:$false | Out-Null
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="vcf_cleanup_") as f:
        f.write(script); script_path = f.name
    try:
        subprocess.run(["pwsh", "-NonInteractive", "-File", script_path],
                       capture_output=True, text=True, timeout=90)
    except Exception:
        pass
    finally:
        try: os.unlink(script_path)
        except Exception: pass


@app.route("/api/check-vlan", methods=["POST"])
def check_vlan():
    """
    VLAN connectivity check for NSX-VPC Distributed mode.
    1. PowerCLI creates temp DVPortGroup + one vmk per host via New-VMHostNetworkAdapter.
    2. SSH to each host: vmkping the DVLAN gateway.
    3. PowerCLI removes all vmks + portgroup.
    """
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url",  ""))
    vc_user  = body.get("username", "")
    vc_pass  = body.get("password", "")
    nsx_raw  = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user", "")
    nsx_pass = body.get("nsx_pass", "")
    esx_pass       = body.get("esx_pass", "")
    host_passwords = body.get("host_passwords") or {}

    result: dict = {"success": False, "tests": [], "summary": "", "error": None}
    pg_name = None
    hosts   = []

    try:
        import ipaddress as _ip, time as _time, paramiko as _para

        # ── 1. DVLAN connection details ──────────────────────────────────────
        dvlan_id_req = (body.get("dvlan_id") or "").strip()
        dvlans = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/distributed-vlan-connections") or {}).get("results", [])
        if not dvlans:
            result["error"] = "No Distributed External Connection found — complete S5-1 first."
            return jsonify(result)
        dvlan = next((d for d in dvlans if d.get("id") == dvlan_id_req), dvlans[0])
        vlan_id    = dvlan.get("vlan_id", 0)
        gw_addrs   = dvlan.get("gateway_addresses") or []
        if not gw_addrs:
            result["error"] = "DVLAN connection has no gateway address configured."
            return jsonify(result)
        gateway_cidr = gw_addrs[0]
        gateway_ip   = gateway_cidr.split("/")[0]
        prefix_len   = int(gateway_cidr.split("/")[1])
        dvlan_net    = _ip.ip_interface(gateway_cidr).network
        mask_str     = str(_ip.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)

        # ── 2. External IP Block overlapping the DVLAN subnet ──────────────
        all_blocks = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/ip-blocks") or {}).get("results", [])
        block_cidr = excl_str = None
        for b in all_blocks:
            if (b.get("visibility") or "").upper() != "EXTERNAL":
                continue
            cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
            try:
                if cidr and _ip.ip_network(cidr, strict=False).overlaps(dvlan_net):
                    block_cidr = cidr
                    desc = b.get("description", "")
                    excl_str = desc.split("Excluded ranges:")[1].strip() \
                               if "Excluded ranges:" in desc else ""
                    break
            except Exception:
                pass
        if not block_cidr:
            result["error"] = "No External IP Block matching the DVLAN subnet — complete S5-3 first."
            return jsonify(result)

        # ── 3. Prepared ESX hosts + NSX VDS name ───────────────────────────
        htns = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/sites/default/enforcement-points"
            "/default/host-transport-nodes") or {}).get("results", [])
        nsx_vds_name = ""
        for h in htns:
            fqdn = (h.get("node_deployment_info") or {}).get("fqdn") or h.get("display_name", "")
            if not fqdn: continue
            hosts.append(fqdn)
            if not nsx_vds_name:
                for hs in (h.get("host_switch_spec") or {}).get("host_switches") or []:
                    nsx_vds_name = hs.get("host_switch_name", "")
                    if nsx_vds_name: break
        if not hosts:
            result["error"] = "No prepared ESX hosts found — complete S3 (NSX Host Preparation) first."
            return jsonify(result)
        if not nsx_vds_name:
            result["error"] = "Could not determine NSX VDS name from host transport nodes."
            return jsonify(result)

        # ── 4. Allocate temp IPs ─────────────────────────────────────────────
        temp_ips = _pick_temp_ips(block_cidr, gateway_cidr, excl_str, len(hosts))
        if not temp_ips:
            result["error"] = "No available IPs in External IP Block for temp vmk."
            return jsonify(result)
        hosts = hosts[:len(temp_ips)]

        # ── 5. PowerCLI: create portgroup + vmk on every host ──────────────
        pg_name = f"vcf-vlan-check-{vlan_id}"
        host_ips_arg = [(h, temp_ips[i], mask_str) for i, h in enumerate(hosts)]
        vmk_map, _pg_created, setup_err = _pcli_setup_vlan_test(
            vc_url, vc_user, vc_pass, nsx_vds_name, pg_name, vlan_id, host_ips_arg)
        if setup_err:
            result["error"] = f"PowerCLI setup failed: {setup_err}"
            return jsonify(result)

        # ── 6. Per-host: SSH → vmkping ────────────────────────────────────
        for idx, fqdn in enumerate(hosts):
            temp_ip = temp_ips[idx]
            vmk_dev = vmk_map.get(fqdn)
            test: dict = {
                "host": fqdn, "vlan_id": vlan_id,
                "temp_ip": temp_ip, "gateway": gateway_ip,
                "vmk": vmk_dev, "result": "error", "output": "", "error": None
            }
            result["tests"].append(test)
            steps = [f"✓ VDS='{nsx_vds_name}', PG='{pg_name}' (VLAN {vlan_id})",
                     f"✓ Temp IP={temp_ip}/{prefix_len}, Gateway={gateway_ip}"]
            ssh_state = None
            ssh_client = None

            try:
                if not vmk_dev:
                    test["error"] = (f"PowerCLI failed to create vmk on {fqdn}. "
                                     f"Check PowerCLI setup output for VMK_ERR lines.")
                    test["output"] = "\n".join(steps); continue

                steps.append(f"✓ vmk created via PowerCLI: {vmk_dev} with IP {temp_ip}/{prefix_len}")

                ok_ssh, ssh_state = _vc_manage_ssh(vc_url, vc_user, vc_pass, fqdn, True)
                if not ok_ssh:
                    test["error"] = f"Could not enable SSH on {fqdn} via vCenter"
                    test["output"] = "\n".join(steps); continue
                if not ssh_state:
                    _time.sleep(5)
                steps.append("✓ SSH enabled")

                host_pwd = host_passwords.get(fqdn) or esx_pass
                ssh_client = _para.SSHClient()
                ssh_client.set_missing_host_key_policy(_para.AutoAddPolicy())
                for attempt in range(6):
                    try:
                        ssh_client.connect(fqdn, username="root",
                                           password=host_pwd, timeout=10)
                        break
                    except Exception as e_ssh:
                        if attempt < 5: _time.sleep(2)
                        else: raise RuntimeError(
                            f"SSH to {fqdn} failed: {e_ssh}\n"
                            "Check that this VM can reach ESX port 22.") from e_ssh
                steps.append("✓ SSH connected")

                def _run(cmd, timeout=30):
                    _, so, se = ssh_client.exec_command(cmd, timeout=timeout)
                    return so.read().decode("utf-8","replace"), se.read().decode("utf-8","replace")

                _time.sleep(2)   # brief pause for vmk IP stack to initialise

                ping_out, ping_err = _run(
                    f"vmkping -I {vmk_dev} -d -s 28 {gateway_ip}", timeout=30)
                ping_combined = (ping_out + ping_err).strip()
                steps.append(f"vmkping:\n{ping_combined}" if ping_combined
                              else "vmkping: no output")
                test["output"] = "\n".join(steps)
                test["result"] = (
                    "pass" if ("0% packet loss" in ping_out or "bytes from" in ping_out)
                    else "fail")

            except Exception as exc:
                test["error"] = f"{exc}\n{traceback.format_exc()}"
                test["output"] = "\n".join(steps)
            finally:
                if ssh_client:
                    try: ssh_client.close()
                    except Exception: pass
                if ssh_state is False:
                    try: _vc_manage_ssh(vc_url, vc_user, vc_pass, fqdn, False)
                    except Exception: pass

        passed = sum(1 for t in result["tests"] if t["result"] == "pass")
        total  = len(result["tests"])
        result["success"] = total > 0 and passed == total
        result["summary"] = f"{passed}/{total} host(s) passed VLAN {vlan_id} connectivity test"

    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        if pg_name and hosts:
            try: _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, pg_name, hosts)
            except Exception: pass

    return jsonify(result)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
