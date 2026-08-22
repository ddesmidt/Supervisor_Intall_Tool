#!/usr/bin/env bash
# VCF Lab API helper — all credentials via env vars, proxy via SOCKS5
# Usage: source vcf_api.sh   then call vc_get, vc_post, nsx_get, etc.

export VC_HOST="vc-mgmt-a.site-a.vcf.lab"
export NSX_HOST="nsx-mgmt-a.site-a.vcf.lab"
export VC_USER="administrator@vsphere.local"
export VC_PASS="VMware123!VMware123!"
export NSX_USER="vcfadmin"
export NSX_PASS="VMware123!VMware123!"
export PROXY="-x socks5h://localhost:1080"

# Refresh vCenter session token (stored in VC_TOKEN)
vc_auth() {
  VC_TOKEN=$(curl $PROXY -sk -X POST "https://$VC_HOST/api/session" \
    -H "Content-Type: application/json" \
    --user "$VC_USER:$VC_PASS" | tr -d '"')
  export VC_TOKEN
}

vc_get()  { curl $PROXY -sk -H "vmware-api-session-id: $VC_TOKEN" "https://$VC_HOST$1"; }
vc_post() { curl $PROXY -sk -X POST -H "vmware-api-session-id: $VC_TOKEN" -H "Content-Type: application/json" -d "$2" "https://$VC_HOST$1"; }

nsx_get()  { curl $PROXY -sk --user "$NSX_USER:$NSX_PASS" "https://$NSX_HOST$1"; }
nsx_put()  { curl $PROXY -sk -X PUT  --user "$NSX_USER:$NSX_PASS" -H "Content-Type: application/json" -d "$2" "https://$NSX_HOST$1"; }
nsx_patch(){ curl $PROXY -sk -X PATCH --user "$NSX_USER:$NSX_PASS" -H "Content-Type: application/json" -d "$2" "https://$NSX_HOST$1"; }
nsx_post() { curl $PROXY -sk -X POST --user "$NSX_USER:$NSX_PASS" -H "Content-Type: application/json" -d "$2" "https://$NSX_HOST$1"; }

j() { python3 -m json.tool; }   # pretty-print pipe alias
