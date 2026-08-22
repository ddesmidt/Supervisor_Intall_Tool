#!/bin/bash
TOKEN=$(curl -sk -X POST https://sddcmanager-a.site-a.vcf.lab/v1/tokens \
  -H 'Content-Type: application/json' \
  -d '{"username":"administrator@vsphere.local","password":"VMware123!VMware123!"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["accessToken"])')

echo "=== VCF Version ==="
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://sddcmanager-a.site-a.vcf.lab/v1/system/version | python3 -m json.tool

echo ""
echo "=== Domains ==="
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://sddcmanager-a.site-a.vcf.lab/v1/domains | python3 -c '
import sys,json
data = json.load(sys.stdin)
for d in data["elements"]:
    print(f"  {d[\"name\"]} ({d[\"type\"]}): {d[\"status\"]}")
'

echo ""
echo "=== Hosts ==="
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://sddcmanager-a.site-a.vcf.lab/v1/hosts | python3 -c '
import sys,json
data = json.load(sys.stdin)
for h in data["elements"]:
    print(f"  {h[\"fqdn\"]} - {h.get(\"status\",\"?\")} - {h.get(\"hardwareModel\",\"?\")} ")
'
