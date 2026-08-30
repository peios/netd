# Guest-side smoke test for netd on a peiso-built image (dist/release). Run with
#   dist/release/drive.py --no-disk --share <dir> --timeout 230 <dir>/prod-smoke.sh
# and read <dir>/netd-report4.txt plus the netd: lines on the console.
{
  echo "== service"; svctl status netd | head -3
  echo "== wait routed"; net wait routed 60; echo "wait exit=$?"
  echo "== status"; net status
  echo "== inventory"; reg ls 'Machine/System/Network/Interfaces'
  for k in $(reg ls 'Machine/System/Network/Interfaces' 2>/dev/null); do k=${k%/}; echo "-- $k"; reg get "Machine/System/Network/Interfaces/$k" 2>&1 | head -14; done
  echo "== remembered lease"; cat /var/state/netd/leases/* 2>&1
  echo "== renew eth0"; net renew eth0; echo "renew exit=$?"; sleep 3; net status | tail -2
  echo "== reconcile"; net reconcile; echo "reconcile exit=$?"
  echo "== disable via inventory"; K=$(reg ls 'Machine/System/Network/Interfaces' | head -1); K=${K%/}; reg set "Machine/System/Network/Interfaces/$K" Enabled dword:0; sleep 3; net status | head -8; echo "routes: $(cat /proc/net/route | wc -l)"
  echo "== re-enable"; reg set "Machine/System/Network/Interfaces/$K" Enabled dword:1; sleep 12; net status | head -12; echo "routes: $(cat /proc/net/route | wc -l)"
  echo "== static profile overrides dhcp"; reg new Machine/System/Network/Profiles/static; reg set Machine/System/Network/Profiles/static Priority dword:100; reg new Machine/System/Network/Profiles/static/Match; reg set Machine/System/Network/Profiles/static/Match Name eth0; reg new Machine/System/Network/Profiles/static/Address; reg set Machine/System/Network/Profiles/static/Address DHCP4 dword:0; reg set Machine/System/Network/Profiles/static/Address Static multi:10.0.2.77/24; reg set Machine/System/Network/Profiles/static/Address Gateway 10.0.2.2; sleep 4; net status | head -14; cat /proc/net/route
  echo "== back to dhcp"; yes | reg del -r Machine/System/Network/Profiles/static; sleep 12; net status | head -14
  echo "== hostname via registry"; reg set Machine/System/Network Hostname workshop; sleep 3; cat /proc/sys/kernel/hostname; head -4 /etc/hosts
  echo "== resolv.conf"; cat /etc/resolv.conf
} > /share/netd-report4.txt 2>&1
