# Requires = ["network:routed"] on a live image (PEI-598): drive.py guest script.
#
# netd declares Provides = ["network"]; peinit resolves the role and holds
# a dependent until netd publishes LEVEL=routed. Three probes: a service
# that needs routed (starts), one that needs a level nobody publishes
# (held), and one naming a role nothing fills (refused at validation).
#
#   ./drive.py --no-disk --build <dir> --share <host dir> \
#       --cmdline-extra 'loglevel=7 ignore_loglevel' netd/tests/vm/network-routed.sh

R=/share
S=Machine/System/Services
export REG_ASSUME_YES=1

step() { echo; echo "== $1"; }

# define <name> <requires>: a SYSTEM oneshot that writes a marker to /share.
#
# peinit reloads on every write under Services and keeps the last table
# that validated, so a definition is admitted by the first write that
# completes it and a later invalid write is refused while the earlier
# version stands. Requires therefore goes in FIRST: an entry validation
# refuses then never produces an admitted definition at all.
define() {
  reg new $S/$1
  reg set $S/$1 Requires "multi:$2"
  reg set $S/$1 ImagePath sz:/bin/sh
  reg set $S/$1 Arguments "multi:-c,echo ran > /share/$1-ran.txt"
  reg set $S/$1 Identity sz:SYSTEM
  reg set $S/$1 Type dword:1
  reg set $S/$1 Readiness dword:1
  reg set $S/$1 RestartPolicy dword:0
  reg set $S/$1 ErrorControl dword:0
}

{
step "netd fills the network role"
reg get $S/netd Provides
step "machine readiness"
net wait routed 60; echo "wait exit=$?"
net status | head -3
svctl status netd
} > $R/01-baseline.txt 2>&1

{
step "Requires network:routed starts once the level is published"
define probe-routed network:routed
svctl start probe-routed; echo "start exit=$?"
sleep 5
svctl status probe-routed
cat /share/probe-routed-ran.txt
} > $R/02-routed.txt 2>&1

{
step "Requires network:never is held: the start never completes"
define probe-never network:never
svctl start probe-never &
sleep 8
svctl status probe-never
ls /share/probe-never-ran.txt 2>&1
} > $R/03-held.txt 2>&1

{
step "Requires nowhere:routed names a role nothing fills: refused"
define probe-unfilled nowhere:routed
svctl start probe-unfilled; echo "start exit=$? (unknown service: the definition was never admitted)"
sleep 3
svctl status probe-unfilled
ls /share/probe-unfilled-ran.txt 2>&1
} > $R/04-unfilled.txt 2>&1

{
step "peinit's log"
evctl 'LOGS FROM peinit SINCE 1h ago TAKE 60'
} > $R/05-logs.txt 2>&1

echo done > $R/done.txt
