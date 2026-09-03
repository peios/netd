# The interface layer on a live image (PEI-598): drive.py guest script.
#
# Everything goes to /share so the host reads files, not serial echo.
# The image has no grep/sed/awk: shell builtins and reg/net only.
#
#   ./drive.py --no-disk --build <dir> --share <host dir> \
#       --cmdline-extra 'loglevel=7 ignore_loglevel' netd/tests/vm/interface-layer.sh

R=/share
N=Machine/System/Network
# reg prompts before a recursive delete and would read the answer from
# the script the console is typing; assume yes.
export REG_ASSUME_YES=1

step() { echo; echo "== $1"; }

{
step "baseline: who spoke for each interface"
net status
step "rules"
net rules
step "profiles"
net profiles
step "readiness on the Network key"
reg get $N Readiness
step "the tree netd wrote"
reg tree $N/Interfaces --values --depth 3
reg tree $N/Networks --values --depth 3
reg get $N Duid
} > $R/01-baseline.txt 2>&1

# The first (only) wired interface's id, from the inventory.
IFID=""
for k in $(reg ls --keys-only $N/Interfaces); do IFID="${k%/}"; break; done
echo "ifid=$IFID" > $R/ifid.txt

{
step "Status is netd-only: a write by the console principal must be refused"
reg sd $N/Interfaces/$IFID/Status
reg set $N/Interfaces/$IFID/Status Verdict DOWN && echo "WRONG: write accepted" || echo "refused as intended"
reg get $N/Interfaces/$IFID/Status Verdict
} > $R/02-status-sd.txt 2>&1

{
step "DOWN by Interface.Id outranks the baseline"
reg new $N/Rules/Interface/dead-card
reg set $N/Rules/Interface/dead-card Interface.Id.Equal "$IFID"
reg set $N/Rules/Interface/dead-card Priority dword:100
reg set $N/Rules/Interface/dead-card Actions multi:DOWN
sleep 4
net status
reg get $N/Interfaces/$IFID/Status Verdict
reg get $N/Interfaces/$IFID/Status Rule
step "delete the rule: back to the baseline"
reg del $N/Rules/Interface/dead-card -r
sleep 6
net status
} > $R/03-down.txt 2>&1

{
step "a derived profile as an exception: static address, inherited DNS"
reg new $N/Profiles/default/probe
reg set $N/Profiles/default/probe Address.Offered dword:0
reg set $N/Profiles/default/probe Address.Static multi:10.0.2.77/24
reg set $N/Profiles/default/probe Route.Offered dword:0
reg set $N/Profiles/default/probe Route.Gateway 10.0.2.2
reg new $N/Rules/Interface/wired/probe
reg set $N/Rules/Interface/wired/probe Interface.Id.Equal "$IFID"
reg set $N/Rules/Interface/wired/probe Actions "multi:JOIN(default/probe)"
sleep 5
net status
step "disable the derived profile: the rule abstains, wired speaks again"
reg set $N/Profiles/default/probe Enabled dword:0
sleep 6
net status
reg del $N/Rules/Interface/wired/probe -r
reg del $N/Profiles/default/probe -r
sleep 6
} > $R/04-exception.txt 2>&1

{
step "a JOIN of no profile refuses the generation; the last good one stands"
reg new $N/Rules/Interface/bogus
reg set $N/Rules/Interface/bogus Actions "multi:JOIN(nope)"
sleep 4
net status
reg del $N/Rules/Interface/bogus -r
sleep 4
step "two JOINs tied on priority refuse the generation"
reg new $N/Rules/Interface/tie-a
reg set $N/Rules/Interface/tie-a Priority dword:50
reg set $N/Rules/Interface/tie-a Actions "multi:JOIN(default)"
reg new $N/Profiles/other
reg new $N/Rules/Interface/tie-b
reg set $N/Rules/Interface/tie-b Priority dword:50
reg set $N/Rules/Interface/tie-b Actions "multi:JOIN(other)"
sleep 4
net status
reg del $N/Rules/Interface/tie-a -r
reg del $N/Rules/Interface/tie-b -r
reg del $N/Profiles/other -r
sleep 4
step "clean again"
net status
} > $R/05-refusals.txt 2>&1

{
step "netd's own log"
evctl 'LOGS FROM netd SINCE 1h ago TAKE 80'
step "service"
svctl status netd
} > $R/06-logs.txt 2>&1

echo done > $R/done.txt
