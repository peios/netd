# The network context on a live image (PEI-598): drive.py guest script.
#
# The kernel reads which network each interface is standing on from
# netd's inventory, so a packet-layer rule can condition on
# Network.Trust. Flipping Trust on the record re-judges every flow on
# that interface. Fresh outbound flows come from `resolv lookup` (one UDP
# flow each); under a REJECT they fail at once as "unavailable local".
#
#   ./drive.py --no-disk --build <dir> --share <host dir> \
#       --cmdline-extra 'loglevel=7 ignore_loglevel' netd/tests/vm/network-context.sh
#
# The console log (drive.py's --console-log) carries the kernel's
# "pnp: network context: N interfaces; generation G" lines.

R=/share
N=Machine/System/Network
export REG_ASSUME_YES=1

step() { echo; echo "== $1"; }
lookups() {
  for i in 1 2 3; do
    resolv lookup "q$i-$1-$$.example.com"; echo "exit=$?"
  done
}

{
step "wait for the network"
net wait routed 60; echo "wait exit=$?"
step "the context as netd wrote it"
IFID=""
for k in $(reg ls --keys-only $N/Interfaces); do IFID="${k%/}"; break; done
NETID=""
for k in $(reg ls --keys-only $N/Networks); do NETID="${k%/}"; break; done
echo "ifid=$IFID netid=$NETID"
reg get $N/Interfaces/$IFID/Status Name
reg get $N/Interfaces/$IFID/Status Network
reg get $N/Interfaces/$IFID/Status LastNetwork
reg tree $N/Networks/$NETID --values --depth 1
step "baseline lookups"
lookups base
} > $R/01-baseline.txt 2>&1

{
step "outbound DNS is refused unless the network is trusted"
reg new $N/Rules/Flow/dns-needs-trust
reg set $N/Rules/Flow/dns-needs-trust Direction.Equal out
reg set $N/Rules/Flow/dns-needs-trust Protocol.Equal udp
reg set $N/Rules/Flow/dns-needs-trust DstPort.Equal dword:53
reg set $N/Rules/Flow/dns-needs-trust Priority dword:10
reg set $N/Rules/Flow/dns-needs-trust Actions "multi:REJECT,REPORT(3)"
reg new $N/Rules/Flow/dns-needs-trust/home
reg set $N/Rules/Flow/dns-needs-trust/home Network.Trust.Equal home
reg set $N/Rules/Flow/dns-needs-trust/home Actions multi:PASS
sleep 3
step "no Trust on the record: the exception is false, lookups are refused"
resolv flush
lookups none
} > $R/02-untrusted.txt 2>&1

{
step "the operator calls the network home: the context changes, lookups work"
reg set $N/Networks/$NETID Trust home
sleep 3
lookups home
step "a different word: refused again"
reg set $N/Networks/$NETID Trust cafe
sleep 3
lookups cafe
step "the word removed: absent, refused"
reg del $N/Networks/$NETID Trust
sleep 3
lookups gone
step "home again, by Name this time is not enough: Trust is the fact"
reg set $N/Networks/$NETID Name palfrey-home
sleep 3
lookups named
reg set $N/Networks/$NETID Trust home
sleep 3
lookups trusted
} > $R/03-trust-flips.txt 2>&1

{
step "Network.Id.Present = 0 names the unknown-network case"
reg new $N/Rules/Flow/unknown-network
reg set $N/Rules/Flow/unknown-network Direction.Equal out
reg set $N/Rules/Flow/unknown-network Network.Id.Present dword:0
reg set $N/Rules/Flow/unknown-network Priority dword:20
reg set $N/Rules/Flow/unknown-network Actions multi:REJECT
sleep 3
step "on a known network the rule is false: lookups still work"
lookups known
reg del $N/Rules/Flow/unknown-network -r
} > $R/04-present.txt 2>&1

{
step "cleanup"
reg del $N/Rules/Flow/dns-needs-trust -r
reg del $N/Networks/$NETID Trust
reg del $N/Networks/$NETID Name
sleep 3
lookups final
step "the inventory as left"
reg get $N/Interfaces/$IFID/Status Network
reg tree $N/Networks/$NETID --values --depth 1
step "netd and resolvd"
svctl status netd
net status | head -5
} > $R/05-cleanup.txt 2>&1

echo done > $R/done.txt
