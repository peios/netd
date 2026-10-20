---
title: The Net Command
type: reference
description: Read active interfaces and leases, compare rules and profiles, verify firewall acceptance, and choose a safe renew or reconcile command with the required access.
related:
  - peios/advanced-peios/netd/introduction/overview
  - peios/networking/configuring-profiles
---

Use `net status` first. It shows what netd accepted and what is present on
each interface. Use `net rules` and `net profiles` to compare that state with
the registry configuration. On the desktop, the same starting point is
[Network Manager's
Overview](~peios/system-tools/network-manager#finding-the-right-view).

```sh
net status
net rules
net profiles
```

`net` does not write profile or rule configuration. Follow [Configuring
profiles](~peios/networking/configuring-profiles) to change it, then return
here to verify the result.

## After a change

- **Profile or interface rule:** check `net status` for the intended
  verdict, rule and profile, no `policy REFUSED` line, and the expected
  addresses and gateway. `net profiles` shows each profile's own values,
  so inherited settings still matter.
- **DNS:** check `resolv status` and a relevant `resolv query <name>`.
- **Firewall rule or network label:** as an administrator, run
  `net policy wait`, then `net policy`. A returned registry write is not
  yet proof that the kernel accepted it.
- **Connectivity:** test the required service. `routed` means there is a
  usable address and a default route, not a successful Internet probe.

The interface and packet policy are accepted independently. A successful
`net policy wait` does not prove that netd accepted a profile; a good
`net status` does not prove that the firewall accepted a rule.

## Reading `net status`

```text
hostname   workshop
readiness  routed

enp0s3  [3f2a1b8e-…]
  verdict    JOIN(default) by wired
  state      up, carrier
  readiness  routed
  hardware   52:54:00:12:34:56 pci-0000:00:03.0 virtio_net
  network    palfrey-home [9c0d4e21-…] trust home
  address    10.0.2.15/24
  gateway    10.0.2.2
  dns        10.0.2.3
  lease      bound from 10.0.2.2, 86395s left
```

`verdict` is what the interface layer said and who said it: the verdict, the
profile (for `JOIN`), and the rule path that spoke — `backstop` when no rule
did. `readiness` is `absent` (down or no carrier), `link`, `addressed` or
`routed`, shown for joined interfaces; the machine's is the highest among
them. `network` is the record under `Machine\System\Network\Networks`
identified on the link, with the `Name` and `Trust` you gave it.

The bracketed value after the name is the interface id — the inventory key
under `Machine\System\Network\Interfaces`.

Read the interface block, not only the machine's readiness: another interface
can make the machine `routed` while this one is unusable. An IPv4 link-local
address counts as `addressed`; IPv6 link-local alone does not. Only joined
interfaces contribute to machine readiness.

A `warning` line can mean DHCP discovery went unanswered or two rules tied and
this interface is ignored. `policy REFUSED:` means the newest interface
generation was rejected and the last good one stands. Correct the named rule
or profile and read status again. A listed registry write is not proof it took
effect.

## Commands

| Command | Does |
|---|---|
| `net status` | Hostname, the machine's readiness, whether the newest generation was refused, and every interface: verdict with the rule and profile behind it, link state, readiness, hardware identity, the network identified on it, addresses, gateway, DNS, lease, warnings. |
| `net wait <level> [seconds]` | Block until the machine reaches `link`, `addressed` or `routed`, or the timeout (default 60) passes. For scripts that need the network. |
| `net renew <interface>` | Renew the DHCP lease now. Accepts a kernel name or an interface id. |
| `net reconcile` | Re-run the reconciler immediately rather than waiting for an event. |
| `net policy` | The kernel's side of the packet policy: whether the filtering engine (NTFE) is enforcing, its generation, whether every change written so far is in force, whether the last re-read was refused, and how many interfaces have a network context. |
| `net policy wait [seconds]` | Block until every change made to `Machine\System\Network` before the command started is in force in the kernel, or the timeout (default 10) passes. Fails if the kernel refused the new generation. For scripts that write a rule and then rely on it. |
| `net rules` | The interface layer, one rule per line: path, priority, conditions, actions. |
| `net profiles` | The profile tree, one profile per line with the values it sets itself. |

## Choose renew or reconcile carefully

`net renew <interface>` asks a DHCPv4 client holding a lease to renew it
without releasing its current address first. A client with no lease is left as
it is; a successful request alone does not prove a new lease arrived. Check
the lease afterward. The argument might be a kernel name or the stable
interface id shown by `net status`.

`net reconcile` asks netd to apply the configured desired state now. It does
not reload a different configuration, undo a write, or make an invalid gateway
reachable. Neither operation requires a reboot.

Use these commands when a restart is unnecessary. On restart, netd asks to
reuse its remembered IPv4 address and keeps that address and applicable routes
while revalidation is pending. A rejection or timeout discards that
provisional state. It must reacquire offered DNS and IPv6 information. See
[startup](~peios/advanced-peios/netd/the-daemon/startup).

Each control request has a 5-second total deadline, including connection,
request transmission, and response reading. A timeout does not prove that a
renew or reconcile request had no effect. Check status before retrying.

## Required access

`status`, `wait`, `renew`, and `reconcile` reach netd through
`/run/netd/control.sock`. The control object is a security descriptor:
`Machine\System\Network\ControlSecurity`, or a compiled default when that is
unset. `status` and `wait` need `NETWORK_QUERY`, which the default grants to
everyone. `renew` and `reconcile` need `NETWORK_CONTROL`, which the default
grants to SYSTEM and Administrators. `rules` and `profiles` read the registry
directly and need only read access to it. `policy` and `policy wait` ask the
kernel through `/dev/peios-ntfe`, which ordinary users might lack access to. A
denied request reports `access denied`.

## Exit status

| Code | Meaning |
|---|---|
| 0 | Done; for `wait`, the level was reached; for `policy wait`, the changes are in force. |
| 1 | netd refused or could not be reached; for `wait`, the timeout passed; for `policy wait`, the timeout passed or the kernel refused the generation. |
| 2 | Usage error. |

## See also

- [Networking](~peios/advanced-peios/netd/introduction/overview)
- [Configuring profiles](~peios/networking/configuring-profiles)
- `regman 'Machine\System\Network'` on the machine, for every key netd reads
  and writes.
- [netd's control
  socket](~peios/advanced-peios/netd/the-control-socket/requests), in the netd
  technical reference manual: the requests behind every `net` command, and
  their replies.
