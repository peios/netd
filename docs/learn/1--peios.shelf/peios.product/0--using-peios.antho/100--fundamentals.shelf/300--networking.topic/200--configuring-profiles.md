---
title: Configuring Profiles
type: how-to
description: Inspect the current network, prepare a profile and matching rule, apply changes live with a recovery plan, and verify the accepted addresses, routes and DNS.
related:
  - peios/advanced-peios/netd/introduction/overview
  - peios/networking/the-net-command
---

Network configuration is two kinds of key under `Machine\System\Network`. A
**profile**, a subkey of `Profiles`, says how an interface stands on a
network: what to take from the network's offer and what to dictate. A
**rule**, a subkey of `Rules\Interface`, says which interfaces stand in which
profile. netd watches the subtree, so a change takes effect within a moment of
the write — no restart, no reload command.

Follow this order: inspect the active interface, prepare the profile, select
it with a rule, then read back the accepted state. For desktop changes, use
[Network Manager](~peios/system-tools/network-manager), whose profile editor
shows inherited values and the interfaces a change affects.

Read the registry value reference on the machine with
`regman 'Machine\System\Network'`.

## Before you change anything

- You need write access to the particular registry keys. Reading status
  does not grant permission to change configuration; protected `Status`
  keys are netd's output, not settings to edit.
- Record the current rule, profile, and values so you can restore them.
  Keep local console access or another recovery path if this network
  carries your remote session.
- Profile and rule writes take effect live. Changing a profile's resolved
  values restarts its interfaces' clients, even for a DNS-only profile
  edit. No reboot or daemon reload is required.
- Use a derived profile for one interface. Editing `default` affects
  every interface using it and descendants that inherit the edited value.
- The commands below are examples. Replace addresses, names, ids, and bus
  paths with your own. The `vpn`, `office`, `laptop`, `untrusted`, and
  `home`
  profile examples assume those profiles already exist.

> [!WARNING]
> Direct `reg` writes do not use Network Manager's **Keep this change?**
> confirmation. A policy edit can disconnect the machine. Have console access
> or another recovery path before changing the interface used for remote
> access.

## See what you have

```sh
net status
net rules
net profiles
```

Keep this output for comparison after the change. `net status` shows each
interface with its verdict: the rule that spoke and the profile it stands in.
An image's baseline is a profile `default` that takes the network's address,
way out and name servers, and a rule `wired` that puts every wired interface
in it at priority 10.

## A static address

Create the profile before a rule names it. This example derives `default/db1`
from `default`, so values not listed here remain inherited, including
`Dns.Offered` and `Address.LinkLocal`. Lists replace inherited lists; they do
not append. An absent value inherits, while a present empty value means none.

Confirm that `10.0.0.5/24` is appropriate and available on your network and
that `10.0.0.1` is its gateway before adapting these example writes:

```sh
reg new Machine/System/Network/Profiles/default/db1
reg set Machine/System/Network/Profiles/default/db1 Address.Offered dword:0
reg set Machine/System/Network/Profiles/default/db1 Address.Static multi:10.0.0.5/24
reg set Machine/System/Network/Profiles/default/db1 Route.Offered dword:0
reg set Machine/System/Network/Profiles/default/db1 Route.Gateway 10.0.0.1
```

Then a rule naming the interface by its bus path (from `net status`, stable
across boots), as an exception under the baseline's `wired` rule so it is
judged only for wired interfaces:

```sh
reg new Machine/System/Network/Rules/Interface/wired/db1
reg set Machine/System/Network/Rules/Interface/wired/db1 Interface.Path.Equal pci-0000:00:03.0
reg set Machine/System/Network/Rules/Interface/wired/db1 Actions 'multi:JOIN(default/db1)'
```

The exception is more specific than `wired`, so it selects `default/db1` for
that interface and stops offered address acquisition. Check for
`JOIN(default/db1) by wired/db1` and the intended address and gateway in
`net status`; `readiness routed` appears once both a usable address and the
default route are in place.

Inherited `Dns.Offered` is a setting, not evidence that a server is available
after address acquisition stops. Check `resolv status`. To pin DNS as well,
set `Dns.Offered = 0` and `Dns.Servers` on this derived profile. The inherited
link-local setting does not add a fallback beside a static address. See
[desired state](~peios/advanced-peios/netd/interfaces/desired-state).

## Verify the accepted settings

```sh
net rules
net profiles
net status
resolv status
```

1. Confirm the rule names the intended profile and matches the intended
   interface. `net profiles` lists each profile's own values, not a
   flattened result; account for inherited values.
2. Check that `net status` has no `policy REFUSED` line. Read the active
   verdict, rule and profile, then the address, gateway, lease and warnings.
3. Check the servers and domains in `resolv status`, and test a relevant
   name with `resolv query <name>`.
4. Test the service you actually need. Readiness `routed` proves a default
   route exists, not that a remote service or the Internet answers.

If you also changed firewall rules or a network's `Name` or `Trust`, an
administrator should run `net policy wait` and check `net policy`. That
verifies the kernel's packet policy; it does not substitute for checking
netd's accepted profile in `net status`.

If the result is wrong, restore the values you recorded and repeat the checks.
`net reconcile` requests another pass; it does not undo a write.
`net renew <interface>` asks to renew an existing DHCP lease without releasing
it first. Both need `NETWORK_CONTROL`, granted to SYSTEM, and Administrators
by default.

## Facts a rule can name

Every `<Fact>.<Operator>` value present must hold. Comparison is exact;
`Equal` takes a list for *any of*.

| Fact | Matches | Example |
|---|---|---|
| `Interface` | the kernel's interface name | `enp0s3` |
| `Interface.Kind` | `wired`, `wireless`, `loopback`, `other` | `wired` |
| `Interface.Id` | the stable id from `net status` | `3f2a1b8e-…` |
| `Interface.Mac` | the hardware address | `52:54:00:12:34:56` |
| `Interface.Path` | the bus path | `pci-0000:00:03.0` |
| `Interface.Driver` | the kernel driver | `virtio_net` |
| `Network.Name` | the `Name` you gave the network's record | `palfrey-home` |
| `Network.Trust` | the `Trust` you gave it | `corporate` |

Prefer `Interface.Path` or `Interface.Id` for a specific card and
`Interface.Kind` or `Interface.Driver` for a class. `Interface` (the name) is
the least stable: the kernel might call the same card something else after a
hardware change. A fact the interface lacks — a tunnel has no `Path` — makes
the condition false, never an error.

## Taking the offer, with adjustments

`default` believes the network about the address, the way out and the name
servers. To keep the address but pin DNS, override two values in a derived
profile and point a rule at it — or, if the whole machine should behave so,
edit `default` itself:

```sh
reg set Machine/System/Network/Profiles/default Dns.Offered dword:0
reg set Machine/System/Network/Profiles/default Dns.Servers multi:1.1.1.1,9.9.9.9
```

Three more `Dns` values decide *which* names an interface's servers are asked
for, which matters the moment a second interface appears — typically a VPN:

```sh
reg set Machine/System/Network/Profiles/vpn Dns.Domains multi:corp.example
reg set Machine/System/Network/Profiles/vpn Dns.Default dword:1
reg set Machine/System/Network/Profiles/vpn Dns.Exclusive dword:1
```

`Dns.Domains` sends names under `corp.example` to this interface's servers.
`Dns.Default` sends *every other* name there too (unset, an interface claims
that only when it carries the default route). `Dns.Exclusive` takes all
queries only while the interface is at least `addressed` and supplies a DNS
server. Without those conditions it does not prevent another interface from
being chosen. Verify the VPN's addresses and server lines before relying on it
to keep names off another network. resolvd owns resolver selection;
`resolvd(8)` describes that service.

To hold an offered address across a server outage:

```sh
reg set Machine/System/Network/Profiles/default Address.OnExpiry Keep
```

`Keep` trades the risk of an address conflict for continuity; the default
`Drop` is the safe choice.

## IPv6

`Address.Offered` covers both families: on a network with router
advertisements the interface gets a stable-privacy address per advertised
prefix, and with `Route.Offered` and `Dns.Offered` the advertised default
route and DNS from RDNSS or stateless DHCPv6. Three values change that:

```sh
reg set Machine/System/Network/Profiles/office Address.Families multi:ipv4
reg set Machine/System/Network/Profiles/laptop Address.Temporary dword:1
reg set Machine/System/Network/Profiles/office Route.Gateway multi:10.0.0.1,fe80::1
```

`Address.Families = ipv4` stops router discovery on interfaces in the profile
and drops IPv6 entries from `Address.Static`. `Address.Temporary` adds
daily-rotating temporary addresses beside the stable one, for machines whose
traffic should not correlate over days; the stable address remains for
inbound. An IPv6 entry in `Route.Gateway` — usually a link-local address —
pins the default router instead of believing advertisements.

The stable address survives reboots and reinstalls that keep `/var/state/netd`
; it is not derived directly from the MAC, and a different network sees an
unrelated address. The [IPv6 address
chapter](~peios/advanced-peios/netd/ipv6/addresses) documents derivation,
lifetimes and rotation.

## Prefer a cable over WiFi

When both interfaces have default routes, the metric decides which is used.
Wired defaults to 100 and wireless to 600, so no configuration is needed. To
invert it, set `Route.Metric` on the profiles. This describes route preference
once links exist; Wi-Fi association is not implemented by netd, wireless is
not in the baseline, and Network Manager shows wireless as **Not managed**.

## Name a network, and behave differently on it

Once an interface has stood on a network, `net status` shows the record's id.
Give it a name and your word on it:

```sh
reg set Machine/System/Network/Networks/<id> Name palfrey-home
reg set Machine/System/Network/Networks/<id> Trust home
```

Changing either label can change both the selected profile and firewall
access. Check the active interface and packet policy afterward.

The following illustrates choosing a profile by network. It is not a Wi-Fi
setup procedure: a supplicant must supply the link, and wireless network-name
identification is unfinished. Create the `untrusted` and `home` profiles
before a rule names them:

```sh
reg new Machine/System/Network/Rules/Interface/radio
reg set Machine/System/Network/Rules/Interface/radio Interface.Kind.Equal wireless
reg set Machine/System/Network/Rules/Interface/radio Actions 'multi:JOIN(untrusted)'
reg new Machine/System/Network/Rules/Interface/radio/home
reg set Machine/System/Network/Rules/Interface/radio/home Network.Name.Equal palfrey-home
reg set Machine/System/Network/Rules/Interface/radio/home Actions 'multi:JOIN(home)'
```

Until a network has been identified on the link, the `Network.*` facts are
absent, so the radio stands in `untrusted` first and moves to `home` once the
network is known. `Trust` is your label, not verified evidence of network
identity: a rule that conditions on it is stating that you accept the
identification. The same word reaches the firewall: a `Flow` rule with
`Network.Trust.Equal = home` sees the network the radio is on, so what you
open at home stays shut at the cafe. See the network context in the
Peios Network Policy specification for the shared firewall contract.

## Hand an interface to something else

An `IGNORE` verdict leaves a matched interface alone: no new addresses,
routes, link changes, or DHCP. If it was previously joined, existing addresses
and routes remain; `IGNORE` is not a cleanup action:

```sh
reg new Machine/System/Network/Rules/Interface/leave-alone
reg set Machine/System/Network/Rules/Interface/leave-alone Interface.Equal tap0
reg set Machine/System/Network/Rules/Interface/leave-alone Actions multi:IGNORE
```

## Take an interface down

A `DOWN` verdict keeps a matched interface administratively down. `DOWN` wins
equal-priority ties, but a higher-priority rule still wins. Check existing
priorities before using the example priority 100:

```sh
reg new Machine/System/Network/Rules/Interface/dead-card
reg set Machine/System/Network/Rules/Interface/dead-card Interface.Id.Equal <id>
reg set Machine/System/Network/Rules/Interface/dead-card Priority dword:100
reg set Machine/System/Network/Rules/Interface/dead-card Actions multi:DOWN
```

The interface id is in `net status`. Delete the rule, or set `Enabled = 0` on
it, to let the remaining rules decide again. Verify that they select the
intended profile; removing `DOWN` alone does not guarantee a `JOIN`.

## Ask for the same address

The address a network last leased is on its record, and netd asks for it
first. Write it yourself for a soft reservation — a request the server might
refuse, unlike a static address:

```sh
reg set Machine/System/Network/Networks/<id> RequestedAddress 10.0.2.50
```

## Set the hostname

```sh
reg set Machine/System/Network Hostname workshop
```

netd applies it on the next pass. A profile with `Hostname.Offered` on adopts
a network-supplied name when this value is unset; `Hostname.Announce` tells
DHCP servers the name so their DNS can register it. Both are off in a bare
profile.

Each change netd makes to the machine's name is recorded in the event log as
`netd.hostname.changed`, with the name before and after
(`config.text-previous` and `config.text`). The netd manual's [hostname
chapter](~peios/what-netd-publishes/the-hostname) says exactly when.

netd validates the name as one network label:
letters, digits, and hyphens, at most 63 of them, not beginning or ending with
a hyphen, and not `localhost`. **System Settings** holds it to that as it is
typed: in its **About** section, **Machine Name** says what is wrong with a
name before it can be applied, and shows the name the machine has now if netd
hasn't applied the new one yet; **Apply** appears once the name has been
changed. The About section also shows what the machine is and runs: the system
and its edition, the kernel, how long it has been up, the hardware, and the
disks.

## When netd refuses

An unknown fact, a `JOIN` naming a missing profile, or an unknown profile
value refuses the whole new interface generation. netd keeps the last good one
and `net status` reports `policy REFUSED` with the reason. Fix the named
entry, then verify the next write was accepted; the registry listing alone
does not tell you what is active.

Two equal-priority rules selecting different profiles also refuse a runtime
reload when the conflict affects an existing interface. At startup, or for an
interface that appears later, the tied interface is instead ignored and its
warning names both rules. Make one rule unambiguously win. The
[generation](~peios/advanced-peios/netd/the-interface-layer/building-a-generation)
and [interface
judgment](~peios/advanced-peios/netd/the-interface-layer/judging-an-interface)
chapters describe that distinction.

A `JOIN` naming an existing but disabled profile abstains; its parent, another
rule, or the backstop answers. Disabling a profile does not exempt malformed
values in it from validation.

## Where to go next

- [The net command](~peios/networking/the-net-command) — read back what netd
  did.
- [Networking](~peios/advanced-peios/netd/introduction/overview) — the model behind these keys.
- `regman 'Machine\System\Network'` — registry values and their meanings.
- [The interface layer as netd runs
  it](~peios/advanced-peios/netd/the-interface-layer/profiles), in the netd
  technical reference manual — how netd reads these keys, builds a generation
  from them and judges each interface.
