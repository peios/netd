---
title: Startup
description: The service definition netd ships, and the order netd does things in when it starts — which failures are fatal and which only degrade it — up to the first pass and READY=1.
---

Startup reads configuration and kernel state before the first reconciliation.
A restart can preserve applicable IPv4 state while the lease is revalidated.

## The service definition

The netd package ships its service definition as a registry seed,
`netd-service.reg`, applied by an image that names it. The definition:

| Value | Setting | Why |
|---|---|---|
| `ImagePath` | `/usr/sbin/netd` | |
| `Triggers` | `boot` | |
| `Identity` | `SYSTEM` | rtnetlink changes, the packet socket,  and a bind to udp/68 each need a privilege only SYSTEM holds |
| `Provides` | `network` | the role a dependent names: `Requires = ["network:routed"]` |
| `Readiness` | `0` (Notify) | readiness is `READY=1` on the notify socket |
| `RuntimeDirectories` | `netd` | peinit creates `/run/netd` for the control socket |
| `RestartPolicy` | `2` (Always) | a stopped network manager is a machine whose leases silently expire |
| `ErrorControl` | `0` | |

A second seed, `netd-default-profile.reg`, ships the baseline policy: the
profile `default` and the rule `wired` (§3.1). It is separate so an image can
run netd without agreeing that every wired interface joins whatever it is
plugged into.

## The startup sequence [*startup.sequence]

netd does these steps in this order:

1. **Opens rtnetlink**: one socket for requests and dumps, and a
   second subscribed to the link, IPv4 and IPv6 address, and IPv4 and
   IPv6 route multicast groups. Failure is fatal.
2. **Opens the control socket** at `/run/netd/control.sock`, removing a
   stale one first (§9.1). Failure is fatal.
3. **Opens the udp/68 absorber** (§5.6). Failure is a warning: netd runs
   without it, and a DHCP server's unicast reply can draw an ICMP
   port-unreachable from the kernel.
4. **Switches the kernel's RA processing off** on every interface that
   exists, and in `all` and `default` (§6.1). This happens before any
   link is brought up.
5. **Reads the configuration** (§2.3) and builds a generation from it
   (§3.2). A generation that fails to build at startup is logged as
   refused, and netd runs with an empty policy, so the backstop ignores
   every interface until a good generation is written.
6. **Arms the registry watch** on `Machine\System\Network`. Failure is a
   warning, and the configuration is then read once, never again.
7. **Dumps the kernel's state** (links, addresses and routes, both
   families). Failure is fatal.
8. **Runs the first pass** (§2.2): every interface is judged, every
   static address applied, every client that is due started.
9. **Sends `READY=1` ** on the notify socket.

Readiness is reported after the first pass, not after any lease arrives.
A lease is a network event, not a startup one. A service that needs an
address waits on a readiness level (§8.2), not on netd being ready.
[*startup.ready-after-first-pass-not-a-lease]

A tie between two rules is not checked at startup: the startup build refuses a
generation only for the build errors of §3.2. A tie present at startup is
judged per interface as a conflict (§3.3), so the interfaces it covers are
ignored with a warning rather than the generation being refused.
[*startup.tie-at-startup-is-a-conflict-not-a-refusal]

If `Machine\System\Network` does not exist when netd starts, the
configuration is empty and the watch cannot be armed, so a key created
later is never read; a restart of netd picks it up.
[*startup.missing-root-is-read-once]

## Restart [*startup.restart-reacquires-the-lease]

netd re-derives everything from the registry and the kernel. Its DHCP clients
start again, and a client remembers nothing across a restart: each one begins
with an INIT-REBOOT request for the address its network last leased (§5.7),
and holds no lease until that request is answered.

During an interface's first DHCP start in this process, netd preserves its
requested IPv4 address at the prefix already installed in the kernel. It also
preserves its netd-marked IPv4 routes while `Route.Offered` allows them; an
explicit `Route.Gateway` takes precedence and the current profile's metric
applies. This provisional state lasts only while INIT-REBOOT is pending. An
unchanged ACK replaces it with the confirmed lease without deleting the
address or route, so IPv4 readiness stays in place.

A NAK or two unanswered requests end revalidation and discard the provisional
state as the client enters fresh discovery (§5.2). Carrier loss or a changed
profile clears it too. Later client restarts in the same process do not adopt
kernel state again. A requested address that is not already installed is never
added merely because it was remembered.

This is not a restored lease: no lease duration, expiry, DNS servers, or other
offered information is inferred from the installed address. Status still
reports no lease until the ACK. DHCP-provided DNS information and IPv6
router-discovery state must be reacquired; this does not promise that every
aspect of a daemon restart is invisible. IPv6 addresses and routes from
advertisements remain desired only after discovery hears the routers again
(§6.1). Static addresses are desired from the first pass and stay.
