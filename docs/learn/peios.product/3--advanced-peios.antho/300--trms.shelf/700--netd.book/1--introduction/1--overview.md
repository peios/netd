---
title: Overview
description: netd is the Peios network manager — a single-threaded reconciler that executes PNP's interface layer, runs its own DHCPv4, router-discovery and DHCPv6 clients, and publishes readiness and DNS facts. What is unusual about it.
---

**netd** is the Peios network manager. It is the executor of the interface
layer of PNP, the Peios Network Policy: it reads which interfaces join which
networks, and how they stand there, from `Machine\System\Network`, and makes
the kernel match. It runs as a SYSTEM service started at boot, and it is the
only program on a Peios machine that configures links, addresses and routes.

Three decisions shape everything else in this manual.

**It is a reconciler, not a command interpreter.** netd keeps no list of
things it has done. On every input — a kernel link or address event, a
registry change, a DHCP or router-discovery packet, a timer, a control request
— it re-derives what each interface should look like and applies the
difference from what the kernel reports. Nothing happens imperatively in a
handler. Two consequences follow directly: a manual change to an interface
netd manages lasts until the next pass, and a restarted netd derives its
desired state afresh. While its first INIT-REBOOT is pending, it preserves the
requested IPv4 address already installed and applicable netd-owned routes
(§2.1). Static configuration is desired from the first pass and stays.

**It owns addresses wholly and routes only by mark.** On an interface netd has
joined, every IPv4 address and every non-link-local IPv6 address is netd's:
anything else is removed. Routes are netd's only when they carry routing
protocol 200, the number netd stamps on every route it adds, so a route
another program adds for itself survives. The kernel's own IPv6 link-local
address is never touched.

**It is the only router-advertisement listener.** netd switches the kernel's
own RA processing off on every interface before it does anything else, and
acts on advertisements itself, so exactly one place decides what an
advertisement means. The kernel still makes link-local addresses and answers
neighbor solicitations; everything an advertisement could configure —
addresses, the default route, DNS, the MTU — is netd's decision, filtered
through the interface's profile.

netd builds and judges the interface layer with `pnp-core`, the same engine
the kernel's NTFE uses for the packet layers, so a rule means the same thing
in every layer. The kernel never reads `Rules\Interface`; netd never reads the
packet layers. Each executor validates and refuses its own layers on its own.

## Where netd sits

```text
   registry (Machine\System\Network)          peinit
        │ Rules\Interface, Profiles,            ▲ READY=1, LEVEL=<level>
        │ Hostname, Duid, ControlSecurity       │
        ▼                                       │
   ┌─────────────────────── netd ──────────────────────┐
   │ interface layer (pnp-core) → profile per interface │
   │ DHCPv4 · router discovery/SLAAC · DHCPv6           │──▶ rtnetlink (links,
   │ reconciler · network identification                │     addresses, routes)
   └────────────────────────────────────────────────────┘
        │ Interfaces\<id>\Status, Networks\<id>,        │ /run/netd/control.sock
        │ Readiness                                     ▼
        ▼                                         net, resolvd (subscribe)
   registry (written back)
```

What netd writes back to the registry is read by others: the kernel reads each
interface's `Status Network` to give the packet layers their `Network.*` facts
(PKM §6.5), services and scripts watch `Readiness`, and resolvd subscribes to
netd's DNS snapshots over the control socket (PSPU §6.9).

## What netd does not do

- **Answer names.** netd reports what each interface contributes to name
  resolution; resolvd routes and answers queries.
- **Filter packets.** The packet layers are NTFE's. netd's own DHCP and
  router-discovery traffic passes them only because the shipped baseline
  policy permits it.
- **Decide who can bind a port.** That is the kernel's port reservation
  table.
- **Associate with wireless networks.** A supplicant brings a wireless
  link up; netd then treats it as any other interface.
- **Hold leases across a reboot.** Nothing about a lease is persisted; a
  rebooted machine asks for the address its network last gave it (§5.7).
