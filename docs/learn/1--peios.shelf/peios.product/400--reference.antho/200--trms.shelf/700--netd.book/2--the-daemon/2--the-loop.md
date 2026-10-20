---
title: The Loop
description: netd's single thread and single poll — its inputs, how each one leads to a full pass or a reconcile, and the converge sequence that repeats until the kernel stops changing.
---

netd is one thread around one `poll(2)`. [*loop.one-thread-one-poll] Every
input is a descriptor in the poll set or a timer deadline, and every handler
records what it learned and lets the end of the iteration act on it. Because
there is one thread, a handler that blocks holds everything up: no DHCP timer
fires and no kernel event is read until it returns.

## Inputs

| Input | Descriptor | What it leads to |
|---|---|---|
| Kernel events | the rtnetlink multicast socket | a fresh dump, then a full pass |
| Registry changes | the watch on `Machine\System\Network` | a reload (§2.3), then a full pass |
| udp/68 absorber | the absorber socket | drained and discarded |
| DHCPv4 replies | one packet socket per running client | the client's actions; a reconcile if the network changed |
| Router advertisements | one ICMPv6 socket per interface doing router discovery | the engine's actions; a full pass if anything changed |
| DHCPv6 replies | one UDP socket per running DHCPv6 client | the client's actions; a reconcile if the DNS facts changed |
| Control requests | the listener and accepted client sockets | the request (§9.2); `reconcile` runs a full pass |
| Time | the earliest deadline of any client | every client's timers, each acted on as above |

The poll timeout is the earliest deadline any DHCPv4, router-discovery or
DHCPv6 client holds, or a pending control request or reply holds (§9.1); with
none, netd waits indefinitely. A deadline already acted on is not held again:
once an address is deprecated, its preferred lifetime is behind it, and its
next deadline is the end of its valid lifetime. So netd sleeps while addresses
sit deprecated, which on an IPv6 network with temporary addresses is most of
the time.

After a kernel event netd does not fold the event into its model. It dumps the
whole state again and always runs a full pass, because a dump taken after an
apply can already show a state whose consequences have not been decided yet.
[*loop.kernel-event-redumps-and-converges]

## A full pass [*loop.full-pass-sequence]

A full pass runs these steps, in this order:

1. identify networks on joined interfaces with carrier (§7.1);
2. bring the interface table in line with the kernel's links and judge
   every non-loopback interface (§3.3), stopping the clients of an
   interface that lost carrier or whose outcome changed;
3. start DHCPv4 clients where due (§5.1);
4. start or stop router discovery and DHCPv6 (§6.1, §6.3);
5. reconcile every interface (§4.3) and dump the kernel's state again.

It then repeats steps 1 to 5 while the dump differs from the one before the
reconcile. [*loop.converge-repeats-until-stable] The steps run at most four
times in one pass, the first run included, even if the dump is still changing
after the fourth.

Applying changes alters what the next decisions see: bringing a link up gives
it carrier, carrier starts a DHCP client, and a lease adds an address. One
pass would leave that chain waiting for a later event that, on a virtual NIC,
has already arrived.

After the repeats, the pass applies the hostname (§8.4) and publishes: the
machine level to peinit and the registry, every joined interface's `Status`,
and a DNS snapshot to subscribers if it changed (§8.2, §8.3).

## Reconcile without a full pass

A DHCPv4 lease arriving, a lease being lost, link-local fallback, and a DHCPv6
answer each change only what an interface should carry, so they lead to a
reconcile of every interface, the hostname, and a publish, without re-judging
anything. If the same iteration also needs a full pass, only the full pass
runs.

A DHCPv4 lease also marks its interface for re-judgment, because the
network on the other side might now be identifiable (§7.1). Any interface
so marked makes the iteration run a full pass.
[*loop.lease-marks-for-rejudgement]
