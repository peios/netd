---
title: What This Manual Covers
description: The scope of the netd manual, the documents it leans on for the policy vocabulary, the resolver channel and the kernel's side of the network context, and the version it describes.
---

This manual describes netd as built: the `netd` workspace's `netd` daemon, the
`dhcp4`, `dhcp6`, and `ndp` state machines, and the `net` command. It also
covers the public `libnetd.so.1` client library, its Rust wrapper, and the
internal `netd-core` policy and protocol types. The source version is 0.1.8;
this manual does not establish installation or release qualification.

## What is covered elsewhere

| Subject | Where |
|---|---|
| The interface layer's vocabulary — facts, verdicts, the collation laws — and every profile value, as an operator writes them | The network policy reference (`~peios/networking/network-policy-reference`) |
| The rule engine itself: ingestion, conditions, collation, refusal | Kernel TRM chapter 6 (PKM §6.4, §6.5); netd links the same `pnp-core` crate |
| The kernel's side of the network context — how `Status Network` becomes `Network.*` facts in the packet layers | PKM §6.5 |
| The netd → resolver channel's contract | PSPU §6.9 |
| What a resolver does with the snapshots | PSPU book 6 and the resolvd manual |
| The query-channel framing the control socket uses | PSPU book 3 |
| How peinit holds a service until a readiness level is published | The peinit manual |
| Every registry value netd reads or writes, one entry each | `regman 'Machine\System\Network'` on a Peios machine |

Where this manual and the network policy reference both mention a profile
value, the reference owns the meaning and this manual owns what netd does with
it: how the value is parsed, when it takes effect, and how it combines with
what a network offers.

## Conventions

Section numbers in this manual are written `§n.m`. A reference into another
book is qualified with the book's short name: `PKM §6.5` is the Kernel TRM,
`PSPU §6.9` the userspace protocols book.

Times are given as netd's monotonic clock sees them. Every timer netd runs —
DHCP retransmission, lease boundaries, advertisement lifetimes, solicitation
backoff — is measured on `CLOCK_MONOTONIC`, so setting the wall clock moves
none of them.
