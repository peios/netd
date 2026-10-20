---
title: Constants
description: Every fixed number, path and identifier netd uses, in one table, with the section that describes it.
---

These constants bound netd's protocol, timing, and control behavior. The
values below describe the implementation rather than configuration defaults.

## Paths

| Path | Use |
|---|---|
| `Machine\System\Network` | configuration root, readiness, DUID (§2.3, §8) |
| `/run/netd/control.sock` | control socket (§9.1) |
| `/run/netd` | runtime directory, created by peinit (§2.1) |
| `/var/state/netd/duid` | the DUID, when the registry has none (§5.7) |
| `/var/state/netd/secret` | the RFC 7217 secret (§6.2) |
| `/usr/sbin/netd` | the daemon |
| `/proc/sys/net/ipv6/conf/<name>/accept_ra` | set to 0 (§6.1) |

## Numbers

| Constant | Value | § |
|---|---|---|
| Routing protocol stamped on netd's routes | 200 | §4.3 |
| Default route metric | 100; 600 for `wireless` | §4.2 |
| Minimum MTU applied | 68 | §4.3 |
| Converge repetitions per pass | at most 4 | §2.2 |
| Registry tree depth read | 16 | §2.3 |
| Control message ceiling | 65536 bytes | §9.2 |
| Control read and write timeout | 2 s | §9.1 |
| DHCPv4 first backoff, ceiling | 4 s, 64 s, ±1 s jitter | §5.2 |
| DISCOVER retransmissions before "nobody answered" | 3 | §5.2 |
| REQUESTs in Requesting before rediscovery | 4 | §5.2 |
| REQUESTs in Rebooting before rediscovery | 2 | §5.2 |
| Renewing and rebinding retransmission floor | 60 s | §5.2 |
| Shortest lease accepted | 4 s | §5.3 |
| DHCPv4 maximum message size advertised | 1500 | §5.1 |
| DHCPv4 message padding | to 300 bytes | §5.1 |
| Domain-search compression jumps per name | 16 | §5.3 |
| Link-local range | 169.254.1.0–169.254.254.255 | §5.5 |
| Router solicitation interval, ceiling | 4 s, 3600 s, ±10% jitter | §6.1 |
| Solicitations before backoff | 3 | §6.1 |
| Prefixes, RDNSS servers, DNSSL domains per advertisement option | 16 | §6.1 |
| SLAAC prefix length | 64 | §6.2 |
| Two-hour rule | 7200 s | §6.2 |
| Temporary address preferred lifetime | 86400 s minus 0–599 s | §6.2 |
| Temporary address valid lifetime | 172800 s | §6.2 |
| Temporary addresses per prefix | 4 | §6.2 |
| Stable address counter attempts | 8 | §6.2 |
| DHCPv6 first retransmission, ceiling | 1 s, 3600 s, ±10% jitter | §6.3 |
| DHCPv6 refresh default, floor | 86400 s, 600 s | §6.3 |
| DHCPv6 servers and domains kept | 16 each | §6.3 |

## Identifiers

| Identifier | Value | § |
|---|---|---|
| Interface id digest prefix | `peios-netd-ifid\|` | §4.1 |
| Network id digest prefix | `peios-netd-network\|` | §7.1 |
| Stable address digest prefix | `peios-ndp-stable-iid\|` | §6.2 |
| DUID-LL header | `00 03 00 01` | §5.7 |
| `Status` descriptor | `O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)` | §8.1 |
| `NETWORK_QUERY`, `NETWORK_CONTROL`, `NETWORK_ALL_ACCESS` | `0x1`, `0x2`, `0x000F0003` | §9.1 |
