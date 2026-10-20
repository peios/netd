---
title: The Client
description: When netd runs a DHCPv4 client on an interface, what it is configured with, its states, and exactly what each message it sends carries.
---

netd's DHCPv4 client is the `dhcp4` crate: the RFC 2131 state machine as a
pure, clock-injected type, driven by netd's loop and sockets.

## Starting and stopping [*dhcp4-client.start-stop]

On every full pass, for each joined interface:

- the interface **wants** a client when its profile has `Address.Offered`
  and IPv4 in its families;
- it **can** run one when it is up with carrier.

A running client is stopped (§5.4) in the step of the pass that brings the
interface table in line with the kernel's links, before clients are started
(§2.2):

- when the link loses carrier or goes down, logged as `interface <name>:
  carrier lost`;
- when the interface's outcome changes, logged as the new verdict
  (§3.3). Any edit to the profile the interface stands in is a change of
  outcome, so it stops the client even when the edited profile still
  wants one, and the same pass starts a new one.

Only a change of outcome changes what an interface wants, so a client its
interface does not want is always stopped the second way. A link that leaves
the
kernel takes its client with it (§5.4).

An interface that wants and can run a client but has none starts one, logging
`interface <name>: dhcp starting`, provided:

- the link has a 6-byte hardware address — otherwise no client is started,
  silently;
- its packet socket opens (§5.6) — otherwise netd logs `no packet socket`
  and tries again on the next pass.

A new client starts with no lease. It is configured with:

| Setting | Value |
|---|---|
| `chaddr` | the interface's MAC |
| client identifier (option 61) | the interface's `ClientId` (§5.7) |
| hostname (option 12) | the machine's `Hostname`, only when the profile has `Hostname.Announce` and `Hostname` is set |
| randomness | 8 bytes of `/dev/urandom` XORed with the interface index, seeding transaction ids and jitter |
| a previous address | the `RequestedAddress` of the interface's network, if one is known; otherwise that of the network named by its `Status LastNetwork` (§5.7) |

With a previous address the client begins in **Rebooting** (RFC 2131
§3.2, INIT-REBOOT). Without one it begins in **Selecting**.
[*dhcp4-client.previous-address-starts-in-rebooting]

## States

| State | Entered | Leaves on |
|---|---|---|
| Selecting | start without a previous address; a NAK while requesting or rebooting; a request that went stale; a reboot nobody confirmed; a lost lease | an acceptable OFFER |
| Requesting | an OFFER in Selecting | an ACK (Bound), a NAK (Selecting), four unanswered transmissions (Selecting) |
| Rebooting | start with a previous address | an ACK (Bound), a NAK (Selecting), two unanswered transmissions (Selecting) |
| Bound | an ACK | T1 (Renewing) |
| Renewing | T1; or an operator `renew` while bound, renewing or rebinding | an ACK (Bound), a NAK (lease lost, Selecting), T2 (Rebinding) |
| Rebinding | T2 | an ACK (Bound), a NAK or the lease's end (lease lost, Selecting) |

The status reply shows a client's state only inside its `lease`, which is
present only while the client holds a lease (§9.2), and `net status` prints it
on the `lease` line. So the state shown is always `bound`, `renewing` or
`rebinding`. A client in Selecting, Requesting or Rebooting holds no lease,
and neither shows a state for it. The `init` state exists only between a stop
and the client being discarded.

[*dhcp4-client.states]

A new transaction id is drawn on entering Selecting, Rebooting, Renewing and
Rebinding. Requesting keeps the id of the Selecting exchange it came from.
[*dhcp4-client.transaction-ids]

## What every message carries [*dhcp4-client.common-fields]

Every message is a BOOTREQUEST with hardware type 1 and length 6, the current
transaction id, `chaddr`, and `secs` set to the whole seconds since the client
started, capped at 65535. Every message except a RELEASE carries, in this
order:

| Option | Content |
|---|---|
| 53 | the message type |
| 61 | the client identifier |
| 57 | maximum message size 1500 |
| 55 | the parameter request list: 1, 3, 6, 12, 15, 26, 28, 42, 51, 58, 59, 119, 121 |
| 12 | the hostname, when configured |

The encoded message ends with option 255 and is padded with zeros to 300
bytes. An option longer than 255 bytes would be cut to 255.

## The messages [*dhcp4-client.messages]

| Message | When | Broadcast flag | `ciaddr` | Option 50 | Option 54 | Sent |
|---|---|---|---|---|---|---|
| DISCOVER | Selecting | set | 0 | the address of a lease that expired, until a NAK or a reboot timeout forgets it | — | broadcast |
| REQUEST | Requesting | set | 0 | the offered address | the offer's | broadcast |
| REQUEST | Rebooting | set | 0 | the previous address | — | broadcast |
| REQUEST | Renewing | clear | the lease address | — | — | unicast to the server |
| REQUEST | Rebinding | clear | the lease address | — | — | broadcast |
| RELEASE | a stop while holding a lease | clear | the lease address | — | the server | unicast to the server |

A RELEASE carries only options 53, 54 and 61.

"Broadcast" and "unicast" are the paths of §5.6: a broadcast leaves the packet
socket from `0.0.0.0` to `255.255.255.255`, rebinding included; a unicast
leaves an ordinary UDP socket bound to the lease address.
