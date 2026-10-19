/* Public networking client and configuration API, ABI major 1. */
#ifndef PEIOS_NETD_H
#define PEIOS_NETD_H

#include <peios/netd-types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEIOS_NETD_ABI_VERSION 1
#define PEIOS_NETD_CONTROL_SOCKET "/run/netd/control.sock"
#define PEIOS_NETD_LEVEL_ABSENT 0
#define PEIOS_NETD_LEVEL_LINK 1
#define PEIOS_NETD_LEVEL_ADDRESSED 2
#define PEIOS_NETD_LEVEL_ROUTED 3
#define PEIOS_NETD_VALUE_OTHER 0
#define PEIOS_NETD_VALUE_INTEGER 1
#define PEIOS_NETD_VALUE_STRING 2
#define PEIOS_NETD_VALUE_STRING_LIST 3
#define PEIOS_NETD_EXPIRY_DROP 0
#define PEIOS_NETD_EXPIRY_KEEP 1
#define PEIOS_NETD_OUTCOME_IGNORE 0
#define PEIOS_NETD_OUTCOME_DOWN 1
#define PEIOS_NETD_OUTCOME_JOIN 2

typedef struct peios_netd_result peios_netd_result;
typedef struct peios_netd_subscription peios_netd_subscription;

/*
 * Ownership and representation
 *
 * All input pointers refer to aligned, initialized, readable objects for the
 * duration of the call. Output slots must be writable and must not alias input.
 * Spans use byte counts; strings are UTF-8 and are not NUL-terminated. A null
 * pointer is allowed only with a zero count. Socket paths and MAC bytes are
 * byte sequences, not UTF-8 text. Socket paths are filesystem paths, not Linux
 * abstract socket addresses. Paths must be nonempty and contain no NUL bytes.
 *
 * Optional strings/facts are absent when data is NULL and len is zero. A present
 * empty string has a non-NULL data pointer and zero length. Boolean fields use
 * 0 or 1. An optional_u32 has present=0 or 1; value is ignored when absent.
 * interface.lease is absent when present=0. Other lease fields are then ignored.
 * Lease durations and remaining times are seconds. Static addresses are CIDRs;
 * gateways and DNS servers are numeric IP addresses. Level values are above.
 *
 * Every operation returns an owned result, including failures. Check result_error
 * before accessing it. No result points into the input data. All returned views,
 * arrays, strings, profiles and diagnostics are borrowed from that result until
 * result_free. Results are immutable and may be read concurrently. Free exactly
 * once, after every reader finishes. There is no caller-supplied allocator.
 * Allocation failure follows the Rust runtime's process-abort policy.
 *
 * Result accessors return NULL or an empty span/count for the wrong result kind.
 * Successful command results have no payload. Error codes are POSIX errno
 * values, returned by result_error without changing thread-local errno. The
 * daemon's textual errors have no machine-readable code and use EIO.
 * Callers must not parse diagnostics as stable machine-readable identifiers.
 */
uint32_t peios_netd_abi_version(void);
void peios_netd_result_free(peios_netd_result *result);
int32_t peios_netd_result_error(const peios_netd_result *result);
peios_netd_bytes peios_netd_result_message(const peios_netd_result *result);
const peios_netd_status *peios_netd_result_status(const peios_netd_result *result);
const peios_netd_snapshot *peios_netd_result_snapshot(const peios_netd_result *result);
const peios_netd_judgment *peios_netd_result_judgment(const peios_netd_result *result);
peios_netd_bytes peios_netd_result_text(const peios_netd_result *result);

/* Each call opens a new connection. timeout_ms must be positive; it bounds the
 * entire connection/send/receive exchange. A full Unix listen queue can return
 * EAGAIN immediately. Failure does not prove a command was not applied: never
 * automatically replay renew/reconcile after an uncertain transport failure.
 * The library preserves the daemon's existing authorization checks.
 */
peios_netd_result *peios_netd_get_status(peios_netd_bytes path, uint64_t timeout_ms);
peios_netd_result *peios_netd_renew(peios_netd_bytes path, uint64_t timeout_ms,
                                    peios_netd_bytes interface);
peios_netd_result *peios_netd_reconcile(peios_netd_bytes path, uint64_t timeout_ms);

/* subscribe sends the subscription request and clears *out on failure. Read
 * the initial snapshot or authorization refusal with subscription_next.
 * Every subscription has one owner. Calls and destruction must not overlap.
 * next's ETIMEDOUT leaves partial framing intact for another call; any other
 * receive failure closes the connection. There is no automatic reconnect.
 * result_free does not close the independently owned subscription.
 */
peios_netd_result *peios_netd_subscribe(peios_netd_bytes path, uint64_t timeout_ms,
                                        peios_netd_subscription **out);
peios_netd_result *peios_netd_subscription_next(peios_netd_subscription *subscription,
                                                uint64_t timeout_ms);
void peios_netd_subscription_free(peios_netd_subscription *subscription);

/* The normalized hostname is returned by result_text. Configuration checking
 * performs no registry writes and requires no running daemon.
 */
peios_netd_result *peios_netd_hostname_check(peios_netd_bytes name);

/* Key arrays describe the neutral registry tree. Value.kind selects integer,
 * text or list; unused fields are ignored. OTHER represents an unsupported
 * registry type so validation can report it rather than silently omitting it.
 * Profiles is the Profiles root; rules is Rules\Interface. NULL means absent.
 * Inputs are limited to 128 key levels, 65536 total keys/values/list items and
 * 4 MiB total UTF-8 text across both trees. Each fact set has a 4 MiB text limit.
 * Disabled profiles remain visible in resolved results with enabled=0.
 */
peios_netd_result *peios_netd_policy_build(const peios_netd_key *rules,
                                           const peios_netd_key *profiles);
peios_netd_result *peios_netd_profiles_resolve(const peios_netd_key *profiles);
size_t peios_netd_policy_profile_count(const peios_netd_result *policy);
const peios_netd_profile *peios_netd_policy_profile(const peios_netd_result *policy, size_t index);
peios_netd_strings peios_netd_policy_lints(const peios_netd_result *policy);
/* Facts describe one interface and its network context. interface_mac is absent
 * or exactly six bytes. Missing facts remain absent; do not use empty strings
 * as a substitute. Judgment.profile is non-NULL only for JOIN.
 */
peios_netd_result *peios_netd_policy_judge(const peios_netd_result *policy,
                                           const peios_netd_facts *facts);

#ifdef __cplusplus
}
#endif
#endif
