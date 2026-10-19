//! Raw declarations are private: only the ownership-aware wrapper calls them.

use std::ffi::c_void;
use netd_abi as abi;

#[link(name = "netd")]
unsafe extern "C" {
    pub(crate) fn peios_netd_result_free(result: *mut c_void);
    pub(crate) fn peios_netd_result_error(result: *const c_void) -> i32;
    pub(crate) fn peios_netd_result_message(result: *const c_void) -> abi::Bytes;
    pub(crate) fn peios_netd_result_status(result: *const c_void) -> *const abi::Status;
    pub(crate) fn peios_netd_result_snapshot(result: *const c_void) -> *const abi::Snapshot;
    pub(crate) fn peios_netd_result_judgment(result: *const c_void) -> *const abi::Judgment;
    pub(crate) fn peios_netd_result_text(result: *const c_void) -> abi::Bytes;
    pub(crate) fn peios_netd_get_status(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub(crate) fn peios_netd_renew(
        path: abi::Bytes,
        timeout_ms: u64,
        interface: abi::Bytes,
    ) -> *mut c_void;
    pub(crate) fn peios_netd_reconcile(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub(crate) fn peios_netd_subscribe(
        path: abi::Bytes,
        timeout_ms: u64,
        out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn peios_netd_subscription_next(
        subscription: *mut c_void,
        timeout_ms: u64,
    ) -> *mut c_void;
    pub(crate) fn peios_netd_subscription_free(subscription: *mut c_void);
    pub(crate) fn peios_netd_hostname_check(name: abi::Bytes) -> *mut c_void;
    pub(crate) fn peios_netd_policy_build(
        rules: *const abi::Key,
        profiles: *const abi::Key,
    ) -> *mut c_void;
    pub(crate) fn peios_netd_policy_profile_count(policy: *const c_void) -> usize;
    pub(crate) fn peios_netd_policy_profile(
        policy: *const c_void,
        index: usize,
    ) -> *const abi::Profile;
    pub(crate) fn peios_netd_policy_lints(policy: *const c_void) -> abi::Strings;
    pub(crate) fn peios_netd_policy_judge(
        policy: *const c_void,
        facts: *const abi::Facts,
    ) -> *mut c_void;
}
