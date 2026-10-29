//! Safe Rust access to libnetd.so. Owned return values outlive the C result;
//! policy and subscription handles release themselves on drop.

use std::ffi::c_void;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::Duration;

use netd_abi as abi;

pub use netd_core::{DnsScope, InterfaceStatus, LeaseStatus, Level, Snapshot, Status};
pub use netd_core::profile::{AddressConfig, DnsConfig, OnExpiry, Profile, StaticAddress};
pub use netd_core::raw::{RawKey, RawValue};
pub use netd_core::hostname::{HOSTNAME_VALUE, MAX as HOSTNAME_MAX};
pub use netd_core::{CONTROL_SOCKET_PATH, NETWORK_KEY};

mod decode;
mod encode;
mod ffi;

/// A POSIX error code and diagnostic returned by libnetd. Diagnostics are for
/// people; their wording is not a stable interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(out)
    }
}
impl std::error::Error for Error {}

pub(crate) fn invalid(message: &str) -> Error {
    Error {
        code: libc::EINVAL,
        message: message.into(),
    }
}

pub(crate) fn span(value: &[u8]) -> abi::Bytes {
    abi::Bytes {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn timeout_ms(timeout: Duration) -> Result<u64, Error> {
    if timeout.is_zero() {
        return Err(invalid("timeout must be positive"));
    }
    let milliseconds = timeout.as_nanos().div_ceil(1_000_000);
    u64::try_from(milliseconds).map_err(|_| invalid("timeout is too large"))
}

pub(crate) struct OwnedResult(NonNull<c_void>);

impl OwnedResult {
    /// Caller must transfer a result pointer returned by this loaded libnetd.
    unsafe fn take(pointer: *mut c_void) -> Result<Self, Error> {
        let result = Self(NonNull::new(pointer).ok_or_else(|| invalid("libnetd returned null"))?);
        // SAFETY: result uniquely owns a live library allocation for these calls.
        let code = unsafe { ffi::peios_netd_result_error(result.0.as_ptr()) };
        if code != 0 {
            // SAFETY: the diagnostic remains borrowed from result until copied.
            let message =
                unsafe { decode::text(ffi::peios_netd_result_message(result.0.as_ptr())) };
            return Err(Error { code, message });
        }
        Ok(result)
    }
}

impl Drop for OwnedResult {
    fn drop(&mut self) {
        // SAFETY: this owner releases its live result exactly once after all
        // wrapper borrows finish; returned public values contain owned copies.
        unsafe { ffi::peios_netd_result_free(self.0.as_ptr()) };
    }
}

/// Connection settings. Each operation opens its own connection. No daemon or
/// registry state changes until an operation is requested.
#[derive(Clone, Debug)]
pub struct Client {
    path: PathBuf,
    timeout_ms: u64,
}

impl Client {
    /// Select a filesystem socket and a total deadline for each operation.
    pub fn new(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, Error> {
        let path = path.as_ref();
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
            return Err(invalid("invalid Unix socket path"));
        }
        Ok(Self {
            path: path.into(),
            timeout_ms: timeout_ms(timeout)?,
        })
    }

    /// Use the installed daemon's control socket with an explicit timeout.
    pub fn system(timeout: Duration) -> Result<Self, Error> {
        Self::new(CONTROL_SOCKET_PATH, timeout)
    }

    /// Read current hostname, readiness and interface state.
    pub fn status(&self) -> Result<Status, Error> {
        // SAFETY: spans borrow self during the synchronous call; take owns its result.
        let result =
            unsafe { OwnedResult::take(ffi::peios_netd_get_status(self.path(), self.timeout_ms))? };
        // SAFETY: libnetd returned a successful status result, live during decoding.
        unsafe { decode::status(ffi::peios_netd_result_status(result.0.as_ptr())) }
    }

    /// Request DHCP renewal. A transport error can leave the outcome unknown;
    /// this wrapper never automatically replays the command.
    pub fn renew(&self, interface: &str) -> Result<(), Error> {
        // SAFETY: both spans are borrowed for the call; take owns the returned result.
        unsafe {
            OwnedResult::take(ffi::peios_netd_renew(
                self.path(),
                self.timeout_ms,
                span(interface.as_bytes()),
            ))?
        };
        Ok(())
    }

    /// Request reconciliation, with the same uncertain-outcome rule as renew.
    pub fn reconcile(&self) -> Result<(), Error> {
        // SAFETY: path is live for the call; take owns the returned result.
        unsafe { OwnedResult::take(ffi::peios_netd_reconcile(self.path(), self.timeout_ms))? };
        Ok(())
    }

    /// Subscribe to complete DNS snapshots. The first next_snapshot call reads
    /// the initial snapshot or reports the daemon's access refusal.
    pub fn subscribe(&self) -> Result<Subscription, Error> {
        let mut subscription = ptr::null_mut();
        // SAFETY: path is borrowed and subscription is an exclusive writable slot.
        unsafe {
            OwnedResult::take(ffi::peios_netd_subscribe(
                self.path(),
                self.timeout_ms,
                &mut subscription,
            ))?
        };
        let handle = NonNull::new(subscription).ok_or_else(|| invalid("missing subscription"))?;
        Ok(Subscription(handle))
    }

    fn path(&self) -> abi::Bytes {
        span(self.path.as_os_str().as_bytes())
    }
}

/// One ordered DNS stream. Exclusive access prevents overlapping reads. Timeout
/// preserves partial input; other receive errors close the underlying stream.
pub struct Subscription(NonNull<c_void>);

impl Subscription {
    /// Read the next complete snapshot, waiting at most timeout in total.
    pub fn next_snapshot(&mut self, timeout: Duration) -> Result<Snapshot, Error> {
        let timeout_ms = timeout_ms(timeout)?;
        // SAFETY: &mut self grants exclusive access to the live subscription.
        let result = unsafe {
            OwnedResult::take(ffi::peios_netd_subscription_next(
                self.0.as_ptr(),
                timeout_ms,
            ))?
        };
        // SAFETY: the snapshot view belongs to the live successful result.
        unsafe { decode::snapshot(ffi::peios_netd_result_snapshot(result.0.as_ptr())) }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: this unique owner closes the subscription exactly once.
        unsafe { ffi::peios_netd_subscription_free(self.0.as_ptr()) };
    }
}

/// Validate a hostname and return its trimmed form, using the daemon's rules.
pub fn check_hostname(name: &str) -> Result<String, Error> {
    // SAFETY: name is readable throughout the call and take assumes result ownership.
    let result =
        unsafe { OwnedResult::take(ffi::peios_netd_hostname_check(span(name.as_bytes())))? };
    // SAFETY: the normalized text is borrowed from result until copied here.
    Ok(unsafe { decode::text(ffi::peios_netd_result_text(result.0.as_ptr())) })
}

/// Owned facts for a policy preview. None means absent, distinct from an empty
/// string. MAC addresses use their six binary octets.
#[derive(Clone, Debug, Default)]
pub struct InterfaceFacts {
    pub interface: Option<String>,
    pub interface_kind: Option<String>,
    pub interface_id: Option<String>,
    pub interface_mac: Option<[u8; 6]>,
    pub interface_path: Option<String>,
    pub interface_driver: Option<String>,
    pub network_id: Option<String>,
    pub network_name: Option<String>,
    pub network_trust: Option<String>,
    pub network_kind: Option<String>,
}

/// The configured action for an interface after policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ignore,
    Down,
    Join(Profile),
}

/// The outcome and its rule attribution, including policy ties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub outcome: Outcome,
    pub rule: String,
    pub backstop: bool,
    pub conflict: bool,
}

/// Validated interface rules and resolved profiles, owned by libnetd.
pub struct Policy(OwnedResult);

impl Policy {
    /// Validate registry-shaped trees without reading or writing the registry.
    /// Limits: 128 key levels, 65536 items, 4 MiB text across both trees.
    pub fn build(rules: Option<&RawKey>, profiles: Option<&RawKey>) -> Result<Self, Error> {
        let mut input = encode::Input::default();
        let rules = input.tree(rules)?;
        let profiles = input.tree(profiles)?;
        // SAFETY: input owns every array and borrows all source strings for this
        // call. Both source trees remain alive until after the library copies them.
        unsafe { OwnedResult::take(ffi::peios_netd_policy_build(rules, profiles)) }.map(Self)
    }

    /// Resolve profile inheritance without interface rules.
    pub fn resolve_profiles(profiles: &RawKey) -> Result<Self, Error> {
        Self::build(None, Some(profiles))
    }

    /// Return resolved profiles in case-folded path order.
    pub fn profiles(&self) -> Result<Vec<Profile>, Error> {
        // SAFETY: the policy result remains live for the count and each projection.
        let count = unsafe { ffi::peios_netd_policy_profile_count(self.0.0.as_ptr()) };
        (0..count)
            .map(|index| {
                // SAFETY: the checked index selects a borrowed view in this live policy.
                unsafe { decode::profile(ffi::peios_netd_policy_profile(self.0.0.as_ptr(), index)) }
            })
            .collect()
    }

    /// Copy nonfatal diagnostics from the validated policy.
    pub fn lints(&self) -> Vec<String> {
        // SAFETY: all projected strings remain live while this policy is borrowed.
        unsafe { decode::strings(ffi::peios_netd_policy_lints(self.0.0.as_ptr())) }
    }

    /// Preview one interface without changing configuration or network state.
    pub fn judge(&self, facts: &InterfaceFacts) -> Result<Judgment, Error> {
        let view = encode::facts(facts);
        // SAFETY: policy, facts and all of view's borrowed strings are live here.
        let result =
            unsafe { OwnedResult::take(ffi::peios_netd_policy_judge(self.0.0.as_ptr(), &view))? };
        // SAFETY: the projected judgment is borrowed from the successful live result.
        unsafe { decode::judgment(ffi::peios_netd_result_judgment(result.0.as_ptr())) }
    }
}
