//! Shared networking API. See peios/netd.h for the C ownership contract.
//!
//! # Safety
//! Non-null pointers passed to exported functions must be live, correctly
//! aligned, and valid for the stated lengths. Input spans are borrowed only
//! during calls. Handles must come from this library and remain alive; mutation
//! and destruction require exclusive access. Immutable results may be read
//! concurrently. Every returned view is borrowed from its result handle.

use std::io;
use std::ptr;

use netd_abi as abi;
use netd_core::{Reply, Request};
use netd_core::policy::{self, Outcome};

mod channel;
mod inputs;
mod views;

use channel::{Channel, deadline, invalid};
use views::Arena;

enum Payload {
    Empty,
    Text(abi::Bytes),
    Status {
        view: abi::Status,
        _interfaces: Vec<abi::Interface>,
    },
    Snapshot {
        view: abi::Snapshot,
        _scopes: Vec<abi::DnsScope>,
    },
    Policy {
        policy: Box<policy::Policy>,
        profiles: Vec<abi::Profile>,
        lints: abi::Strings,
    },
    Judgment {
        view: abi::Judgment,
        _profile: Option<Box<abi::Profile>>,
    },
}

/// An owned result. Its contents and all borrowed views are immutable.
pub struct ResultHandle {
    error_code: i32,
    message: abi::Bytes,
    arena: Arena,
    payload: Payload,
}

/// One DNS subscription. Calls require exclusive access to preserve framing.
pub struct Subscription {
    channel: Option<Channel>,
}

impl Default for ResultHandle {
    fn default() -> Self {
        Self {
            error_code: 0,
            message: views::absent(),
            arena: Arena::default(),
            payload: Payload::Empty,
        }
    }
}

impl ResultHandle {
    fn error(error: io::Error) -> Self {
        let mut result = Self::default();
        result.error_code = error.raw_os_error().unwrap_or(match error.kind() {
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => libc::EINVAL,
            io::ErrorKind::TimedOut => libc::ETIMEDOUT,
            io::ErrorKind::PermissionDenied => libc::EACCES,
            io::ErrorKind::NotConnected => libc::ENOTCONN,
            _ => libc::EIO,
        });
        result.message = result.arena.text(error.to_string());
        result
    }

    fn reply(reply: Reply) -> io::Result<Self> {
        let mut result = Self::default();
        result.payload = match reply {
            Reply::Ok => Payload::Empty,
            Reply::Error(message) => return Err(io::Error::other(message)),
            Reply::Status(status) => {
                let interfaces: Vec<_> = status
                    .interfaces
                    .iter()
                    .map(|value| result.arena.interface(value))
                    .collect();
                let view = abi::Status {
                    hostname: result.arena.text(&status.hostname),
                    level: views::level(status.level),
                    refusal: result.arena.maybe_text(status.refusal.as_deref()),
                    interfaces: interfaces.as_ptr(),
                    interface_count: interfaces.len(),
                };
                Payload::Status {
                    view,
                    _interfaces: interfaces,
                }
            }
            Reply::Snapshot(snapshot) => {
                let scopes: Vec<_> = snapshot
                    .scopes
                    .iter()
                    .map(|value| result.arena.scope(value))
                    .collect();
                let view = abi::Snapshot {
                    hostname: result.arena.text(&snapshot.hostname),
                    scopes: scopes.as_ptr(),
                    scope_count: scopes.len(),
                };
                Payload::Snapshot {
                    view,
                    _scopes: scopes,
                }
            }
        };
        Ok(result)
    }
}

fn finish(result: io::Result<ResultHandle>) -> *mut ResultHandle {
    Box::into_raw(Box::new(result.unwrap_or_else(ResultHandle::error)))
}

fn exchange(path: &[u8], timeout_ms: u64, request: Request) -> io::Result<ResultHandle> {
    let end = deadline(timeout_ms)?;
    let mut channel = Channel::connect(path, end)?;
    channel.send(&request, end)?;
    let reply = channel.receive(end)?;
    let expected = matches!(
        (&request, &reply),
        (_, Reply::Error(_))
            | (Request::Status, Reply::Status(_))
            | (Request::Renew { .. } | Request::Reconcile, Reply::Ok)
    );
    if !expected {
        return Err(invalid("unexpected netd reply type"));
    }
    ResultHandle::reply(reply)
}

/// Return the C ABI major version, independent of the component version.
#[unsafe(no_mangle)]
pub extern "C" fn peios_netd_abi_version() -> u32 {
    1
}

/// Release a result and all its borrowed views; null is accepted.
/// # Safety
/// The handle must be null or a live, exclusively owned result from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_result_free(result: *mut ResultHandle) {
    if !result.is_null() {
        // SAFETY: the caller transfers its unique live result allocation back.
        drop(unsafe { Box::from_raw(result) });
    }
}

/// Zero means success; otherwise return a POSIX error number. Null is EINVAL.
/// # Safety
/// A non-null handle must be a live result borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_result_error(result: *const ResultHandle) -> i32 {
    // SAFETY: the caller supplies a live result or null.
    unsafe { result.as_ref() }.map_or(libc::EINVAL, |result| result.error_code)
}

/// Return the diagnostic text borrowed from result; null yields an absent span.
/// # Safety
/// A non-null handle must be a live result borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_result_message(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: the caller supplies a live result or null.
    unsafe { result.as_ref() }.map_or_else(views::absent, |result| result.message)
}

/// Query the complete status. The timeout covers connection, send and receive.
/// # Safety
/// The socket path span must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_get_status(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    // SAFETY: path is borrowed under the exported span contract.
    finish(
        unsafe { inputs::bytes(path) }.and_then(|path| exchange(path, timeout_ms, Request::Status)),
    )
}

/// Request renewal. On I/O failure the command may already have been applied;
/// callers must not automatically replay it.
/// # Safety
/// Both spans must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_renew(
    path: abi::Bytes,
    timeout_ms: u64,
    interface: abi::Bytes,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees both spans remain readable for this call.
        let (path, interface) = unsafe { (inputs::bytes(path)?, inputs::text(interface)?) };
        exchange(
            path,
            timeout_ms,
            Request::Renew {
                interface: interface.into(),
            },
        )
    })())
}

/// Request reconciliation, with the same uncertain-outcome rule as renewal.
/// # Safety
/// The socket path span must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_reconcile(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    // SAFETY: path is borrowed under the exported span contract.
    finish(
        unsafe { inputs::bytes(path) }
            .and_then(|path| exchange(path, timeout_ms, Request::Reconcile)),
    )
}

/// Open a subscription and send its request. Receive the initial snapshot with
/// subscription_next; an access refusal is reported there. out is cleared first.
/// # Safety
/// path must be readable; out must be a live writable, nonaliased pointer slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_subscribe(
    path: abi::Bytes,
    timeout_ms: u64,
    out: *mut *mut Subscription,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees exclusive access to a valid output slot.
        let output = unsafe { out.as_mut() }.ok_or_else(|| invalid("null subscription output"))?;
        *output = ptr::null_mut();
        let end = deadline(timeout_ms)?;
        // SAFETY: the borrowed path span is readable for the duration of the call.
        let mut channel = Channel::connect(unsafe { inputs::bytes(path)? }, end)?;
        channel.send(&Request::Subscribe, end)?;
        *output = Box::into_raw(Box::new(Subscription {
            channel: Some(channel),
        }));
        Ok(ResultHandle::default())
    })())
}

/// Read one DNS snapshot. Timeout retains partial framing for the next call;
/// all other receive failures close the channel and make it unusable.
/// # Safety
/// The subscription must be a live handle exclusively borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_subscription_next(
    subscription: *mut Subscription,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        let end = deadline(timeout_ms)?;
        // SAFETY: the caller grants exclusive access to its live subscription.
        let subscription =
            unsafe { subscription.as_mut() }.ok_or_else(|| invalid("null subscription"))?;
        let channel = subscription
            .channel
            .as_mut()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTCONN))?;
        let reply = channel.receive(end).and_then(|reply| match reply {
            Reply::Snapshot(_) => Ok(reply),
            Reply::Error(message) => Err(io::Error::other(message)),
            _ => Err(invalid("expected DNS snapshot")),
        });
        if let Err(error) = &reply
            && error.kind() != io::ErrorKind::TimedOut
        {
            subscription.channel = None;
        }
        ResultHandle::reply(reply?)
    })())
}

/// Close a subscription; null is accepted.
/// # Safety
/// The handle must be null or a live, exclusively owned subscription.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_subscription_free(subscription: *mut Subscription) {
    if !subscription.is_null() {
        // SAFETY: the caller transfers unique ownership of the live allocation.
        drop(unsafe { Box::from_raw(subscription) });
    }
}

/// Validate and trim a hostname; obtain the normalized name with result_text.
/// # Safety
/// name must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_hostname_check(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller supplies a readable borrowed UTF-8 span.
        let name = netd_core::hostname::check(unsafe { inputs::text(name)? }).map_err(invalid)?;
        let mut result = ResultHandle::default();
        result.payload = Payload::Text(result.arena.text(name));
        Ok(result)
    })())
}

/// Validate profiles and interface rules together. Null denotes an absent tree.
/// Inputs are copied; result remains independent of the source trees.
/// # Safety
/// Every reachable key, value and span must remain live and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_policy_build(
    rules: *const abi::Key,
    profiles: *const abi::Key,
) -> *mut ResultHandle {
    finish((|| {
        let mut budget = inputs::Budget::default();
        // SAFETY: the caller guarantees validity of the complete borrowed trees.
        let (rules, profiles) = unsafe { (budget.key(rules, 0)?, budget.key(profiles, 0)?) };
        let policy = policy::build(rules.as_ref(), profiles.as_ref()).map_err(invalid)?;
        let mut result = ResultHandle::default();
        let profiles = policy
            .profiles
            .values()
            .map(|profile| result.arena.profile(profile))
            .collect();
        let lints = result.arena.strings(&policy.lints);
        result.payload = Payload::Policy {
            policy: Box::new(policy),
            profiles,
            lints,
        };
        Ok(result)
    })())
}

/// Resolve profile inheritance without interface rules; result is a policy view.
/// # Safety
/// profiles has the same borrowed-tree contract as policy_build.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_profiles_resolve(
    profiles: *const abi::Key,
) -> *mut ResultHandle {
    // SAFETY: forwarded unchanged to the shared configuration boundary.
    unsafe { peios_netd_policy_build(ptr::null(), profiles) }
}

/// Judge interface/network facts against a validated policy.
/// # Safety
/// policy must be a live immutable result; facts and its spans must be readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_policy_judge(
    policy: *const ResultHandle,
    facts: *const abi::Facts,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: both references are borrowed under the exported contract.
        let policy = unsafe { policy.as_ref() }.ok_or_else(|| invalid("null policy"))?;
        let Payload::Policy { policy, .. } = &policy.payload else {
            return Err(invalid("not a policy result"));
        };
        // SAFETY: facts and its spans are live for this call.
        let snapshot = unsafe { inputs::facts(facts)? };
        let judgment = policy.judge(&snapshot);
        let mut result = ResultHandle::default();
        let profile = judgment
            .outcome
            .profile()
            .map(|profile| Box::new(result.arena.profile(profile)));
        let view = abi::Judgment {
            outcome: match judgment.outcome {
                Outcome::Ignore => 0,
                Outcome::Down => 1,
                Outcome::Join(_) => 2,
            },
            rule: result.arena.text(judgment.rule),
            backstop: u32::from(judgment.backstop),
            conflict: u32::from(judgment.conflict),
            profile: profile.as_deref().map_or(ptr::null(), ptr::from_ref),
        };
        result.payload = Payload::Judgment {
            view,
            _profile: profile,
        };
        Ok(result)
    })())
}

macro_rules! view_getter {
    ($name:ident, $variant:ident, $view:ty) => {
        /// Return a borrowed view, or null for an error, null handle or wrong kind.
        /// # Safety
        /// Non-null result must remain live while this view or its fields are used.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(result: *const ResultHandle) -> *const $view {
            // SAFETY: the caller supplies a live borrowed result or null.
            match unsafe { result.as_ref() }.map(|result| &result.payload) {
                Some(Payload::$variant { view, .. }) => view,
                _ => ptr::null(),
            }
        }
    };
}

view_getter!(peios_netd_result_status, Status, abi::Status);
view_getter!(peios_netd_result_snapshot, Snapshot, abi::Snapshot);
view_getter!(peios_netd_result_judgment, Judgment, abi::Judgment);

/// Return a normalized hostname, or an absent span for other result kinds.
/// # Safety
/// A non-null result must remain live while the returned view is used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_result_text(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: the caller supplies a live borrowed result or null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Text(text)) => *text,
        _ => views::absent(),
    }
}

/// Count resolved profiles; invalid or other-kind results have zero profiles.
/// # Safety
/// A non-null result must be live and borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_policy_profile_count(result: *const ResultHandle) -> usize {
    // SAFETY: the caller supplies a live borrowed result or null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Policy { profiles, .. }) => profiles.len(),
        _ => 0,
    }
}

/// Return a profile in case-folded path order; out-of-range returns null.
/// # Safety
/// A non-null result must remain live while the returned view is used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_policy_profile(
    result: *const ResultHandle,
    index: usize,
) -> *const abi::Profile {
    // SAFETY: the caller supplies a live borrowed result or null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Policy { profiles, .. }) => {
            profiles.get(index).map_or(ptr::null(), ptr::from_ref)
        }
        _ => ptr::null(),
    }
}

/// Return policy lint messages, borrowed from result; other kinds return empty.
/// # Safety
/// A non-null result must remain live while the returned views are used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_netd_policy_lints(result: *const ResultHandle) -> abi::Strings {
    // SAFETY: the caller supplies a live borrowed result or null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Policy { lints, .. }) => *lints,
        _ => abi::Strings {
            data: ptr::null(),
            len: 0,
        },
    }
}
