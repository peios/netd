//! Checked wait deadlines shared by the readiness and policy commands.

use std::time::{Duration, Instant};

pub(super) fn after(timeout: Duration) -> Result<Instant, &'static str> {
    Instant::now()
        .checked_add(timeout)
        .ok_or("timeout is too large")
}

/// Bound one request or polling pause by the remaining overall wait budget.
pub(super) fn budget(deadline: Instant, now: Instant, limit: Duration) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .map(|left| left.min(limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrepresentable_wait_returns_an_error_instead_of_panicking() {
        assert!(after(Duration::from_secs(u64::MAX)).is_err());
    }

    #[test]
    fn slow_requests_and_polling_cannot_extend_the_wait_budget() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(2);
        assert_eq!(
            budget(deadline, start, Duration::from_secs(5)),
            Some(Duration::from_secs(2))
        );
        // A response consumed most of the budget; neither the normal poll delay
        // nor the next request may allocate time beyond the original deadline.
        let after_response = start + Duration::from_millis(1850);
        assert_eq!(
            budget(deadline, after_response, Duration::from_millis(500)),
            Some(Duration::from_millis(150))
        );
        assert_eq!(
            budget(deadline, after_response, Duration::from_secs(5)),
            Some(Duration::from_millis(150))
        );
        assert_eq!(budget(deadline, deadline, Duration::from_secs(5)), None);
        assert_eq!(
            budget(
                deadline,
                deadline + Duration::from_millis(1),
                Duration::from_secs(5)
            ),
            None
        );
    }
}
