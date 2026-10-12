//! IPv4 configuration kept while the first INIT-REBOOT is being answered.

use std::net::{IpAddr, Ipv4Addr};

use crate::model::{Observed, RTPROT_NETD, Route};
use crate::reconcile::Desired;

/// Existing kernel state, not a confirmed DHCP lease or a source of timers.
pub struct Ipv4 {
    addresses: Vec<(Ipv4Addr, u8)>,
    routes: Vec<Route>,
}

impl Ipv4 {
    pub fn capture(observed: &Observed, index: u32, requested: Option<Ipv4Addr>) -> Option<Self> {
        let requested = requested?;
        let addresses: Vec<_> = observed
            .addresses_of(index)
            .filter(|a| a.address == IpAddr::V4(requested))
            .map(|a| (requested, a.prefix))
            .collect();
        if addresses.is_empty() {
            return None;
        }
        let routes = observed
            .routes_of(index)
            .filter(|r| r.is_v4() && r.protocol == RTPROT_NETD)
            .cloned()
            .collect();
        Some(Self { addresses, routes })
    }

    pub fn preserve(&self, desired: &mut Desired, offered_routes: bool, metric: u32) {
        desired.addresses.extend(self.addresses.iter().copied());
        if !offered_routes {
            return;
        }
        for route in &self.routes {
            let (IpAddr::V4(destination), Some(IpAddr::V4(gateway))) =
                (route.destination, route.gateway)
            else {
                continue;
            };
            if route.is_default() {
                // An explicit profile gateway takes precedence immediately.
                desired.default_route.get_or_insert((gateway, metric));
            } else {
                desired
                    .routes
                    .push((destination, route.prefix, gateway, metric));
            }
        }
    }
}
