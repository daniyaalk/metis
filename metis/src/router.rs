use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeType};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Maps `(ProbeType, Option<port>)` to module indices.
///
/// `None` port means the module registered for all ports on that probe type.
/// `Some(port)` means the module registered for that specific port only.
///
/// On dispatch, a module receives an event at most once even if it matches on
/// both a wildcard registration and a port-specific one.
pub struct RouteTable {
    modules: Vec<Arc<Mutex<dyn Module>>>,
    routes: HashMap<(ProbeType, Option<u16>), Vec<usize>>,
}

impl RouteTable {
    pub fn new(modules: Vec<Arc<Mutex<dyn Module>>>) -> Self {
        Self {
            modules,
            routes: HashMap::new(),
        }
    }

    pub fn register(&mut self, probe_type: ProbeType, port: Option<u16>, module_idx: usize) {
        self.routes
            .entry((probe_type, port))
            .or_default()
            .push(module_idx);
    }

    /// Dispatches `event` to every module whose registration matches its probe
    /// type and port. Each matching module is called exactly once.
    pub fn dispatch(&self, event: &ProbeEvent) {
        let probe_type = event.probe_type();
        let port = event.dest_port();
        let mut dispatched = HashSet::new();

        if let Some(idxs) = self.routes.get(&(probe_type, None)) {
            for &idx in idxs {
                if dispatched.insert(idx) {
                    self.modules[idx].lock().unwrap().on_event(event);
                }
            }
        }

        if let Some(port) = port {
            if let Some(idxs) = self.routes.get(&(probe_type, Some(port))) {
                for &idx in idxs {
                    if dispatched.insert(idx) {
                        self.modules[idx].lock().unwrap().on_event(event);
                    }
                }
            }
        }
    }
}
