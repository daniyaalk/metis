use crate::modules::Module;
use crate::probes::kprobes::sock_def_readable::SockDefReadableProbe;
use crate::probes::kprobes::tcp_sendmsg::TcpSendMsgProbe;
use crate::probes::tracepoints::tcp_probe::TcpProbe;
use crate::probes::tracepoints::tcp_receive_reset::TcpReceiveReset;
use crate::probes::tracepoints::tcp_retransmit_skb::TcpRetransmitSkb;
use crate::probes::tracepoints::tcp_send_reset::TcpSendReset;
use crate::probes::{ProbeRequirement, ProbeType};
use crate::router::RouteTable;
use aya::Ebpf;
use std::sync::{Arc, Mutex};

pub struct Orchestrator {
    modules: Vec<Arc<Mutex<dyn Module>>>,
    /// Percentage of tcp_sendmsg events to capture (0.0–100.0). Shared by all modules.
    tcp_sendmsg_sample_rate: f32,
}

impl Orchestrator {
    pub fn new(modules: Vec<Arc<Mutex<dyn Module>>>, tcp_sendmsg_sample_rate: f32) -> Self {
        Self { modules, tcp_sendmsg_sample_rate }
    }

    /// Builds the routing table, merges port configs, loads every required
    /// eBPF program exactly once, and spawns all event-loop tasks.
    pub async fn run(self, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        let (route_table, merged) = self.build(&self.modules);
        let rt = Arc::new(route_table);

        if merged.tcp_probe {
            let rt = rt.clone();
            TcpProbe.attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        if merged.tcp_send_reset {
            let rt = rt.clone();
            TcpSendReset.attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        if let Some(cfg) = merged.tcp_retransmit_skb {
            let rt = rt.clone();
            TcpRetransmitSkb::new(cfg.to_bpf_ports()).attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        if let Some(cfg) = merged.tcp_receive_reset {
            let rt = rt.clone();
            TcpReceiveReset::new(cfg.to_bpf_ports()).attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        if let Some(cfg) = merged.tcp_send_msg {
            let rt = rt.clone();
            TcpSendMsgProbe::new(cfg.to_bpf_ports(), self.tcp_sendmsg_sample_rate)
                .attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        if merged.sock_def_readable {
            let rt = rt.clone();
            SockDefReadableProbe.attach(ebpf, move |e| rt.dispatch(&e))?;
        }

        Ok(())
    }

    fn build(&self, modules: &[Arc<Mutex<dyn Module>>]) -> (RouteTable, MergedConfigs) {
        let mut table = RouteTable::new(modules.to_vec());
        let mut cfg = MergedConfigs::default();

        for (idx, module) in modules.iter().enumerate() {
            for req in module.lock().unwrap().required_probes() {
                match req {
                    ProbeRequirement::TcpProbe { dest_ports } => {
                        cfg.tcp_probe = true;
                        register_ports(&mut table, ProbeType::TcpProbe, dest_ports, idx);
                    }
                    ProbeRequirement::TcpSendReset { dest_ports } => {
                        cfg.tcp_send_reset = true;
                        register_ports(&mut table, ProbeType::TcpSendReset, dest_ports, idx);
                    }
                    ProbeRequirement::TcpRetransmitSkb { dest_ports } => {
                        absorb(&mut cfg.tcp_retransmit_skb, dest_ports.clone());
                        register_ports(&mut table, ProbeType::TcpRetransmitSkb, dest_ports, idx);
                    }
                    ProbeRequirement::TcpReceiveReset { dest_ports } => {
                        absorb(&mut cfg.tcp_receive_reset, dest_ports.clone());
                        register_ports(&mut table, ProbeType::TcpReceiveReset, dest_ports, idx);
                    }
                    ProbeRequirement::TcpSendMsg { dest_ports } => {
                        absorb(&mut cfg.tcp_send_msg, dest_ports.clone());
                        register_ports(&mut table, ProbeType::TcpSendMsg, dest_ports, idx);
                    }
                    ProbeRequirement::SockDefReadable { dest_ports } => {
                        cfg.sock_def_readable = true;
                        register_ports(&mut table, ProbeType::SockDefReadable, dest_ports, idx);
                    }
                }
            }
        }

        (table, cfg)
    }
}

// ── Port configuration ────────────────────────────────────────────────────────

/// Merged port set for a single port-filtered probe.
enum PortConfig {
    /// At least one module requested all ports; insert key `0` as sentinel.
    All,
    /// Union of all explicitly requested port lists.
    Specific(Vec<u16>),
}

impl PortConfig {
    fn to_bpf_ports(&self) -> Vec<u16> {
        match self {
            PortConfig::All => vec![0],
            PortConfig::Specific(ports) => ports.clone(),
        }
    }
}

#[derive(Default)]
struct MergedConfigs {
    tcp_probe: bool,
    tcp_send_reset: bool,
    tcp_retransmit_skb: Option<PortConfig>,
    tcp_receive_reset: Option<PortConfig>,
    tcp_send_msg: Option<PortConfig>,
    sock_def_readable: bool,
}

/// Merges `incoming` (from one module's `ProbeRequirement`) into `existing`.
/// `None` incoming means "all ports" (no kernel-side filter).
fn absorb(existing: &mut Option<PortConfig>, incoming: Option<Vec<u16>>) {
    *existing = Some(match (existing.take(), incoming) {
        // First module requesting this probe
        (None, None) => PortConfig::All,
        (None, Some(ports)) => PortConfig::Specific(ports),
        // Already "all ports" — stays that way regardless
        (Some(PortConfig::All), _) => PortConfig::All,
        // Existing specific set but new module wants all ports
        (Some(PortConfig::Specific(_)), None) => PortConfig::All,
        // Merge two specific port sets
        (Some(PortConfig::Specific(mut existing_ports)), Some(new_ports)) => {
            existing_ports.extend(new_ports);
            existing_ports.sort_unstable();
            existing_ports.dedup();
            PortConfig::Specific(existing_ports)
        }
    });
}

fn register_ports(
    table: &mut RouteTable,
    probe_type: ProbeType,
    dest_ports: Option<Vec<u16>>,
    module_idx: usize,
) {
    match dest_ports {
        None => table.register(probe_type, None, module_idx),
        Some(ports) => {
            for port in ports {
                table.register(probe_type, Some(port), module_idx);
            }
        }
    }
}
