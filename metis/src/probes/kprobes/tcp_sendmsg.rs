use crate::probes::Probe;
use aya::Ebpf;
use aya::programs::KProbe;

pub struct TCPSendMsgProbe {
    dest_ports: Vec<u16>,
}

impl TCPSendMsgProbe {
    pub fn new(dest_ports: Vec<u16>) -> Self {
        Self { dest_ports }
    }
}

impl Probe for TCPSendMsgProbe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()> {
        let mut map =
            aya::maps::HashMap::<_, u16, u8>::try_from(ebpf.map_mut("TCP_SENDMSG_PORTS").unwrap())
                .or(Err(()))?;

        for port in &self.dest_ports {
            map.insert(*port, 1, 0).or(Err(()))?;
        }

        let program = ebpf.program_mut("tcp_sendmsg").unwrap();
        let program: &mut KProbe = program.try_into().unwrap();
        program.load().or(Err(()))?;
        program.attach("tcp_sendmsg", 0).or(Err(()))?;

        Ok(())
    }
}
