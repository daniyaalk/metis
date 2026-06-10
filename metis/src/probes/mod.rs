use aya::Ebpf;

pub mod kprobes;

#[derive(Hash, Eq, PartialEq, Clone)]
pub enum ProbeRequirement {
    TcpSendMsg {
        dest_ports: Vec<u16>,
    },

    TcpRecvMsg,

    MysqlQuery,
}


pub trait Probe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()>;
}