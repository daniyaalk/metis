use crate::probes::ProbeEvent;
use metis_common::KProbeChunk;
use std::collections::HashMap;

struct AssemblyBuffer {
    dest_ip: [u8; 16],
    ip_family: u8,
    dest_port: u16,
    socket_ptr: u64,
    timestamp_ns: u64,
    data: Vec<u8>,
}

/// Reassembles chunked kprobe payloads into complete `ProbeEvent`s.
pub struct KProbeAssembler {
    sessions: HashMap<u64, AssemblyBuffer>,
}

impl KProbeAssembler {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, chunk: &KProbeChunk) -> Option<ProbeEvent> {
        let session = self
            .sessions
            .entry(chunk.socket_ptr)
            .or_insert_with(|| AssemblyBuffer {
                dest_ip: chunk.dest_ip,
                ip_family: chunk.ip_family,
                dest_port: chunk.dest_port,
                socket_ptr: chunk.socket_ptr,
                timestamp_ns: chunk.timestamp_ns,
                data: Vec::new(),
            });

        let len = chunk.len as usize;
        if len > 0 {
            session.data.extend_from_slice(&chunk.data[..len]);
        }

        if chunk.complete {
            let buf = self.sessions.remove(&chunk.socket_ptr)?;
            Some(ProbeEvent::TcpSendMsg {
                dest_ip: buf.dest_ip,
                ip_family: buf.ip_family,
                dest_port: buf.dest_port,
                socket_ptr: buf.socket_ptr,
                timestamp_ns: buf.timestamp_ns,
                payload: buf.data,
            })
        } else {
            None
        }
    }
}
