use crate::probes::ProbeEvent;
use metis_common::KProbeChunk;
use std::collections::HashMap;

struct AssemblyBuffer {
    dest_port: u16,
    data: Vec<u8>,
}

/// Reassembles chunked kprobe payloads into complete `ProbeEvent`s.
///
/// Each instance is single-threaded and lives inside the event-loop task for
/// one kprobe ring buffer, so no locking is needed.
pub struct KProbeAssembler {
    sessions: HashMap<u64, AssemblyBuffer>,
}

impl KProbeAssembler {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Feed one chunk in. Returns a complete `ProbeEvent` once the final chunk
    /// for a session arrives; returns `None` for intermediate chunks.
    pub fn ingest(&mut self, chunk: &KProbeChunk) -> Option<ProbeEvent> {
        let session = self
            .sessions
            .entry(chunk.session_id)
            .or_insert_with(|| AssemblyBuffer {
                dest_port: chunk.dest_port,
                data: Vec::new(),
            });

        let len = chunk.len as usize;
        if len > 0 {
            session.data.extend_from_slice(&chunk.data[..len]);
        }

        if chunk.complete {
            let buf = self.sessions.remove(&chunk.session_id)?;
            Some(ProbeEvent::TcpSendMsg {
                dest_port: buf.dest_port,
                payload: buf.data,
            })
        } else {
            None
        }
    }
}
