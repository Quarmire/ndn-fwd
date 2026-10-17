//! A tiny UDP forwarding shim between two daemons that can flip one byte of
//! every packet travelling back toward the consumer side: a man in the middle
//! that tampers with Data in transit.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Shim {
    pub flip: Arc<AtomicBool>,
    pub flipped: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Shim {
    /// Listen on `at`; datagrams from `consumer` go to `producer` untouched,
    /// datagrams from `producer` go back to `consumer`, with the last byte
    /// flipped while `flip` is set (for packets large enough to carry Data:
    /// the last byte of an NDNLPv2 packet whose fragment is a Data is in its
    /// SignatureValue).
    pub fn start(at: SocketAddr, consumer: SocketAddr, producer: SocketAddr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind(at)?;
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let flip = Arc::new(AtomicBool::new(false));
        let flipped = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (f, n, s) = (flip.clone(), flipped.clone(), stop.clone());
        let thread = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !s.load(Ordering::Relaxed) {
                let Ok((len, from)) = sock.recv_from(&mut buf) else { continue };
                let pkt = &mut buf[..len];
                if from == consumer {
                    let _ = sock.send_to(pkt, producer);
                } else if from == producer {
                    if f.load(Ordering::Relaxed) && len > 200 {
                        pkt[len - 1] ^= 0xff;
                        n.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = sock.send_to(pkt, consumer);
                }
            }
        });
        Ok(Shim {
            flip,
            flipped,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Shim {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
