//! Per-protocol install adapters. Each protocol's `prepare` helper runs
//! async pre-build work (UDP binds, anchor reads) and returns an
//! installer implementing [`ndn_engine::InstallableProtocol`]; the
//! installer wires `InProcFace` pairs and queues post-build FIB writes,
//! neighbour seeds, and Producer `serve` tasks via
//! [`ndn_engine::PostBuildQueue`].

pub mod dv;
pub mod nlsr;
