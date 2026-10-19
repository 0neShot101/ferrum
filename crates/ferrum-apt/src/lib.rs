//! APT trust roots, authenticated descriptors, bounded control-file parsing and
//! repository paths for Ferrum.
//!
//! This crate is unaware of HTTP, disk-cache replacement and object storage.

pub mod digest;
pub mod index;
pub mod pacman;
pub mod path;
pub mod release;
pub mod rpm;
pub mod selection;
pub mod signature;
