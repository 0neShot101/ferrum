//! Ferrum APT mirror gateway, private fixture mode (`PLAN.md` B04).
//!
//! The library exists so integration tests can start the gateway in-process on
//! ephemeral ports; the binary is a thin `serve` command over [`app::run`].

// The composed publication/SDK futures exceed rustc's default query depth.
#![recursion_limit = "256"]

pub mod admin;
pub mod app;
pub mod clock;
pub mod config;
pub mod fetch;
pub mod fixture_s3;
pub mod health;
pub mod http;
pub mod maintenance;
pub mod server;
pub mod sync;
