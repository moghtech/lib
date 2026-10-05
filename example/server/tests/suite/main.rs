#![allow(unused_crate_dependencies)]

//! Integration tests against the running example server, which
//! cover the Mogh libraries the way an app uses them.
//!
//! Every test spawns its own server (own port, database and
//! config) plus a mock identity provider, see [common].

mod common;

mod api_keys;
mod app_api;
mod disabled_users;
mod local_auth;
mod oidc;
mod providers;
mod reauth;
mod security;
mod server;
mod supporter;
mod token_exchange;
mod two_factor;
mod workload;
