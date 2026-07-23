//! The panic probe: a method on each handle that panics on purpose.
//!
//! It exists so the firewall can be proven from JavaScript rather than only by a
//! Rust unit test — a caught panic must arrive as `RINE_MLS_PANIC` and retire the
//! handle. The whole module is compiled only under the `panic-probe` feature,
//! which no published artifact is built with, and the npm package test asserts
//! the method is absent from what ships.
//!
//! Each probe needs its own `impl` block rather than sitting beside the real
//! methods: `napi-derive` reads a `#[napi] impl` before `#[cfg]` strips anything
//! inside it, and would register a method whose body no longer exists.

use napi_derive::napi;

use crate::client::MlsClient;
use crate::error::{guard, MlsError};
use crate::group::MlsGroup;

const MESSAGE: &str = "panic probe: deliberate unwind inside the MLS core";

#[napi]
impl MlsClient {
    #[napi]
    pub fn panic_probe(&mut self) -> Result<(), MlsError> {
        guard(&mut self.poison, || -> rine_mls_core::Result<()> {
            panic!("{MESSAGE}")
        })
    }
}

#[napi]
impl MlsGroup {
    #[napi]
    pub fn panic_probe(&mut self) -> Result<(), MlsError> {
        guard(&mut self.poison, || -> rine_mls_core::Result<()> {
            panic!("{MESSAGE}")
        })
    }
}
