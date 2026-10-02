// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! One process-wide rustls crypto provider. `reqwest` is built with `rustls-no-provider` (so it
//! shares iroh's `ring` instead of pulling in aws-lc-rs and its C build); that means somebody
//! has to install the default provider before the first client is built. Idempotent.

use std::sync::Once;

static INSTALL: Once = Once::new();

pub fn install() {
    INSTALL.call_once(|| {
        // A second install (some other crate got there first) is harmless: any provider will do.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
