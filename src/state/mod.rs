pub mod merge;

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::model::SystemNetworkState;

/// Shared state type — lock-free concurrent access via ArcSwap.
pub type SharedState = Arc<ArcSwap<SystemNetworkState>>;

/// Create a new shared state initialized with an empty network state.
pub fn new_shared_state() -> SharedState {
    Arc::new(ArcSwap::from_pointee(SystemNetworkState::empty()))
}
