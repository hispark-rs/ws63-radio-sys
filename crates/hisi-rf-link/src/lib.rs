//! Deterministic host-side transforms for HiSilicon radio artifacts.

#[cfg(feature = "tool")]
pub mod normalize;

/// Link order and archive-selection contract for the WS63 Wi-Fi payload.
pub const WS63_ARCHIVE_PROFILE: &str = include_str!("../profiles/ws63.toml");
/// Hash-bound task classification used by the runtime compatibility audit.
pub const WS63_SCHEDULING_PROFILE: &str = include_str!("../profiles/ws63-scheduling.toml");
/// Bounded LiteOS/architecture namespace required by the current payload.
pub const WS63_RUNTIME_COMPAT_PROFILE: &str = include_str!("../profiles/ws63-runtime-compat.toml");
/// Native hostap archive and legacy-boundary contract.
pub const WS63_SUPPLICANT_BOUNDARY_PROFILE: &str =
    include_str!("../profiles/ws63-supplicant-boundary.toml");
