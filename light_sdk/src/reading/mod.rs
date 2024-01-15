#[cfg(not(feature = "blocking"))]
pub mod asynchronous;
#[cfg(feature = "blocking")]
pub mod blocking;
