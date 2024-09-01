pub mod buffer;
pub mod protocol;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("End of buffer")]
    BufferEnd,
    #[error("Limit of `{0}` jumps exceeded")]
    MaxJumps(u32),
    #[error("Single label exceeds the max characters of length (63)")]
    LabelExceedsMaxLengthSize,
    #[error("Error Reading Socket: `{source}`")]
    SocketIO { source: std::io::Error },
    #[error("Error Binding Socket: `{source}`")]
    SocketBind { source: std::io::Error },
}
