#[derive(Debug, thiserror::Error)]
pub enum OTSenderError {
    #[error("Sender Invalid Input Length")]
    InvalidInputLength,

    #[error("Sender IO Error")]
    IoError(std::io::Error),

    #[error("Consistency check failed")]
    ConsistencyCheckFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum OTReceiverError {
    #[error("Receiver Invalid Input Length")]
    InvalidInputLength,

    #[error("Receiver IO Error")]
    IoError(std::io::Error),
}

impl From<std::io::Error> for OTSenderError {
    fn from(e: std::io::Error) -> OTSenderError {
        OTSenderError::IoError(e)
    }
}

impl From<std::io::Error> for OTReceiverError {
    fn from(e: std::io::Error) -> OTReceiverError {
        OTReceiverError::IoError(e)
    }
}
