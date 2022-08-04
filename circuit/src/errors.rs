#[derive(Debug, thiserror::Error)]
pub enum CircuitEvalError {
    #[error("uninitialized value, wire {0}")]
    UninitializedValue(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitLoadError {
    #[error("encountered error while parsing circuit")]
    ParsingError(#[from] anyhow::Error),
    /// An I/O error occurred.
    #[error("encountered io error while loading circuit")]
    IoError(#[from] std::io::Error),
    /// Error occurred when mapping models
    #[error("encountered error while mapping protobuf model to core model")]
    MappingError,
}
