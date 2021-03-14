pub use super::parser::ParseGetResponseError;

#[derive(Debug, thiserror::Error)]
pub enum GetDeviceError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseGetDevice(#[from] ParseGetResponseError),
}

#[derive(Debug, thiserror::Error)]
pub enum SetDeviceError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Received non-zero error number in response: `{0}`")]
    ServerError(String),
    #[error("Received empty response")]
    EmptyResponse,
    #[error("Failed to parse response: `{0}`")]
    InvalidResponse(String),
    #[error("Invalid end of response. Expected empty line but saw: `{0}`")]
    InvalidEndOfResponse(String),
}
