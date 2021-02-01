pub use super::parser::ParseGetResponseError;

#[derive(Debug, thiserror::Error)]
pub enum GetDeviceError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseGetDevice(#[from] ParseGetResponseError),
}
