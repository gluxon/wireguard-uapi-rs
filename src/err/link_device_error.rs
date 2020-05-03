use neli::err::{NlError, SerError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LinkDeviceError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlSerError(SerError),

    #[error("Interface names must be 1 to IFNAMSIZ-1 characters")]
    InvalidInterfaceName,

    #[error(
        "Unable to get interface from WireGuard. Make sure it exists and you have permissions to access it."
    )]
    AccessError,
}

impl From<NlError> for LinkDeviceError {
    fn from(error: NlError) -> Self {
        LinkDeviceError::NlError(error)
    }
}

impl From<SerError> for LinkDeviceError {
    fn from(error: SerError) -> Self {
        LinkDeviceError::NlSerError(error)
    }
}

impl From<std::io::Error> for LinkDeviceError {
    fn from(error: std::io::Error) -> Self {
        LinkDeviceError::NlError(error.into())
    }
}
