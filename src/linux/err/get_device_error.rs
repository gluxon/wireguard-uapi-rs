use super::ParseDeviceError;
use neli::err::{NlError, SerError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GetDeviceError {
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

    #[error(transparent)]
    ParseDeviceError(ParseDeviceError),
}

impl From<NlError> for GetDeviceError {
    fn from(error: NlError) -> Self {
        GetDeviceError::NlError(error)
    }
}

impl From<SerError> for GetDeviceError {
    fn from(error: SerError) -> Self {
        GetDeviceError::NlSerError(error)
    }
}

impl From<ParseDeviceError> for GetDeviceError {
    fn from(error: ParseDeviceError) -> Self {
        GetDeviceError::ParseDeviceError(error)
    }
}
