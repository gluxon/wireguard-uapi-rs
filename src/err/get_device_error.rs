use crate::err::ParseDeviceError;
use failure::Fail;
use neli::err::{NlError, SerError};

#[derive(Fail, Debug)]
pub enum GetDeviceError {
    #[fail(display = "{}", _0)]
    NlError(#[fail(cause)] NlError),

    #[fail(display = "{}", _0)]
    NlSerError(#[fail(cause)] SerError),

    #[fail(display = "Interface names must be 1 to IFNAMSIZ-1 characters")]
    InvalidInterfaceName,

    #[fail(
        display = "Unable to get interface from WireGuard. Make sure it exists and you have permissions to access it."
    )]
    AccessError,

    #[fail(display = "{}", _0)]
    ParseDeviceError(#[fail(cause)] ParseDeviceError),
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
