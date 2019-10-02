use failure::Fail;
use neli::err::{NlError, SerError};

#[derive(Fail, Debug)]
pub enum LinkDeviceError {
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
