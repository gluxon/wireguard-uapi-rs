use crate::err::ParseAttributeError;
use failure::Fail;
use neli::err::{DeError, NlError};

#[derive(Fail, Debug)]
pub enum ParseDeviceError {
    #[fail(display = "{}", _0)]
    NlError(#[fail(cause)] NlError),

    #[fail(display = "{}", _0)]
    NlDeError(#[fail(cause)] DeError),

    #[fail(display = "{}", _0)]
    String(String),

    #[fail(display = "{}", _0)]
    ParseAttributeError(#[fail(cause)] ParseAttributeError),

    #[fail(display = "Encountered unknown device attribute id {}", id)]
    UnknownDeviceAttributeError { id: u16 },

    #[fail(display = "Encountered unknown peer attribute id {}", id)]
    UnknownPeerAttributeError { id: u16 },

    #[fail(display = "Encountered unknown allowed ip attribute id {}", id)]
    UnknownAllowedIpAttributeError { id: u16 },
}

impl From<NlError> for ParseDeviceError {
    fn from(error: NlError) -> Self {
        ParseDeviceError::NlError(error)
    }
}

impl From<DeError> for ParseDeviceError {
    fn from(error: DeError) -> Self {
        ParseDeviceError::NlDeError(error)
    }
}

impl From<String> for ParseDeviceError {
    fn from(string: String) -> Self {
        ParseDeviceError::String(string)
    }
}

impl From<ParseAttributeError> for ParseDeviceError {
    fn from(error: ParseAttributeError) -> Self {
        ParseDeviceError::ParseAttributeError(error)
    }
}
