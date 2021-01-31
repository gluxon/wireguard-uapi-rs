use crate::linux::err::ParseAttributeError;
use neli::err::{DeError, NlError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseDeviceError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlDeError(DeError),

    #[error("{0}")]
    String(String),

    #[error(transparent)]
    ParseAttributeError(ParseAttributeError),

    #[error("Encountered unknown device attribute id {}", id)]
    UnknownDeviceAttributeError { id: u16 },

    #[error("Encountered unknown peer attribute id {}", id)]
    UnknownPeerAttributeError { id: u16 },

    #[error("Encountered unknown allowed ip attribute id {}", id)]
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
