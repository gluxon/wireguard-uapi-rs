use super::ParseAttributeError;
use neli::err::{DeError, NlError, SerError};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ListDevicesError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlDeError(DeError),

    #[error(transparent)]
    NlSerError(SerError),

    #[error(transparent)]
    ParseAttributeError(ParseAttributeError),

    #[error(transparent)]
    IoError(io::Error),

    // TODO: Print netlink error message when neli exposes it.
    #[error("Unknown netlink error while reading devices.")]
    Unknown,
}

impl From<NlError> for ListDevicesError {
    fn from(error: NlError) -> Self {
        Self::NlError(error)
    }
}

impl From<DeError> for ListDevicesError {
    fn from(error: DeError) -> Self {
        Self::NlDeError(error)
    }
}

impl From<SerError> for ListDevicesError {
    fn from(error: SerError) -> Self {
        Self::NlSerError(error)
    }
}

impl From<ParseAttributeError> for ListDevicesError {
    fn from(error: ParseAttributeError) -> Self {
        Self::ParseAttributeError(error)
    }
}

impl From<io::Error> for ListDevicesError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}
