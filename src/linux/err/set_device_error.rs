use neli::err::{NlError, SerError};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SetDeviceError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlSerError(SerError),

    #[error(transparent)]
    IoError(io::Error),
}

impl From<NlError> for SetDeviceError {
    fn from(error: NlError) -> Self {
        SetDeviceError::NlError(error)
    }
}

impl From<SerError> for SetDeviceError {
    fn from(error: SerError) -> Self {
        SetDeviceError::NlSerError(error)
    }
}

impl From<io::Error> for SetDeviceError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}
