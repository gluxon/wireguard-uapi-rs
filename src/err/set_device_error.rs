use neli::err::{NlError, SerError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SetDeviceError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlSerError(SerError),
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
