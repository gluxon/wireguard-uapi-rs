use failure::Fail;
use neli::err::{NlError, SerError};

#[derive(Fail, Debug)]
pub enum SetDeviceError {
    #[fail(display = "{}", _0)]
    NlError(#[fail(cause)] NlError),

    #[fail(display = "{}", _0)]
    NlSerError(#[fail(cause)] SerError),
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
