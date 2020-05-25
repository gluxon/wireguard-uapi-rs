use neli::err::NlError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    NlError(NlError),

    #[error("Unable to connect to the WireGuard DKMS. Is WireGuard installed?")]
    ResolveFamilyError(#[source] NlError),
}

impl From<NlError> for ConnectError {
    fn from(error: NlError) -> Self {
        ConnectError::NlError(error)
    }
}

impl From<std::io::Error> for ConnectError {
    fn from(error: std::io::Error) -> Self {
        ConnectError::NlError(error.into())
    }
}
