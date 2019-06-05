use failure::Fail;
use neli::err::NlError;

#[derive(Fail, Debug)]
pub enum ConnectError {
    #[fail(display = "{}", _0)]
    NlError(#[fail(cause)] NlError),

    #[fail(display = "Unable to connect to the WireGuard DKMS. Is WireGuard installed?")]
    ResolveFamilyError(#[fail(cause)] NlError),
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
