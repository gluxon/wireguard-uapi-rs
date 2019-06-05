use failure::Fail;
use libc;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

#[derive(Fail, Debug)]
pub enum ParseAttributeError {
    #[fail(
        display = "Error parsing Netlink attribute. Expected {} bytes, found {}.",
        expected, found
    )]
    StaticLengthError { expected: usize, found: usize },

    #[fail(display = "{}", _0)]
    ParseSockAddrError(#[fail(cause)] ParseSockAddrError),

    #[fail(display = "{}", _0)]
    ParseIpAddrError(#[fail(cause)] ParseIpAddrError),

    #[fail(display = "{}", _0)]
    FromUtf8Error(#[fail(cause)] FromUtf8Error),

    #[fail(display = "{}", _0)]
    TryFromIntError(#[fail(cause)] TryFromIntError),

    #[fail(display = "Expected a null-terminated string in Netlink response")]
    InvalidCStringError,
}

impl From<FromUtf8Error> for ParseAttributeError {
    fn from(error: FromUtf8Error) -> Self {
        ParseAttributeError::FromUtf8Error(error)
    }
}

impl From<TryFromIntError> for ParseAttributeError {
    fn from(error: TryFromIntError) -> Self {
        ParseAttributeError::TryFromIntError(error)
    }
}

#[derive(Fail, Debug)]
pub enum ParseSockAddrError {
    #[fail(display = "Unrecognized address family")]
    UnrecognizedAddressFamilyError { id: libc::c_int },
}

impl From<ParseSockAddrError> for ParseAttributeError {
    fn from(error: ParseSockAddrError) -> Self {
        ParseAttributeError::ParseSockAddrError(error)
    }
}

#[derive(Fail, Debug)]
pub enum ParseIpAddrError {
    #[fail(
        display = "Payload does not correspond to known ip address lengths. Found {}.",
        found
    )]
    InvalidIpAddrLengthError { found: usize },
}

impl From<ParseIpAddrError> for ParseAttributeError {
    fn from(error: ParseIpAddrError) -> Self {
        ParseAttributeError::ParseIpAddrError(error)
    }
}
