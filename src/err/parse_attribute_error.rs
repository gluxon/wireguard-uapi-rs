use std::num::TryFromIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseAttributeError {
    #[error(
        "Error parsing Netlink attribute. Expected {} bytes, found {}.",
        expected,
        found
    )]
    StaticLengthError { expected: usize, found: usize },

    #[error("{0}")]
    ParseSockAddrError(#[source] ParseSockAddrError),

    #[error("{0}")]
    ParseIpAddrError(#[source] ParseIpAddrError),

    #[error("{0}")]
    FromUtf8Error(#[source] FromUtf8Error),

    #[error("{0}")]
    TryFromIntError(#[source] TryFromIntError),

    #[error("Expected a null-terminated string in Netlink response")]
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

#[derive(Error, Debug)]
pub enum ParseSockAddrError {
    #[error("Unrecognized address family")]
    UnrecognizedAddressFamilyError { id: libc::c_int },
}

impl From<ParseSockAddrError> for ParseAttributeError {
    fn from(error: ParseSockAddrError) -> Self {
        ParseAttributeError::ParseSockAddrError(error)
    }
}

#[derive(Error, Debug)]
pub enum ParseIpAddrError {
    #[error(
        "Payload does not correspond to known ip address lengths. Found {}.",
        found
    )]
    InvalidIpAddrLengthError { found: usize },
}

impl From<ParseIpAddrError> for ParseAttributeError {
    fn from(error: ParseIpAddrError) -> Self {
        ParseAttributeError::ParseIpAddrError(error)
    }
}
