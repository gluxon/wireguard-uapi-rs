use crate::get;
use crate::userspace::error::GetDeviceError;
use crate::userspace::parser::parse;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

const GET_CMD: &str = "get=1\n";

pub struct Client<P: AsRef<Path>> {
    path: P,
}

impl<P: AsRef<Path>> Client<P> {
    pub fn create(path: P) -> Self {
        Self { path }
    }

    pub fn get(&self) -> Result<get::Device, GetDeviceError> {
        let mut stream = UnixStream::connect(&self.path)?;

        stream.write_all(GET_CMD.as_bytes())?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(parse(&response)?)
    }
}
