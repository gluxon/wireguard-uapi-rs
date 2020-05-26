use super::parser::parse;
use crate::get;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

const GET_CMD: &str = "get=1\n";

pub struct Socket {
    stream: UnixStream,
}

impl Socket {
    pub fn connect<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(Self { stream })
    }

    pub fn get(&mut self) -> std::io::Result<get::Device> {
        self.stream.write(GET_CMD.as_bytes())?;

        let mut response = String::new();
        self.stream.read_to_string(&mut response)?;

        Ok(parse(&response).unwrap())
    }
}
