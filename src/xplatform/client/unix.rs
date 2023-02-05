use crate::get;
use crate::xplatform::error::GetDeviceError;
use crate::xplatform::error::SetDeviceError;
use crate::xplatform::parser::parse;
use crate::xplatform::set;
use std::io::BufRead;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

const GET_CMD: &str = "get=1\n\n";
const SET_CMD: &str = "set=1\n";

pub struct Client<P: AsRef<Path>> {
    path: P,
}

impl<P: AsRef<Path>> Client<P> {
    /// A path to the unix socket file. Ex: `/var/run/wireguard/utun0.sock`
    pub fn create(path: P) -> Self {
        Self { path }
    }

    pub fn get(&self) -> Result<get::Device, GetDeviceError> {
        let mut stream = UnixStream::connect(&self.path)?;

        stream.write_all(GET_CMD.as_bytes())?;

        let reader = std::io::BufReader::new(stream);
        let response_lines = reader.lines();

        Ok(parse(response_lines)?)
    }

    pub fn set(&self, set_request: set::Device) -> Result<(), SetDeviceError> {
        let mut stream = UnixStream::connect(&self.path)?;

        stream.write_all(SET_CMD.as_bytes())?;
        // TODO: This likely buffers the entire set_request in memory before
        // sending it across the socket. We can probably do better.
        stream.write_fmt(format_args!("{set_request}"))?;
        stream.write_all(b"\n")?;

        let reader = std::io::BufReader::new(stream);
        let mut response_lines = reader.lines();

        // The response for protocol_version=1 is expected to be a single
        // "errno=N" line followed by an empty line.
        let errno_line = response_lines
            .next()
            .ok_or(SetDeviceError::EmptyResponse)??;

        let (raw_key, raw_value) = {
            let mut tokens = errno_line.trim().splitn(2, '=');
            let raw_key = tokens.next().unwrap();
            let raw_value = match tokens.next() {
                Some(val) => val,
                None => return Err(SetDeviceError::InvalidResponse(errno_line)),
            };

            (raw_key, raw_value)
        };

        match (raw_key, raw_value) {
            ("errno", "0") => {}
            ("errno", val) => return Err(SetDeviceError::ServerError(val.to_string())),
            (_, _) => return Err(SetDeviceError::InvalidResponse(errno_line)),
        }

        let empty_line = response_lines
            .next()
            .ok_or(SetDeviceError::EmptyResponse)??;
        if !empty_line.is_empty() {
            return Err(SetDeviceError::InvalidEndOfResponse(empty_line));
        }

        Ok(())
    }
}
