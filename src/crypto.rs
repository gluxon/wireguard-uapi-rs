pub use std::convert::TryFrom;

pub const KEY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Key([u8; KEY_SIZE]);

pub type PresharedKey = Key;
pub type PrivateKey = Key;
pub type PublicKey = Key;

#[derive(Debug, thiserror::Error)]
pub enum KeyParseError {
    #[error("Invalid key length: {0} (expected {})", KEY_SIZE)]
    InvalidLength(usize),
}

impl Key {
    pub fn zero() -> Self {
        Key([0u8; KEY_SIZE])
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for Key {
    fn from(value: [u8; KEY_SIZE]) -> Self {
        Key(value)
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = KeyParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.len();

        if len != KEY_SIZE {
            return Err(KeyParseError::InvalidLength(len));
        }

        let mut key = Key::zero();

        key.0.copy_from_slice(value);

        Ok(key)
    }
}
