//! A helper module for dealing with bytes

use std::fmt::Display;

/// A helper to show bytes in hex
pub struct ByteBuf<'a>(pub &'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter,
    ) -> std::result::Result<(), std::fmt::Error> {
        for byte in self.0 {
            f.write_fmt(format_args!("{:02x}", byte))?;
        }
        Ok(())
    }
}

impl<'a> Display for ByteBuf<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}
