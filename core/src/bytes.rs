//! A helper module for dealing with bytes
use std::fmt::{self, Display, Formatter, UpperHex, LowerHex, Debug};

pub struct ByteBuf<'a>(pub &'a [u8]);

impl<'a> Display for ByteBuf<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl<'a> LowerHex for ByteBuf<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<'a> UpperHex for ByteBuf<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<'a> Debug for ByteBuf<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("ByteBuf")
         .field(&self.to_hex_string())
         .finish()
    }
}

impl<'a> ByteBuf<'a> {
    // Converts the byte buffer into a hexadecimal string
    pub fn to_hex_string(&self) -> String {
        self.0.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    // Returns the length of the byte buffer
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Returns a slice of the byte buffer
    pub fn slice(&self, start: usize, end: usize) -> &[u8] {
        &self.0[start..end]
    }
}
