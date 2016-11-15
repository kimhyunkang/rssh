use std::{fmt, str};
use std::error::Error;

use serde::de;

pub struct BinaryDecoder<'a> {
    buf: &'a [u8],
    pos: usize
}

#[derive(Debug, PartialEq)]
pub enum DecoderError {
    UnsupportedType(&'static str),
    UnexpectedEOF,
    NonBoolean,
    Utf8Error(str::Utf8Error),
    Serde(de::value::Error)
}

impl Error for DecoderError {
    fn description(&self) -> &str {
        match *self {
            DecoderError::UnsupportedType(ref name) => "Unsupported Type",
            DecoderError::UnexpectedEOF => "Unexpected EOF",
            DecoderError::NonBoolean => "Met non-boolean value",
            DecoderError::Utf8Error(ref e) => Error::description(e),
            DecoderError::Serde(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            DecoderError::UnsupportedType(_) => None,
            DecoderError::UnexpectedEOF => None,
            DecoderError::NonBoolean => None,
            DecoderError::Utf8Error(ref e) => e.cause(),
            DecoderError::Serde(ref e) => e.cause(),
        }
    }
}

impl de::Error for DecoderError {
    fn custom<T: Into<String>>(desc: T) -> DecoderError {
        DecoderError::Serde(de::value::Error::Custom(desc.into()))
    }

    fn end_of_stream() -> DecoderError {
        DecoderError::Serde(de::value::Error::EndOfStream)
    }
}

impl fmt::Display for DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecoderError::UnsupportedType(ref name) => write!(f, "UnsupportedType({})", name),
            DecoderError::UnexpectedEOF => write!(f, "Unexpected EOF"),
            DecoderError::NonBoolean => write!(f, "NonBoolean"),
            DecoderError::Utf8Error(ref e) => write!(f, "Utf8Error: {}", e),
            DecoderError::Serde(ref e) => write!(f, "Serde: {}", e)
        }
    }
}

impl From<str::Utf8Error> for DecoderError {
    fn from(e: str::Utf8Error) -> DecoderError {
        DecoderError::Utf8Error(e)
    }
}

impl<'a> BinaryDecoder<'a> {
    pub fn new<'n>(data: &'n [u8]) -> BinaryDecoder<'n> {
        BinaryDecoder { buf: data, pos: 0 }
    }

    fn parse_u32(&mut self) -> Result<u32, DecoderError> {
        if self.buf.len() < self.pos + 4 {
            Err(DecoderError::UnexpectedEOF)
        } else {
            let v = ((self.buf[self.pos] as u32) << 24)
                + ((self.buf[self.pos+1] as u32) << 16)
                + ((self.buf[self.pos+2] as u32) << 8)
                + self.buf[self.pos+3] as u32;
            self.pos += 4;
            Ok(v)
        }
    }

    fn parse_u8(&mut self) -> Result<u8, DecoderError> {
        if self.buf.len() < self.pos + 1 {
            Err(DecoderError::UnexpectedEOF)
        } else {
            let v = self.buf[self.pos];
            self.pos += 1;
            Ok(v)
        }
    }

    fn parse_bytes(&mut self) -> Result<&[u8], DecoderError> {
        let len = try!(self.parse_u32()) as usize;
        if self.buf.len() < self.pos + len {
            Err(DecoderError::UnexpectedEOF)
        } else {
            let old_pos = self.pos;
            self.pos += len;
            Ok(&self.buf[old_pos .. self.pos])
        }
    }
}

impl<'a> de::Deserializer for BinaryDecoder<'a> {
    type Error = DecoderError;

    fn deserialize<V>(&mut self, _visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        Err(DecoderError::UnsupportedType("struct"))
    }

    fn deserialize_u32<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        visitor.visit_u32(try!(self.parse_u32()))
    }

    fn deserialize_u8<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        visitor.visit_u8(try!(self.parse_u8()))
    }

    fn deserialize_bool<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        match try!(self.parse_u8()) {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            _ => Err(DecoderError::NonBoolean)
        }
    }

    fn deserialize_str<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        self.parse_bytes().and_then(|bytes| {
            str::from_utf8(bytes).map_err(|e| e.into())
        }).and_then(|s| {
            visitor.visit_str(s)
        })
    }

    fn deserialize_bytes<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        self.parse_bytes().and_then(|bytes| visitor.visit_bytes(bytes))
    }

    fn deserialize_string<V>(&mut self, mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        self.parse_bytes().and_then(|bytes| {
            str::from_utf8(bytes).map_err(|e| e.into())
        }).and_then(|s| {
            visitor.visit_string(s.into())
        })
    }

    fn deserialize_struct<V>(&mut self,
                             _name: &'static str,
                             _fields: &'static [&'static str],
                             mut visitor: V)
            -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        struct SeqVisitor<'a, 'b: 'a> {
            deserializer: &'a mut BinaryDecoder<'b>,
            len: usize,
        }

        impl<'a, 'b: 'a> de::SeqVisitor for SeqVisitor<'a, 'b> {
            type Error = DecoderError;

            fn visit<T>(&mut self) -> Result<Option<T>, Self::Error>
                where T: de::Deserialize,
            {
                if self.len > 0 {
                    self.len -= 1;
                    let value = try!(de::Deserialize::deserialize(self.deserializer));
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }

            fn end(&mut self) -> Result<(), Self::Error> {
                if self.len == 0 {
                    Ok(())
                } else {
                    Err(DecoderError::Serde(de::value::Error::Custom("expected end".into())))
                }
            }
        }

        let len = try!(de::Deserialize::deserialize(self));

        visitor.visit_seq(SeqVisitor { deserializer: self, len: len })
    }

    fn deserialize_struct_field<V>(&mut self,
                                   _visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor,
    {
        let message = "bincode does not support Deserializer::deserialize_struct_field";
        Err(DecoderError::Serde(de::value::Error::Custom(message.into())))
    }

    fn deserialize_seq<V>(&mut self,
                          mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor,
    {
        struct SeqVisitor<'a, 'b: 'a> {
            deserializer: &'a mut BinaryDecoder<'b>,
            len: usize,
        }

        impl<'a, 'b: 'a> de::SeqVisitor for SeqVisitor<'a, 'b> {
            type Error = DecoderError;

            fn visit<T>(&mut self) -> Result<Option<T>, Self::Error>
                where T: de::Deserialize,
            {
                if self.len > 0 {
                    self.len -= 1;
                    let value = try!(de::Deserialize::deserialize(self.deserializer));
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }

            fn end(&mut self) -> Result<(), Self::Error> {
                if self.len == 0 {
                    Ok(())
                } else {
                    Err(DecoderError::Serde(de::value::Error::Custom("expected end".into())))
                }
            }
        }

        let len = try!(de::Deserialize::deserialize(self));

        visitor.visit_seq(SeqVisitor { deserializer: self, len: len })
    }

    fn deserialize_seq_fixed_size<V>(&mut self,
                                     _len: usize,
                                     mut visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor,
    {
        self.deserialize_seq(visitor)
    }

    forward_to_deserialize! {
        usize u16 u64 isize i8 i16 i32 i64 f32 f64 char option
        unit map unit_struct newtype_struct
        tuple_struct tuple enum ignored_any
    }
}

pub fn deserialize<T: de::Deserialize>(bytes: &[u8]) -> Result<T, DecoderError> {
    let mut decoder = BinaryDecoder::new(bytes);
    de::Deserialize::deserialize(&mut decoder)
}

#[cfg(test)]
mod test {
    use super::deserialize;

    #[derive(Debug, PartialEq, Deserialize)]
    struct Test1 {
        pkt_len: u32,
        pad_len: u8
    }

    #[test]
    fn decode_u32() {
        let val = deserialize::<u32>(&[0, 1, 2, 3]);
        assert_eq!(Ok(0x010203), val);
    }

    #[test]
    fn decode_u8() {
        let val = deserialize::<u8>(&[30]);
        assert_eq!(Ok(30), val);
    }
}
