use std::{fmt, str};
use std::error::Error;
use std::marker::PhantomData;

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
            DecoderError::UnsupportedType(_) => "Unsupported Type",
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

pub fn de_inner<D: de::Deserializer, T: de::Deserialize>(d: &mut D) -> Result<T, D::Error> {
    struct NestedVisitor<U> {
        _x: PhantomData<U>
    };

    impl <U: de::Deserialize> de::Visitor for NestedVisitor<U> {
        type Value = U;

        fn visit_bytes<E>(&mut self, v: &[u8]) -> Result<U, E>
            where E: de::Error
        {
            let mut decoder = BinaryDecoder::new(v);
            de::Deserialize::deserialize(&mut decoder)
                .map_err(|e| de::Error::custom(e.to_string()))
        }
    }

    let visitor = NestedVisitor { _x: PhantomData };
    d.deserialize_bytes(visitor)
}

pub fn de_bytes<D: de::Deserializer>(d: &mut D) -> Result<Vec<u8>, D::Error> {
    struct IntoVisitor;

    impl de::Visitor for IntoVisitor {
        type Value = Vec<u8>;

        fn visit_bytes<E>(&mut self, v: &[u8]) -> Result<Vec<u8>, E>
        {
            Ok(v.into())
        }
    }

    d.deserialize_bytes(IntoVisitor)
}

pub trait Name: de::Deserialize + for<'a> From<&'a str> {
}

impl <T> Name for T where T: de::Deserialize + for<'a> From<&'a str> {
}

pub fn de_name_list<D: de::Deserializer, T: Name>(d: &mut D) -> Result<Vec<T>, D::Error> {
    struct IntoVisitor<U> {
        _x: PhantomData<U>
    }

    impl <U: Name> de::Visitor for IntoVisitor<U> {
        type Value = Vec<U>;

        fn visit_str<E>(&mut self, v: &str) -> Result<Vec<U>, E>
        {
            Ok(v.split(',').map(|s| s.into()).collect())
        }
    }

    let visitor = IntoVisitor { _x: PhantomData };
    d.deserialize_str(visitor)
}

macro_rules! impl_error {
    ($func:ident($($arg:ty),*), $errtype:expr) => {
        #[inline]
        fn $func<__V>(&mut self, $(_: $arg,)* _visitor: __V) -> ::std::result::Result<__V::Value, Self::Error>
            where __V: de::Visitor
            {
                Err(DecoderError::UnsupportedType($errtype))
            }
    };
}

impl<'a> de::Deserializer for BinaryDecoder<'a> {
    type Error = DecoderError;

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

    fn deserialize_tuple<V>(&mut self,
                            len: usize,
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

        visitor.visit_seq(SeqVisitor { deserializer: self, len: len })
    }

    fn deserialize_struct<V>(&mut self,
                             _name: &'static str,
                             fields: &'static [&'static str],
                             visitor: V)
            -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_struct_field<V>(&mut self, visitor: V) -> Result<V::Value, DecoderError>
        where V: de::Visitor
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_enum<V>(&mut self,
                           _name: &'static str,
                           _variants: &'static [&'static str],
                           mut visitor: V) -> Result<V::Value, Self::Error>
        where V: de::EnumVisitor
    {
        struct KeyVisitor<'a, 'b: 'a> {
            deserializer: &'a mut BinaryDecoder<'b>,
        }

        impl <'a, 'b: 'a> de::VariantVisitor for KeyVisitor<'a, 'b> {
            type Error = DecoderError;

            fn visit_variant<T>(&mut self) -> Result<T, DecoderError>
                where T: de::Deserialize
            {
                de::Deserialize::deserialize(self.deserializer)
            }

            fn visit_newtype<T>(&mut self) -> Result<T, DecoderError>
                where T: de::Deserialize
            {
                de::Deserialize::deserialize(self.deserializer)
            }

            fn visit_tuple<V>(&mut self,
                              len: usize,
                              visitor: V) -> Result<V::Value, DecoderError>
                where V: de::Visitor
            {
                de::Deserializer::deserialize_tuple(self.deserializer, len, visitor)
            }

            fn visit_struct<V>(&mut self,
                               fields: &'static [&'static str],
                               visitor: V) -> Result<V::Value, DecoderError>
                where V: de::Visitor
            {
                de::Deserializer::deserialize_tuple(self.deserializer, fields.len(), visitor)
            }
        }

        visitor.visit(KeyVisitor { deserializer: self })
    }

    impl_error!(deserialize(), "struct");
    impl_error!(deserialize_usize(), "usize");
    impl_error!(deserialize_u16(), "u16");
    impl_error!(deserialize_u64(), "u64");
    impl_error!(deserialize_isize(), "isize");
    impl_error!(deserialize_i8(), "i8");
    impl_error!(deserialize_i16(), "i16");
    impl_error!(deserialize_i32(), "i32");
    impl_error!(deserialize_i64(), "i64");
    impl_error!(deserialize_f32(), "f32");
    impl_error!(deserialize_f64(), "f64");
    impl_error!(deserialize_char(), "char");
    impl_error!(deserialize_option(), "option");
    impl_error!(deserialize_unit(), "unit");
    impl_error!(deserialize_map(), "map");
    impl_error!(deserialize_seq(), "seq");
    impl_error!(deserialize_seq_fixed_size(usize), "seq_fixed_size");
    impl_error!(deserialize_unit_struct(&'static str), "unit_struct");
    impl_error!(deserialize_newtype_struct(&'static str), "newtype_struct");
    impl_error!(deserialize_tuple_struct(&'static str, usize), "tuple_struct");
    impl_error!(deserialize_ignored_any(), "ignored_any");
}

pub fn deserialize<T: de::Deserialize>(bytes: &[u8]) -> Result<T, DecoderError> {
    let mut decoder = BinaryDecoder::new(bytes);
    de::Deserialize::deserialize(&mut decoder)
}
