use std::error::Error;
use std::fmt;

use serde::ser;

pub struct BinaryEncoder {
    buf: Vec<u8>
}

impl BinaryEncoder {
    pub fn new() -> BinaryEncoder {
        BinaryEncoder { buf: Vec::new() }
    }
}

#[derive(Debug, PartialEq)]
pub enum EncoderError {
    UnsupportedType(&'static str),
    DataTooLarge(usize),
    Serde(String)
}

impl fmt::Display for EncoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncoderError::UnsupportedType(ref e) => write!(f, "UnsupportedType({})", e),
            EncoderError::DataTooLarge(n) => write!(f, "DataTooLarge({})", n),
            EncoderError::Serde(ref e) => write!(f, "Serde({})", e),
        }
    }
}

impl Error for EncoderError {
    fn description(&self) -> &str {
        match *self {
            EncoderError::UnsupportedType(_) => "UnsupportedType",
            EncoderError::DataTooLarge(_) => "DataTooLarge",
            EncoderError::Serde(ref e) => e.as_ref(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            EncoderError::UnsupportedType(_) => None,
            EncoderError::DataTooLarge(_) => None,
            EncoderError::Serde(_) => None,
        }
    }
}

impl ser::Error for EncoderError {
    fn custom<T: Into<String>>(msg: T) -> EncoderError {
        EncoderError::Serde(msg.into())
    }
}

macro_rules! impl_error {
    ($func:ident($($arg:ty),*), $errtype:expr) => {
        #[inline]
        fn $func(&mut self, $(_: $arg),*) -> ::std::result::Result<(), Self::Error>
        {
            Err(EncoderError::UnsupportedType($errtype))
        }
    };

    ($func:ident<$tyvar:ident>($($arg:ty),*), $errtype:expr) => {
        #[inline]
        fn $func<$tyvar: ser::Serialize>(&mut self, $(_: $arg),*) -> ::std::result::Result<(), Self::Error>
        {
            Err(EncoderError::UnsupportedType($errtype))
        }
    };

    ($func:ident($($arg:ty),*) -> $ret:ty, $errtype:expr) => {
        #[inline]
        fn $func(&mut self, $(_: $arg),*) -> ::std::result::Result<$ret, Self::Error>
        {
            Err(EncoderError::UnsupportedType($errtype))
        }
    };
}

impl ser::Serializer for BinaryEncoder {
    type Error = EncoderError;
    type SeqState = ();
    type TupleState = ();
    type TupleStructState = ();
    type TupleVariantState = ();
    type MapState = ();
    type StructState = ();
    type StructVariantState = ();

    fn serialize_bool(&mut self, v: bool) -> Result<(), EncoderError> {
        let b = if v { 1 } else { 0 };
        self.buf.push(b);
        Ok(())
    }

    fn serialize_u8(&mut self, v: u8) -> Result<(), EncoderError> {
        self.buf.push(v);
        Ok(())
    }

    fn serialize_u32(&mut self, v: u32) -> Result<(), EncoderError> {
        self.buf.push((v >> 24) as u8);
        self.buf.push((v >> 16) as u8);
        self.buf.push((v >> 8) as u8);
        self.buf.push(v as u8);
        Ok(())
    }

    fn serialize_str(&mut self, v: &str) -> Result<(), EncoderError> {
        self.serialize_bytes(v.as_ref())
    }

    fn serialize_bytes(&mut self, v: &[u8]) -> Result<(), EncoderError> {
        if v.len() > 0xffffffff {
            return Err(EncoderError::DataTooLarge(v.len()))
        }

        try!(self.serialize_u32(v.len() as u32));
        self.buf.extend_from_slice(v);
        Ok(())
    }

    fn serialize_struct(&mut self, _name: &'static str, _len: usize)
            -> Result<(), EncoderError>
    {
        Ok(())
    }

    fn serialize_struct_elt<T: ser::Serialize>(&mut self,
                                               _st: &mut (),
                                               _name: &'static str,
                                               elt: T)
            -> Result<(), EncoderError>
    {
        elt.serialize(self)
    }

    fn serialize_struct_end(&mut self, _st: ()) -> Result<(), EncoderError>
    {
        Ok(())
    }

    impl_error!(serialize_isize(isize), "isize");
    impl_error!(serialize_i8(i8), "i8");
    impl_error!(serialize_i16(i16), "i16");
    impl_error!(serialize_i32(i32), "i32");
    impl_error!(serialize_i64(i64), "i64");
    impl_error!(serialize_usize(usize), "usize");
    impl_error!(serialize_u16(u16), "u16");
    impl_error!(serialize_u64(u64), "u64");
    impl_error!(serialize_f32(f32), "f32");
    impl_error!(serialize_f64(f64), "f64");
    impl_error!(serialize_char(char), "char");
    impl_error!(serialize_unit(), "unit");
    impl_error!(serialize_unit_struct(&'static str), "unit_struct");
    impl_error!(serialize_unit_variant(&'static str, usize, &'static str), "unit_variant");
    impl_error!(serialize_newtype_struct<T>(&'static str, T), "newtype_struct");
    impl_error!(serialize_newtype_variant<T>(&'static str, usize, &'static str, T), "newtype_variant");
    impl_error!(serialize_none(), "none");
    impl_error!(serialize_some<T>(T), "some");
    impl_error!(serialize_seq(Option<usize>), "seq");
    impl_error!(serialize_seq_elt<T>(&mut Self::SeqState, T), "seq_elt");
    impl_error!(serialize_seq_end(Self::SeqState), "seq_end");
    impl_error!(serialize_seq_fixed_size(usize) -> Self::SeqState, "seq_fixed_size");
    impl_error!(serialize_tuple(usize) -> Self::TupleState, "tuple");
    impl_error!(serialize_tuple_elt<T>(&mut Self::TupleState, T), "tuple_elt");
    impl_error!(serialize_tuple_end(Self::TupleState), "tuple_end");
    impl_error!(serialize_tuple_struct(&'static str, usize) -> Self::TupleStructState, "tuple_struct");
    impl_error!(serialize_tuple_struct_elt<T>(&mut Self::TupleStructState, T), "tuple_struct_elt");
    impl_error!(serialize_tuple_struct_end(Self::TupleStructState), "tuple_struct_end");
    impl_error!(serialize_tuple_variant(&'static str, usize, &'static str, usize) -> Self::TupleVariantState, "tuple_variant");
    impl_error!(serialize_tuple_variant_elt<T>(&mut Self::TupleVariantState, T), "tuple_variant_elt");
    impl_error!(serialize_tuple_variant_end(Self::TupleVariantState), "tuple_variant_end");
    impl_error!(serialize_map(Option<usize>) -> Self::MapState, "map");
    impl_error!(serialize_map_key<T>(&mut Self::MapState, T), "map_key");
    impl_error!(serialize_map_value<T>(&mut Self::MapState, T), "map_value");
    impl_error!(serialize_map_end(Self::MapState), "map_end");
    impl_error!(serialize_struct_variant(&'static str, usize, &'static str, usize) -> Self::StructVariantState, "struct_variant");
    impl_error!(serialize_struct_variant_elt<T>(&mut Self::StructVariantState, &'static str, T), "struct_variant_elt");
    impl_error!(serialize_struct_variant_end(Self::StructVariantState), "struct_variant_end");
}

pub fn serialize<T: ser::Serialize>(val: &T) -> Result<Vec<u8>, EncoderError> {
    let mut encoder = BinaryEncoder::new();
    try!(val.serialize(&mut encoder));
    Ok(encoder.buf)
}
