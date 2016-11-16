pub mod decoder;
pub mod encoder;

pub use self::decoder::BinaryDecoder;
pub use self::encoder::BinaryEncoder;

macro_rules! test_codec {
    ($mod_name:ident, $val:expr, $bytes:expr) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn decode() {
                let result = deserialize($bytes);
                assert_eq!(Ok($val), result);
            }

            #[test]
            fn encode() {
                let result = serialize(&$val);
                assert_eq!(Ok($bytes.to_vec()), result);
            }
        }
    };

    ($mod_name:ident<$tyname:ident>, $val:expr, $bytes:expr) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn decode() {
                let result = deserialize::<$tyname>($bytes);
                assert_eq!(Ok($val), result);
            }

            #[test]
            fn encode() {
                let result = serialize::<$tyname>(&$val);
                assert_eq!(Ok($bytes.to_vec()), result);
            }
        }
    }
}

#[cfg(test)]
mod test {
    pub use super::decoder::{deserialize, de_inner, de_bytes};
    pub use super::encoder::serialize;
    pub use serde::bytes::ByteBuf;

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub struct TestStruct {
        pkt_len: u32,
        pad_len: u8
    }

    #[derive(Debug, PartialEq, Deserialize)]
    pub struct OuterStruct {
        #[serde(deserialize_with = "de_bytes")]
        data: Vec<u8>,
        #[serde(deserialize_with = "de_inner")]
        inner: TestStruct
    }

    #[derive(Debug, PartialEq, Deserialize)]
    pub enum TestEnum {
        #[serde(rename = "newtype")]
        NewtypeVariant(u32),
        #[serde(rename = "tuple")]
        TupleVariant(String, String),
        #[serde(rename = "struct")]
        StructVariant { a: u32, b: String }
    }

    #[derive(Debug, PartialEq, Deserialize)]
    pub struct EnumWrapper {
        #[serde(deserialize_with = "de_inner")]
        e: TestEnum,
        flag: bool
    }

    test_codec!(prim_false, false, &[0]);
    test_codec!(prim_true, true, &[1]);
    test_codec!(prim_u8, 30u8, &[30]);
    test_codec!(prim_u32, 0x010203u32, &[0, 1, 2, 3]);

    test_codec!(
        bytebuf<ByteBuf>,
        b"test".to_vec().into(),
        &[0, 0, 0, 4, b't', b'e', b's', b't']
    );

    test_codec!(
        prim_string,
        "test".to_string(),
        &[0, 0, 0, 4, b't', b'e', b's', b't']
    );

    test_codec!(
        plain_struct,
        TestStruct { pkt_len: 0x010203, pad_len: 30 },
        &[0, 1, 2, 3, 30]
    );

    #[test]
    fn decode_inner_struct() {
        let val = deserialize::<OuterStruct>(&[0, 0, 0, 4, b't', b'e', b's', b't', 0, 0, 0, 5, 0, 1, 2, 3, 30]);
        let expected = OuterStruct {
            data: b"test".to_vec(),
            inner: TestStruct { pkt_len: 0x010203, pad_len: 30 }
        };
        assert_eq!(Ok(expected), val);
    }

    #[test]
    fn decode_enum_newtype() {
        let data = &[0, 0, 0, 7, b'n', b'e', b'w', b't', b'y', b'p', b'e', 0, 0, 1, 2];
        let val = deserialize::<TestEnum>(data);
        let expected = TestEnum::NewtypeVariant(0x0102);
        assert_eq!(Ok(expected), val);
    }

    #[test]
    fn decode_enum_tuple() {
        let data = &[0, 0, 0, 5, b't', b'u', b'p', b'l', b'e',
            0, 0, 0, 1, b'a',
            0, 0, 0, 2, b'b', b'c'
        ];
        let val = deserialize::<TestEnum>(data);
        let expected = TestEnum::TupleVariant("a".to_string(), "bc".to_string());
        assert_eq!(Ok(expected), val);
    }

    #[test]
    fn decode_enum_struct() {
        let data = &[0, 0, 0, 6, b's', b't', b'r', b'u', b'c', b't',
            0, 0, 1, 2,
            0, 0, 0, 1, b'x',
        ];
        let val = deserialize::<TestEnum>(data);
        let expected = TestEnum::StructVariant { a: 0x0102, b: "x".to_string() };
        assert_eq!(Ok(expected), val);
    }

    #[test]
    fn decode_wrapped_enum() {
        let data = &[
            0, 0, 0, 19,
            0, 0, 0, 6, b's', b't', b'r', b'u', b'c', b't',
            0, 0, 1, 2,
            0, 0, 0, 1, b'x',
            1
        ];

        let val = deserialize::<EnumWrapper>(data);
        let expected = EnumWrapper {
            e: TestEnum::StructVariant { a: 0x0102, b: "x".to_string() },
            flag: true
        };

        assert_eq!(Ok(expected), val);
    }
}