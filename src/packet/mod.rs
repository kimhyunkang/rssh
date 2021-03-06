pub mod decoder;
pub mod encoder;
pub mod types;

pub use self::decoder::{BinaryDecoder, deserialize, deserialize_msg};
pub use self::encoder::{BinaryEncoder, serialize, serialize_msg};

#[cfg(test)]
mod test {
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

    pub use super::decoder::{deserialize, de_inner, de_bytes, de_name_list};
    pub use super::encoder::{serialize, ser_inner, ser_bytes, ser_name_list};
    pub use serde::bytes::ByteBuf;
    pub use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub struct TestStruct {
        pkt_len: u32,
        pad_len: u8
    }

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub struct OuterStruct {
        #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
        data: Vec<u8>,
        #[serde(deserialize_with = "de_inner", serialize_with = "ser_inner")]
        inner: TestStruct
    }

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub enum TestEnum {
        #[serde(rename = "newtype")]
        NewtypeVariant(u32),
        #[serde(rename = "tuple")]
        TupleVariant(String, String),
        #[serde(rename = "struct")]
        StructVariant { a: u32, b: String },
        #[serde(rename = "bytes-struct")]
        BytesStruct {
            #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
            a: Vec<u8>,
            b: bool
        }
    }

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub struct EnumWrapper {
        #[serde(deserialize_with = "de_inner", serialize_with = "ser_inner")]
        e: TestEnum,
        flag: bool
    }

    #[derive(Debug, PartialEq)]
    pub enum NameEnum {
        TestName,
        AnotherName,
        Unknown(String)
    }

    impl AsRef<str> for NameEnum {
        fn as_ref(&self) -> &str {
            match *self {
                NameEnum::TestName => "test-name",
                NameEnum::AnotherName => "another-name",
                NameEnum::Unknown(ref s) => s.as_ref()
            }
        }
    }

    impl <'r> From<&'r str> for NameEnum {
        fn from(s: &str) -> NameEnum {
            match s {
                "test-name" => NameEnum::TestName,
                "another-name" => NameEnum::AnotherName,
                _ => NameEnum::Unknown(s.to_string())
            }
        }
    }

    impl Deserialize for NameEnum {
        fn deserialize<D: Deserializer>(d: &mut D) -> Result<NameEnum, D::Error> {
            pub use serde::de::Visitor;

            struct IntoVisitor;

            impl Visitor for IntoVisitor {
                type Value = NameEnum;

                fn visit_str<E>(&mut self, v: &str) -> Result<NameEnum, E>
                {
                    Ok(v.into())
                }
            }

            d.deserialize_str(IntoVisitor)
        }
    }

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    pub struct NameListWrapper {
        #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
        e: Vec<NameEnum>,
        #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
        f: Vec<u8>
    }

    impl Serialize for NameEnum {
        fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
            s.serialize_str(self.as_ref())
        }
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

    test_codec!(
        inner_struct,
        OuterStruct {
            data: b"test".to_vec(),
            inner: TestStruct { pkt_len: 0x010203, pad_len: 30 }
        },
        &[0, 0, 0, 4, b't', b'e', b's', b't', 0, 0, 0, 5, 0, 1, 2, 3, 30]
    );

    test_codec!(
        enum_newtype,
        TestEnum::NewtypeVariant(0x0102),
        &[0, 0, 0, 7, b'n', b'e', b'w', b't', b'y', b'p', b'e', 0, 0, 1, 2]
    );

    test_codec!(
        enum_tuple,
        TestEnum::TupleVariant("a".to_string(), "bc".to_string()),
        &[0, 0, 0, 5, b't', b'u', b'p', b'l', b'e',
            0, 0, 0, 1, b'a',
            0, 0, 0, 2, b'b', b'c'
        ]
    );

    test_codec!(
        enum_struct,
        TestEnum::StructVariant { a: 0x0102, b: "x".to_string() },
        &[0, 0, 0, 6, b's', b't', b'r', b'u', b'c', b't',
            0, 0, 1, 2,
            0, 0, 0, 1, b'x',
        ]
    );

    test_codec!(
        enum_bytes_in_struct,
        TestEnum::BytesStruct { a: b"test".to_vec(), b: true },
        b"\x00\x00\x00\x0cbytes-struct\x00\x00\x00\x04test\x01"
    );

    test_codec!(
        wrapped_enum,
        EnumWrapper {
            e: TestEnum::StructVariant { a: 0x0102, b: "x".to_string() },
            flag: true
        },
        &[
            0, 0, 0, 19,
            0, 0, 0, 6, b's', b't', b'r', b'u', b'c', b't',
            0, 0, 1, 2,
            0, 0, 0, 1, b'x',
            1
        ]
    );

    test_codec!(
        empty_name_list,
        NameListWrapper {
            e: vec![],
            f: b"test-name".to_vec()
        },
        b"\x00\x00\x00\x00\x00\x00\x00\x09test-name"
    );

    test_codec!(
        name_list,
        NameListWrapper {
            e: vec![NameEnum::TestName, NameEnum::Unknown("unknown".to_string()), NameEnum::AnotherName],
            f: b"test-name".to_vec()
        },
        b"\x00\x00\x00\x1Etest-name,unknown,another-name\x00\x00\x00\x09test-name"
    );
}
