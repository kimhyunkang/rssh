use std::marker::PhantomData;
use super::decoder::{Name, de_bytes, de_inner, de_name_list};
use super::encoder::{ser_bytes, ser_inner, ser_name_list};

use serde::{de, ser};

struct IntoVisitor<T>(PhantomData<T>);

impl <T> de::Visitor for IntoVisitor<T> where T: Name {
    type Value = T;

    fn visit_str<E>(&mut self, v: &str) -> Result<T, E>
    {
        Ok(v.into())
    }
}

macro_rules! impl_name_enum {
    ($ty:ident {$($variant:ident => $name:expr),*}) => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, PartialEq, Clone)]
        pub enum $ty {
            $($variant),*,
            Unknown(String)
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                match *self {
                    $($ty::$variant => $name),*,
                    $ty::Unknown(ref s) => s.as_ref()
                }
            }
        }

        impl <'r> From<&'r str> for $ty {
            fn from(s: &str) -> $ty {
                match s {
                    $($name => $ty::$variant),*,
                    _ => $ty::Unknown(s.into())
                }
            }
        }

        impl de::Deserialize for $ty {
            fn deserialize<D: de::Deserializer>(d: &mut D) -> Result<$ty, D::Error> {
                d.deserialize_str(IntoVisitor(PhantomData))
            }
        }

        impl ser::Serialize for $ty {
            fn serialize<S: ser::Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
                s.serialize_str(self.as_ref())
            }
        }
    }
}

impl_name_enum!(KexAlgorithm {
    ECDH_SHA2_NISTP256 => "ecdh-sha2-nistp256",
    CURVE25519_SHA256 => "curve25519-sha256@libssh.org"
});

impl_name_enum!(ServerHostKeyAlgorithm {
    SSH_RSA => "ssh-rsa"
});

impl_name_enum!(EncryptionAlgorithm {
    AES256_CBC => "aes256-cbc",
    AES256_CTR => "aes256-ctr"
});

impl_name_enum!(MacAlgorithm {
    HMAC_SHA2_256 => "hmac-sha2-256"
});

impl_name_enum!(CompressionAlgorithm {
    NONE => "none"
});

impl_name_enum!(Language {
    EN => "en"
});

#[derive(Debug, Deserialize, Serialize)]
pub struct AlgorithmNegotiation {
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub kex_algorithms: Vec<KexAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub server_host_key_algorithms: Vec<ServerHostKeyAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub mac_algorithms_client_to_server: Vec<MacAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub mac_algorithms_server_to_client: Vec<MacAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub compression_algorithms_client_to_server: Vec<CompressionAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub compression_algorithms_server_to_client: Vec<CompressionAlgorithm>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub languages_client_to_server: Vec<Language>,
    #[serde(deserialize_with = "de_name_list", serialize_with = "ser_name_list")]
    pub languages_server_to_client: Vec<Language>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KexInit {
    #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
    pub e: Vec<u8>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KexReply {
    #[serde(deserialize_with = "de_inner", serialize_with = "ser_inner")]
    pub server_key: ServerKey,
    #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
    pub f: Vec<u8>,
    #[serde(deserialize_with = "de_inner", serialize_with = "ser_inner")]
    pub signature: Signature
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum ServerKey {
    #[serde(rename="ssh-rsa")]
    SSH_RSA {
        #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
        e: Vec<u8>,
        #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
        n: Vec<u8>
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum Signature {
    #[serde(rename="ssh-rsa")]
    SSH_RSA {
        #[serde(deserialize_with = "de_bytes", serialize_with = "ser_bytes")]
        signature: Vec<u8>
    }
}
