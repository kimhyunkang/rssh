use packet::types::ServerKey;
use transport::hton;

use std::convert::TryFrom;
use ring::digest::{Context, Digest};

#[derive(Debug, Default)]
pub struct KeyBuilder {
    pub v_c: Option<String>,
    pub v_s: Option<String>,
    pub i_c: Option<Vec<u8>>,
    pub i_s: Option<Vec<u8>>,
    pub k_s: Option<Vec<u8>>,
    pub e: Option<Vec<u8>>,
    pub f: Option<Vec<u8>>,
    pub k: Option<Vec<u8>>,
    pub server_key: Option<ServerKey>
}

#[derive(Debug)]
pub struct KeyBuilderError;

impl KeyBuilder {
    pub fn digest(&self, mut ctx: Context) -> Result<Digest, KeyBuilderError> {
        macro_rules! update_digest {
            ($field:ident) => {
                {
                    if let Some(ref $field) = self.$field {
                        let len: u32 = match TryFrom::try_from($field.len()) {
                            Ok(l) => l,
                            Err(_) => return Err(KeyBuilderError)
                        };
                        ctx.update(&hton(len));
                        ctx.update($field);
                    } else {
                        return Err(KeyBuilderError);
                    }
                }
            }
        }

        macro_rules! update_digest_string {
            ($field:ident) => {
                {
                    if let Some(ref $field) = self.$field {
                        let len: u32 = match TryFrom::try_from($field.len()) {
                            Ok(l) => l,
                            Err(_) => return Err(KeyBuilderError)
                        };
                        ctx.update(&hton(len));
                        ctx.update($field.as_bytes());
                    } else {
                        return Err(KeyBuilderError);
                    }
                }
            }
        }

        update_digest_string!(v_c);
        update_digest_string!(v_s);
        update_digest!(i_c);
        update_digest!(i_s);
        update_digest!(k_s);
        update_digest!(e);
        update_digest!(f);
        update_digest!(k);

        Ok(ctx.finish())
    }
}

#[cfg(test)]
mod test {
    use super::KeyBuilder;

    use std::str;
    use ring::digest;
    use rustc_serialize::hex::FromHex;

    #[test]
    fn keybuilder_hash() {
        let test_data = include_bytes!("../test_data/test.dat");
        let mut test_payloads: Vec<Vec<u8>> = test_data.split(|&c| c == b'\n').map(|slice| str::from_utf8(slice).unwrap().from_hex().unwrap()).collect();
        let v_c = String::from_utf8(test_payloads.remove(0)).unwrap();
        let v_s = String::from_utf8(test_payloads.remove(0)).unwrap();
        let i_c = test_payloads.remove(0);
        let i_s = test_payloads.remove(0);
        let k_s = test_payloads.remove(0);
        let e = test_payloads.remove(0);
        let f = test_payloads.remove(0);
        let k = test_payloads.remove(0);
        let h = test_payloads.remove(0);
        let keybuilder = KeyBuilder { v_c: Some(v_c), v_s: Some(v_s), i_c: Some(i_c), i_s: Some(i_s), k_s: Some(k_s), e: Some(e), f: Some(f), k: Some(k), server_key: None };
        let hash = digest::Context::new(&digest::SHA256);
        assert_eq!(keybuilder.digest(hash).unwrap().as_ref(), h.as_slice());
    }
}
