use packet::types::ServerKey;
use transport::hton;

use std::convert::TryFrom;
use ring::digest::{Algorithm, Context, Digest};

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
    pub fn digest(&self, algorithm: &'static Algorithm) -> Result<Digest, KeyBuilderError> {
        let mut ctx = Context::new(algorithm);

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
