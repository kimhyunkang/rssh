pub struct KeyContext {
    v_c: String,
    v_s: String,
    i_c: Vec<u8>,
    i_s: Vec<u8>,
    k_s: Vec<u8>,
    e: Vec<u8>,
    f: Vec<u8>,
    k: Vec<u8>
}

pub enum ClientHandshakeState {
    VersionExchange { v_c: String, v_s: Option<String>, end_of_write: bool },
    AlgorithmExchange { i_c: String, i_s: Option<String>, end_of_write: bool },
    KeyWrite { e: Vec<u8>, flushing: bool },
    KexReply
}
