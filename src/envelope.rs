// This is a wire type. Its serde schema is duplicated in
// archetype-proxy-client/src-tauri/src/envelope.rs; change both copies together
// or client and server will fail to decode each other's frames.
use serde::{Deserialize, Serialize};

/// One frame of a sealed response stream.
///
/// The response travels as a sequence of `seal_stream` frames: a single `Head`
/// carrying the status and headers, followed by `Body` frames for the payload.
/// Status and headers ride inside the stream because the OpenHTTPA client
/// discards the transport-level response line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamFrame {
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Body {
        #[serde(with = "serde_bytes_hex")]
        data: Vec<u8>,
    },
}

mod serde_bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
