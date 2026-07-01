// SHARED DTO -- keep BYTE-IDENTICAL with
// archetype-proxy-client/src-tauri/src/envelope.rs.
//
// The proxy seals its response to the client as a SEQUENCE of OpenHTTPA
// `seal_stream` frames rather than one monolithic AEAD blob, so large bodies
// never buffer fully in memory on either side. Each frame's plaintext is a
// serde-JSON `StreamFrame`:
//
//   * The FIRST frame is `StreamFrame::Head { status, headers }`. The OpenHTTPA
//     transport drops the real HTTP status (the client's trusted-request path
//     errors on non-2xx and discards status/headers), so the TRUE upstream (or
//     proxy-generated) status + headers MUST travel sealed INSIDE the stream.
//     The server always sends transport-level 200; the real status lives here.
//   * Every SUBSEQUENT frame is `StreamFrame::Body { data }` carrying one chunk
//     of the response body, streamed as it arrives from the upstream.
//
// Wire framing of each `seal_stream` frame (set by OpenHTTPA, not us):
//   [ len: u32 BE ][ counter: u64 BE ][ AES-256-GCM ciphertext ]
// with AAD = "openhttpa:"+base_id || cumulative_SHA384(prev ciphertexts).
//
// Promotion to a shared `archetype-proxy-common` crate is a future option.
use serde::{Deserialize, Serialize};

/// One sealed frame in the response stream (see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamFrame {
    /// First frame: the real upstream / proxy-generated status + headers.
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// Subsequent frames: one chunk of the response body (hex on the wire).
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
