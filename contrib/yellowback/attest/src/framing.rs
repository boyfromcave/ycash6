//! The 74-byte attestation (proposal §4; plan §3.3):
//! `seq u16 ‖ priceMicroUsd u32 ‖ citedHeight u32 ‖ sig 64`, fixed-width little-endian.
//!
//! The agent never builds one of these from parts — the node signs (`yed_signattestation`)
//! and returns the hex — but both modes decode them: `attest` to log what it publishes and
//! `subscribe` to read the `seq` it filters on.

use std::fmt;

pub const ATTESTATION_SIZE: usize = 74;
pub const SIG_SIZE: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct Attestation {
    pub seq: u16,
    pub price_micro_usd: u32,
    pub cited_height: u32,
    pub sig: [u8; SIG_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    Length(usize),
    Hex(String),
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FramingError::Length(n) => write!(f, "attestation is {n} bytes, not {ATTESTATION_SIZE}"),
            FramingError::Hex(e) => write!(f, "attestation hex: {e}"),
        }
    }
}

impl std::error::Error for FramingError {}

impl Attestation {
    pub fn decode(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() != ATTESTATION_SIZE {
            return Err(FramingError::Length(bytes.len()));
        }
        let mut sig = [0u8; SIG_SIZE];
        sig.copy_from_slice(&bytes[10..74]);
        Ok(Attestation {
            seq: u16::from_le_bytes([bytes[0], bytes[1]]),
            price_micro_usd: u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            cited_height: u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            sig,
        })
    }

    pub fn decode_hex(hex_str: &str) -> Result<Self, FramingError> {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| FramingError::Hex(e.to_string()))?;
        Self::decode(&bytes)
    }

    pub fn encode(&self) -> [u8; ATTESTATION_SIZE] {
        let mut out = [0u8; ATTESTATION_SIZE];
        out[0..2].copy_from_slice(&self.seq.to_le_bytes());
        out[2..6].copy_from_slice(&self.price_micro_usd.to_le_bytes());
        out[6..10].copy_from_slice(&self.cited_height.to_le_bytes());
        out[10..74].copy_from_slice(&self.sig);
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }
}

impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attestation{{seq {}, {} µUSD, citedHeight {}, sig {}…}}",
            self.seq,
            self.price_micro_usd,
            self.cited_height,
            hex::encode(&self.sig[..4])
        )
    }
}

/// A subscriber's message body: raw 74 bytes, or the same as hex text (an HTTPS endpoint may
/// serve either). Anything else is dropped.
pub fn parse_message(body: &[u8]) -> Result<Attestation, FramingError> {
    if body.len() == ATTESTATION_SIZE {
        return Attestation::decode(body);
    }
    match std::str::from_utf8(body) {
        Ok(text) if text.trim().len() == 2 * ATTESTATION_SIZE => Attestation::decode_hex(text),
        _ => Err(FramingError::Length(body.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Attestation {
        Attestation {
            seq: 0x0102,
            price_micro_usd: 567_585,
            cited_height: 0x00030405,
            sig: [0xab; SIG_SIZE],
        }
    }

    #[test]
    fn layout_is_little_endian_74_bytes() {
        let bytes = sample().encode();
        assert_eq!(bytes.len(), ATTESTATION_SIZE);
        assert_eq!(&bytes[0..2], &[0x02, 0x01]);
        assert_eq!(&bytes[2..6], &567_585u32.to_le_bytes());
        assert_eq!(&bytes[6..10], &[0x05, 0x04, 0x03, 0x00]);
        assert!(bytes[10..].iter().all(|b| *b == 0xab));
    }

    #[test]
    fn round_trip_bytes_and_hex() {
        let a = sample();
        assert_eq!(Attestation::decode(&a.encode()).unwrap(), a);
        assert_eq!(Attestation::decode_hex(&a.to_hex()).unwrap(), a);
        assert_eq!(a.to_hex().len(), 148);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert_eq!(Attestation::decode(&[0u8; 73]), Err(FramingError::Length(73)));
        assert_eq!(Attestation::decode(&[0u8; 75]), Err(FramingError::Length(75)));
        assert!(matches!(Attestation::decode_hex("zz"), Err(FramingError::Hex(_))));
        assert!(matches!(Attestation::decode_hex("0102"), Err(FramingError::Length(2))));
    }

    #[test]
    fn message_accepts_raw_or_hex() {
        let a = sample();
        assert_eq!(parse_message(&a.encode()).unwrap(), a);
        assert_eq!(parse_message(format!("{}\n", a.to_hex()).as_bytes()).unwrap(), a);
        assert!(parse_message(b"hello").is_err());
        assert!(parse_message(&[0u8; 148]).is_err());
    }
}
