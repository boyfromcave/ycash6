// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The light seat's own key (beta4 item 3d, light attestor contract §2): the seat key file and the three signatures
//! the node's wallet makes for an attestor, made here byte for byte as ycashd makes them.
//!
//! - **The key file**: mode 0600 (group/world-readable is refused); its first non-empty line that is not a `#`
//!   comment is the seat's compressed secp256k1 private key in WIF, exactly what `ycash-cli dumpprivkey` prints
//!   (version 0x80 on mainnet, 0xef on testnet and regtest, the 0x01 compressed flag).
//! - **An attestation** (`yed_signattestation`, `attest.cpp` `AttestMessage`): `CKey::Sign` (RFC 6979, low S) of
//!   the 32-byte message, as the 64-byte compact `r ‖ s`.
//! - **A cancel co-signature** (`yed_signcancelcosign`, `vault::SignRecoverable`) and **the endpoint binding**
//!   (`signmessage`, `CKey::SignCompact`): the 65-byte recoverable form, header `31 + recid` (a compressed key),
//!   low S. `signmessage` signs `binding::message_hash` and returns it base64.
//!
//! RFC 6979 makes all three deterministic, so a statement signed here is the node's to the byte (the golden test
//! below holds a `signmessage` of the beta3 ycashd for the same key).

use std::path::Path;

use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use sha2::{Digest, Sha256};

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58Check decode: the payload without its 4-byte checksum.
pub fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&b| b == c)? as u32;
        for b in bytes.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&bytes);
    if out.len() < 4 {
        return None;
    }
    let (payload, check) = out.split_at(out.len() - 4);
    let sum = Sha256::digest(Sha256::digest(payload));
    (sum[..4] == *check).then(|| payload.to_vec())
}

/// Base58Check encode `payload` (the tests' WIF fixtures).
#[cfg(test)]
pub fn base58check_encode(payload: &[u8]) -> String {
    let sum = Sha256::digest(Sha256::digest(payload));
    let mut data = payload.to_vec();
    data.extend_from_slice(&sum[..4]);
    let mut digits: Vec<u8> = Vec::new();
    for &b in &data {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut s = "1".repeat(zeros);
    s.extend(digits.iter().rev().map(|&d| B58[d as usize] as char));
    s
}

/// The seat's key.
pub struct SeatKey {
    sk: SigningKey,
    pubkey: [u8; 33],
    mainnet: bool,
}

impl std::fmt::Debug for SeatKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SeatKey({})", hex::encode(self.pubkey))
    }
}

impl SeatKey {
    /// The key from a WIF string (a compressed key; mainnet 0x80, testnet/regtest 0xef).
    pub fn from_wif(wif: &str) -> Result<Self, String> {
        let p = base58check_decode(wif.trim()).ok_or("the key is not a valid WIF string (base58check)")?;
        let mainnet = match p.first() {
            Some(0x80) => true,
            Some(0xef) => false,
            _ => return Err("the key is not a WIF private key (version byte 0x80 or 0xef)".into()),
        };
        if p.len() != 34 || p[33] != 0x01 {
            return Err("the key is not a compressed WIF private key (dumpprivkey prints compressed keys)".into());
        }
        let sk = SigningKey::from_slice(&p[1..33]).map_err(|_| "the WIF key is not a valid secp256k1 scalar")?;
        let pubkey = sk
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| "public key")?;
        Ok(SeatKey { sk, pubkey, mainnet })
    }

    /// Read the key file: refused when group- or world-readable; the first non-empty, non-`#` line is the WIF.
    pub fn load(path: &Path) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
            if m.mode() & 0o077 != 0 {
                return Err(format!(
                    "key file {} is readable by group or others (mode {:04o}): chmod 600 it",
                    path.display(),
                    m.mode() & 0o7777
                ));
            }
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| format!("key file {} holds no key", path.display()))?;
        Self::from_wif(line).map_err(|e| format!("key file {}: {e}", path.display()))
    }

    pub fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey)
    }

    /// The WIF's network: mainnet (0x80) or a test network (0xef).
    pub fn mainnet(&self) -> bool {
        self.mainnet
    }

    /// `CKey::Sign` of a 32-byte digest as the compact `r ‖ s` (low S), what an attestation carries.
    pub fn sign_compact(&self, msg: &[u8; 32]) -> [u8; 64] {
        let (sig, _) = self.sign_low_s(msg);
        sig.to_bytes().into()
    }

    /// The 65-byte recoverable signature `vault::SignRecoverable` / `CKey::SignCompact` make: header 31 + recid.
    pub fn sign_recoverable(&self, msg: &[u8; 32]) -> [u8; 65] {
        let (sig, recid) = self.sign_low_s(msg);
        let mut out = [0u8; 65];
        out[0] = 31 + recid.to_byte();
        out[1..].copy_from_slice(&sig.to_bytes());
        out
    }

    /// `signmessage`'s result for `msg`: the recoverable signature over `binding::message_hash`, base64.
    pub fn sign_message(&self, msg: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.sign_recoverable(&crate::binding::message_hash(msg)))
    }

    fn sign_low_s(&self, msg: &[u8; 32]) -> (Signature, RecoveryId) {
        let (sig, recid) = self.sk.sign_prehash_recoverable(msg);
        match sig.normalize_s() {
            low if low != sig => (low, RecoveryId::from_byte(recid.to_byte() ^ 1).expect("recid")),
            _ => (sig, recid),
        }
    }
}

#[cfg(test)]
pub mod testkit {
    use super::*;

    /// A WIF of the 32-byte scalar `0x11 .. i` (the cosig testkit's keys), testnet/regtest version.
    pub fn wif(i: u8) -> String {
        let mut p = vec![0xef];
        let mut b = [0u8; 32];
        b[31] = i;
        b[0] = 0x11;
        p.extend_from_slice(&b);
        p.push(0x01);
        base58check_encode(&p)
    }

    pub fn key(i: u8) -> SeatKey {
        SeatKey::from_wif(&wif(i)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A regtest key and what the beta3 ycashd (v6.22.0-beta3, 8bfd4621e) answered for it after `importprivkey`:
    /// `validateaddress` and `signmessage <address> "yellowback light attestor golden"`.
    const GOLDEN_WIF: &str = "cQrgXJs4CUVseW1QfUCrDfHV6PLx5uJyaHC6LT2xrHJWN9QXpuwx";
    const GOLDEN_PUBKEY: &str = "02b44cf6ea2337c3051720afb3f84e00ceccb7c97ec9eb85ba577d9cbcc90282dc";
    const GOLDEN_MESSAGE: &str = "yellowback light attestor golden";
    const GOLDEN_SIGNATURE: &str =
        "IGSOe2HcLJl/kzjZrdiPVdkHW4EFeF+79Am/CuZnt8t2BDYVAiQLZj56BIvFwWoR5N19F74mrm3Jcc0L5UOotNY=";

    #[test]
    fn golden_signmessage_is_the_nodes_to_the_byte() {
        let k = SeatKey::from_wif(GOLDEN_WIF).unwrap();
        assert!(!k.mainnet());
        assert_eq!(k.pubkey_hex(), GOLDEN_PUBKEY);
        assert_eq!(k.sign_message(GOLDEN_MESSAGE), GOLDEN_SIGNATURE);
        let sig: [u8; 65] = base64::engine::general_purpose::STANDARD
            .decode(GOLDEN_SIGNATURE)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(crate::binding::recover_signer(GOLDEN_MESSAGE, &sig), Some(k.pubkey()));
    }

    /// A regtest attestor key and the attestation the beta3 ycashd's `yed_signattestation 0 750000 135` returned for it
    /// (the light e2e run: the light seat had signed the same statement, and the two are the same 74 bytes).
    #[test]
    fn golden_attestation_is_the_nodes_to_the_byte() {
        let k = SeatKey::from_wif("cVR9z4JsoPT2wLaXnyxwPDJoQwZi9LqPjsdLZGvqJPvT5wvYTNct").unwrap();
        assert_eq!(
            k.pubkey_hex(),
            "033385efe25f82d37c24f50c7f412fe1b0c3800019fce00503046ccf3d77562091"
        );
        let bh =
            crate::cosig::internal_from_display("089a678ec76e923eb5fa0bb6924bb8c4c554090322703a8aec0c97fa4792570f")
                .unwrap();
        let sig = k.sign_compact(&crate::cosig::attest_message(0, 750_000, 135, &bh));
        let att = crate::framing::Attestation {
            seq: 0,
            price_micro_usd: 750_000,
            cited_height: 135,
            sig,
        };
        assert_eq!(
            att.to_hex(),
            "0000b0710b00870000005cb1590b7e78128b63bd3f1b83a0e54dd054962f5be21829bb37b181bb758715229273b21de7738f4a81b588e45230ababc432f2548fde9297c6b3067125d8bb"
        );
    }

    #[test]
    fn wif_round_trip_and_refusals() {
        let k = testkit::key(7);
        assert_eq!(
            k.pubkey(),
            crate::cosig::testkit::pubkey(&crate::cosig::testkit::key(7))
        );
        // mainnet version byte
        let mut p = base58check_decode(&testkit::wif(7)).unwrap();
        p[0] = 0x80;
        assert!(SeatKey::from_wif(&base58check_encode(&p)).unwrap().mainnet());
        // uncompressed
        let mut u = p.clone();
        u.pop();
        assert!(SeatKey::from_wif(&base58check_encode(&u))
            .unwrap_err()
            .contains("compressed"));
        // wrong version, bad checksum, garbage
        let mut v = p.clone();
        v[0] = 0x00;
        assert!(SeatKey::from_wif(&base58check_encode(&v)).is_err());
        let mut w = testkit::wif(7);
        w.replace_range(10..11, if &w[10..11] == "a" { "b" } else { "a" });
        assert!(SeatKey::from_wif(&w).is_err());
        assert!(SeatKey::from_wif("0OIl").is_err());
    }

    #[test]
    fn signatures_verify_like_the_nodes() {
        let k = testkit::key(3);
        let bh = [9u8; 32];
        let m = crate::cosig::attest_message(4, 50_000, 120, &bh);
        let sig = k.sign_compact(&m);
        assert!(crate::cosig::verify_attestation(&k.pubkey(), 4, 50_000, 120, &bh, &sig));
        assert_eq!(sig, k.sign_compact(&m), "RFC 6979: deterministic");
        // the recoverable form is the cosig testkit's (the node's SignRecoverable) and recovers to the key
        let r = k.sign_recoverable(&m);
        assert_eq!(r, crate::cosig::testkit::sign(&crate::cosig::testkit::key(3), &m));
        assert_eq!(crate::cosig::recover(&m, &r), Some(k.pubkey()));
        assert_eq!(&r[1..], &sig[..]);
    }

    #[test]
    fn the_key_file_is_parsed_and_its_mode_checked() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("seat.key");
        std::fs::write(&p, format!("# seat 1\n\n  {}  \n", testkit::wif(5))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(SeatKey::load(&p).unwrap_err().contains("chmod 600"));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(SeatKey::load(&p).unwrap().pubkey(), testkit::key(5).pubkey());
        std::fs::write(&p, "# nothing\n").unwrap();
        assert!(SeatKey::load(&p).unwrap_err().contains("holds no key"));
    }
}
