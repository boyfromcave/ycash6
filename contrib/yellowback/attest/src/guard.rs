// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The light seat's equivocation guard (S16; light attestor contract §4): every statement the seat key signed,
//! attestations and cancel co-signatures alike, appended and fsynced before the signature leaves the agent.
//!
//! The file is ycashd's own `<datadir>/yellowback/attest-signed.dat` byte for byte (`src/yellowback/wallet.cpp`
//! `RecordSigned` / `LoadSigned`): the magic `"YBS" 2`, then one 106-byte line per signature, `seq LE16 ‖
//! citedHeight LE32 ‖ price LE32 ‖ sig 64 ‖ blockHash 32` (the cited block's hash in internal byte order). So a seat
//! moved from a node to a light host takes its node's guard file along unchanged (and back). A v1 file (`"YBS" 1`,
//! 74-byte lines with no hash) is honoured for every hash and rewritten as v2 on load, as the node does; a torn
//! last line (the process died mid-append, so it never returned that signature) is ignored. A file with another
//! magic is refused: the agent then signs nothing rather than sign without its record.
//!
//! Lines are keyed on (seq, citedHeight, blockHash): after a reorg across citedHeight a signature for the new block
//! is not equivocation (EQV-1 verifies under the block's real hash, audit C-5).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAGIC: [u8; 4] = [b'Y', b'B', b'S', 2];
pub const MAGIC_V1: [u8; 4] = [b'Y', b'B', b'S', 1];
pub const LINE: usize = 2 + 4 + 4 + 64 + 32;
pub const LINE_V1: usize = 2 + 4 + 4 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub seq: u16,
    pub cited_height: u32,
    pub price: u32,
    pub sig: [u8; 64],
    /// Internal byte order; all zero for a v1 line (honoured for every hash).
    pub block_hash: [u8; 32],
}

impl Signed {
    fn encode(&self) -> [u8; LINE] {
        let mut b = [0u8; LINE];
        b[0..2].copy_from_slice(&self.seq.to_le_bytes());
        b[2..6].copy_from_slice(&self.cited_height.to_le_bytes());
        b[6..10].copy_from_slice(&self.price.to_le_bytes());
        b[10..74].copy_from_slice(&self.sig);
        b[74..106].copy_from_slice(&self.block_hash);
        b
    }

    fn decode(b: &[u8]) -> Self {
        let mut block_hash = [0u8; 32];
        if b.len() >= LINE {
            block_hash.copy_from_slice(&b[74..106]);
        }
        Signed {
            seq: u16::from_le_bytes([b[0], b[1]]),
            cited_height: u32::from_le_bytes(b[2..6].try_into().expect("4")),
            price: u32::from_le_bytes(b[6..10].try_into().expect("4")),
            sig: b[10..74].try_into().expect("64"),
            block_hash,
        }
    }
}

#[derive(Debug)]
pub struct Guard {
    path: PathBuf,
    lines: BTreeMap<(u16, u32, [u8; 32]), Signed>,
}

impl Guard {
    /// Load `path` (absent: an empty guard; the file is created on the first signature).
    pub fn load(path: &Path) -> Result<Guard, String> {
        let mut g = Guard {
            path: path.to_path_buf(),
            lines: BTreeMap::new(),
        };
        g.reload()?;
        Ok(g)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the file (another process with the same guard, e.g. the `cosign` command, may have appended).
    pub fn reload(&mut self) -> Result<(), String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.lines.clear();
                return Ok(());
            }
            Err(e) => return Err(format!("guard file {}: {e}", self.path.display())),
        };
        if raw.len() < 4 {
            return Err(format!(
                "guard file {} is damaged (shorter than its magic); refusing to sign without it",
                self.path.display()
            ));
        }
        let legacy = raw[0..4] == MAGIC_V1;
        if !legacy && raw[0..4] != MAGIC {
            return Err(format!(
                "guard file {} is not an attest-signed.dat (bad magic); refusing to sign without it",
                self.path.display()
            ));
        }
        let size = if legacy { LINE_V1 } else { LINE };
        let mut lines = BTreeMap::new();
        let whole = (raw.len() - 4) / size;
        for chunk in raw[4..].chunks_exact(size) {
            let s = Signed::decode(chunk);
            lines.insert((s.seq, s.cited_height, s.block_hash), s);
        }
        self.lines = lines;
        if !legacy && 4 + whole * size != raw.len() {
            // an interrupted append never returned its signature: cut it off so the next line starts aligned
            tracing::warn!(
                "guard file {}: a torn last line ({} bytes) is cut off",
                self.path.display(),
                raw.len() - 4 - whole * size
            );
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&self.path)
                .map_err(|e| format!("guard file {}: {e}", self.path.display()))?;
            f.set_len((4 + whole * size) as u64)
                .and_then(|_| f.sync_all())
                .map_err(|e| format!("guard file {}: {e}", self.path.display()))?;
        }
        if legacy {
            self.rewrite_v2()?;
        }
        Ok(())
    }

    /// The node's v1 → v2 rewrite: every line, in the v2 layout, renamed over the file.
    fn rewrite_v2(&self) -> Result<(), String> {
        let tmp = self.path.with_extension("v2");
        let mut buf = MAGIC.to_vec();
        for s in self.lines.values() {
            buf.extend_from_slice(&s.encode());
        }
        let mut f = open_new(&tmp)?;
        f.write_all(&buf)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("guard file {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("guard file {}: {e}", self.path.display()))
    }

    /// `LookupSigned`: the line of (seq, citedHeight, blockHash), or a v1 line of (seq, citedHeight).
    pub fn lookup(&self, seq: u16, cited_height: u32, block_hash: &[u8; 32]) -> Option<&Signed> {
        self.lines
            .get(&(seq, cited_height, *block_hash))
            .or_else(|| self.lines.get(&(seq, cited_height, [0u8; 32])))
    }

    /// `RecordSigned`: append one line and fsync it; kept in memory only once it is on disk.
    pub fn record(&mut self, s: Signed) -> Result<(), String> {
        let fresh = !self.path.exists();
        if !fresh {
            let mut head = [0u8; 4];
            let ok = std::fs::File::open(&self.path)
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
                .is_ok();
            if !ok || head != MAGIC {
                return Err(format!(
                    "guard-write-failed: {} is not a v2 guard file; nothing was signed",
                    self.path.display()
                ));
            }
        }
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| format!("guard-write-failed: {}: {e}", dir.display()))?;
        }
        let mut buf = Vec::with_capacity(4 + LINE);
        if fresh {
            buf.extend_from_slice(&MAGIC);
        }
        buf.extend_from_slice(&s.encode());
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o
            .open(&self.path)
            .map_err(|e| format!("guard-write-failed: {}: {e}", self.path.display()))?;
        f.write_all(&buf)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("guard-write-failed: {}: {e}", self.path.display()))?;
        self.lines.insert((s.seq, s.cited_height, s.block_hash), s);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }
}

fn open_new(p: &Path) -> Result<std::fs::File, String> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p).map_err(|e| format!("guard file {}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u16, h: u32, price: u32, bh: u8) -> Signed {
        Signed {
            seq,
            cited_height: h,
            price,
            sig: [seq as u8; 64],
            block_hash: [bh; 32],
        }
    }

    #[test]
    fn appends_reloads_and_is_the_nodes_layout() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("seat.guard");
        let mut g = Guard::load(&p).unwrap();
        assert!(g.lookup(3, 100, &[1; 32]).is_none());
        g.record(line(3, 100, 50_000, 1)).unwrap();
        g.record(line(3, 110, 51_000, 1)).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(raw.len(), 4 + 2 * LINE);
        assert_eq!(&raw[0..4], b"YBS\x02");
        // seq LE16, citedHeight LE32, price LE32, sig, hash: the node's SerializationOp order
        assert_eq!(&raw[4..14], &[3, 0, 100, 0, 0, 0, 0x50, 0xc3, 0, 0]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        }
        let g2 = Guard::load(&p).unwrap();
        assert_eq!(g2.len(), 2);
        assert_eq!(g2.lookup(3, 100, &[1; 32]).unwrap().price, 50_000);
        assert!(
            g2.lookup(3, 100, &[2; 32]).is_none(),
            "another block's hash is another line"
        );
        assert!(g2.lookup(4, 100, &[1; 32]).is_none());
    }

    #[test]
    fn a_torn_tail_is_ignored_a_bad_magic_refused_v1_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g");
        let mut g = Guard::load(&p).unwrap();
        g.record(line(1, 10, 100, 7)).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw.extend_from_slice(&[1, 2, 3]);
        std::fs::write(&p, &raw).unwrap();
        let mut g = Guard::load(&p).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(std::fs::read(&p).unwrap().len(), 4 + LINE, "the torn tail is cut off");
        g.record(line(1, 11, 101, 7)).unwrap();
        assert_eq!(Guard::load(&p).unwrap().lookup(1, 11, &[7; 32]).unwrap().price, 101);

        std::fs::write(&p, b"XXXX").unwrap();
        assert!(Guard::load(&p).unwrap_err().contains("bad magic"));
        std::fs::write(&p, b"YB").unwrap();
        assert!(Guard::load(&p).is_err());

        // v1: no hash, honoured for every hash, rewritten as v2
        let mut v1 = MAGIC_V1.to_vec();
        v1.extend_from_slice(&line(2, 20, 200, 0).encode()[..LINE_V1]);
        std::fs::write(&p, &v1).unwrap();
        let mut g = Guard::load(&p).unwrap();
        assert_eq!(g.lookup(2, 20, &[5; 32]).unwrap().price, 200);
        assert_eq!(&std::fs::read(&p).unwrap()[0..4], &MAGIC);
        g.record(line(2, 21, 201, 5)).unwrap();
        assert_eq!(Guard::load(&p).unwrap().len(), 2);
    }
}
