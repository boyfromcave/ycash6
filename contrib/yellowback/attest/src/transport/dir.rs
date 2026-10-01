//! `dir` transport: a directory both sides can reach. A publish writes
//! `<path>/<seq>-<citedHeight>.att` (74 raw bytes) through a temporary name and one rename, so a
//! reader never sees a partial file; a subscriber lists the directory every 2 s and delivers each
//! `.att` file it has not seen. Files already present at start are delivered too: the node's pool
//! is empty after a restart and rejects anything stale on its own.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::framing::Attestation;

use super::{BoxFuture, Transport};

pub const POLL: Duration = Duration::from_secs(2);

pub struct DirTransport {
    path: PathBuf,
    seen: HashSet<PathBuf>,
    pending: Vec<PathBuf>,
    poll: Duration,
}

impl DirTransport {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path).with_context(|| format!("transport dir {}", path.display()))?;
        Ok(DirTransport {
            path: path.to_path_buf(),
            seen: HashSet::new(),
            pending: Vec::new(),
            poll: POLL,
        })
    }

    #[cfg(test)]
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    pub fn file_name(message: &[u8]) -> String {
        match Attestation::decode(message) {
            Ok(a) => format!("{}-{}.att", a.seq, a.cited_height),
            Err(_) => format!("raw-{}.att", hex::encode(&message[..message.len().min(8)])),
        }
    }

    fn scan(&mut self) -> anyhow::Result<()> {
        let mut new: Vec<PathBuf> = std::fs::read_dir(&self.path)
            .with_context(|| format!("transport dir {}", self.path.display()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "att") && !self.seen.contains(p))
            .collect();
        // oldest first, so a subscriber that starts late replays in publication order
        new.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        for p in new {
            self.seen.insert(p.clone());
            self.pending.push(p);
        }
        Ok(())
    }
}

impl Transport for DirTransport {
    fn name(&self) -> &'static str {
        "dir"
    }

    fn publish<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let name = Self::file_name(message);
            let final_path = self.path.join(&name);
            let tmp = self.path.join(format!(".{name}.{}.tmp", std::process::id()));
            tokio::fs::write(&tmp, message)
                .await
                .with_context(|| format!("write {}", tmp.display()))?;
            tokio::fs::rename(&tmp, &final_path)
                .await
                .with_context(|| format!("rename to {}", final_path.display()))?;
            self.seen.insert(final_path); // never read our own publication back
            Ok(())
        })
    }

    fn recv(&mut self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async move {
            loop {
                if self.pending.is_empty() {
                    self.scan()?;
                }
                if !self.pending.is_empty() {
                    let p = self.pending.remove(0);
                    match tokio::fs::read(&p).await {
                        Ok(bytes) => return Ok(bytes),
                        Err(e) => {
                            tracing::debug!("dir: {} unreadable, skipped: {e}", p.display());
                            continue;
                        }
                    }
                }
                tokio::time::sleep(self.poll).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::Attestation;

    fn att(seq: u16, h: u32) -> Vec<u8> {
        Attestation {
            seq,
            price_micro_usd: 500_000,
            cited_height: h,
            sig: [seq as u8; 64],
        }
        .encode()
        .to_vec()
    }

    #[tokio::test]
    async fn publish_then_subscribe_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut pub_side = DirTransport::open(dir.path()).unwrap();
        let mut sub_side = DirTransport::open(dir.path())
            .unwrap()
            .with_poll(Duration::from_millis(20));
        pub_side.publish(&att(7, 100)).await.unwrap();
        assert_eq!(std::fs::metadata(dir.path().join("7-100.att")).unwrap().len(), 74);
        let got = sub_side.recv().await.unwrap();
        assert_eq!(got, att(7, 100));
        // a second publication arrives; the first is not delivered twice; a partial temp file is invisible
        std::fs::write(dir.path().join(".junk.tmp"), b"partial").unwrap();
        pub_side.publish(&att(8, 104)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), sub_side.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Attestation::decode(&got).unwrap().seq, 8);
        assert!(tokio::time::timeout(Duration::from_millis(100), sub_side.recv())
            .await
            .is_err());
        // the publisher never reads its own files back
        assert!(tokio::time::timeout(Duration::from_millis(100), pub_side.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn late_subscriber_replays_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = DirTransport::open(dir.path()).unwrap();
        for h in [10u32, 14, 18] {
            p.publish(&att(1, h)).await.unwrap();
            std::thread::sleep(Duration::from_millis(15));
        }
        let mut s = DirTransport::open(dir.path())
            .unwrap()
            .with_poll(Duration::from_millis(20));
        let mut heights = Vec::new();
        for _ in 0..3 {
            heights.push(Attestation::decode(&s.recv().await.unwrap()).unwrap().cited_height);
        }
        assert_eq!(heights, vec![10, 14, 18]);
    }

    #[test]
    fn file_names() {
        assert_eq!(DirTransport::file_name(&att(12, 3456)), "12-3456.att");
        assert_eq!(DirTransport::file_name(b"xyz"), "raw-78797a.att");
    }
}
