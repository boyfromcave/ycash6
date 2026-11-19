// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The `yew-attestor` CLI (light attestor contract §3): the light seat's transactions — the heartbeat, the cancel
//! (`yed_buildcancel` + `set_signcancel` ported to YEW core) and the on-chain "YF" record — are built, signed with
//! the same seat key file and sent through the same lightwalletd endpoints by YEW core, which already builds vault
//! transactions. The agent runs it as a child process: one JSON object on stdout; exit 0 is success, exit 1 carries
//! `{"error", "code"}`.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::rpc::RpcError;

/// How long one command may take (it validates and sends through every endpoint).
pub const TIMEOUT: Duration = Duration::from_secs(180);
/// The most stdout a command may print.
const OUTPUT_CAP: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct YewCli {
    pub program: PathBuf,
    pub key_file: PathBuf,
    pub endpoints: Vec<String>,
    /// `--insecure`: some endpoint is plain http:// (loopback, or allowed by `allow_insecure`).
    pub insecure: bool,
    pub timeout: Duration,
}

/// The CLI's network name for the node's (`yed_getinfo.network`: main, test, regtest).
pub fn network_arg(network: &str) -> Result<&'static str, RpcError> {
    match network {
        "main" | "mainnet" => Ok("mainnet"),
        "test" | "testnet" => Ok("testnet"),
        "regtest" => Ok("regtest"),
        other => Err(RpcError::Node {
            code: -8,
            message: format!("yew-attestor: unknown network {other:?}"),
        }),
    }
}

impl YewCli {
    /// Run `yew-attestor <global options> <args>`, `stdin` written to its standard input when given.
    pub async fn run(&self, network: &str, args: &[String], stdin: Option<String>) -> Result<Value, RpcError> {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.arg("--network")
            .arg(network_arg(network)?)
            .arg("--key-file")
            .arg(&self.key_file);
        for e in &self.endpoints {
            cmd.arg("--lightwalletd").arg(e);
        }
        if self.insecure {
            cmd.arg("--insecure");
        }
        cmd.args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let what = args.first().cloned().unwrap_or_default();
        let mut child = cmd.spawn().map_err(|e| {
            RpcError::Transport(format!(
                "yew-attestor {what}: cannot run {}: {e}",
                self.program.display()
            ))
        })?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes())
                .await
                .map_err(|e| RpcError::Transport(format!("yew-attestor {what}: stdin: {e}")))?;
        }
        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| RpcError::Transport(format!("yew-attestor {what}: no answer within {:?}", self.timeout)))?
            .map_err(|e| RpcError::Transport(format!("yew-attestor {what}: {e}")))?;
        let stderr = String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2000)])
            .trim()
            .to_string();
        if !stderr.is_empty() {
            tracing::debug!("yew-attestor {what}: {stderr}");
        }
        let stdout = &out.stdout[..out.stdout.len().min(OUTPUT_CAP)];
        let text = String::from_utf8_lossy(stdout);
        let v: Option<Value> = text
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .and_then(|l| serde_json::from_str(l.trim()).ok())
            .filter(Value::is_object);
        match (out.status.success(), v) {
            (true, Some(v)) => Ok(v),
            (false, Some(v)) if v.get("error").is_some() => {
                let error = v.get("error").and_then(Value::as_str).unwrap_or("").to_string();
                let code = v.get("code").and_then(Value::as_str).unwrap_or("").to_string();
                let message = if code.is_empty() || error.starts_with(&code) {
                    error
                } else {
                    format!("{code}: {error}")
                };
                Err(RpcError::Node { code: -1, message })
            }
            _ => Err(RpcError::Transport(format!(
                "yew-attestor {what}: exit {} without a JSON object on stdout{}",
                out.status.code().map_or("by signal".to_string(), |c| c.to_string()),
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(" (stderr: {stderr})")
                }
            ))),
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! A stand-in `yew-attestor` for the tests: a shell script that logs its arguments (and stdin) and prints the
    //! answer the test put in a file per command.
    use std::path::{Path, PathBuf};

    pub struct FakeYew {
        pub dir: tempfile::TempDir,
        pub program: PathBuf,
    }

    impl FakeYew {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let program = dir.path().join("yew-attestor");
            let script = r#"#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/args.log"
cmd=""
for a in "$@"; do
  case "$a" in heartbeat|cancel|op-return|join|leave|withdraw|address) cmd="$a";; esac
done
if [ "$cmd" = "cancel" ]; then cat > "$d/stdin.log"; fi
if [ -f "$d/$cmd.exit" ]; then cat "$d/$cmd.out"; exit "$(cat "$d/$cmd.exit")"; fi
cat "$d/$cmd.out"
"#;
            std::fs::write(&program, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            FakeYew { dir, program }
        }

        pub fn answer(&self, cmd: &str, json: &str, exit: i32) {
            std::fs::write(self.dir.path().join(format!("{cmd}.out")), format!("{json}\n")).unwrap();
            let p = self.dir.path().join(format!("{cmd}.exit"));
            if exit != 0 {
                std::fs::write(p, exit.to_string()).unwrap();
            } else {
                let _ = std::fs::remove_file(p);
            }
        }

        pub fn args(&self) -> Vec<String> {
            read_lines(&self.dir.path().join("args.log"))
        }

        pub fn stdin(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("stdin.log")).unwrap_or_default()
        }
    }

    fn read_lines(p: &Path) -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeYew;
    use super::*;

    fn cli(f: &FakeYew) -> YewCli {
        YewCli {
            program: f.program.clone(),
            key_file: "/k".into(),
            endpoints: vec!["http://127.0.0.1:1".into(), "https://b:9067".into()],
            insecure: true,
            timeout: Duration::from_secs(10),
        }
    }

    #[tokio::test]
    async fn runs_with_the_global_options_and_maps_errors() {
        let f = FakeYew::new();
        f.answer("heartbeat", r#"{"txid":"ab"}"#, 0);
        let v = cli(&f)
            .run("regtest", &["heartbeat".into(), "--set".into(), "ff".into()], None)
            .await
            .unwrap();
        assert_eq!(v["txid"], "ab");
        assert_eq!(
            f.args()[0],
            "--network regtest --key-file /k --lightwalletd http://127.0.0.1:1 --lightwalletd https://b:9067 --insecure heartbeat --set ff"
        );
        f.answer("heartbeat", r#"{"error":"no confirmed coin","code":"no-funds"}"#, 1);
        let e = cli(&f).run("main", &["heartbeat".into()], None).await.unwrap_err();
        assert!(
            matches!(&e, RpcError::Node { message, .. } if message == "no-funds: no confirmed coin"),
            "{e}"
        );
        assert!(f.args()[1].starts_with("--network mainnet "));
        f.answer("cancel", "", 2);
        let e = cli(&f)
            .run(
                "test",
                &["cancel".into(), "--cosigs".into(), "-".into()],
                Some("[\"aa\"]".into()),
            )
            .await
            .unwrap_err();
        assert!(matches!(e, RpcError::Transport(_)));
        assert_eq!(f.stdin(), "[\"aa\"]");
        assert!(cli(&f).run("other", &[], None).await.is_err());
    }
}
